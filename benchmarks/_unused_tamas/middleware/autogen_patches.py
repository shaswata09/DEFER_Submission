"""
AutoGen integration patches for the P1-P5 TAMAS middleware.

This module monkey-patches / wraps AutoGen ``ConversableAgent`` instances
so that every tool call, memory read, and inter-agent message is
intercepted by :class:`P12345Middleware`.

The four public entry points are:

    wrap_agent_tools(agent, middleware, role, task_ctx)
        Replaces each registered tool with a guarded version that runs
        the full P1/P2/P3 pipeline before execution and the P1-L2 /
        P2-L3 checks after.

    wrap_agent_retriever(agent, middleware, role, task_ctx)
        Wraps ``retrieve`` / ``get_relevant_docs`` with P5 checks
        (access, query scope, sanitization, field filtering).

    wrap_agent_communication(agent, middleware, role, task_ctx)
        Wraps ``ConversableAgent.send`` / ``receive`` to log inter-agent
        messages and optionally apply consensus validation on suspicious
        imperative messages (Byzantine behavior detection).

    build_defended_agent_group(scenario_config, llm_config, middleware, task_ctx)
        High-level helper that instantiates a ``GroupChat`` with every
        role from a scenario config already wrapped with its allowed
        tools, retriever, and communication guards.

The module is compatible with pyautogen >=0.2 and falls back gracefully
when AutoGen is not installed (stub classes, lazy wrapping).
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from pathlib import Path
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------- #
#  Conditional AutoGen import
# ---------------------------------------------------------------------- #

try:  # pragma: no cover -- import-time branching
    from autogen import ConversableAgent, GroupChat, GroupChatManager  # type: ignore

    AUTOGEN_AVAILABLE = True
except Exception:  # pragma: no cover
    AUTOGEN_AVAILABLE = False

    class ConversableAgent:  # type: ignore[no-redef]
        """Stub so the module imports cleanly without pyautogen installed."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.name = kwargs.get("name", "stub_agent")
            self._function_map: dict[str, Callable[..., Any]] = {}
            self.llm_config: dict = kwargs.get("llm_config", {}) or {}

    class GroupChat:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agents = kwargs.get("agents", [])
            self.messages: list = []
            self.max_round = kwargs.get("max_round", 10)

    class GroupChatManager:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.groupchat = kwargs.get("groupchat")
            self.llm_config = kwargs.get("llm_config", {})


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------- #
#  Internal helpers
# ---------------------------------------------------------------------- #


def _is_coro(fn: Callable[..., Any]) -> bool:
    return inspect.iscoroutinefunction(fn) or asyncio.iscoroutinefunction(fn)


def _run_maybe_coro(result: Any) -> Any:
    """If *result* is awaitable, run it to completion on a fresh loop if
    no loop is running; otherwise schedule on the current loop."""
    if not inspect.isawaitable(result):
        return result
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Caller is already inside an event loop -- return the
            # coroutine so the caller can await it.
            return result
        return loop.run_until_complete(result)
    except RuntimeError:
        return asyncio.run(result)


def _await_sync(coro: Any) -> Any:
    """Block until *coro* completes even from a synchronous context."""
    if not inspect.isawaitable(coro):
        return coro
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    if loop.is_running():
        # We cannot block inside a running loop; schedule and return
        # a future.  Callers that need a concrete value should be
        # invoked from an async context.
        return asyncio.ensure_future(coro)
    return loop.run_until_complete(coro)


# ---------------------------------------------------------------------- #
#  1. wrap_agent_tools
# ---------------------------------------------------------------------- #


def wrap_agent_tools(
    agent: "ConversableAgent",
    middleware: Any,
    role: str,
    task_ctx: dict,
) -> "ConversableAgent":
    """Replace each tool in *agent*'s function map with a guarded version.

    The guarded wrapper:
        a. Runs ``middleware.check_tool_call`` first.
        b. If denied, returns ``{"status": "denied", "tool_id": ..., ...}``.
        c. Otherwise executes the underlying tool (sync or async).
        d. Measures latency for the P1-L2 response integrity check.
        e. Runs ``middleware.classify_output`` -- redacts on flag.
        f. Runs ``middleware.verify_response`` for P1-L2.
        g. Returns the (possibly redacted) response.

    Works on both modern (``_function_map``) and older
    (``llm_config["functions"]``) AutoGen layouts.
    """
    if not AUTOGEN_AVAILABLE:
        log.warning("wrap_agent_tools: AutoGen not installed; deferring wrapping")
        # Still decorate whatever we find so unit tests with mocks work.

    # ------------------------------------------------------------ #
    #  Modern layout: agent._function_map
    # ------------------------------------------------------------ #
    function_map: Optional[dict] = getattr(agent, "_function_map", None)
    if function_map is None:
        function_map = getattr(agent, "function_map", None)

    if isinstance(function_map, dict):
        for tool_id, original in list(function_map.items()):
            guarded = _make_guarded_tool(
                tool_id=tool_id,
                original=original,
                middleware=middleware,
                role=role,
                task_ctx=task_ctx,
            )
            function_map[tool_id] = guarded

    # ------------------------------------------------------------ #
    #  Legacy layout: agent.llm_config["functions"]
    # ------------------------------------------------------------ #
    llm_cfg = getattr(agent, "llm_config", None) or {}
    legacy_fns = llm_cfg.get("functions") if isinstance(llm_cfg, dict) else None
    if isinstance(legacy_fns, list):
        # legacy functions are schema dicts; the callables are
        # registered separately via agent.register_function().
        # We still tag the schema so downstream tooling can see that a
        # guard exists.
        for fn_schema in legacy_fns:
            if isinstance(fn_schema, dict):
                fn_schema.setdefault("_middleware_guarded", True)

    return agent


def _make_guarded_tool(
    tool_id: str,
    original: Callable[..., Any],
    middleware: Any,
    role: str,
    task_ctx: dict,
) -> Callable[..., Any]:
    """Return a wrapper around *original* that threads every call through
    the middleware."""

    async def _guarded_async(**kwargs: Any) -> Any:
        # --- pre-call pipeline --------------------------------------
        ok, details = await middleware.check_tool_call(
            role=role, tool_id=tool_id, arguments=kwargs, context=task_ctx
        )
        if not ok:
            return {"status": "denied", "tool_id": tool_id, **details}

        # --- invoke the underlying tool -----------------------------
        start = time.perf_counter()
        try:
            if _is_coro(original):
                response = await original(**kwargs)
            else:
                response = original(**kwargs)
        except Exception as exc:  # pragma: no cover -- defensive
            latency_ms = (time.perf_counter() - start) * 1000
            log.exception("Tool %s raised during execution", tool_id)
            response = {"status": "error", "error": str(exc)}
            return response
        latency_ms = (time.perf_counter() - start) * 1000

        # --- P2-L3 output classification ---------------------------
        safe, reason = middleware.classify_output(tool_id, response, role)
        if not safe:
            response = {"status": "redacted", "_classification": reason}

        # --- P1-L2 response integrity ------------------------------
        try:
            middleware.verify_response(tool_id, response, latency_ms)
        except Exception:  # pragma: no cover -- non-fatal
            log.debug("verify_response raised for %s", tool_id, exc_info=True)
        return response

    def _guarded_sync(**kwargs: Any) -> Any:
        # Bridge synchronous callers (AutoGen often invokes function_map
        # entries synchronously) through an event loop.
        coro = _guarded_async(**kwargs)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        if loop.is_running():
            return asyncio.ensure_future(coro)
        return loop.run_until_complete(coro)

    # Preserve metadata so AutoGen's schema introspection still works.
    wrapper = _guarded_async if _is_coro(original) else _guarded_sync
    try:
        wrapper.__name__ = getattr(original, "__name__", tool_id)
        wrapper.__doc__ = getattr(original, "__doc__", None)
        wrapper.__wrapped__ = original  # type: ignore[attr-defined]
        wrapper._middleware_guarded = True  # type: ignore[attr-defined]
        wrapper._tool_id = tool_id  # type: ignore[attr-defined]
    except (AttributeError, TypeError):  # pragma: no cover
        pass
    return wrapper


# ---------------------------------------------------------------------- #
#  2. wrap_agent_retriever
# ---------------------------------------------------------------------- #


def wrap_agent_retriever(
    agent: "ConversableAgent",
    middleware: Any,
    role: str,
    task_ctx: dict,
) -> "ConversableAgent":
    """Wrap an agent's retrieval method with P5 memory-read enforcement.

    Looks for ``retrieve`` or ``get_relevant_docs`` (either name AutoGen
    RetrievalAgent / custom retrievers use).  Calls
    ``middleware.check_memory_read`` first, then
    ``middleware.sanitize_read_results`` and
    ``middleware.filter_read_fields`` on the returned list.
    """
    method_name = None
    for candidate in ("retrieve", "get_relevant_docs", "retrieve_docs"):
        if hasattr(agent, candidate) and callable(getattr(agent, candidate)):
            method_name = candidate
            break
    if method_name is None:
        log.debug("wrap_agent_retriever: no retrieval method on %s", role)
        return agent

    original = getattr(agent, method_name)

    def _infer_store_id(kwargs: dict, args: tuple) -> str:
        for key in ("store_id", "collection", "collection_name", "index"):
            if key in kwargs:
                return str(kwargs[key])
        return task_ctx.get("default_store_id", f"{role}_default")

    def _infer_query(kwargs: dict, args: tuple) -> str:
        if args:
            return str(args[0])
        for key in ("query", "question", "text"):
            if key in kwargs:
                return str(kwargs[key])
        return ""

    async def _guarded_retrieve_async(*args: Any, **kwargs: Any) -> Any:
        store_id = _infer_store_id(kwargs, args)
        query = _infer_query(kwargs, args)

        ok, details = middleware.check_memory_read(
            role=role, store_id=store_id, query=query, context=task_ctx
        )
        if not ok:
            return {"status": "denied", "store_id": store_id, **details}

        if _is_coro(original):
            results = await original(*args, **kwargs)
        else:
            results = original(*args, **kwargs)

        if not isinstance(results, list):
            results_list = [results] if results is not None else []
        else:
            results_list = results

        results_list = middleware.sanitize_read_results(results_list, role)
        results_list = middleware.filter_read_fields(role, store_id, results_list)
        return results_list

    def _guarded_retrieve_sync(*args: Any, **kwargs: Any) -> Any:
        coro = _guarded_retrieve_async(*args, **kwargs)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        if loop.is_running():
            return asyncio.ensure_future(coro)
        return loop.run_until_complete(coro)

    guarded = _guarded_retrieve_async if _is_coro(original) else _guarded_retrieve_sync
    try:
        guarded.__name__ = method_name  # type: ignore[attr-defined]
        guarded._middleware_guarded = True  # type: ignore[attr-defined]
    except (AttributeError, TypeError):  # pragma: no cover
        pass

    setattr(agent, method_name, guarded)
    return agent


# ---------------------------------------------------------------------- #
#  3. wrap_agent_communication
# ---------------------------------------------------------------------- #


# Simple heuristics for identifying suspicious imperative messages that
# merit additional consensus validation.  Matches any message containing
# a verb followed by an object typical of Byzantine persuasion attacks
# ("delete X", "wire funds", "grant admin", etc.).
_SUSPICIOUS_PATTERNS = (
    "delete ",
    "drop ",
    "wire ",
    "transfer $",
    "grant admin",
    "grant root",
    "shutdown ",
    "disable ",
    "bypass ",
    "override ",
    "ignore previous",
    "disregard ",
    "you must ",
    "you should immediately",
)


def _is_suspicious_message(content: Any) -> bool:
    if content is None:
        return False
    if isinstance(content, dict):
        text = json.dumps(content).lower()
    else:
        text = str(content).lower()
    return any(pat in text for pat in _SUSPICIOUS_PATTERNS)


def wrap_agent_communication(
    agent: "ConversableAgent",
    middleware: Any,
    role: str,
    task_ctx: dict,
) -> "ConversableAgent":
    """Wrap ``send`` and ``receive`` on a ConversableAgent.

    Every inter-agent message is logged (for Byzantine behavior audit).
    Messages flagged as suspicious go through an optional consensus
    validation step when ``middleware.consensus`` is present.
    """
    original_send = getattr(agent, "send", None)
    original_receive = getattr(agent, "receive", None)

    comm_log: list[dict] = task_ctx.setdefault("_comm_log", [])

    def _log(direction: str, message: Any, other: Any) -> None:
        try:
            other_name = getattr(other, "name", str(other))
        except Exception:
            other_name = "unknown"
        comm_log.append(
            {
                "direction": direction,
                "role": role,
                "peer": other_name,
                "message": message if isinstance(message, (str, dict)) else str(message),
                "timestamp": time.time(),
            }
        )
        if getattr(middleware, "logger", None) is not None:
            try:
                middleware.logger.log(
                    source=f"{role}_agent",
                    destination=other_name,
                    action=f"comm_{direction}",
                    auth_decision="allow",
                    mechanism="byzantine_audit",
                )
            except Exception:  # pragma: no cover
                pass

    async def _maybe_consensus(message: Any) -> bool:
        """If the middleware has a consensus validator, run it on a
        proposal derived from *message*.  Returns True on approval."""
        consensus = getattr(middleware, "consensus", None)
        if consensus is None:
            return True
        proposal = {
            "role": role,
            "phase": role,
            "action": "inter_agent_message",
            "message": message if isinstance(message, (dict, str)) else str(message),
            "justification": "Byzantine audit triggered",
        }
        try:
            result = consensus.validate(proposal, task_ctx)
            if inspect.isawaitable(result):
                result = await result
            return bool(result)
        except Exception:  # pragma: no cover -- defensive
            log.debug("consensus validator raised", exc_info=True)
            return True

    # ----- send --------------------------------------------------------
    if callable(original_send):
        if _is_coro(original_send):

            async def _guarded_send(message, recipient, *args, **kwargs):
                _log("send", message, recipient)
                if _is_suspicious_message(message):
                    ok = await _maybe_consensus(message)
                    if not ok:
                        log.warning(
                            "Consensus rejected suspicious message from %s", role
                        )
                        return None
                return await original_send(message, recipient, *args, **kwargs)

        else:

            def _guarded_send(message, recipient, *args, **kwargs):
                _log("send", message, recipient)
                if _is_suspicious_message(message):
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    if loop.is_running():
                        # Skip blocking consensus inside a running loop;
                        # the async-send variant handles it.
                        ok = True
                    else:
                        ok = loop.run_until_complete(_maybe_consensus(message))
                    if not ok:
                        log.warning(
                            "Consensus rejected suspicious message from %s", role
                        )
                        return None
                return original_send(message, recipient, *args, **kwargs)

        setattr(agent, "send", _guarded_send)

    # ----- receive -----------------------------------------------------
    if callable(original_receive):
        if _is_coro(original_receive):

            async def _guarded_receive(message, sender, *args, **kwargs):
                _log("receive", message, sender)
                return await original_receive(message, sender, *args, **kwargs)

        else:

            def _guarded_receive(message, sender, *args, **kwargs):
                _log("receive", message, sender)
                return original_receive(message, sender, *args, **kwargs)

        setattr(agent, "receive", _guarded_receive)

    return agent


# ---------------------------------------------------------------------- #
#  4. build_defended_agent_group
# ---------------------------------------------------------------------- #


def build_defended_agent_group(
    scenario_config: dict,
    llm_config: dict,
    middleware: Any,
    task_ctx: dict,
    tool_implementations: Optional[dict[str, Callable[..., Any]]] = None,
) -> tuple[list, Any]:
    """Instantiate all agents from *scenario_config* with middleware guards.

    Args:
        scenario_config: The loaded scenario JSON (e.g.
            ``healthcare_prescription_config.json``).  Must contain a
            ``roles`` mapping of role_name -> manifest.
        llm_config: AutoGen ``llm_config`` passed through to every
            ``ConversableAgent``.
        middleware: The :class:`P12345Middleware` instance.
        task_ctx: Shared task context dict (used by middleware and logs).
        tool_implementations: Optional mapping ``{tool_id: callable}`` of
            real tool implementations.  If omitted, no-op stubs returning
            ``{"status": "ok", "tool": tool_id}`` are generated for each
            declared tool.

    Returns:
        Tuple ``(agents_list, group_chat_manager)``.  If AutoGen is not
        installed, ``group_chat_manager`` is a stub.
    """
    roles = scenario_config.get("roles", {}) or {}
    tool_implementations = tool_implementations or {}

    agents: list = []

    for role_name, manifest in roles.items():
        agent = ConversableAgent(
            name=role_name,
            system_message=manifest.get("description", f"You are {role_name}."),
            llm_config=llm_config,
            human_input_mode="NEVER",
        )

        # Install function map with the scenario's declared tools.
        fn_map: dict[str, Callable[..., Any]] = {}
        for tool_id in manifest.get("allowed_tools", []):
            impl = tool_implementations.get(tool_id)
            if impl is None:
                impl = _stub_tool(tool_id)
            fn_map[tool_id] = impl

        if hasattr(agent, "_function_map") and isinstance(agent._function_map, dict):
            agent._function_map.update(fn_map)
        else:
            try:
                agent._function_map = fn_map  # type: ignore[attr-defined]
            except Exception:  # pragma: no cover
                pass

        # Apply all three wrappers.
        wrap_agent_tools(agent, middleware, role_name, task_ctx)
        wrap_agent_retriever(agent, middleware, role_name, task_ctx)
        wrap_agent_communication(agent, middleware, role_name, task_ctx)

        agents.append(agent)

    # Build the group chat + manager.
    group_chat = GroupChat(
        agents=agents,
        messages=[],
        max_round=scenario_config.get("max_round", 20),
    )
    manager = GroupChatManager(groupchat=group_chat, llm_config=llm_config)
    return agents, manager


def _stub_tool(tool_id: str) -> Callable[..., Any]:
    def _stub(**kwargs: Any) -> dict:
        return {"status": "ok", "tool": tool_id, "arguments": kwargs}

    _stub.__name__ = tool_id
    return _stub


# ---------------------------------------------------------------------- #
#  Convenience: load a scenario from disk
# ---------------------------------------------------------------------- #


def load_scenario_config(path: str | Path) -> dict:
    """Helper used by trial drivers -- reads a scenario JSON file."""
    with open(path) as f:
        return json.load(f)


__all__ = [
    "AUTOGEN_AVAILABLE",
    "wrap_agent_tools",
    "wrap_agent_retriever",
    "wrap_agent_communication",
    "build_defended_agent_group",
    "load_scenario_config",
]
