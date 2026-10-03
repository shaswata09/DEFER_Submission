"""
Domain-agnostic LLM-powered phase agent.

Each agent loads its system prompt and tool schemas from the domain config,
uses the primary LLM to reason and propose tool calls, and returns
structured output for handoff.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from openai import OpenAI

from config import BASE_DIR, model_display_name
from logging_utils import ExperimentLogger


@dataclass
class ToolCallProposal:
    tool_id: str
    arguments: dict
    justification: str = ""
    # Assigned by the host when the proposal is first seen; links the
    # ``tool_proposed`` audit event to every later event for this call.
    # Deliberately not part of ``to_proposal()``: P3 hashes proposals for
    # replay detection and the id must not make every call look unique.
    call_id: str = ""

    def to_proposal(self) -> dict:
        return {
            "tool_id": self.tool_id,
            "arguments": self.arguments,
            "justification": self.justification,
        }


@dataclass
class AgentResult:
    phase: str
    proposed_tool_calls: list[ToolCallProposal] = field(default_factory=list)
    tool_responses: list[dict] = field(default_factory=list)
    reasoning: str = ""
    summary: str = ""
    memory_reads: list[dict] = field(default_factory=list)
    memory_writes: list[dict] = field(default_factory=list)
    latency_ms: float = 0.0
    tokens_prompt: int = 0
    tokens_completion: int = 0

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "proposed_tool_calls": [tc.to_proposal() for tc in self.proposed_tool_calls],
            "tool_responses": self.tool_responses,
            "reasoning": self.reasoning,
            "summary": self.summary,
            "memory_reads": self.memory_reads,
            "memory_writes": self.memory_writes,
            "latency_ms": self.latency_ms,
            "tokens_prompt": self.tokens_prompt,
            "tokens_completion": self.tokens_completion,
        }


class BaseAgent:
    """Domain-agnostic LLM-powered agent for a single phase."""

    def __init__(
        self,
        phase: str,
        domain: str,
        config: str = "agenticcyops",
        llm_url: str = "http://localhost:8000/v1",
        llm_provider: str = "openai",
        llm_model: Optional[str] = None,
        api_key_env: Optional[str] = None,
        extra_body: Optional[dict] = None,
        manifest: Optional[dict] = None,
        tool_schemas: Optional[list[dict]] = None,
        all_tool_schemas: Optional[list[dict]] = None,
        logger: Optional[ExperimentLogger] = None,
    ):
        """
        Args:
            llm_provider: "openai" for vLLM/OpenAI-compatible, "anthropic" for Claude API
            llm_model: Model name override (e.g. "claude-sonnet-4-5-20250929")
            api_key_env: Env-var name to read the OpenAI-compatible API key
                from (e.g. "NVIDIA_API_KEY" for NVIDIA cloud). Absent for
                self-hosted vLLM which ignores the key.
            extra_body: Optional dict of model-specific extras passed in
                every chat.completions.create call (e.g. NVIDIA Nemotron
                reasoning toggle).
        """
        self.phase = phase
        self.domain = domain
        self.config = config
        self.llm_url = llm_url
        self.llm_provider = llm_provider
        self.manifest = manifest or {}
        self.tool_schemas = tool_schemas or []
        self.all_tool_schemas = all_tool_schemas or []
        self.logger = logger
        self._api_key_env = api_key_env
        self._extra_body = extra_body
        # Sampling (H7): the primary samples at PRIMARY_TEMPERATURE (default
        # 0.7); the harness sets a per-trial seed which is passed to the
        # server (vLLM / OpenAI honour it; Anthropic has no seed) and logged.
        self.temperature: float = float(os.environ.get("PRIMARY_TEMPERATURE", "0.7"))
        self.seed: Optional[int] = None

        if llm_provider == "anthropic":
            from anthropic import Anthropic
            from config import load_env
            load_env()
            self._anthropic_client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
            self._model_name = llm_model or "claude-sonnet-4-5-20250929"
            self._client = None
        else:
            from config import load_env
            load_env()
            api_key = os.environ.get(api_key_env, "") if api_key_env else "unused"
            self._client = OpenAI(base_url=llm_url, api_key=api_key)
            self._model_name = llm_model
            self._anthropic_client = None

        self._system_prompt = self._load_prompt()

    def set_seed(self, seed: Optional[int]) -> None:
        """Per-trial sampling seed (H7)."""
        self.seed = None if seed is None else int(seed)

    def set_temperature(self, temperature: float) -> None:
        self.temperature = float(temperature)

    def _load_prompt(self) -> str:
        path = BASE_DIR / "domains" / self.domain / "prompts" / f"{self.phase}.txt"
        if path.exists():
            return path.read_text().strip()
        return f"You are a {self.phase} agent. Analyze the input and propose actions."

    def _detect_model(self):
        if self._model_name is None:
            try:
                models = self._client.models.list()
                if models.data:
                    self._model_name = models.data[0].id
            except Exception:
                pass
            if self._model_name is None:
                self._model_name = "default"

    def switch_model(self, url: str = None, provider: str = "openai", model: str = None):
        """Switch LLM endpoint or provider (for diversity checks)."""
        self.llm_provider = provider
        if provider == "anthropic":
            from anthropic import Anthropic
            from config import load_env
            load_env()
            self._anthropic_client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
            self._model_name = model or "claude-sonnet-4-5-20250929"
            self._client = None
        else:
            self.llm_url = url or self.llm_url
            self._client = OpenAI(base_url=self.llm_url, api_key="unused")
            self._model_name = model

    def _format_context(self, context: dict) -> str:
        """Build user message from incident context and prior phase outputs."""
        parts = []

        incident = context.get("incident", {})
        # ``memory_ops`` is harness scripting (which reads / writes to
        # perform), not part of the alert the operator would see.
        shown = {k: v for k, v in incident.items() if k != "memory_ops"} if isinstance(incident, dict) else incident
        parts.append("## Incident")
        parts.append(json.dumps(shown, indent=2, default=str))

        # Results of this phase's memory reads (performed by the host
        # before this call, H4)
        reads = (context.get("memory_context") or {}).get(self.phase) or []
        entries = [(r.get("store"), d) for r in reads if isinstance(r, dict)
                   for d in (r.get("documents") or [])]
        if entries:
            parts.append("\n## Memory Context")
            for store, doc in entries[:6]:
                parts.append(f"[{store}] {doc}")

        # Include prior phase handoffs
        for phase in ("monitor", "analyze", "admin"):
            handoff_key = f"{phase}_handoff"
            if handoff_key in context:
                hd = context[handoff_key]
                parts.append(f"\n## {phase.title()} Phase Results")
                parts.append(hd.get("phase_summary", "No summary available."))
                if hd.get("tool_results"):
                    parts.append(f"Tool results: {json.dumps(hd['tool_results'][:5], default=str)}")

        return "\n\n".join(parts)

    def get_tools_for_llm(self) -> Optional[list[dict]]:
        """Return tool schemas based on config.

        CRITICAL: This controls what the agent can even TRY to call.
        - flat/acl_hardened: Agent sees ALL tools (can attempt out-of-scope calls)
        - agenticcyops: Agent sees ONLY manifest tools (doesn't know others exist)
        """
        # v3.1.4: also JUDGEONLY and any run with P2 disabled (the orchestrator
        # sets ``show_all_tools``): tool hiding is part of capability scoping
        if self.config in ("flat", "acl_hardened", "llm_judge") or getattr(self, "show_all_tools", False):
            return self.all_tool_schemas or self.tool_schemas or None
        else:
            return self.tool_schemas or None

    async def execute(self, context: dict) -> AgentResult:
        """Reason about the task and propose tool calls."""
        import time
        self._detect_model()

        user_message = self._format_context(context)
        tools = self.get_tools_for_llm()

        start = time.perf_counter()

        if self.llm_provider == "anthropic":
            result, tokens_prompt, tokens_completion = self._call_anthropic(user_message, tools)
        else:
            result, tokens_prompt, tokens_completion = self._call_openai(user_message, tools)

        latency_ms = (time.perf_counter() - start) * 1000

        if self.logger:
            self.logger.log(
                source=f"{self.phase}_agent",
                destination="llm",
                action="llm_call",
                auth_decision="allow",
                latency_ms=latency_ms,
                tokens_prompt=tokens_prompt,
                tokens_completion=tokens_completion,
                extra={
                    "model": model_display_name(self._model_name),
                    "provider": self.llm_provider,
                    "temperature": self.temperature,
                    "seed": self.seed,
                    "tools_visible": len(tools) if tools else 0,
                    "config": self.config,
                },
            )

        result.latency_ms = latency_ms
        result.tokens_prompt = tokens_prompt
        result.tokens_completion = tokens_completion
        return result

    def _call_openai(self, user_message: str, tools) -> tuple:
        """Call OpenAI-compatible API (vLLM, GPT-4o, NVIDIA cloud, ...)."""
        kwargs = {
            "model": self._model_name,
            "messages": [
                {"role": "system", "content": self._system_prompt},
                {"role": "user", "content": user_message},
            ],
            "temperature": self.temperature,
            "max_tokens": 4096,
        }
        if self.seed is not None:
            kwargs["seed"] = int(self.seed)
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if self._extra_body:
            kwargs["extra_body"] = self._extra_body

        # Throttle + retry on rate-limit-shaped errors (NIM 404 cold-evict,
        # 429).  Throttle is inside the retry loop so each retry waits for
        # the next available slot.  No-op for vLLM / Anthropic endpoints.
        from utils.rate_limiter import throttle_for_url, call_with_retry
        def _do_call():
            throttle_for_url(self.llm_url)
            return self._client.chat.completions.create(**kwargs)
        response = call_with_retry(_do_call)

        tokens_prompt = response.usage.prompt_tokens or 0 if response.usage else 0
        tokens_completion = response.usage.completion_tokens or 0 if response.usage else 0

        return self._parse_response(response), tokens_prompt, tokens_completion

    def _call_anthropic(self, user_message: str, tools) -> tuple:
        """Call Anthropic Claude API with tool use support."""
        # Convert OpenAI tool schemas to Anthropic format
        anthropic_tools = []
        if tools:
            for t in tools:
                func = t.get("function", t)
                anthropic_tools.append({
                    "name": func["name"],
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {}),
                })

        kwargs = {
            "model": self._model_name,
            "system": self._system_prompt,
            "messages": [{"role": "user", "content": user_message}],
            "temperature": self.temperature,
            "max_tokens": 4096,
        }
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        response = self._anthropic_client.messages.create(**kwargs)

        tokens_prompt = response.usage.input_tokens or 0
        tokens_completion = response.usage.output_tokens or 0

        return self._parse_anthropic_response(response), tokens_prompt, tokens_completion

    def _parse_anthropic_response(self, response) -> AgentResult:
        """Parse Anthropic response into AgentResult."""
        result = AgentResult(phase=self.phase)

        for block in response.content:
            if block.type == "text":
                result.reasoning += block.text
                try:
                    parsed = json.loads(block.text)
                    if not isinstance(parsed, dict):
                        raise TypeError("non-object JSON")
                    result.summary = parsed.get("triage_summary",
                                     parsed.get("response_summary",
                                     parsed.get("summary", block.text[:200])))
                except (json.JSONDecodeError, TypeError, ValueError):
                    result.summary = block.text[:200]

            elif block.type == "tool_use":
                result.proposed_tool_calls.append(
                    ToolCallProposal(
                        tool_id=block.name,
                        arguments=block.input or {},
                        justification=f"Claude proposed: {block.name}",
                    )
                )

        if not result.summary:
            result.summary = result.reasoning[:200] if result.reasoning else "No content"

        return result

    def _parse_response(self, response) -> AgentResult:
        """Parse LLM response into AgentResult."""
        message = response.choices[0].message
        result = AgentResult(phase=self.phase)

        # Extract reasoning/content
        content = message.content or ""
        result.reasoning = content

        # Try to parse JSON from content.  Models sometimes answer with a
        # JSON array or scalar; anything that is not an object is treated as
        # free text (this raised AttributeError and voided the trial before).
        try:
            parsed = json.loads(content)
            if not isinstance(parsed, dict):
                raise TypeError("non-object JSON")
            result.summary = parsed.get("triage_summary",
                             parsed.get("response_summary",
                             parsed.get("summary", content[:200])))
            # Extract memory write proposals
            for key in ("memory_writes", "proposed_writes"):
                if key in parsed and isinstance(parsed[key], list):
                    result.memory_writes = [w for w in parsed[key] if isinstance(w, dict)]
        except (json.JSONDecodeError, TypeError, ValueError):
            result.summary = content[:200] if content else "No content"

        # Extract tool calls from structured response
        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                if not isinstance(args, dict):
                    # v3.1: a list or string crashed P2 in the defended configs only
                    args = {}
                result.proposed_tool_calls.append(
                    ToolCallProposal(
                        tool_id=tc.function.name,
                        arguments=args,
                        justification=f"LLM proposed: {tc.function.name}",
                    )
                )

        # Fallback: parse pythonic tool calls from text content
        # Llama-4 outputs [func_name(arg="val")] in text instead of structured calls
        if not result.proposed_tool_calls and content:
            import re
            # Match patterns like [func_name(key="val", ...)] or func_name(key="val")
            pattern = r'\[?(\w+)\(([^)]*)\)\]?'
            for match in re.finditer(pattern, content):
                func_name = match.group(1)
                args_str = match.group(2)
                # Only accept known tool IDs (starts with T/H/F/L followed by digit)
                if not re.match(r'^[THFL]\d', func_name):
                    continue
                # Parse args: key="val" or key='val'
                args = {}
                for arg_match in re.finditer(r'(\w+)\s*=\s*["\']([^"\']*)["\']', args_str):
                    args[arg_match.group(1)] = arg_match.group(2)
                result.proposed_tool_calls.append(
                    ToolCallProposal(
                        tool_id=func_name,
                        arguments=args,
                        justification=f"Parsed from text: {func_name}",
                    )
                )

        return result
