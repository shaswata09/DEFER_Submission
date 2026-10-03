"""
MCP Tool Server Template.

Reusable base class for domain tool stubs. Each tool is a FastAPI app
with MCP protocol support, observable state, and structured logging.

Usage:
    server = BaseMCPServer(
        tool_id="T8_iam_pam",
        tool_name="IAM/PAM Credential Manager",
        description="Revoke, reset, or escalate user credentials",
        input_schema={...},
        handler=my_handler_function,
    )
    app = server.app  # FastAPI app
"""

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from logging_utils import ExperimentLogger
from mcp_servers.signing import sign


class ToolCallRequest(BaseModel):
    """Request body for tool invocation."""
    arguments: dict
    source: str = "unknown"
    incident_id: Optional[str] = None


class InjectRequest(BaseModel):
    """Harness-only: response override for the next call(s) (H5)."""
    response: Any
    mode: str = "merge"       # merge | replace
    calls: int = 1


class BaseMCPServer:
    """Generic MCP tool server template."""

    def __init__(
        self,
        tool_id: str,
        tool_name: str,
        description: str,
        input_schema: dict,
        handler: Callable,
        logger: Optional[ExperimentLogger] = None,
    ):
        self.tool_id = tool_id
        self.tool_name = tool_name
        self.description = description
        self.input_schema = input_schema
        self.handler = handler
        self.logger = logger

        self.state: dict[str, Any] = {
            "actions_log": [],
            "call_count": 0,
            "last_call": None,
        }
        # Harness-injected responses (H5 ``tool_response`` channel).  Only
        # honoured when the server runs under the harness
        # (HARNESS_INJECTION=1); a production deployment never applies them.
        self.harness_injection = os.environ.get("HARNESS_INJECTION", "") == "1"
        self._injections: list[dict] = []

        self.app = FastAPI(title=tool_name, description=description)
        self._register_routes()

    def _register_routes(self):
        tool_id = self.tool_id

        @self.app.post(f"/tools/{tool_id}/call")
        async def call_tool(request: ToolCallRequest):
            return await self._handle_call(request)

        @self.app.get(f"/tools/{tool_id}/schema")
        async def get_schema():
            return {
                "name": self.tool_id,
                "description": self.description,
                "inputSchema": self.input_schema,
            }

        @self.app.get("/state")
        async def get_state():
            return self.state

        @self.app.post("/reset")
        async def reset_state():
            self.state = {
                "actions_log": [],
                "call_count": 0,
                "last_call": None,
            }
            self._injections = []
            return {"status": "reset", "tool_id": self.tool_id}

        @self.app.post("/inject")
        async def inject(request: InjectRequest):
            """Queue a response override for the next ``calls`` invocations.

            ``mode="merge"`` (default) lays ``response`` over the real
            result; ``mode="replace"`` returns ``response`` as the result.
            Refused unless the server was started with HARNESS_INJECTION=1.
            """
            if not self.harness_injection:
                raise HTTPException(status_code=403,
                                    detail="injection disabled (HARNESS_INJECTION != 1)")
            for _ in range(max(1, request.calls)):
                self._injections.append({"mode": request.mode, "response": request.response})
            return {"status": "queued", "tool_id": self.tool_id, "pending": len(self._injections)}

        @self.app.get("/health")
        async def health():
            return {"status": "ok", "tool_id": self.tool_id}

    async def _handle_call(self, request: ToolCallRequest) -> dict:
        start = time.perf_counter()
        payload_hash = hashlib.sha256(
            json.dumps(request.arguments, sort_keys=True, default=str).encode()
        ).hexdigest()[:8]

        try:
            result = await self.handler(request.arguments, self.state)
            injected = False
            if self.harness_injection and self._injections:
                inj = self._injections.pop(0)
                injected = True
                if inj.get("mode") == "replace" or not isinstance(result, dict):
                    result = inj.get("response")
                else:
                    result = {**result, **(inj.get("response") or {})}

            self.state["call_count"] += 1
            self.state["last_call"] = datetime.now(timezone.utc).isoformat()

            elapsed_ms = (time.perf_counter() - start) * 1000

            if self.logger:
                self.logger.log_tool_call(
                    agent=request.source,
                    tool=self.tool_id,
                    auth_decision="allow",
                    mechanism="none",
                    payload=request.arguments,
                    latency_ms=elapsed_ms,
                )

            out = {
                "status": "success",
                "tool_id": self.tool_id,
                "result": result,
                "payload_hash": payload_hash,
            }
            sig = sign(out)
            if sig:
                out["signature"] = sig
            if injected:
                out["_harness_injected"] = True   # audit marker; stripped before the model sees it
            return out

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if self.logger:
                self.logger.log_tool_call(
                    agent=request.source,
                    tool=self.tool_id,
                    auth_decision="error",
                    mechanism="none",
                    latency_ms=elapsed_ms,
                )
            out = {
                "status": "error",
                "tool_id": self.tool_id,
                "error": str(e),
            }
            sig = sign(out)
            if sig:
                out["signature"] = sig
            return out

    def get_openai_tool_schema(self) -> dict:
        """Return OpenAI-compatible tool definition for LLM tool_choice."""
        return {
            "type": "function",
            "function": {
                "name": self.tool_id,
                "description": self.description,
                "parameters": self.input_schema,
            },
        }
