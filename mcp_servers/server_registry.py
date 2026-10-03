"""
Tool Server Registry.

Manages tool servers for a given domain. Starts/stops servers,
resolves tool endpoints, and provides schemas for LLM tool_choice.

Usage:
    registry = ServerRegistry(domain="cyberops", logger=logger)
    await registry.start_all(base_port=9000)
    url = registry.get_tool_url("T8_iam_pam")
    schemas = registry.get_all_schemas()
    await registry.stop_all()
"""

import asyncio
import importlib
import httpx
from pathlib import Path
from typing import Optional

import uvicorn

from config import BASE_DIR
from logging_utils import ExperimentLogger
from mcp_servers.base_server import BaseMCPServer


class ServerRegistry:
    """Loads and manages tool servers for a given domain."""

    def __init__(
        self,
        domain: str,
        logger: Optional[ExperimentLogger] = None,
    ):
        self.domain = domain
        self.logger = logger
        self._servers: dict[str, BaseMCPServer] = {}
        self._ports: dict[str, int] = {}
        self._uvicorn_servers: list = []
        self._tasks: list[asyncio.Task] = []

    def _discover_tools(self) -> list[tuple[str, str]]:
        """Discover tool modules in domains/{domain}/tools/.

        Returns list of (module_path, tool_id) tuples.
        """
        tools_dir = BASE_DIR / "domains" / self.domain / "tools"
        results = []
        for phase_dir in sorted(tools_dir.iterdir()):
            if not phase_dir.is_dir() or phase_dir.name.startswith("_"):
                continue
            for tool_file in sorted(phase_dir.glob("[a-z]*.py")):
                module_path = f"domains.{self.domain}.tools.{phase_dir.name}.{tool_file.stem}"
                results.append((module_path, tool_file.stem))
        return results

    def load_tools(self):
        """Import all tool modules and call their create_server() functions."""
        for module_path, tool_stem in self._discover_tools():
            try:
                mod = importlib.import_module(module_path)
                server = mod.create_server(logger=self.logger)
                self._servers[server.tool_id] = server
            except Exception as e:
                print(f"  Warning: Failed to load {module_path}: {e}")

    def assign_ports(self, base_port: int = 9000) -> dict:
        """Deterministic tool -> port map: sorted tool ids, sequential ports.

        Both sides use this one method -- ``start_all`` (the process that
        serves the tools) and every client (harness, baseline runner).
        Until 2026-09 the servers were numbered in module-discovery order
        while the clients assumed sorted order, so most calls reached the
        wrong tool's server and came back as 404 "Not Found".
        """
        self._ports = {tool_id: base_port + i for i, tool_id in enumerate(sorted(self._servers))}
        return dict(self._ports)

    async def start_all(self, base_port: int = 9000):
        """Start all loaded tool servers on sequential ports."""
        self.load_tools()
        self.assign_ports(base_port)
        for tool_id, port in self._ports.items():
            server = self._servers[tool_id]
            config = uvicorn.Config(
                server.app,
                host="127.0.0.1",
                port=port,
                log_level="warning",
            )
            uv_server = uvicorn.Server(config)
            task = asyncio.create_task(uv_server.serve())
            self._uvicorn_servers.append(uv_server)
            self._tasks.append(task)

    async def stop_all(self):
        """Stop all running tool servers."""
        for server in self._uvicorn_servers:
            server.should_exit = True
        for task in self._tasks:
            task.cancel()
        self._uvicorn_servers.clear()
        self._tasks.clear()

    def get_tool_url(self, tool_id: str) -> str:
        """Get the HTTP endpoint for a tool."""
        port = self._ports.get(tool_id)
        if port is None:
            raise KeyError(f"Tool {tool_id} not registered")
        return f"http://127.0.0.1:{port}"

    async def call_tool(self, tool_id: str, arguments: dict, source: str = "unknown") -> dict:
        """Call a tool via HTTP."""
        url = self.get_tool_url(tool_id)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{url}/tools/{tool_id}/call",
                json={"arguments": arguments, "source": source},
                timeout=30,
            )
            return resp.json()

    def get_all_schemas(self) -> list[dict]:
        """Get OpenAI-compatible tool schemas for all loaded tools."""
        return [s.get_openai_tool_schema() for s in self._servers.values()]

    def get_phase_schemas(self, allowed_tools: list[str]) -> list[dict]:
        """Get schemas for tools allowed by a phase manifest."""
        return [
            s.get_openai_tool_schema()
            for tid, s in self._servers.items()
            if tid in allowed_tools
        ]

    def list_tools(self) -> dict[str, int]:
        """Return mapping of tool_id -> port."""
        return dict(self._ports)
