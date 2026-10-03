"""
ACL Middleware for acl_hardened configuration.

HTTP-level enforcement that wraps tool calls. In acl_hardened mode,
the agent sees ALL tools (like flat) but out-of-scope calls get
HTTP 403 at this layer — mimicking network-level ACLs.

This is distinct from DEFER which enforces at the application
layer (ManifestEnforcer) BEFORE the LLM even sees the tools.
"""

from typing import Optional

from host.manifest_enforcer import ManifestEnforcer
from logging_utils import ExperimentLogger


class ACLMiddleware:
    """HTTP-level ACL enforcement for acl_hardened config.

    In acl_hardened, the LLM sees all 16 tools and can attempt to call
    any of them. This middleware intercepts the call and returns 403
    for out-of-scope tools — simulating network-level ACLs.

    Key difference from ManifestEnforcer:
    - ManifestEnforcer (P2): prevents the call at application layer
    - ACLMiddleware: lets the call through but blocks at "network" layer
    - In the experiment, this means the LLM was still manipulated into
      attempting the call, even though it was blocked.
    """

    def __init__(
        self,
        enforcer: ManifestEnforcer,
        logger: Optional[ExperimentLogger] = None,
    ):
        self.enforcer = enforcer
        self.logger = logger

    async def check_tool_call(
        self, agent_phase: str, tool_id: str
    ) -> tuple[bool, str]:
        """Check if a tool call is allowed by ACLs.

        Returns (allowed, reason). Logs 403 denials.
        """
        allowed, reason = self.enforcer.validate_tool_call(agent_phase, tool_id)
        if not allowed:
            if self.logger:
                self.logger.log_tool_call(
                    agent=f"{agent_phase}_agent",
                    tool=tool_id,
                    auth_decision="deny",
                    mechanism="acl_network_layer",
                    interception_step=2,
                )
            return False, f"403 Forbidden: {reason}"
        return True, "allowed"

    async def check_memory_read(
        self, agent_phase: str, store_id: str
    ) -> tuple[bool, str]:
        """Check if a memory read is allowed."""
        allowed, reason = self.enforcer.validate_memory_read(agent_phase, store_id)
        if not allowed:
            if self.logger:
                self.logger.log_memory_read(
                    agent=f"{agent_phase}_agent",
                    store=store_id,
                    auth_decision="deny",
                    mechanism="acl_network_layer",
                )
            return False, f"403 Forbidden: {reason}"
        return True, "allowed"

    async def check_memory_write(
        self, agent_phase: str, store_id: str
    ) -> tuple[bool, str]:
        """Check if a memory write is allowed.

        Note: In acl_hardened, there's NO write-boundary filtering (P4).
        Only ACL-level access control. The content is NOT checked for
        semantic relevance.
        """
        allowed, reason = self.enforcer.validate_memory_write(agent_phase, store_id)
        if not allowed:
            if self.logger:
                self.logger.log_memory_write(
                    agent=f"{agent_phase}_agent",
                    store=store_id,
                    auth_decision="deny",
                    mechanism="acl_network_layer",
                )
            return False, f"403 Forbidden: {reason}"
        return True, "allowed"
