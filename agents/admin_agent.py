"""Response/Remediation phase agent. Thin wrapper around BaseAgent."""

from agents.base_agent import BaseAgent


class AdminAgent(BaseAgent):
    def __init__(self, domain: str, config: str = "agenticcyops", **kwargs):
        super().__init__(phase="admin", domain=domain, config=config, **kwargs)
