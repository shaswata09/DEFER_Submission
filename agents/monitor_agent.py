"""Monitor/Triage phase agent. Thin wrapper around BaseAgent."""

from agents.base_agent import BaseAgent


class MonitorAgent(BaseAgent):
    def __init__(self, domain: str, config: str = "agenticcyops", **kwargs):
        super().__init__(phase="monitor", domain=domain, config=config, **kwargs)
