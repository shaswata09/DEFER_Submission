"""defense-freeze-v3.1.4: the handoff channel reaches the next agent, and tool
hiding belongs to P2 (JUDGEONLY and a run without P2 see every tool)."""
from agents.base_agent import BaseAgent
from host.orchestrator import _render_handoff_fields


def test_injected_handoff_fields_are_rendered_as_text():
    text = _render_handoff_fields({"assessed_severity": "critical",
                                   "recommended_actions": ["revoke s.patel"]})
    assert "critical" in text and "s.patel" in text
    assert _render_handoff_fields({}) == ""


class _Stub(BaseAgent):
    def __init__(self, config):                     # no model, no logger
        self.config = config
        self.tool_schemas = [{"name": "phase_tool"}]
        self.all_tool_schemas = [{"name": "phase_tool"}, {"name": "other_tool"}]


def test_tool_visibility_follows_p2():
    assert len(_Stub("flat").get_tools_for_llm()) == 2
    assert len(_Stub("llm_judge").get_tools_for_llm()) == 2     # JUDGEONLY: no P2
    assert len(_Stub("agenticcyops").get_tools_for_llm()) == 1
    a = _Stub("agenticcyops")
    a.show_all_tools = True                                      # set by the host under -P2
    assert len(a.get_tools_for_llm()) == 2
