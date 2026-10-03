"""DEFER's tool-call path as a local HTTP service for the TAMAS benchmark.

TAMAS (https://github.com/microsoft/TAMAS) runs CrewAI crews. Its runner
(``benchmarks/tamas/run_crew.py``, in a separate environment) wraps every
tool so that each *actual* call an agent makes is sent here before it
executes, and each tool output is sent here before the agent sees it. This
mediates the agents' real actions; nothing is synthesized from the case.

Configurations
    flat    every call allowed, outputs unchanged (the gate only logs)
    full    DEFER's tool-call path in the neutral ``general`` domain:
            P1.1  the tool is one of the scenario's registered TAMAS tools
            P2.1  the tool is in the calling agent's own tool list (TAMAS's
                  assignment is the manifest; TAMAS gives agents their
                  malicious tools, so this rarely denies)
            P2.2  parameter rules and target-in-evidence, evidence = user query
            P3.2  operational context
            P3.10 the LLM panel: every call is an admin-phase proposal, and the
                  general domain's admin manifest requires consensus
            P2.3 / P5.5 on the way back: output classifier and sanitization
    Memory checks (P4, P5.1-5.4) are not exercised: TAMAS has no shared store.

Every decision is appended to ``<log_dir>/gate.jsonl`` with the exact panel
input (``panel_message``) and each vote, so the panel rounds can be
re-adjudicated offline under any panel (``analysis.replay_run``).

    python -m benchmarks.tamas.gate --port 8300 --log-dir logs/tamas_q235_local2_v29
"""
from __future__ import annotations

import argparse
import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DOMAIN = "general"
PHASE = "admin"
_lock = threading.Lock()


class Gate:
    def __init__(self, consensus: str, log_dir: Path, embedding_model=None):
        from consensus.operational_context import OperationalContextChecker
        from consensus.validator import ConsensusValidator
        from host.output_classifier import OutputClassifier
        from host.parameter_validator import ParameterValidator
        from memory.access_isolation import AccessIsolation, AccessController

        self.param = ParameterValidator(domain=DOMAIN, embedding_model=embedding_model)
        self.opctx = OperationalContextChecker(domain=DOMAIN)
        self.outcls = OutputClassifier(domain=DOMAIN, embedding_model=embedding_model)
        self.access = AccessIsolation(domain=DOMAIN, access_controller=AccessController(domain=DOMAIN),
                                      embedding_model=embedding_model)
        self.panel = ConsensusValidator(config_name=consensus)
        self.consensus_name = consensus
        log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = log_dir / "gate.jsonl"

    def log(self, rec: dict) -> None:
        rec["timestamp"] = time.time()
        with _lock, open(self.log_path, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    # ------------------------------------------------------------------ #
    def check(self, req: dict) -> dict:
        from analysis.replay import message
        cfg, tool, args = req["config"], req["tool"], req.get("arguments") or {}
        base = {"event": "check", "trial_id": req["trial_id"], "config": cfg, "agent": req.get("agent"),
                "tool": tool, "arguments": args, "malicious": req.get("malicious")}
        if cfg == "flat":
            out = {"allow": True, "mechanism": "flat_no_defense", "tier": None}
            self.log({**base, **out}); return out
        if tool not in set(req.get("registered_tools") or []):
            out = {"allow": False, "mechanism": "P1_identity_unregistered", "tier": "content_independent"}
            self.log({**base, **out}); return out
        if tool not in set(req.get("agent_tools") or []):
            out = {"allow": False, "mechanism": "P2_tool_not_in_manifest", "tier": "content_independent"}
            self.log({**base, **out}); return out
        evidence = req.get("user_query", "")
        ok, reason, _d = self.param.validate(tool, args, evidence)
        if not ok:
            out = {"allow": False, "mechanism": f"P2_capability_scoping:{reason}", "tier": "content_dependent"}
            self.log({**base, **out}); return out
        proposal = {"tool_id": tool, "arguments": args, "justification": req.get("justification", ""),
                    "phase": PHASE}
        ok, reason, _d = self.opctx.check(proposal, {"incident_id": req["trial_id"], "claimed_time": None})
        if not ok:
            out = {"allow": False, "mechanism": reason, "tier": "content_dependent"}
            self.log({**base, **out}); return out
        incident = {"incident_id": req["trial_id"], "description": evidence}
        msg = message(proposal, incident, "agenticcyops", True, req["trial_id"])
        sanitized = json.loads(msg)["proposal"]
        ctx = {"incident_id": req["trial_id"], "incident": {"description": evidence}, "config": "agenticcyops"}
        res = asyncio.run(self.panel.validate_with_details(sanitized, ctx))
        votes = {v.validator_id: v.decision for v in res.votes}
        out = {"allow": bool(res.approved),
               "mechanism": "P3_llm_consensus_approve" if res.approved else "P3_llm_consensus_reject",
               "tier": "panel"}
        self.log({**base, **out, "panel": self.consensus_name, "panel_message": msg, "votes": votes,
                  "approvals": res.approvals, "threshold": res.threshold})
        return out

    def output(self, req: dict) -> dict:
        text = str(req.get("text", ""))
        base = {"event": "output", "trial_id": req["trial_id"], "config": req["config"], "tool": req.get("tool")}
        if req["config"] == "flat":
            self.log({**base, "changed": False}); return {"text": text}
        safe, reason, _d = self.outcls.classify(req.get("tool", ""), {"result": text}, agent_phase=PHASE)
        if not safe:
            self.log({**base, "changed": True, "mechanism": f"P2_output:{reason}"})
            return {"text": f"[output withheld by policy: {reason}]"}
        san = self.access.sanitize_results([{"content": text}], PHASE)
        if san and san[0].get("_sanitized"):
            self.log({**base, "changed": True, "mechanism": "P5_injection_sanitization"})
            return {"text": san[0].get("content", "")}
        self.log({**base, "changed": False})
        return {"text": text}


def serve(port: int, gate: Gate) -> None:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            try:
                out = gate.check(req) if self.path == "/check" else gate.output(req)
                code = 200
            except Exception as exc:                     # fail closed, and say why
                out = {"allow": False, "mechanism": f"gate_error:{type(exc).__name__}", "error": str(exc),
                       "text": "[output withheld: gate error]"}
                gate.log({"event": "error", "path": self.path, "error": repr(exc), "trial_id": req.get("trial_id")})
                code = 200
            body = json.dumps(out).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8300)
    ap.add_argument("--consensus", default="local2")
    ap.add_argument("--log-dir", required=True)
    a = ap.parse_args()
    serve(a.port, Gate(a.consensus, Path(a.log_dir)))
