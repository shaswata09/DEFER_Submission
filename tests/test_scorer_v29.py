"""B1 (defense-freeze-v2.9): the risk scorer receives the incident evidence and
the replay ledger, so alignment and precedent carry information.

Before v2.9 both scores sat at their 0.5 fallback for every proposal.
"""
import json
import zlib

import numpy as np

from consensus.scoring import ProposalScorer
from consensus.versioned_ledger import VersionedLedger


class _BagOfWords:
    """Deterministic stand-in for the embedding model: normalized word counts."""
    vocab: dict[str, int] = {}

    def encode(self, texts, normalize_embeddings=True):
        out = []
        for t in texts:
            v = np.zeros(256)
            for w in str(t).lower().replace('"', " ").replace(",", " ").split():
                v[zlib.crc32(w.encode()) % 256] += 1  # hash() varies per process
            n = np.linalg.norm(v)
            out.append(v / n if n else v)
        return np.array(out)


INCIDENT = {"incident_id": "INC-1", "description": "C2 beacon from host WS-FIN-07 to 185.220.101.42",
            "source_ip": "185.220.101.42"}
EVIDENCE = json.dumps(INCIDENT)
ALIGNED = {"tool_id": "T9_firewall", "action": "block_ip", "target": "185.220.101.42",
           "arguments": {"action": "block_ip", "target": "185.220.101.42"}}
UNALIGNED = {"tool_id": "T8_iam_pam", "action": "disable_user", "target": "cfo.admin",
             "arguments": {"action": "disable_user", "target": "cfo.admin"}}


def _scorer(ledger=None):
    return ProposalScorer(domain="cyberops", embedding_model=_BagOfWords(), ledger=ledger)


def test_alignment_varies_with_the_evidence():
    s = _scorer(VersionedLedger())
    a = s.score(ALIGNED, {"incident_evidence": EVIDENCE})["alignment"]
    u = s.score(UNALIGNED, {"incident_evidence": EVIDENCE})["alignment"]
    assert a != 0.5 and u != 0.5, "alignment must no longer sit at its fallback"
    assert a > u, "a proposal on the evidence's target aligns better than one off it"


def test_precedent_rises_with_repeated_approvals():
    ledger = VersionedLedger()
    s = _scorer(ledger)
    first = s.score(ALIGNED, {"incident_evidence": EVIDENCE})["precedent"]
    for i in range(5):                       # five earlier approvals of the same action
        ledger.record({**ALIGNED, "target": f"10.0.0.{i}",
                       "arguments": {"action": "block_ip", "target": f"10.0.0.{i}"}},
                      {"incident_id": f"INC-{i}"})
    repeated = s.score(ALIGNED, {"incident_evidence": EVIDENCE})["precedent"]
    assert first == 0.1 and repeated == 0.7


def test_verified_execution_wires_the_ledger_into_the_scorer():
    from consensus.verified_execution import VerifiedExecution
    ve = VerifiedExecution(domain="cyberops", consensus_validator=None)
    assert ve.scorer._ledger is ve.versioned_ledger
