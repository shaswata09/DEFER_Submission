"""Re-adjudicate every logged panel round with local validators.

    python -m analysis.replay_run build        # then build-asb and build-tamas, which append
    python -m analysis.replay_run query --validator L2_gemma --url http://127.0.0.1:8101/v1

``build`` enumerates the rounds of every arm (``analysis.replay.rounds``),
writes each distinct panel message once to ``cache/replay/messages.jsonl``
and the round index to ``cache/replay/rounds.jsonl``. ``query`` sends every
message a validator has not answered yet to one OpenAI-compatible local
server, exactly as ``consensus.validator`` calls a local validator
(temperature 0, 2,048 output tokens, ``<think>`` blocks stripped, the same
JSON parsing, malformed output counts as a rejection), and appends the votes
to ``cache/validators/<validator>.jsonl``. Validators vote independently, so
any panel can then be composed offline from the cached votes.

No API model is called: the URL must be a local server.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import time
from dataclasses import asdict
from pathlib import Path

from config import BASE_DIR

REPLAY_DIR = BASE_DIR / "cache" / "replay"
VOTE_DIR = BASE_DIR / "cache" / "validators"

# (label, group, config, domains, suffix, include_unjudged)
ARMS = [
    ("full", "q235_div4", "agenticcyops", ("cyberops", "healthcare", "finance", "legal"), "", True),
    ("judgeonly", "q235_div4", "llm_judge", ("cyberops",), "", False),
    *[(f"full_minus_p{i}", "q235_div4", "agenticcyops", ("cyberops",), f"_disabled_P{i}", False)
      for i in (1, 2, 4, 5)],
    ("scout", "scout_div4", "agenticcyops", ("cyberops", "finance"), "", False),
    ("mistral", "mistral_div3p", "agenticcyops", ("cyberops", "finance"), "", False),
    ("llama8b", "llama8b_div4", "agenticcyops", ("cyberops", "finance"), "", False),
    ("permissive_gate", "q235_div4", "agenticcyops_gate_permissive", ("cyberops",), "", False),
    ("e2", "q235_div4_e2", "agenticcyops", ("cyberops", "healthcare", "finance", "legal"), "", False),
    # live boundary runs of two more primaries at defense-freeze-v2.9 (local2 panel)
    ("oss120_full", "oss120_local2_v29", "agenticcyops", ("cyberops",), "", True),
    ("oss120_judgeonly", "oss120_local2_v29", "llm_judge", ("cyberops",), "", False),
    ("llama8b_full", "llama8b_local2_v29", "agenticcyops", ("cyberops",), "", True),
    ("llama8b_judgeonly", "llama8b_local2_v29", "llm_judge", ("cyberops",), "", False),
]

TAMAS_RUNS = {"tamas_full": "logs/tamas_q235_local2_v29"}


def build() -> None:
    from analysis.replay import rounds
    REPLAY_DIR.mkdir(parents=True, exist_ok=True)
    messages: dict[str, str] = {}
    with open(REPLAY_DIR / "rounds.jsonl", "w") as fr:
        for label, group, config, domains, suffix, unjudged in ARMS:
            n = 0
            for r in rounds(group, config, domains, suffix, include_unjudged=unjudged):
                messages.setdefault(r.key, r.message)
                row = asdict(r)
                row.pop("message")
                row["arm"] = label
                fr.write(json.dumps(row) + "\n")
                n += 1
            print(f"{label:18s} {n:6d} rounds")
    with open(REPLAY_DIR / "messages.jsonl", "w") as fm:
        for k, m in messages.items():
            fm.write(json.dumps({"key": k, "message": m}) + "\n")
    print(f"distinct messages: {len(messages)}")


PANEL_MECHS = ("P3_consensus_reject", "P3_consensus_approve")


def build_asb() -> None:
    """Append the ASB rounds that reached the panel: the frozen live run and
    the 405 emitted actions of the panel replay. The ASB adapter judges a
    proposal synthesized from the case (``DefensePipeline._build_proposal``),
    not the agent's arguments, so the message depends only on the case and
    the resolved attacker tool."""
    import csv
    import glob
    import hashlib
    from benchmarks.asb.run_e2e import _resolve_attacker_target, load_cases
    from benchmarks.injecagent.harness.trial_driver import DefensePipeline

    cases = {c["asb_case_id"]: c for c in load_cases(["DPI", "IPI", "MP", "POT"])}
    known = {json.loads(ln)["key"] for ln in open(REPLAY_DIR / "messages.jsonl")}
    fm = open(REPLAY_DIR / "messages.jsonl", "a")
    fr = open(REPLAY_DIR / "rounds.jsonl", "a")
    for arm, run in (("asb_frozen", "frozen_full"), ("asb_replay405", "single")):
        path = glob.glob(str(BASE_DIR / "results" / "asb" / f"e2e_validator_group_q235_div4_{run}" / "*" / "results.csv"))[0]
        n = 0
        for r in csv.DictReader(open(path)):
            if r["config"] != "agenticcyops" or r["defense_mechanism"] not in PANEL_MECHS:
                continue
            case = cases[r["asb_case_id"]]
            target = _resolve_attacker_target(case, r["emitted_action"])
            proposal = DefensePipeline._build_proposal(None, case, target, "admin")
            msg = json.dumps({"proposal": proposal, "incident_context": {
                "incident_id": f"IA_{case.get('ia_case_id', case.get('User Tool', 'unknown'))}",
                "description": case.get("User Instruction", ""),
                "config": "agenticcyops"}}, default=str)
            key = hashlib.sha256(msg.encode()).hexdigest()
            if key not in known:
                fm.write(json.dumps({"key": key, "message": msg}) + "\n")
                known.add(key)
            fr.write(json.dumps({"key": key, "arm": arm, "group": "asb", "domain": "general",
                                 "config": "agenticcyops", "trial_id": f"{r['asb_case_id']}_t{r['trial_id']}",
                                 "call_id": "", "tool": target, "role": "attack_effect",
                                 "path": "p3_panel", "attack_type": r["attack_type"],
                                 "logged_mechanism": r["defense_mechanism"]}) + "\n")
            n += 1
        print(f"{arm:14s} {n} rounds")
    print(f"distinct messages now: {len(known)}")


def build_tamas() -> None:
    """Append the TAMAS panel rounds. The gate (benchmarks/tamas/gate.py) logs
    the exact panel input of every round, so the message is read, not rebuilt."""
    import hashlib
    known = {json.loads(ln)["key"] for ln in open(REPLAY_DIR / "messages.jsonl")}
    fm = open(REPLAY_DIR / "messages.jsonl", "a")
    fr = open(REPLAY_DIR / "rounds.jsonl", "a")
    for arm, rel in TAMAS_RUNS.items():
        path = BASE_DIR / rel / "gate.jsonl"
        if not path.exists():
            print(f"{arm}: {path} missing"); continue
        n, seq = 0, {}
        for ln in open(path):
            e = json.loads(ln)
            if e.get("event") != "check" or "panel_message" not in e:
                continue
            msg = e["panel_message"]
            key = hashlib.sha256(msg.encode()).hexdigest()
            if key not in known:
                fm.write(json.dumps({"key": key, "message": msg}) + "\n")
                known.add(key)
            tid = e["trial_id"]
            seq[tid] = seq.get(tid, -1) + 1
            fr.write(json.dumps({"key": key, "arm": arm, "group": "tamas", "domain": "general",
                                 "config": e.get("config"), "trial_id": tid, "call_id": f"{tid}:{seq[tid]}",
                                 "tool": e.get("tool"), "role": "tamas", "path": "p3_panel",
                                 "logged_votes": e.get("votes", {}), "logged_mechanism": e.get("mechanism")}) + "\n")
            n += 1
        print(f"{arm:14s} {n} rounds")
    print(f"distinct messages now: {len(known)}")


def load_votes(validator: str) -> dict[str, dict]:
    path = VOTE_DIR / f"{validator}.jsonl"
    out = {}
    if path.exists():
        for ln in open(path):
            v = json.loads(ln)
            out[v["key"]] = v
    return out


async def _query(validator: str, url: str, concurrency: int, max_tokens: int,
                 extra_body: dict | None, limit: int | None) -> None:
    from openai import AsyncOpenAI
    from consensus.validator import _parse_vote
    from analysis.replay import chat

    if not re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?/", url):
        raise SystemExit("refusing a non-local validator URL: the replay must not call an API")
    VOTE_DIR.mkdir(parents=True, exist_ok=True)
    done = load_votes(validator)
    todo = [json.loads(ln) for ln in open(REPLAY_DIR / "messages.jsonl")]
    todo = [m for m in todo if m["key"] not in done][:limit]
    client = AsyncOpenAI(base_url=url, api_key="unused")
    model = (await client.models.list()).data[0].id
    print(f"{validator}: {model}, {len(done)} cached, {len(todo)} to query")
    sem = asyncio.Semaphore(concurrency)
    out = open(VOTE_DIR / f"{validator}.jsonl", "a")
    t0, n = time.time(), 0

    async def one(m):
        nonlocal n
        async with sem:
            for attempt in range(3):
                try:
                    r = await client.chat.completions.create(
                        model=model, messages=chat(m["message"]), temperature=0.0,
                        max_tokens=max_tokens, extra_body=extra_body or None)
                    break
                except Exception as exc:            # server hiccup: retry, then record
                    if attempt == 2:
                        rec = {"key": m["key"], "validator": validator, "model": model,
                               "decision": "error", "reason": f"{type(exc).__name__}: {exc}"[:200]}
                        out.write(json.dumps(rec) + "\n")
                        return
                    await asyncio.sleep(5)
            content = r.choices[0].message.content or "{}"
            content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
            vote = _parse_vote(content)
            u = r.usage
            rec = {"key": m["key"], "validator": validator, "model": model,
                   "decision": str(vote.get("decision", "reject")).lower(),
                   "confidence": vote.get("confidence"), "reason": str(vote.get("reason", ""))[:300],
                   "prompt_tokens": getattr(u, "prompt_tokens", None),
                   "completion_tokens": getattr(u, "completion_tokens", None),
                   "finish_reason": r.choices[0].finish_reason}
            out.write(json.dumps(rec) + "\n")
            n += 1
            if n % 1000 == 0:
                out.flush()
                print(f"  {validator}: {n}/{len(todo)} ({n / (time.time() - t0):.1f}/s)", flush=True)

    await asyncio.gather(*(one(m) for m in todo))
    out.close()
    print(f"{validator}: done, {n} votes in {time.time() - t0:.0f}s")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    sub.add_parser("build-asb")
    sub.add_parser("build-tamas")
    q = sub.add_parser("query")
    q.add_argument("--validator", required=True)
    q.add_argument("--url", required=True)
    q.add_argument("--concurrency", type=int, default=64)
    q.add_argument("--max-tokens", type=int, default=2048)
    q.add_argument("--reasoning-effort", default=None)
    q.add_argument("--limit", type=int, default=None)
    q.add_argument("--replay-dir", default=None, help="read messages from this directory (e.g. cache/replay_v3)")
    a = ap.parse_args()
    if a.cmd == "build":
        build()
    elif a.cmd == "build-asb":
        build_asb()
    elif a.cmd == "build-tamas":
        build_tamas()
    else:
        if a.replay_dir:
            global REPLAY_DIR
            REPLAY_DIR = BASE_DIR / a.replay_dir
        extra = {"reasoning_effort": a.reasoning_effort} if a.reasoning_effort else None
        asyncio.run(_query(a.validator, a.url, a.concurrency, a.max_tokens, extra, a.limit))


if __name__ == "__main__":
    main()
