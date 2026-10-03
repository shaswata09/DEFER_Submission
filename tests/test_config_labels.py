"""A1: one configuration label per arm.

Every aggregation keys on the exact ``config`` from the run header and on the
group a run was routed to, never on a file-name prefix. These tests pin the
numbers the paper reports, computed from the committed logs.
"""
import re

import pytest

from analysis.benign_cost import proposal_denials
from analysis.generate_tables import added_arms, t11_benign_denials
from analysis.runlogs import header_config, run_logs

GROUP = "q235_div4"


def test_cyberops_full_benign_denial_is_the_reported_value():
    """CyberOps DEFER benign cost as run: 103 of 873 proposals denied or
    escalated, 11.8 % (88 denied + 15 bulk-action escalations)."""
    assert proposal_denials(GROUP, "cyberops", "agenticcyops") == (103, 873)


def test_t11_prints_the_reported_value_with_its_interval():
    t11 = t11_benign_denials(GROUP)
    row = next(l for l in t11.splitlines() if l.startswith("| cyberops |"))
    full = row.split("|")[4].strip()          # Flat | ACL | FULL
    assert re.match(r"11\.8 \[\d+\.\d, \d+\.\d\] \(103/873, k=20\)", full), full


@pytest.mark.parametrize("label,group,cfg", added_arms(GROUP))
def test_each_added_arm_is_its_own_row(label, group, cfg):
    t11 = t11_benign_denials(GROUP)
    rows = [l for l in t11.splitlines() if l.startswith(f"| {label} |")]
    assert rows, f"{label}: no row in T11"
    assert all(f"`{cfg}`" in r and f"| {group} |" in r for r in rows)


def test_file_prefix_never_selects_another_arm():
    """``agenticcyops_*.jsonl`` also names every agenticcyops_<variant> log.
    Selection must go by the header, so FULL never picks those up."""
    files = run_logs(GROUP, "cyberops", "agenticcyops")
    assert files
    assert {header_config(f) for f in files} == {"agenticcyops"}
    assert not any(f.name.startswith("agenticcyops_") and not re.match(r"agenticcyops_\d{8}_", f.name)
                   for f in files)


@pytest.mark.parametrize("routed", ["q235_div4_e9", "q235_div4_e2", "q235_div4_e16null", "q235_div4_outage"])
def test_routed_experiments_leave_the_main_group(routed):
    """Later experiments that reused the main log directories and config
    labels (run_groups.yaml) must not be counted as the main group."""
    moved = {f for d in ("cyberops", "finance", "healthcare", "legal") for f in run_logs(routed, d)}
    assert moved, f"{routed}: nothing routed"
    main = {f for d in ("cyberops", "finance", "healthcare", "legal") for f in run_logs(GROUP, d)}
    assert not (moved & main)
