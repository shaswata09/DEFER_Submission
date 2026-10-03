"""A2: one tier mapping, total over every interception the logs contain."""
import csv
from pathlib import Path

import pytest

from analysis import tiers
from analysis.make_figures import DEV_DOMAIN, DEV_GROUP, asb_mechanisms
from config import BASE_DIR


def _populations() -> dict[str, list[str]]:
    rows = list(csv.DictReader(open(BASE_DIR / "results/eval_attacks/all_trials.csv")))

    def blocked(domains):
        return [t["blocked_by"] for t in rows
                if t["group"] == DEV_GROUP and t["domain"] in domains and t["ap"] != "benign"
                and not t.get("suffix") and t["config"] == "agenticcyops" and t["outcome"] == "blocked"]

    live = []
    for g in ("A", "C", "D", "E"):
        live += asb_mechanisms(BASE_DIR / "results_legacy_v1/asb" / f"e2e_validator_group_{g}"
                               / "general" / "results.csv")
    return {
        "development": blocked({DEV_DOMAIN}),
        "transfer": blocked({"finance", "healthcare", "legal"}),
        "asb_replay": asb_mechanisms(BASE_DIR / "results/asb/e2e_validator_group_q235_div4_div4"
                                     / "general" / "results.csv"),
        "asb_live": live,
    }


@pytest.mark.parametrize("population", ["development", "transfer", "asb_replay", "asb_live"])
def test_every_first_interception_in_the_logs_is_mapped(population):
    mechs = _populations()[population]
    assert mechs, f"{population}: no interceptions found"
    _shares, n, unmapped = tiers.shares(mechs)
    assert not unmapped, f"{population}: unmapped {sorted(set(unmapped))}"
    assert n == len(mechs)


@pytest.mark.parametrize("mechanism,tier", [
    # the two the earlier mapping had wrong
    ("P3_handoff_validation", "content_dependent"),
    ("P2_target_not_in_evidence", "similarity"),
    # one from each tier
    ("P4_schema_violation", "content_independent"),
    ("P2_parameter_rule_violation", "content_dependent"),
    ("P4_similarity_reject", "similarity"),
    ("P3_llm_consensus_reject", "panel"),
    ("P3_write_judge_reject", "panel"),
    # embedding thresholds are similarity, whichever principle they sit in
    ("P2_sensitive_content_detected", "similarity"),
    ("P5_irrelevant_query", "similarity"),
])
def test_tier_of(mechanism, tier):
    assert tiers.tier_of(mechanism) == tier


def test_p2_2_branch_decides_its_tier_once_logged():
    assert tiers.tier_of("P2_target_not_in_evidence", deny_branch="cosine") == "similarity"
    assert tiers.tier_of("P2_target_not_in_evidence", deny_branch="substring") == "content_dependent"


def test_unknown_and_empty_labels_are_not_given_a_tier():
    for m in ("", None, "nan", "P9_not_a_check"):
        assert tiers.tier_of(m) is None


def test_no_other_mapping_exists():
    """figstyle, generate_tables and make_figures import tiers; none defines its own."""
    for name in ("figstyle.py", "generate_tables.py", "make_figures.py"):
        src = (BASE_DIR / "analysis" / name).read_text()
        assert "from analysis import tiers" in src, name
        for old in ("def tier_of", "def tier4_of", "_CONTENT_DEPENDENT", "_SIM_MECHS", "_LLM_MECHS"):
            assert old not in src, f"{name} still defines {old}"


def test_cascade_annotation_is_everything_but_the_panel():
    """The pipeline figure's "deterministic %" must be 100 minus the panel's
    share of development interceptions (it once summed a tier key that the
    four-way mapping no longer has, and printed the similarity share alone)."""
    import re
    import tempfile
    from pathlib import Path

    from analysis.make_figures import ALL_TRIALS, load_trials, write_cascade_defs
    with tempfile.TemporaryDirectory() as d:
        write_cascade_defs(load_trials(ALL_TRIALS), Path(d))
        tex = (Path(d) / "cascade_pipeline_defs.tex").read_text()
    det = int(re.search(r"\\def\\deterministicpct\{(\d+)\}", tex).group(1))
    # the figure describes the reported configuration (the v3.1 runs), on the
    # 75 variants of the development split (the v3.1 runs also carry E2 siblings)
    from analysis.make_figures import REPORTED_GROUP
    rows = list(csv.DictReader(open(ALL_TRIALS)))
    keep = {(t["ap"], t["variant"]) for t in rows if t["group"] == DEV_GROUP
            and t["domain"] == DEV_DOMAIN and t["ap"] != "benign"}
    blocked = [t["blocked_by"] for t in rows
               if t["group"] == REPORTED_GROUP and t["domain"] == DEV_DOMAIN
               and t["ap"] != "benign" and not t.get("suffix") and t["config"] == "agenticcyops"
               and t["outcome"] == "blocked" and (t["ap"], t["variant"]) in keep]
    shares, _n, _u = tiers.shares(blocked)
    assert det == round(100 * (1 - shares["panel"]))
