"""
Attack-path taxonomy: separates IPI-flavoured APs from structural ones.

IPI APs are the ones where attacker-controlled text steers the LLM via
incident description, tool response, memory read, or handoff context.
Existing IPI defenses (Yi et al., NAACL 2025 Findings) are designed to
catch this class.

Structural APs target system mechanics (replay, accumulation, integrity,
direct memory tampering) and are out-of-scope for input-side defenses.
Including them is deliberate: it surfaces the architectural gap.
"""

IPI_APS = {"ap1", "ap2", "ap3", "ap4", "ap5", "ap8", "ap9", "ap10", "ap11", "ap14"}
STRUCTURAL_APS = {"ap6", "ap7", "ap12", "ap13", "ap15"}

AP_NAMES = {
    "ap1":  "Tool Redirection",
    "ap2":  "Memory Poisoning",
    "ap3":  "Confused Deputy",
    "ap4":  "Cross-Phase Exfiltration",
    "ap5":  "Bulk Irreversible",
    "ap6":  "Replay Attack",
    "ap7":  "Action Chain",
    "ap8":  "Parameter Manipulation",
    "ap9":  "Handoff Poisoning",
    "ap10": "Validator Manipulation",
    "ap11": "Operational Context Violation",
    "ap12": "Concurrent Bypass",
    "ap13": "Adversarial Memory Write",
    "ap14": "Read Injection",
    "ap15": "Infrastructure Integrity",
}


def category(ap: str) -> str:
    """Returns 'IPI' or 'Structural' for an AP id."""
    a = ap.lower()
    if a in IPI_APS:
        return "IPI"
    if a in STRUCTURAL_APS:
        return "Structural"
    return "Unknown"


def ap_color(ap: str) -> str:
    """Consistent plot colours: red=IPI, blue=Structural."""
    c = category(ap)
    if c == "IPI":
        return "#d62728"
    if c == "Structural":
        return "#1f77b4"
    return "#7f7f7f"
