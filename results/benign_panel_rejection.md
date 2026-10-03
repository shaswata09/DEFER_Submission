# Benign panel rejection vs security let-through (q235_div4)

Security = ASB injected actions let through under DEFER (lower is safer).
Benign rejection = share of benign proposals the panel rejects (lower is less
disruptive). `single`/`div3`/`div4`/`div3x` recompose exactly from the recorded
div4 votes; `lin3` needs V2/V7, which never voted on a benign proposal (n/a).
`div3x` (E8) is DIV4 without the Qwen validator, so no member shares the
primary's lineage. Its security cell is n/a because the ASB logs record only the
final defense decision, not per-validator votes, so a let-through number for a
panel that never ran would need a fresh (paid) replay of the 1,275 trials.

| Panel | Members (thr) | Security: let through | Benign reject: cyberops | Benign reject: finance | Benign reject: healthcare | Benign reject: legal | Benign reject: ALL |
|---|---|---|---|---|---|---|---|
| single | V1 (1) | 41/1275 (3.2%) | 7.2% (29/404) | 10.0% (7/70) | 27.5% (33/120) | 40.3% (27/67) | 14.5% (96/661) |
| div3 | V1,V5,V6 (2) | 12/1275 (0.9%) | 4.2% (17/404) | 24.3% (17/70) | 30.0% (36/120) | 38.8% (26/67) | 14.5% (96/661) |
| div4 | V1,V5,V4,V6 (3) | 0/1275 (0.0%) | 5.9% (24/404) | 24.3% (17/70) | 44.2% (53/120) | 53.7% (36/67) | 19.7% (130/661) |
| lin3 | V1,V2,V7 (2) | 108/1275 (8.5%) | n/a | n/a | n/a | n/a | n/a |
| div3x | V5,V4,V6 (2) | n/a | 4.2% (17/404) | 24.3% (17/70) | 40.0% (48/120) | 50.7% (34/67) | 17.5% (116/661) |

Reading: `div4` is the deployed panel -- it lets through 0 injected actions while still approving ~80% of benign proposals, so its perfect security is not an artifact of blanket rejection. Benign rejection rises with panel size (single/div3 -> div4) and is concentrated in legal and healthcare.
