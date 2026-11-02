# Results: the forgery table, one rung up

`ladder.py`. The five forgeries of `experiments/rederivability/forge.py`, rebuilt with a customer-operated attester in front of the decider; 5 records. Columns 3–4 are `experiments/rederivability/RESULTS.md` §6's; columns 5–7 are new.

| forgery | what it misreports | `replay` (honest module) | verdict, `dr.verify` | `arrival` | `arrivals_accounted` | verdict, with attester |
|---|---|---|---|---|---|---|
| `f1-canonicalisation-widened` | the host operation folds confusable characters, so a lookalike host becomes the allow-listed one | failed | **FAILED** | established | established | **FAILED** |
| `f2-context-key-dropped` | request construction removes a context key the policy reads | failed | **FAILED** | established | established | **FAILED** |
| `f3-reason-relabelled` | the reason names a forbid that did not fire | failed | **FAILED** | established | established | **FAILED** |
| `f4-entity-source-swapped` | the policy declares the store; the producer evaluates with the caller's entities | failed | **FAILED** | established | established | **FAILED** |
| `f5-input-fabricated` | the retained input of seq 24 is a benign call the agent never made; the decision is honestly computed from it | established | **ESTABLISHED** | failed | unknown | **FAILED** |

## Read-off

- F1–F4 are unchanged by the attester: their inputs did arrive, so `arrival` establishes on all four and the verdict is still the one replay under the honest module gives. The forgery is in the decider, and the attester has nothing to say about deciders — which is the right silence.
- F5 moves. It was the one row that passed every check; with the attester it is **FAILED** on `arrival`: *seq 24: the retained input is not what arrived; arrival 24 was signed over a different input*
- So the ladder's L3 is reached, and what it accepts on trust is what the ladder said: the attester, and the seam between arrival and decision. The roof is now one rung higher and still a roof.
