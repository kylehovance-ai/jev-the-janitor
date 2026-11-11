# Calibration notes: what was measured

All figures from live `jev-1.13.0`, September 2026, on 26 notes from one production vault (21 long dated reports of 9 to 51 KB, 5 near-empty stubs) plus the invented fixture vault. Raw numbers are reproducible with the taxonomy fingerprints given. The fingerprints below were recorded when the two instruction sentences lived outside the file; 0.4.3 moved them in without changing a word, so the current file fingerprints as `be00a24c7a68` at wording identical to `65bd5bfc7207`, and every figure recorded under `65bd5bfc7207` stands for it.

**Wording is the model.** Same 26 notes, same model, three taxonomy revisions:

| change | fingerprint | effect on the 26 notes (21 scans, 5 stubs) |
|---|---|---|
| baseline | `869d90f3047f` | the 21 scans split 9 project_decision / 7 durable_memory / 5 ephemeral, median confidence 0.33 |
| split one compound noul into two, buckets untouched | `86dab0bbb6c6` | 23 of 26 labels unchanged; 3 near-ties flipped; every answer within noise |
| add one bucket, `log_entry`, one sentence | `65bd5bfc7207` | 21 of 21 to `log_entry` at confidence 1.00; control vault unaffected |

**The strongest single number.** The 21 scans went from a three-way split at median confidence 0.33 to 21 of 21 in `log_entry` at 1.00, from one added sentence. Two caveats so that reads as evidence rather than a boast. Ceiling confidence on every note is unusual, not just good: it means the description fits the material exactly, and it is a fitted result on the corpus that motivated the fit. And it came with a control: the invented fixture vault, run live under the same taxonomy, put `log_entry` at 0.00 on all ten non-log notes and 1.00 on the one invented run log, and every other question on the 26 real notes stayed within the noise band. A result with a control is worth several without one.

A missing bucket shows up as a low-confidence spread, and no amount of extra context fixes it. On one 51 KB note sent at 1,200 / 3,000 / 6,000 / 12,000 characters and in full under the baseline taxonomy, bucket confidence stayed between 0.24 and 0.43 whatever Jev saw. Adding the bucket took the same note to 1.00 at 1,200 characters.

Adding the bucket also corrected a neighbouring classification nobody was trying to fix. Five near-empty stubs, each recording that a scheduled run had found nothing, had been `junk` at 0.86. Under the new taxonomy they went to `log_entry` at 0.97. That is the better answer: a record that a run happened and found nothing is information, and the corpus itself treats zero-result nights as state. `junk` implies no information value.

**Questions are isolated: a vendor claim, now measured.** TypeSafe documents that questions in one call are evaluated in parallel and in isolation. Until this run that was taken on their word. The middle row above is a direct test: adding and renaming nouls moved the bucket and score answers by a mean absolute 0.035, max 0.11, all near-ties. The bottom row is a second: changing only the bucket set moved every noul and the score by a mean absolute 0.03 or less. It holds on this corpus, and it matters to anyone composing a battery of questions.

**Jev is not deterministic, and the confidence floor is the answer.** The identical input sent twice moved bucket probabilities by 0.03 to 0.04 and flipped the winning bucket on a near-tie (0.34 versus 0.36). The 0.55 confidence floor in `policy.py` routes every such near-tie to human review regardless of which label won, so across two full runs on the same notes, 3 labels flipped and 0 actions did. Do not "optimise" the floor away as an arbitrary constant. `bucket_margin` in the report is the number to watch.

**Compound questions get half-answered.** The baseline had one noul, `actionable_decision`. On a note reading "Recommendation: the owner should schedule a review", it scored 0.84; Jev had answered the "actionable" half. Split into `records_a_decision` and `is_actionable`, the same note scored 0.22 and 0.92. Ask one thing per question.

**Score benefits from more text; Choice does not.** On the fixed-note experiment, `persist` climbed steadily from 1.35 to 1.66 as the excerpt grew and its confidence rose from 0.31 to 0.48, while bucket confidence plateaued after the first substantive section. Spend excerpt budget on Score questions.

**Latency is flat in input size.** Steady-state calls returned in 170 to 310 ms whether the state was 1,700 tokens or 15,000. First call in a session about 530 ms for connection setup. Excerpt strategy is a judgment-quality question, not a latency one.

**Redaction order changed in 0.1.2.** Up to 0.1.1 the excerpt was cut to 1,200 characters and then redacted; since 0.1.2 the body is redacted and then cut. On a note with a redaction hit in its first 1,200 characters the excerpt Jev sees is therefore slightly different from what the recorded runs below saw, and its vote can move. Of the 26 calibration notes exactly one had such a hit; every figure below was recorded under the old order and is reported as recorded.

**The excerpt cap can land on preamble.** On the 21 real scans, the 1,200-character excerpt covered 2.3% to 11.8% of the body, and in 20 of 21 it was entirely the note's opening status preamble; the substance began below the cap. Under the baseline taxonomy Jev was judging headers. The cap is not the bug; taking the first 1,200 characters is. A smarter excerpt for structured notes is v0.2 work.

**Exact duplicates are arithmetic.** Five stubs with identical content under date-differing headings scored 0.13 to 0.17 on the title-based duplicate noul. Jev answered the question it was given. Identical content is now detected locally by hash, ignoring a leading heading, and reported as `exact_duplicate_of`. The noul stays for near-duplicates.

**Note age is not a question for Jev.** `persist` showed no gradient across four months of dated notes (r = 0.18). Jev cannot do date arithmetic and TypeSafe says so. Compute age in code.
