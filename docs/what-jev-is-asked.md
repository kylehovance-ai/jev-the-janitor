# What Jev is asked

The taxonomy is [`janitor/taxonomies/vault_memory.yaml`](../janitor/taxonomies/vault_memory.yaml). Its sentences are the whole knowledge base Jev has for this job; there is no built-in notion of "durable" or "scratch". Every word Jev is asked is in that file, and it is sent exactly as written, with every call: the questions are not redacted and the denylist does not apply to them, so keep names and secrets out of a question file. Each entry under `questions` is one question with a `type` (`choice` with `options`, `score` with `levels`, or `noul`), its `instructions`, and its criteria, sent in file order, so the fingerprint stamped on every vote covers all of the wording. (Through 0.4.2 the `instructions` sentences of `bucket` and `persist` were Python strings outside the fingerprint; 0.4.3 moved them into the file without changing a word, and the state plus serialized questions for every note of a 192-note corpus was byte-identical before and after.) The format describes a whole question set, not this tool's questions, so a file with a different Choice, its own Scores and its own Nouls loads the same way; the vault scan itself requires a `bucket` choice, a `persist` score and the five nouls below. A file in the 0.4.x layout (`buckets`, `persist`, `nouls` at the top level) still loads and sends exactly what it did, with the two built-in sentences filled in; its fingerprint does not cover those two sentences until you convert it.

**Choice `bucket`**

- `durable_memory`: a standing fact worth keeping across sessions
- `project_decision`: a dated choice future work must honor
- `code_note`: implementation, command, schema, benchmark
- `reference`: third-party docs, quotes, links
- `log_entry`: a dated run report, scan, digest or snapshot, kept as a record of the day
- `ephemeral`: scratch, chat debris, moods
- `junk`: empty, boilerplate, noise
- `needs_review`: not enough signal, a human should look

**Score `persist`**: drop / park / promote. Jev returns a probability-weighted position on the rubric, so 1.25 means "between park and promote, leaning park", not an index.

**Nouls**: `contains_secret`, `looks_like_duplicate`, `records_a_decision`, `is_actionable`, `safe_to_leave_in_git`. Each is a probability in [0, 1]. Decision and actionability are separate questions on purpose; see the [calibration notes](calibration.md).

All seven go in one call against the same redacted state. Thresholds that turn votes into actions live in [`janitor/policy.py`](../janitor/policy.py). Change them there, not in the questions.

Measured API limits (September 2026): 32,768 input tokens per call including the questions, at most 255 options in a Choice, at most 10 levels in a Score, and at least 1,000 questions per call before the token ceiling binds. Loading a taxonomy that exceeds the option or level limit fails locally, before any request.

**Edit the descriptions and the votes move. Re-calibrate after any change.** The YAML is not configuration. It is sensitive to phrasing in ways you cannot predict by reading it, and the numbers [in the calibration notes](calibration.md) show how much.
