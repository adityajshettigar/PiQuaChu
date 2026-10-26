# PiQuaChu — Phase 2 report: detection depth, bounded data flow, external validation

**Status:** implemented, verified locally, **awaiting user sign-off**
**Date:** 2026-10-19
**Baseline:** Phase 1 report (`docs/engineering/phase-1-report.md`), accepted state 732
checks / 49 corpus cases / F1 0.9846.
**Scope of this phase:** detection depth (bounded Python and Java data flow), a shared
evidence model with stable fingerprints, a responsibly expanded regression corpus,
external validation against pinned repositories with manually reviewed ground truth,
and honest metric provenance. **No** CI provider integrations, RBAC/tenant runtime
features, or production deployment changes.

---

## 1. Design and supported flow scope

### 1.1 Engines

| Engine | Responsibility | Granularity |
|---|---|---|
| `semgrep` | pattern/AST rules over all supported languages | call site |
| `ast` | zero-dependency Python AST fallback (aliases, secrets, AES-128, toy RSA) | call site |
| `dataflow-py` (new) | bounded intraprocedural constant propagation into Python crypto sinks | file, per scope |
| `dataflow-java` (new) | bounded `javalang`-based local propagation into JCA sinks | file, per class/method |
| `aux` | unusual extensions, TLS/SSH config evidence | file/line |
| `deps` | manifests + lockfiles, advisory matching | dependency |
| `keyfiles` | PEM/OpenSSH/PuTTY/PKCS#12 key material (no key bytes) | file |

`scanner.scan_directory()` now merges the engines, normalizes them into one evidence
model, deduplicates by evidence identity and reports disagreements.

### 1.2 What the data-flow pass actually does (implemented)

* Literal and constant assignment chains (`ALGO = "md5"` → `algo = ALGO` → sink).
* Alias imports (`import hashlib as h`, `from x import y as z`).
* Statically resolvable string expressions: `+`, `%`, f-strings, `str.format`,
  `bytes()`/`str()` of a known value.
* `if/else` joins: identical values on every branch resolve (high confidence);
  **divergent** constants become *unresolved* evidence instead of a guess.
* Single-return wrapper forwarding (depth 1), including a constant default argument.
* Environment/config values (`os.environ[...]`, `os.getenv`, `os.environ.get`,
  `config.get`, subscript on config-like names) are tracked as **unresolved**, never
  rendered, and reported as inconclusive evidence.
* Value-dependent sinks: `hashlib.new`, `hmac.new(digestmod=)`, `oqs.KeyEncapsulation`,
  `oqs.Signature`, PyCryptodome `AES.new` mode argument, `hashlib.pbkdf2_hmac` salt,
  Java `MessageDigest/Signature/Cipher/KeyPairGenerator/KeyAgreement.getInstance`,
  `new Random(seed)`.
* API-shaped sinks without a value: `modes.ECB()`, classical `algorithms.TripleDES/ARC4/
  Blowfish`, Java `Cipher` transformation classification (ECB, no-padding RSA, DES/3DES/
  RC4, default-mode).

### 1.3 What it does **not** do (do not claim otherwise)

* **No interprocedural taint analysis** beyond depth-1 single-return wrappers.
* No attribute/field tracking on Python objects (Java `static final` fields *are*
  propagated within a class), no class-method flows, closures or callbacks.
* No path-sensitive reasoning; joins are value-merges, not symbolic execution.
* No `eval`/`exec` of scanned code, no import of scanned packages, no execution of
  the scanned project, no setup-script or build-hook execution.
* Dynamically constructed names (`getattr(mod, "new")(x)`), reflection, DI containers
  and decorator-generated code are invisible.
* Java support is limited to `javalang` 0.13.0's grammar (records, sealed types and
  newer syntax can fail to parse — recorded as diagnostics, never silently dropped).
* Bounds: per file, single pass, no path explosion; recursion guarded by
  `RecursionError` handling. A file that fails to parse is counted and skipped; other
  files are still analyzed.

---

## 2. Findings schema changes (versioned)

New module `backend/evidence.py` (`evidence.py`, model **`evidence-v2`**, engine version
**`2.3.0`**). Every engine annotates before enrichment, so all consumers see one shape:

| Field | Meaning |
|---|---|
| `rule_id` | stable rule identifier (unchanged vocabulary) |
| `engine`, `engine_version`, `model_version` | provenance |
| `language` | `python` / `java` / other |
| `file` | **root-relative** normalized path (no host paths, no absolute paths) |
| `line_start`, `line_end`, `column_start` | display evidence only |
| `evidence_type` | `literal`, `constant_propagated`, `data_flow`, `ast_api_pattern`, `dependency_advisory`, `key_material`, `transport_config`, `inconclusive` |
| `confidence_tier` (+ `confidence_score`) | `high` 0.9, `medium` 0.6, `low` 0.3, `inconclusive` 0.1 — a claim about **evidence strength**, not impact |
| `observed_value` | resolved value, never a secret/config value |
| `source_description`, `sink_description` | where the value came from / where it is used |
| `evidence_rationale`, `evidence_limitations` | why this was concluded, what was not proven |
| `inconclusive`, `informational` | inconclusive evidence is excluded from scores and risk verdicts |
| `fingerprint` | `pqc1-<24 hex>` — stable identity (see below) |
| `provenance[]`, `engine_count`, `cross_engine_confirmed` | every engine that saw it |

**Fingerprint identity** = rule id + normalized **root-relative** file identity +
normalized evidence signature (call/sink signature or a hash of the normalized source
line) + scope (module/class/function). Line numbers are *not* identity, so a line shift
does not create a new finding, while two identical call sites in `a/Utils.java` and
`b/Utils.java` stay distinct. No source text is embedded in the fingerprint.

**Deduplication and disagreement.** Two collapse passes: (1) identical fingerprint;
(2) same rule on the same file **and** line (a pattern engine can only offer a
source-line signature while a data-flow engine knows the sink, so the same rule on the
same line is the same evidence). Provenance is retained, the highest-confidence
evidence describes the finding, and `cross_engine_confirmed` is set. Different *rules*
on the same line are **never** merged: both are kept and reported in
`engine_disagreements`.

Diagnostics added to every scan result: `parser_failures` (per language, with
normalized file paths and error type), `files_analyzed`, `unresolved_values`, `engines`.

---

## 3. Engine / ruleset / corpus versions

| Artifact | Version | Fingerprint |
|---|---|---|
| Evidence model | `evidence-v2` | engine `2.3.0` |
| Compliance matrix semantics | `evidence-v1` (unchanged: the matrix did not change) | — |
| Ruleset | `ruleset-v2`, 106 rules | sha256 `c3d95c356257b3648d1ff4566ad0b7a2eb9f9eedab95887c48967113a4545493` |
| Corpus | `corpus-v2`, 62 cases (59 binary, 3 uncertain) | sha256 `9b95aab7cfb2ec7b0df2ccb1929cd74e0951ea1d7314b92a040e4670128f8e89` |
| Metrics schema | `metrics-v2` | — |
| Parser dependency | `javalang` 0.13.0 (optional; absence is reported, never assumed) | — |
| semgrep | 1.154.0 | — |

New module `backend/metrics.py` supplies `ruleset_fingerprint()`,
`corpus_fingerprint()`, `age_seconds()`, `annotate()` (freshness/staleness) and
`release_gates()`. `worker.py benchmark` and `/api/v1/reliability` now publish
`metric_source`, ruleset/corpus hashes, `generated_at`, `age_seconds`, `stale`,
`release_gates` and `external_validation` (`not-run` until a report is published via
`PIQUACHU_EXTERNAL_REPORT`). A cached report older than the 5-minute TTL is flagged
`stale` and refreshed in the background — it is never presented as current.

---

## 4. Added fixture / corpus case IDs (13 new, 49 → 62)

| Case | Category | Expectation |
|---|---|---|
| `50_py_dataflow_md5_alias_chain` | Data-Flow (Python) | risk, `weak-crypto-python-md5`, high |
| `51_py_dataflow_sha1_string_expression` | Data-Flow (Python) | risk, `weak-crypto-python-sha1`, high |
| `52_py_dataflow_wrapper_forwarding` | Data-Flow (Python) | risk, `weak-crypto-python-md5`, medium |
| `53_py_dataflow_env_value_unresolved` | Data-Flow (Uncertain) | `UNDERTERMINED`, `dataflow-unresolved-algorithm-python` |
| `54_py_dataflow_ecb_mode_object` | Data-Flow (Python) | risk, `deprecated-ecb-python` |
| `55_py_dataflow_join_same_value` | Data-Flow (Python) | risk, md5, high |
| `56_py_dataflow_join_divergent` | Data-Flow (Uncertain) | `UNDERTERMINED`, unresolved |
| `57_java_dataflow_md5_alias_chain` | Data-Flow (Java) | risk, `weak-crypto-java-md5`, high |
| `58_java_dataflow_cipher_ecb_transformation` | Data-Flow (Java) | risk, `deprecated-ecb-java`, high |
| `59_java_dataflow_parameter_unresolved` | Data-Flow (Uncertain) | `UNDERTERMINED`, unresolved |
| `60_dataflow_false_positive_bait` | FP bait | no findings (comments, docs, unused JSON) |
| `61_py_parser_failure_isolation` | Parser robustness | risk found + ≥1 parser failure recorded |
| `62_java_parser_failure_isolation` | Parser robustness | risk found + ≥1 parser failure recorded |

Each new case carries `rationale`, `label_source` (reviewer + date), `kind`
(`synthetic-corpus`), `expect_rules`, `forbid_rules`, `expect_confidence` and
`expect_parser_failures`, so a case cannot pass by matching an unrelated rule. The
runner distinguishes a synthetic fixture from external ground truth and reports
`UNDERTERMINED` cases **outside** the confusion matrix. No existing label was changed:
the single pre-existing miss (`34_minified_js_rsa`) is still a documented, budgeted
known miss in `KNOWN_MISSES`, and a *new* miss fails the hermetic gate.

---

## 5. External validation

### 5.1 Targets (pinned, static analysis only)

| # | Repository | Ref | Commit SHA | License | Scope |
|---|---|---|---|---|---|
| 1 | OWASP Juice Shop | `v17.1.1` | `39b46860612990ae18d499a20472172839fe8c77` | MIT | repo root; scanner default skips (`node_modules`, `dist`, `build`, `coverage`, `vendor`, `.git`, `__pycache__`, `venv`, `target`, `out`) |
| 2 | paramiko | `3.5.1` | `ed8b09751ff20340332d4b1bb2b10e32aedc57ff` | LGPL-2.1 | `paramiko/` package (46 files, 20,749 lines) |

Rules honoured: no repository source was executed, no dependency was installed, no
build/test/container hook ran, nothing was uploaded and no remote LLM saw the code.
Checkouts live in `/tmp/pqc-ext/…` (outside the repository). The committed report
contains identifiers, locations and short evidence descriptions only — **no source
snippets, no absolute paths**.

### 5.2 Human ground-truth methodology

1. **Scope** fixed first, with exclusions and documented blind spots.
2. **Candidate enumeration** by documented regex sweeps over the scope (crypto imports,
   digest/cipher/keygen/signature/KEX/RNG APIs, algorithm-selection strings).
3. **Manual review** of each candidate in the actual source at the pinned commit.
4. **Rubric** (`LABELING_RUBRIC` in `external_ground_truth.py`) classifies each site as
   `risk` (quantum-vulnerable/deprecated crypto actually selected), `benign` (crypto
   that must not be reported) or `uncertain` (algorithm chosen dynamically; excluded
   from the matrix).
5. **Recall denominator includes scanner misses** — the eligible call sites were
   enumerated by hand, not read off scanner output.
6. **Matching**: a finding matches a site on the same normalized file within ±2 lines
   (multi-line call expressions). Each finding is attributed to exactly one site
   (nearest line), so an adjacent benign site cannot absorb a real false positive.
   Ambiguous attributions are counted (`ambiguous_attributions: 0`).
7. Two labelling corrections were made *during* review, both recorded in the ground
   truth as "added during review after the first run flagged this line"
   (`kex_ecdh_nist.py:71`, `:117`, `Gruntfile.js:77`) — i.e. scanner output prompted
   re-review, and the *label* was corrected, never a rule.

### 5.3 Results (site-level, micro)

| Target | Risk sites | Benign sites | TP | FP | FN | TN | Uncertain | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|---|
| OWASP Juice Shop | 8 | 5 | 2 | 0 | 6 | 5 | 0 | 1.0000 | 0.2500 | 0.4000 |
| paramiko | 31 | 10 | 16 | 3 | 15 | 8 | 2 | 0.8421 | 0.5161 | 0.6400 |
| **Pooled (micro)** | 39 | 15 | 18 | 3 | 21 | 13 | 2 | **0.8571** | **0.4615** | **0.6000** |
| **Macro (mean of targets)** | — | — | — | — | — | — | — | 0.9210 | 0.3831 | 0.5200 |

Micro pools all reviewed call sites; macro averages the two targets equally. They are
reported separately and never blended into a single headline number.

**Recall by category (pooled risk sites):**

| Category | Juice Shop | paramiko |
|---|---|---|
| hashing | 2/2 (1.00) | 3/5 (0.60) |
| signature | 0/5 (0.00) | 6/8 (0.75) |
| key-exchange | — | 5/7 (0.71) |
| key-generation | — | 2/3 (0.67) |
| symmetric | — | 0/6 (0.00) |
| key-derivation | — | 0/1 (0.00) |
| configuration | — | 0/1 (0.00) |
| randomness | 0/1 (0.00) | — |

**Confidence tier of true positives** (instrumented from the evidence model):
`high` for the value-propagated Python/Java sinks, `medium` for pattern-engine matches
and wrapper flows; no TP relied on an inconclusive tier (those are excluded by design).

**Example false positives (all three are paramiko, all explainable, no snippets):**

| Location | Rule | Why it is a false positive |
|---|---|---|
| `hostkeys.py:296`, `:301` | `weak-crypto-python-sha1` | `sha1()` is instantiated only for `digest_size`; the bytes come from `os.urandom` |
| `config.py:449` | `weak-crypto-python-sha1` | SHA-1 used to expand a config-string token, not for security |

**Example false negatives (grouped, with the underlying reason):**

| Group | Sites | Reason |
|---|---|---|
| Algorithm-negotiation lists | `PAR-023…029` (preferred MAC/KEX/cipher tables) | Python-side support for "SHA-1/3DES offered in a list" patterns is absent; the scanner only matches call sites and config files |
| Callable references | `PAR-018` (`generate_key_bytes(md5, …)`) | A weak hash passed **as a value** (function reference) into a KDF helper is not resolved |
| Attribute-only algorithm selection | `PAR-019` (`"ssh-rsa": hashes.SHA1`) | Algorithm chosen through a dict of class attributes, no call |
| Uncovered algorithms | `PAR-003` (DSA keygen), `PAR-007` (Ed25519/`nacl`), `PAR-015/016` (AES-128/3DES table entries) | No rule targets DSA key generation, `nacl`, or cipher-table entries in Python |
| JWT/RSA verification (JS) | `JS-003…007` plus `JS-002` | No JS/TS rule for `jwt.sign/verify` RS256 or `Math.random()`-as-secret |

**Uncertain sites (excluded from the matrix):** `PAR-040` (`ed25519key.py:131`) and
`PAR-041` (`pkey.py:595`) — the cipher class is read from parsed key-file metadata and
the reviewer could not fix one label; both are currently unflagged.

**Parser failures observed:** Juice Shop `{python: 2}` (two Python-2-style fixtures under
`test/files/`, counted and skipped, no impact on other files); paramiko `{}` (clean).

### 5.4 What these metrics do and do not prove

**Do prove:** on two pinned, independently authored repositories, out of 39 hand-reviewed
quantum-vulnerable/deprecated crypto call sites, the scanner found 18 with 3 false
positives; the misses are enumerated, grouped and explained; the pipeline runs without
executing target code and without leaking paths or source.

**Do not prove:** that the same precision/recall holds for other languages, frameworks or
code styles (two targets, one reviewer, per-site ±2-line matching); that the ground truth
is complete (one reviewer, no second-labeler adjudication); that a *clean* file is safe;
that a finding is a real vulnerability (static discovery ≠ exploitability, and no
compliance certification is implied); finally, the numbers are **not** a release gate —
real-world corpora naturally miss things.

### 5.5 Release gates (separate, never collapsed)

| Gate | Rule | Current |
|---|---|---|
| `hermetic_fixtures` | no miss outside the documented `KNOWN_MISSES` budget | pass |
| `hermetic_expectations` | every per-case `expect_rules`/`forbid_rules`/confidence assertion holds | pass |
| `false_positive_floor` | zero false positives on the hermetic corpus | pass |
| `external_baseline` | only with a justified, documented threshold — otherwise reported `not-run` | not-run (deliberate) |

`F1 = 1.0` on external code is explicitly **not** a gate.

---

## 6. Commands and results

Environment: `backend/venv`, Python 3.14.8, semgrep 1.154.0, javalang 0.13.0.

```bash
cd backend
python test_dataflow.py            # 98 checks passed
python test_compliance.py          # 68 checks passed
python test_standards.py           # 157 checks passed
python test_cbom.py                # 175 checks passed
python test_extras.py              # 73 checks passed
python test_docs.py                # 161 checks passed
python worker.py benchmark         # 62 cases, precision 1.0000, recall 0.9762, F1 0.9880
semgrep --config rules.yaml --validate   # 0 errors / 106 rules
python report_counts.py --no-suites      # 106 rules, 62 corpus cases, 10 fixtures + external summary
python -m benchmark.external_eval --all --workdir /tmp/pqc-ext
cd ../frontend && npm run build && npm run lint
```

| Check | Result |
|---|---|
| `test_dataflow.py` (new) | **98 checks passed** |
| `test_compliance.py` | 68 checks passed |
| `test_standards.py` | 157 checks passed |
| `test_cbom.py` | 175 checks passed |
| `test_extras.py` | 73 checks passed |
| `test_docs.py` | 161 checks passed |
| `test_api.py` | **not re-run in this phase** (see limitations) |
| Hermetic benchmark | 62 cases — TP 41, FP 0, FN 1 (known), TN 17; P 1.0000 R 0.9762 F1 0.9880; gates pass |
| `semgrep --validate` | 0 errors |
| External evaluation | pooled micro P 0.8571 R 0.4615 F1 0.6000; committed report `docs/engineering/data/phase-2-external-validation.json` |
| Frontend `npm run build` / `npm run lint` | **not re-run** — no frontend file changed in Phase 2 (see UAT item 7) |

New/updated test coverage (in `backend/test_dataflow.py`): alias and assignment
propagation, constant string expressions, unknown env/config values (with an explicit
"the env value is never rendered" assertion), wrapper calls, join agreement and join
ambiguity, source-to-sink detection, false-positive suppression, Java parser coverage and
failure behaviour, bounded runtime (4,000 assignments + 200 functions under 10 s), zip
hardening before parsing, multiple-engine deduplication, stable fingerprints under line
shifts, same-named files not colliding, provenance retention, disagreement retention, no
secret/source/host-path egress, mixed-language tree, metric provenance, staleness
reporting, release-gate behaviour, reliability-endpoint response shape (benchmark-free),
and a static assertion that the new parsers contain no extraction/execution primitives.

---

## 7. Limitations, remaining false negatives and test gaps

**Limitations (reported, not hidden)**

* Bounded data flow only — see §1.3. Interprocedural taint analysis is *not* implemented
  and is not claimed.
* Java coverage is bounded by `javalang`'s grammar; parser failures are counted with
  normalized paths and error types.
* External ground truth has **one reviewer** and no second-labeler adjudication; the two
  `uncertain` sites are declared rather than guessed.
* Two targets only, concentrated in Python (crypto-dense) and TypeScript (crypto-sparse).
  Language/category recall for Go, C/C++, PHP and Rust is **not** externally measured.
* **No blind/holdout corpus subset.** The 13 new hermetic cases were authored while the
  two data-flow engines were being built, so hermetic scores are tuned by construction
  and are regression evidence, not unbiased generalisation. The external ground truth
  was authored *after* the engines were frozen (only two label corrections were made
  from its findings, both recorded), which is why the external numbers — not the
  hermetic ones — are the honest generalisation signal.
* `test_api.py` was **not re-run after the last edits** at the user's explicit request
  (the suite's `/api/v1/reliability` path triggers a full corpus benchmark and is
  resource-heavy). The endpoint's response contract is instead covered by a
  benchmark-free test in `test_dataflow.py` (16 checks: provenance, freshness,
  `last_successful_run`, `stale` anchored on `generated_at` rather than the cache slot,
  `external_validation: not-run`, separate gates, no host paths, a failed refresh that
  keeps the last good report and surfaces the failure, 401 without key).
  A full `python test_api.py` run is still required before merge — see UAT.
* `report_counts.py` (which runs every suite, including `test_api.py`) was therefore not
  re-executed end-to-end in this phase; `--no-suites` was used to verify counts and the
  external summary.
* Pre-existing `backend/pytest.ini` points at a non-existent `tests/` directory; the
  suites are script-style by design.
* Two expected empty/malformed corpus cases still log fallback `Semgrep execution failed`
  messages (pre-existing; metrics unaffected).

**Known remaining false negatives (documented, not fixed in this phase)** — the five
groups in §5.3. The highest-value follow-ups: Python/JS support for
algorithm-negotiation lists and "weak hash passed as a callable" (would convert
`PAR-018` and `PAR-023…029`), JWT/RSA signature rules for JS/TS (would convert six
Juice Shop sites), and rules for DSA keygen / `nacl` signatures.

---

## 8. User UAT checklist (PENDING USER CONFIRMATION)

| # | Action | Expected | Status |
|---|---|---|---|
| 1 | `cd backend && python test_dataflow.py` | 98 checks pass, exit 0 | PENDING |
| 2 | `cd backend && python worker.py benchmark` | 62 cases, F1 0.9880, gates pass, 1 known FN | PENDING |
| 3 | `cd backend && python report_counts.py` | all suites pass (including `test_api.py`), counts 106 rules / 62 cases / 10 fixtures | PENDING |
| 4 | Clone both pinned repos to `/tmp/pqc-ext` and run `python -m benchmark.external_eval --all --workdir /tmp/pqc-ext` | reproduces P 0.8571 / R 0.4615 / F1 0.6000, `pinned_verified: true` for both targets | PENDING |
| 5 | Inspect `docs/engineering/data/phase-2-external-validation.json` | no source snippets, no absolute paths, ground truth rubric + per-site outcomes present | PENDING |
| 6 | `cd backend && python cipher_cli.py selfcheck` and `semgrep --config rules.yaml --validate` | exit 0; 106 rules; 0 errors | PENDING |
| 7 | `cd frontend && npm run build && npm run lint` | both exit 0 | PENDING |
| 8 | Decide whether the external F1 0.6000 is an acceptable **starting** baseline (recommended: yes as a recorded baseline, never as a gate) | decision recorded | PENDING |

**Stop condition:** Phase 2 ends here. Phase 3 has not been started and will not start
without explicit sign-off.
