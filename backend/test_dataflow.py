#!/usr/bin/env python3
# backend/test_dataflow.py
"""
test_dataflow.py — Phase 2 evidence-model, data-flow and metrics tests
=====================================================================
Covers the Phase 2 acceptance surface without pytest:

  * Python bounded constant propagation (aliases, chains, string expressions,
    joins, wrappers, env/config values, API mode objects)
  * Java bounded constant propagation (JCA getInstance sinks, cipher
    transformations, parameters, static fields, parser failures)
  * Cross-engine deduplication + provenance retention + disagreement reporting
  * Stable fingerprints under line shifts and across same-named files
  * Bounded runtime / no path explosion
  * No egress: no absolute paths, no source snippets, no secret values
  * Metric provenance: ruleset/corpus hashes, age/staleness, release gates

Run:  venv/bin/python test_dataflow.py   (no pytest required)
"""

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dataflow_java  # noqa: E402
import dataflow_python  # noqa: E402
import evidence  # noqa: E402
import metrics  # noqa: E402
import scanner  # noqa: E402

PASSED = []


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ✓ {name}")


def _tree(files: dict) -> str:
    root = tempfile.mkdtemp(prefix="pqc-df-")
    for rel, content in files.items():
        path = os.path.join(root, rel)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return root


def _py(files: dict) -> list:
    root = _tree(files)
    return dataflow_python.analyze_directory(root)["findings"]


def _java(files: dict) -> list:
    root = _tree(files)
    return dataflow_java.analyze_directory(root)["findings"]


def _rules(findings) -> set:
    return {f["rule_id"] for f in findings}


# ---------------------------------------------------------------------------
# Python data-flow
# ---------------------------------------------------------------------------

def test_python_alias_and_chain():
    findings = _py({"m.py": (
        "import hashlib as h\n"
        "ALGO = 'md5'\n"
        "def f(data):\n"
        "    algo = ALGO\n"
        "    selected = algo\n"
        "    return h.new(selected, data).digest()\n"
    )})
    got = [f for f in findings if f["rule_id"] == "weak-crypto-python-md5"]
    check("python: alias import + assignment chain -> md5", len(got) == 1,
          _rules(findings))
    check("python: chain evidence is constant_propagated",
          got and got[0]["evidence_type"] == "constant_propagated")
    check("python: chain confidence high", got and got[0]["confidence_tier"] == "high")
    check("python: observed value recorded", got and got[0].get("observed_value") == "md5")


def test_python_string_expressions():
    findings = _py({"s.py": (
        "import hashlib\n"
        "P = 'sh'\n"
        "def a(d):\n"
        "    n = P + 'a1'\n"
        "    return hashlib.new(n, d)\n"
        "def b(d):\n"
        "    n = '%s%s' % ('sh', 'a1')\n"
        "    return hashlib.new(n, d)\n"
        "def c(d):\n"
        "    n = '{}1'.format('sha')\n"
        "    return hashlib.new(n, d)\n"
    )})
    got = [f for f in findings if f["rule_id"] == "weak-crypto-python-sha1"]
    check("python: concat/%/format all resolve to sha1", len(got) == 3, len(got))
    check("python: string expressions report the resolved value",
          all(f.get("observed_value") == "sha1" for f in got))


def test_python_env_value_is_inconclusive_not_a_pass():
    # The environment *value* must never be rendered; only the source name may
    # appear. Set a real-looking value so the assertion is meaningful.
    env_name = "PIQUACHU_TEST_DIGEST_ALGO"
    env_value = "md5-value-that-must-not-leak"
    os.environ[env_name] = env_value
    try:
        findings = _py({"e.py": (
            "import os, hashlib\n"
            "def f(d):\n"
            f"    algo = os.environ.get('{env_name}')\n"
            "    return hashlib.new(algo, d)\n"
        )})
    finally:
        os.environ.pop(env_name, None)
    rules = _rules(findings)
    check("python: env value -> unresolved evidence",
          "dataflow-unresolved-algorithm-python" in rules, rules)
    unresolved = [f for f in findings
                  if f["rule_id"] == "dataflow-unresolved-algorithm-python"]
    check("python: env evidence is inconclusive",
          unresolved and unresolved[0]["confidence_tier"] == "inconclusive")
    check("python: env evidence is informational (cannot drive risk)",
          unresolved and unresolved[0].get("informational") is True)
    blob = repr(findings)
    check("python: env value is never rendered", env_value not in blob)
    check("python: the env source name is recorded instead",
          unresolved and env_name in (unresolved[0].get("source_description") or ""),
          unresolved[0].get("source_description") if unresolved else None)


def test_python_wrapper_forwarding():
    findings = _py({"w.py": (
        "import hashlib\n"
        "def make_hash(algo='md5'):\n"
        "    return hashlib.new(algo)\n"
        "def use(d):\n"
        "    return make_hash()\n"
    )})
    got = [f for f in findings if f["rule_id"] == "weak-crypto-python-md5"]
    check("python: wrapper default propagated to sink", len(got) == 1, _rules(findings))
    check("python: wrapper evidence is data_flow",
          got and got[0]["evidence_type"] == "data_flow")
    check("python: wrapper confidence medium (crosses a call)",
          got and got[0]["confidence_tier"] == "medium")


def test_python_joins():
    same = _py({"j.py": (
        "import hashlib\n"
        "def f(flag):\n"
        "    if flag:\n"
        "        algo = 'md5'\n"
        "    else:\n"
        "        algo = 'md5'\n"
        "    return hashlib.new(algo).digest()\n"
    )})
    check("python: agreeing join resolves to md5",
          "weak-crypto-python-md5" in _rules(same), _rules(same))
    check("python: agreeing join stays high confidence",
          any(f["confidence_tier"] == "high" for f in same))

    divergent = _py({"j2.py": (
        "import hashlib\n"
        "def f(flag):\n"
        "    if flag:\n"
        "        algo = 'md5'\n"
        "    else:\n"
        "        algo = 'sha256'\n"
        "    return hashlib.new(algo).digest()\n"
    )})
    rules = _rules(divergent)
    check("python: divergent join is not claimed as md5",
          "weak-crypto-python-md5" not in rules, rules)
    check("python: divergent join is reported as unresolved",
          "dataflow-unresolved-algorithm-python" in rules, rules)
    check("python: divergent join never counts as a risk finding",
          all(f.get("informational") for f in divergent))


def test_python_api_sinks():
    findings = _py({"c.py": (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "def enc(key, data):\n"
        "    return Cipher(algorithms.AES(key), modes.ECB()).encryptor()\n"
    )})
    check("python: ECB mode object detected",
          "deprecated-ecb-python" in _rules(findings), _rules(findings))


def test_python_false_positive_bait():
    findings = _py({"bait.py": (
        '"""md5 and sha1 are retired; ECB is forbidden."""\n'
        "RETIRED = {'md5': True, 'sha1': True}\n"
        "WARNING = 'ECB mode is not allowed'\n"
    )})
    check("python: unused algorithm strings raise nothing", not findings,
          [f["rule_id"] for f in findings])


def test_python_parser_failure_isolation():
    root = _tree({"good.py": "import hashlib\nhashlib.new('md5')\n",
                  "bad.py": "def broken(:\n    pass\n"})
    res = dataflow_python.analyze_directory(root)
    check("python: parse failure counted", res["diagnostics"]["parser_failures"].get("python") == 1,
          res["diagnostics"])
    check("python: good file still analyzed",
          any(f["rule_id"] == "weak-crypto-python-md5" for f in res["findings"]))
    check("python: failure file path is relative",
          res["diagnostics"]["parser_failure_files"] == ["bad.py"],
          res["diagnostics"]["parser_failure_files"])


def test_python_runtime_is_bounded():
    lines = ["import hashlib"]
    lines += [f"v{i} = 'x{i}'" for i in range(4000)]
    lines += [f"def f{i}(d):\n    a = v{i}\n    return hashlib.new(a, d)" for i in range(200)]
    root = _tree({"big.py": "\n".join(lines) + "\n"})
    started = time.monotonic()
    res = dataflow_python.analyze_directory(root)
    elapsed = time.monotonic() - started
    check("python: 4000 assignments + 200 functions completes", res["findings"] is not None)
    check("python: bounded runtime (< 10s)", elapsed < 10.0, f"{elapsed:.2f}s")


# ---------------------------------------------------------------------------
# Java data-flow
# ---------------------------------------------------------------------------

def test_java_constant_propagation():
    findings = _java({"A.java": (
        "import java.security.MessageDigest;\n"
        "import javax.crypto.Cipher;\n"
        "public class A {\n"
        "    static final String ALG = \"MD\" + \"5\";\n"
        "    static final String T = \"AES/ECB/PKCS5Padding\";\n"
        "    public MessageDigest md() throws Exception {\n"
        "        String algo = ALG;\n"
        "        return MessageDigest.getInstance(algo);\n"
        "    }\n"
        "    public Cipher c() throws Exception {\n"
        "        return Cipher.getInstance(T);\n"
        "    }\n"
        "}\n"
    )})
    rules = _rules(findings)
    check("java: MD5 via static field + local chain", "weak-crypto-java-md5" in rules, rules)
    check("java: ECB transformation via static field", "deprecated-ecb-java" in rules, rules)
    check("java: ECB observed value retained",
          any(f.get("observed_value") == "AES/ECB/PKCS5Padding" for f in findings))


def test_java_parameter_is_inconclusive():
    findings = _java({"P.java": (
        "import java.security.MessageDigest;\n"
        "public class P {\n"
        "    public MessageDigest md(String algorithm) throws Exception {\n"
        "        return MessageDigest.getInstance(algorithm);\n"
        "    }\n"
        "}\n"
    )})
    rules = _rules(findings)
    check("java: parameter-driven algorithm -> unresolved",
          "dataflow-unresolved-algorithm-java" in rules, rules)
    got = [f for f in findings if f["rule_id"] == "dataflow-unresolved-algorithm-java"]
    check("java: parameter source is named",
          got and got[0].get("source_description") == "parameter:algorithm")
    check("java: parameter evidence is inconclusive",
          got and got[0]["confidence_tier"] == "inconclusive")
    check("java: absent algorithm is not read as safe or unsafe",
          "weak-crypto-java-md5" not in rules, rules)


def test_java_safe_value_negative():
    findings = _java({"Safe.java": (
        "import java.security.MessageDigest;\n"
        "public class Safe {\n"
        "    public MessageDigest md() throws Exception {\n"
        "        return MessageDigest.getInstance(\"SHA-256\");\n"
        "    }\n"
        "}\n"
    )})
    check("java: SHA-256 is not flagged", not findings, [f["rule_id"] for f in findings])


def test_java_parser_failure():
    root = _tree({"Good.java": (
        "import java.security.MessageDigest;\n"
        "public class Good {\n"
        "    public MessageDigest md() throws Exception {\n"
        "        return MessageDigest.getInstance(\"MD5\");\n"
        "    }\n"
        "}\n"
    ), "Broken.java": "public class Broken { void f( { }\n"})
    res = dataflow_java.analyze_directory(root)
    check("java: grammar failure recorded",
          res["diagnostics"]["parser_failures"].get("java") == 1, res["diagnostics"])
    check("java: valid file still reported",
          any(f["rule_id"] == "weak-crypto-java-md5" for f in res["findings"]))
    check("java: failure names the file and error type",
          any(e.startswith("Broken.java:")
              for e in res["diagnostics"].get("parser_failure_errors", [])),
          res["diagnostics"].get("parser_failure_errors"))
    check("java: parser availability is reported explicitly",
          res["diagnostics"].get("javalang_available") is True,
          res["diagnostics"].get("javalang_available"))


# ---------------------------------------------------------------------------
# Evidence model: fingerprints, dedupe, provenance
# ---------------------------------------------------------------------------

def test_fingerprints_are_stable_and_scoped():
    root = _tree({"a.py": "import hashlib\nalgo='md5'\nhashlib.new(algo)\n"})
    first = scanner.scan_directory(root)["findings"]
    with open(os.path.join(root, "a.py"), "w", encoding="utf-8") as fh:
        fh.write("\n\n# header comment shifts every line down\n" + 
                 "import hashlib\nalgo='md5'\nhashlib.new(algo)\n")
    second = scanner.scan_directory(root)["findings"]
    fp1 = {f["rule_id"]: f["fingerprint"] for f in first}
    fp2 = {f["rule_id"]: f["fingerprint"] for f in second}
    check("fingerprints: stable under line shift", fp1 == fp2, (fp1, fp2))
    check("fingerprints: line evidence moved",
          min(f["line"] for f in second) > min(f["line"] for f in first))
    check("fingerprints: well formed",
          all(f["fingerprint"].startswith("pqc1-") and len(f["fingerprint"]) == 29
              for f in second), [f["fingerprint"] for f in second])
    check("fingerprints: no source text embedded",
          all("hashlib" not in f["fingerprint"] for f in second))


def test_same_named_files_do_not_collide():
    body = "import hashlib\nalgo = 'md5'\nhashlib.new(algo)\n"
    root = _tree({"pkg1/a.py": body, "pkg2/a.py": body})
    findings = scanner.scan_directory(root)["findings"]
    fps = {f["fingerprint"] for f in findings}
    check("fingerprints: pkg1/pkg2 identical files stay distinct", len(fps) == 2, fps)
    check("fingerprints: paths keep directory identity",
          {f["file"] for f in findings} == {"pkg1/a.py", "pkg2/a.py"},
          {f["file"] for f in findings})


def test_cross_engine_dedupe_and_provenance():
    root = _tree({"d.py": "import hashlib\nh = hashlib.new('md5')\n"})
    result = scanner.scan_directory(root)
    line2 = [f for f in result["findings"] if f["line"] == 2]
    check("dedupe: one finding per rule per call site", len(line2) == 1,
          [(f["rule_id"], f["engine"]) for f in line2])
    engines = {p.get("engine") for p in (line2[0].get("provenance") or [])}
    check("dedupe: both engines retained as provenance",
          {"semgrep", "dataflow-py"} <= engines, engines)
    check("dedupe: cross-engine confirmation flagged",
          line2[0].get("cross_engine_confirmed") is True)
    check("dedupe: highest-confidence evidence wins",
          line2[0]["evidence_type"] == "constant_propagated",
          line2[0]["evidence_type"])


def test_disagreement_is_reported_not_merged():
    findings = [
        evidence.annotate({"file": "x.py", "line": 10, "vulnerability": "rule-a"},
                          engine="semgrep", evidence_type="ast_api_pattern",
                          confidence="medium", evidence_signature="pattern:a"),
        evidence.annotate({"file": "x.py", "line": 10, "vulnerability": "rule-b"},
                          engine="dataflow-py", evidence_type="constant_propagated",
                          confidence="high", evidence_signature="call:b"),
    ]
    deduped, disagreements = evidence.reconcile(findings)
    check("disagreement: contradictory rules are both kept", len(deduped) == 2,
          [(f["rule_id"], f["engine"]) for f in deduped])
    check("disagreement: reported explicitly", len(disagreements) == 1, disagreements)
    check("disagreement: names both rules",
          disagreements and disagreements[0]["rules"] == ["rule-a", "rule-b"])


def test_no_source_or_host_path_egress():
    root = _tree({"deep/nested/leak.py": (
        "import hashlib\n"
        "TOKEN = 'super-secret-value-should-not-appear'\n"
        "hashlib.new('md5')\n"
    )})
    result = scanner.scan_directory(root)
    blob = repr(result["findings"])
    check("egress: no absolute host path in findings", root not in blob)
    check("egress: stored path is relative",
          all(not str(f.get("file", "")).startswith("/") for f in result["findings"]))
    check("egress: fingerprints carry no source text",
          all("hashlib" not in f.get("fingerprint", "")
              for f in result["findings"]))
    check("egress: nested directory identity retained",
          any(f["file"] == "deep/nested/leak.py" for f in result["findings"]),
          {f["file"] for f in result["findings"]})


def test_mixed_language_tree():
    root = _tree({
        "py/agent.py": "import hashlib\nalgo='md5'\nhashlib.new(algo)\n",
        "java/Agent.java": (
            "import java.security.MessageDigest;\n"
            "public class Agent {\n"
            "    public MessageDigest md() throws Exception {\n"
            "        String a = \"MD5\";\n"
            "        return MessageDigest.getInstance(a);\n"
            "    }\n"
            "}\n"
        ),
        "README.md": "Uses md5 today; migrating.\n",
    })
    result = scanner.scan_directory(root)
    check("mixed: python data-flow finding present",
          any(f.get("language") == "python" and f["engine"] == "dataflow-py"
              for f in result["findings"]))
    check("mixed: java data-flow finding present",
          any(f.get("language") == "java" and f["engine"] == "dataflow-java"
              for f in result["findings"]))
    check("mixed: unrelated docs produce no finding",
          not any("README" in str(f.get("file")) for f in result["findings"]))


# ---------------------------------------------------------------------------
# Metric provenance and release gates
# ---------------------------------------------------------------------------

def test_metric_provenance():
    import hashlib
    rules = metrics.ruleset_fingerprint()
    with open(metrics.RULES_PATH, "rb") as fh:
        expected = hashlib.sha256(fh.read()).hexdigest()
    check("metrics: ruleset hash matches rules.yaml", rules["sha256"] == expected)
    check("metrics: ruleset reports a rule count", rules["rules"] > 0)
    corpus = metrics.corpus_fingerprint()
    check("metrics: corpus hash is deterministic",
          corpus["sha256"] == metrics.corpus_fingerprint()["sha256"])
    check("metrics: corpus counts binary + uncertain cases",
          corpus["binary_cases"] + corpus["uncertain_cases"] == corpus["cases"],
          corpus)


def test_staleness_is_reported():
    stale = {
        "generated_at": "2020-01-01T00:00:00+00:00",
        "confusion": {"tp": 1, "fp": 0, "fn": 0, "tn": 1},
        "metrics": {"f1": 1.0},
    }
    out = metrics.annotate(stale, max_age_seconds=60)
    check("metrics: age computed from generated_at", out["age_seconds"] > 60,
          out["age_seconds"])
    check("metrics: stale cache is flagged", out["stale"] is True)
    fresh = metrics.annotate({"generated_at": metrics.datetime.now(
        metrics.timezone.utc).isoformat()}, max_age_seconds=300)
    check("metrics: fresh report is not flagged stale", fresh["stale"] is False)


def test_release_gates():
    good = metrics.release_gates({
        "confusion": {"fp": 0, "fn": 1},
        "metrics": {"f1": 0.98},
        "errors": [],
        "expectation_failures": [],
        "unexpected_misses": [],
        "corpus_size": 62,
    }, known_misses={"known": "documented"})
    check("gates: documented miss passes hermetic gate",
          good["hermetic_fixtures"] == "pass", good)
    check("gates: zero FP floor passes", good["false_positive_floor"] == "pass")
    check("gates: external baseline stays not-run without a run",
          good["external_baseline"] == "not-run")

    bad = metrics.release_gates({
        "confusion": {"fp": 1, "fn": 0},
        "metrics": {"f1": 0.9},
        "errors": [],
        "expectation_failures": ["case-x"],
        "unexpected_misses": ["case-x"],
        "corpus_size": 62,
    }, known_misses={})
    check("gates: new miss fails the hermetic gate",
          bad["hermetic_fixtures"] == "fail", bad)
    check("gates: broken per-case assertions fail",
          bad["hermetic_expectations"] == "fail")
    check("gates: false positive fails the FP floor",
          bad["false_positive_floor"] == "fail")


def test_benchmark_report_is_versioned():
    from benchmark import runner
    report = runner.run_all()
    check("benchmark: metric source is hermetic",
          report["metric_source"] == "hermetic")
    check("benchmark: ruleset fingerprint attached",
          report["ruleset"]["sha256"] and report["ruleset"]["version"])
    check("benchmark: corpus fingerprint attached",
          report["corpus"]["cases"] == report["corpus_size"])
    check("benchmark: generated_at present", bool(report["generated_at"]))
    check("benchmark: release gates computed",
          report["release_gates"]["hermetic_fixtures"] == "pass",
          report["release_gates"])
    check("benchmark: uncertain cases excluded from confusion",
          report["confusion"]["tp"] + report["confusion"]["fp"] +
          report["confusion"]["fn"] + report["confusion"]["tn"]
          == report["binary_cases"], report["confusion"])
    check("benchmark: every data-flow case passes its assertions",
          not report["expectation_failures"], report["expectation_failures"])


def test_reliability_endpoint_provenance():
    """Endpoint publishes provenance/freshness without a benchmark run.

    The cached report is injected so this check is fast and deterministic; the
    full-corpus *metric* correctness is covered by test_benchmark_report_is_versioned.
    """
    import app as api

    now = metrics.datetime.now(metrics.timezone.utc).isoformat()
    fake = {
        "generated_at": now,
        "metric_source": "hermetic",
        "corpus_size": 3,
        "confusion": {"tp": 1, "fp": 0, "fn": 0, "tn": 2},
        "metrics": {"accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1": 1.0},
        "release_gates": {"hermetic_fixtures": "pass",
                          "hermetic_expectations": "pass",
                          "false_positive_floor": "pass",
                          "external_baseline": "not-run", "details": {}},
    }
    original_cache = dict(api._reliability_cache)
    original_compute = api._compute_reliability
    api._reliability_cache.update({"at": time.time(), "report": fake})
    api._compute_reliability = lambda: None  # never launch a scan from a unit test
    try:
        client = api.app.test_client()
        r = client.get("/api/v1/reliability",
                       headers={"X-API-Key": "super-secret-key-123"})
        check("reliability: ready response", r.status_code == 200, r.status_code)
        body = r.get_json()
        check("reliability: metric source labelled",
              body.get("metric_source") == "hermetic", body.get("metric_source"))
        check("reliability: ruleset fingerprint attached",
              bool((body.get("ruleset") or {}).get("sha256")))
        check("reliability: corpus fingerprint attached",
              bool((body.get("corpus") or {}).get("sha256")))
        check("reliability: age reported",
              isinstance(body.get("age_seconds"), (int, float)), body.get("age_seconds"))
        check("reliability: fresh report not stale", body.get("stale") is False)
        check("reliability: last successful run reported",
              bool(body.get("last_successful_run")), body.get("last_successful_run"))
        check("reliability: external metrics not fabricated",
              (body.get("external_validation") or {}).get("metric_source") == "not-run",
              body.get("external_validation"))
        check("reliability: external baseline is not-run, not pass",
              (body.get("release_gates") or {}).get("external_baseline") == "not-run")
        check("reliability: no host paths in payload",
              "/home/" not in repr(body) and "/tmp/" not in repr(body))

        # Stale metric: an old generated_at is stale even in a fresh cache slot.
        api._reliability_cache.update(
            {"at": time.time(), "report": dict(
                fake, generated_at="2020-01-01T00:00:00+00:00")})
        stale = client.get("/api/v1/reliability",
                           headers={"X-API-Key": "super-secret-key-123"}).get_json()
        check("reliability: stale cache flagged", stale.get("stale") is True)
        check("reliability: stale report keeps its real age",
              (stale.get("age_seconds") or 0) > 60, stale.get("age_seconds"))

        # A failed background refresh must not replace the last good metric.
        api._reliability_cache.update({
            "at": time.time(), "report": fake, "last_error": None,
            "last_success": fake["generated_at"]})
        api._compute_reliability = lambda: api._reliability_cache.update(
            {"last_error": {"at": "2026-10-19T00:00:00+00:00",
                            "error": "simulated benchmark failure"}})
        api._compute_reliability()
        after = client.get("/api/v1/reliability",
                           headers={"X-API-Key": "super-secret-key-123"}).get_json()
        check("reliability: failed run keeps last good report",
              (after.get("metrics") or {}).get("f1") == 1.0, after.get("metrics"))
        check("reliability: failed run is surfaced, not swallowed",
              "last_attempt_failed" in after, after.get("last_attempt_failed"))
        check("reliability: good report is not marked stale after a failure",
              after.get("stale") is False)

        unauth = client.get("/api/v1/reliability")
        check("reliability: unauthorized without key", unauth.status_code == 401)
    finally:
        api._reliability_cache.clear()
        api._reliability_cache.update(original_cache)
        api._compute_reliability = original_compute


def test_zip_hardening_precedes_parsing():
    """New parsers run only on already-extracted, budget-checked content."""
    import zipfile

    # 1) Archive guards still fire before any analysis can happen.
    buf = __import__("io").BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../escape.py", "x = 1\n")
    buf.seek(0)
    try:
        with zipfile.ZipFile(buf) as zf:
            scanner.safe_extract_zip(zf, tempfile.mkdtemp(prefix="pqc-zip-"))
        check("zip: traversal rejected before analysis", False)
    except scanner.ZipExtractionError:
        check("zip: traversal rejected before analysis", True)

    # Budgets are supplied by the API layer (app.MAX_ZIP_ENTRIES /
    # MAX_DECOMPRESSED_BYTES); mirror them here so the guard is exercised.
    import app as api
    buf = __import__("io").BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(api.MAX_ZIP_ENTRIES + 1):
            zf.writestr(f"f{i}.py", "x = 1\n")
    buf.seek(0)
    try:
        with zipfile.ZipFile(buf) as zf:
            scanner.safe_extract_zip(
                zf, tempfile.mkdtemp(prefix="pqc-zip-"),
                max_entries=api.MAX_ZIP_ENTRIES,
                max_bytes=api.MAX_DECOMPRESSED_BYTES)
        check("zip: entry flood rejected before analysis", False)
    except scanner.ZipExtractionError:
        check("zip: entry flood rejected before analysis", True)

    # 2) The parsers themselves never extract archives or execute code.
    here = os.path.dirname(os.path.abspath(__file__))
    import ast as pyast
    for module in ("dataflow_python.py", "dataflow_java.py"):
        with open(os.path.join(here, module), "r", encoding="utf-8") as fh:
            src = fh.read()
        forbidden = [tok for tok in ("zipfile", "subprocess", "os.system")
                     if tok in src]
        tree = pyast.parse(src)
        dynamic = sorted({n.func.id for n in pyast.walk(tree)
                          if isinstance(n, pyast.Call)
                          and isinstance(n.func, pyast.Name)
                          and n.func.id in {"eval", "exec", "compile",
                                            "__import__"}})
        forbidden.extend(dynamic)
        check(f"{module}: no extraction/execution primitives", not forbidden, forbidden)


def main() -> int:
    tests = [
        test_python_alias_and_chain,
        test_python_string_expressions,
        test_python_env_value_is_inconclusive_not_a_pass,
        test_python_wrapper_forwarding,
        test_python_joins,
        test_python_api_sinks,
        test_python_false_positive_bait,
        test_python_parser_failure_isolation,
        test_python_runtime_is_bounded,
        test_java_constant_propagation,
        test_java_parameter_is_inconclusive,
        test_java_safe_value_negative,
        test_java_parser_failure,
        test_fingerprints_are_stable_and_scoped,
        test_same_named_files_do_not_collide,
        test_cross_engine_dedupe_and_provenance,
        test_disagreement_is_reported_not_merged,
        test_no_source_or_host_path_egress,
        test_mixed_language_tree,
        test_metric_provenance,
        test_staleness_is_reported,
        test_release_gates,
        test_benchmark_report_is_versioned,
        test_reliability_endpoint_provenance,
        test_zip_hardening_precedes_parsing,
    ]
    print("=" * 64)
    print("Phase 2 — evidence model, data-flow and metrics")
    print("=" * 64)
    for test in tests:
        print(f"\n[{test.__name__.replace('test_', '').replace('_', ' ')}]")
        test()
    print("\n" + "=" * 64)
    print(f"ALL {len(PASSED)} CHECKS PASSED ✅")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
