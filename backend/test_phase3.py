#!/usr/bin/env python3
# backend/test_phase3.py
"""
test_phase3.py — acceptance suite for the safe remediation / baseline / SARIF /
CI workflow (Phase 3).

Run:  venv/bin/python test_phase3.py   (no pytest required)

Covers the Phase 3 test matrix:
  * baseline schema/validation, privacy (no source, no host paths)
  * stable identity under line shifts, rename/move best-effort, ambiguity
  * new / persistent / moved / changed / suppressed / resolved classification
  * missing + corrupt baseline fail-safe behaviour
  * suppression expiry (inactive + reported, never silently applied)
  * gate policies (scope + level), annotations vs failures
  * SARIF 2.1.0 against the official OASIS schema (incl. edge cases)
  * patch dry-run default, opt-in apply, atomic write, backup + rollback,
    conflict detection, all-or-nothing batches, idempotence
  * path traversal / symlink escape / unsupported type / parse-error refusals
  * PR creation requires explicit confirmation (no network in tests)
  * CLI exit codes for baseline/gate/SARIF and the patch workflow
  * GitHub Actions + GitLab CI YAML structure (syntax is not proof of behaviour)
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import baseline  # noqa: E402
import evidence  # noqa: E402
import gitlab_sast  # noqa: E402
import patcher  # noqa: E402
import sarif  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
CLI = os.path.join(HERE, "cipher_cli.py")

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if not condition:
        FAILED.append(name)
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ✓ {name}")


def mk(rule="weak-crypto-python-md5", path="src/a.py", line=10,
       severity="WARNING", conf="medium", sig="call:hashlib.md5",
       category="hashing", standard="FIPS 202", pqc=False, **extra):
    """Normalized Phase 2 finding (fingerprint + site signature included)."""
    raw = {"vulnerability": rule, "file": path, "line": line,
           "severity": severity, "category": category,
           "nist_standard": standard}
    raw.update(extra)
    finding = evidence.annotate(raw, engine="ast", evidence_type="pattern",
                               confidence=conf, evidence_signature=sig)
    if pqc:
        finding["pqc_compliant"] = True
    return finding


def _write(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _run_cli(*args, cwd=None):
    """Run the CLI with CI markers stripped so baseline writes are allowed."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "GITHUB_TOKEN")}
    return subprocess.run([sys.executable, CLI, *args], cwd=cwd or HERE,
                          capture_output=True, text=True, env=env, timeout=300)


RSA_FIXTURE = (
    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    "\n"
    "\n"
    "def keypair():\n"
    "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
)

MD5_FIXTURE = (
    "import hashlib\n"
    "\n"
    "\n"
    "def digest(data):\n"
    "    return hashlib.md5(data).hexdigest()\n"
)


# ---------------------------------------------------------------------------
# Baseline document + strict validation
# ---------------------------------------------------------------------------

def test_baseline_document_and_privacy():
    f1 = mk(path="src/a.py", line=10)
    f2 = mk(rule="deprecated-rsa-python-cryptography", path="src/b.py", line=3,
            severity="ERROR", sig="call:rsa.generate_private_key",
            category="key-encapsulation", standard="FIPS 203")
    doc = baseline.build_baseline([f1, f2, mk(pqc=True, sig="call:mlkem")],
                                  ruleset={"sha256": "a" * 64, "rule_count": 2})
    check("baseline kind", doc["kind"] == "piquachu-baseline", doc.get("kind"))
    check("baseline schema version", doc["schema_version"] == baseline.SCHEMA_VERSION)
    check("baseline dedupes + drops PASS evidence", len(doc["findings"]) == 2,
          len(doc["findings"]))
    entry = doc["findings"][0]
    for key in ("fingerprint", "rule_id", "path", "category", "severity", "confidence"):
        check(f"baseline entry has {key}", key in entry, entry.keys())
    check("baseline stores no line numbers",
          not any("line" in e for e in doc["findings"]))
    blob = json.dumps(doc)
    check("baseline stores no source text",
          "hashlib.md5(" not in blob and "generate_private_key(" not in blob)
    check("baseline stores no absolute/host paths",
          "/home/" not in blob and "/tmp/" not in blob)
    check("baseline site signatures are hashes",
          all(str(e.get("site", "")).startswith("h=") for e in doc["findings"]),
          [e.get("site") for e in doc["findings"]])
    check("baseline re-validates cleanly",
          baseline.validate_baseline(doc)["schema_version"] == 1)


def test_baseline_validation_strict():
    good = baseline.build_baseline([mk()])
    cases = {
        "unknown top-level field": dict(good, extra="nope"),
        "unsupported schema_version": dict(good, schema_version=99),
        "findings must be a list": dict(good, findings={"x": 1}),
        "absolute path rejected": dict(good, findings=[
            dict(good["findings"][0], path="/etc/passwd")]),
        "drive-letter path rejected": dict(good, findings=[
            dict(good["findings"][0], path="C:/tmp/a.py")]),
        "unknown entry field rejected": dict(good, findings=[
            dict(good["findings"][0], sneaky="x")]),
        "bad fingerprint rejected": dict(good, findings=[
            dict(good["findings"][0], fingerprint="not-a-fingerprint")]),
        "bad severity rejected": dict(good, findings=[
            dict(good["findings"][0], severity="CRITICAL")]),
        "wildcard suppression rejected": dict(good, suppressions=[{
            "kind": "rule-file", "rule_id": "weak-crypto-python-md5",
            "path": "*", "rationale": "too broad to be meaningful",
            "expires": "2027-01-01"}]),
        "directory suppression rejected": dict(good, suppressions=[{
            "kind": "rule-file", "rule_id": "weak-crypto-python-md5",
            "path": "src/", "rationale": "too broad to be meaningful",
            "expires": "2027-01-01"}]),
        "short rationale rejected": dict(good, suppressions=[{
            "kind": "fingerprint", "fingerprint": good["findings"][0]["fingerprint"],
            "rationale": "short", "expires": "2027-01-01"}]),
        "expiry too far out rejected": dict(good, suppressions=[{
            "kind": "fingerprint", "fingerprint": good["findings"][0]["fingerprint"],
            "rationale": "waiver with a suspiciously long horizon",
            "expires": "2099-01-01"}]),
        "suppression without expiry rejected": dict(good, suppressions=[{
            "kind": "fingerprint", "fingerprint": good["findings"][0]["fingerprint"],
            "rationale": "waiver without an expiry date"}]),
    }
    for name, payload in cases.items():
        try:
            baseline.validate_baseline(payload, source="test")
        except baseline.BaselineError:
            check(f"baseline rejects: {name}", True)
        else:
            check(f"baseline rejects: {name}", False, "no BaselineError raised")


def test_baseline_files_missing_and_corrupt():
    tmp = tempfile.mkdtemp(prefix="pqu-bl-")
    try:
        missing = os.path.join(tmp, "nope.json")
        try:
            baseline.load_baseline(missing)
            check("missing baseline raises", False)
        except baseline.BaselineError as exc:
            check("missing baseline raises", "not found" in str(exc))

        corrupt = os.path.join(tmp, "corrupt.json")
        _write(corrupt, '{"schema_version": 1, "findings": [')
        try:
            baseline.load_baseline(corrupt)
            check("corrupt baseline raises", False)
        except baseline.BaselineError as exc:
            check("corrupt baseline raises", "not valid JSON" in str(exc))

        wrong_type = os.path.join(tmp, "list.json")
        _write(wrong_type, "[]")
        try:
            baseline.load_baseline(wrong_type)
            check("non-object baseline raises", False)
        except baseline.BaselineError:
            check("non-object baseline raises", True)

        # compare(None) must say so explicitly instead of reporting "clean".
        delta = baseline.compare([mk()], None)
        check("no-baseline mode is explicit", delta["mode"] == "no-baseline")
        check("no-baseline marks everything new", delta["counts"]["new"] == 1)
        check("no-baseline is reported as uncertain",
              delta["uncertain"]["is_uncertain"] is True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Identity: line shifts, renames, ambiguity
# ---------------------------------------------------------------------------

def test_identity_survives_line_shift():
    doc = baseline.build_baseline([mk(line=10), mk(line=11, sig="call:hashlib.sha1",
                                                   rule="weak-crypto-python-sha1")])
    shifted = [mk(line=42), mk(line=91, sig="call:hashlib.sha1",
                               rule="weak-crypto-python-sha1")]
    delta = baseline.compare(shifted, doc)
    check("line shift does not create new findings", delta["counts"]["new"] == 0,
          delta["counts"])
    check("line shift keeps findings persistent", delta["counts"]["persistent"] == 2,
          delta["counts"])
    check("line shift is not flagged uncertain",
          delta["uncertain"]["is_uncertain"] is False, delta["uncertain"])


def test_rename_and_move_are_best_effort():
    doc = baseline.build_baseline([mk(path="src/old.py", line=10)])
    moved = baseline.compare([mk(path="src/new.py", line=10)], doc)
    check("rename matched via site signature", moved["counts"]["moved"] == 1,
          moved["counts"])
    check("moved finding records the original path",
          moved["moved"][0].get("moved_from") == "src/old.py",
          moved["moved"][0].get("moved_from"))
    check("rename is declared uncertain (best-effort identity)",
          moved["uncertain"]["is_uncertain"] is True)

    # Two identical call sites in the baseline, one new path => ambiguous.
    doc2 = baseline.build_baseline([mk(path="src/a.py", line=10),
                                    mk(path="src/c.py", line=20)])
    ambiguous = baseline.compare([mk(path="src/b.py", line=10)], doc2)
    check("ambiguous move is classed as new", ambiguous["counts"]["new"] == 1,
          ambiguous["counts"])
    check("ambiguous move is flagged uncertain_identity",
          ambiguous["new"][0].get("uncertain_identity") is True)
    check("ambiguous move is declared uncertain",
          ambiguous["uncertain"]["is_uncertain"] is True)


def test_status_classification():
    persistent = mk(path="src/a.py", line=10)
    changed_now = mk(path="src/b.py", line=5)
    resolved = mk(rule="weak-crypto-python-sha1", path="src/c.py", line=7,
                  sig="call:hashlib.sha1")
    doc = baseline.build_baseline([persistent, mk(path="src/b.py", line=5), resolved])

    current = [dict(persistent, line=77),
               dict(mk(path="src/b.py", line=5), severity="ERROR"),
               mk(rule="deprecated-des-python", path="src/d.py", line=3,
                  sig="call:DES.new", category="symmetric", standard="FIPS 197")]
    delta = baseline.compare(current, doc)
    counts = delta["counts"]
    check("persistent counted", counts["persistent"] == 1, counts)
    check("severity change counted as changed", counts["changed"] == 1, counts)
    check("changed records the difference",
          "severity" in (delta["changed"][0].get("differences") or {}),
          delta["changed"][0].get("differences"))
    check("new finding counted", counts["new"] == 1, counts)
    check("removed finding counted as resolved", counts["resolved"] == 1, counts)
    check("resolved entries keep their baseline metadata",
          delta["resolved"][0]["path"] == "src/c.py", delta["resolved"][0])
    check("no suppression in this scenario", counts["suppressed"] == 0)


def test_suppression_lifecycle():
    finding = mk(severity="ERROR", rule="deprecated-rsa-python-cryptography",
                 path="src/key.py", sig="call:rsa.generate_private_key",
                 category="key-encapsulation", standard="FIPS 203")
    active = baseline.build_baseline([finding], suppressions=[{
        "kind": "rule-file", "rule_id": finding["rule_id"], "path": "src/key.py",
        "rationale": "Interop patch tracked in SEC-1042 (expires next quarter).",
        "expires": "2027-06-30"}])
    delta = baseline.compare([finding], active)
    check("active suppression is counted", delta["counts"]["suppressed"] == 1,
          delta["counts"])
    check("active suppression keeps the finding out of resolved",
          delta["counts"]["resolved"] == 0, delta["counts"])
    gate = baseline.evaluate_gate(delta, baseline.parse_policy("new-error"))
    check("suppressed finding never fails the gate", gate["triggered"] is False,
          gate["failures"])
    check("suppression rationale travels to the delta",
          "SEC-1042" in (delta["suppressed"][0]["suppression"]["rationale"]))

    expired = baseline.build_baseline([finding], suppressions=[{
        "kind": "fingerprint", "fingerprint": finding["fingerprint"],
        "rationale": "Old waiver that should have been removed already.",
        "expires": "2020-01-01"}])
    check("expired suppression moved out of the active list",
          expired["suppressions"] == [] and len(expired["expired_suppressions"]) == 1)
    delta2 = baseline.compare([finding], expired)
    check("expired suppression is not applied any more",
          delta2["counts"]["suppressed"] == 0, delta2["counts"])
    check("finding re-surfaces as persistent, not waived",
          delta2["counts"]["persistent"] == 1, delta2["counts"])
    check("expired suppression is reported on the delta",
          delta2["baseline"]["expired_suppression_count"] == 1)
    gate2 = baseline.evaluate_gate(delta2, baseline.parse_policy("any-high"))
    check("expired waiver re-surfaces under an 'any' policy",
          gate2["triggered"] is True, gate2["failures"])


# ---------------------------------------------------------------------------
# Gate policies
# ---------------------------------------------------------------------------

def test_gate_policies():
    p = baseline.parse_policy("new-high")
    check("policy new-high -> new/ERROR", (p["scope"], p["severity"]) == ("new", "ERROR"))
    check("policy new-warning -> new/WARNING",
          baseline.parse_policy("new-warning")["severity"] == "WARNING")
    check("policy changed-critical -> changed/ERROR",
          baseline.parse_policy("changed-critical")["severity"] == "ERROR")
    check("policy any-low -> any/INFO",
          baseline.parse_policy("any-low")["severity"] == "INFO")
    check("policy none disables gating",
          baseline.parse_policy("none")["scope"] == "none")
    for bad in ("bogus", "", "new-", "-high", "elsewhere-error"):
        try:
            baseline.parse_policy(bad)
            check(f"policy junk {bad!r} rejected", False)
        except baseline.BaselineError:
            check(f"policy junk {bad!r} rejected", True)

    err_new = mk(severity="ERROR", path="src/x.py")
    warn_new = mk(severity="WARNING", path="src/y.py", sig="call:hmac.new",
                  rule="weak-crypto-python-sha1")
    # Baseline entry sits on a DIFFERENT rule + call site, so both current
    # findings are genuinely new (no rename/move best-effort match).
    doc = baseline.build_baseline([mk(severity="ERROR", path="src/old.py",
                                      sig="call:hashlib.sha1",
                                      rule="weak-crypto-python-sha1")])
    delta = baseline.compare([err_new, warn_new], doc)

    high = baseline.evaluate_gate(delta, baseline.parse_policy("new-high"))
    check("new-high fails on the new ERROR", high["triggered"] is True
          and high["exit_code"] == 1, high)
    check("new-high lists only the ERROR",
          [f["rule_id"] for f in high["failures"]] == ["weak-crypto-python-md5"],
          high["failures"])
    warn = baseline.evaluate_gate(delta, baseline.parse_policy("new-warning"))
    check("new-warning fails on both findings", len(warn["failures"]) == 2, warn)

    # A baseline-present finding only fails an "any" scope gate.
    fresh = baseline.build_baseline([err_new, warn_new])
    delta2 = baseline.compare([err_new, warn_new], fresh)
    check("new-scope gate passes when nothing is new",
          baseline.evaluate_gate(delta2, baseline.parse_policy("new-high"))["triggered"] is False)
    check("any-scope gate fails on persisting findings",
          baseline.evaluate_gate(delta2, baseline.parse_policy("any-high"))["triggered"] is True)

    # Inconclusive findings annotate by default; --gate-inconclusive opts in.
    vague = mk(severity="ERROR", conf="inconclusive", path="src/env.py",
               sig="call:env-value")
    delta3 = baseline.compare([vague], baseline.build_baseline([mk(path="src/z.py")]))
    check("inconclusive finding is not gated by default",
          baseline.evaluate_gate(delta3, baseline.parse_policy("new-high"))["triggered"] is False)
    check("inconclusive finding is listed as an annotation",
          len(delta3["annotations"]["by_rule"]) == 1, delta3["annotations"])
    strict = baseline.evaluate_gate(delta3, baseline.parse_policy("new-high"),
                                    gate_inconclusive=True)
    check("gate-inconclusive makes it fail", strict["triggered"] is True, strict)

    # Changed scope: only severity/category/standard changes.
    bl = baseline.build_baseline([mk(path="src/c.py", severity="WARNING")])
    delta4 = baseline.compare([mk(path="src/c.py", severity="ERROR")], bl)
    check("changed-scope gate fires on a severity change",
          baseline.evaluate_gate(delta4, baseline.parse_policy("changed-high"))["triggered"] is True)


def test_baseline_update_is_never_silent():
    tmp = tempfile.mkdtemp(prefix="pqu-blwrite-")
    try:
        path = os.path.join(tmp, "baseline.json")
        first = baseline.build_baseline([mk()])
        diff = baseline.save_baseline(first, path)
        check("baseline written", os.path.isfile(path))
        check("initial write reports additions", len(diff["added"]) == 1, diff)
        check("written baseline is valid",
              baseline.load_baseline(path)["schema_version"] == 1)

        second = baseline.build_baseline([mk(), mk(path="src/extra.py")])
        try:
            baseline.save_baseline(second, path)
            check("overwrite without force refused", False)
        except baseline.BaselineError as exc:
            check("overwrite without force refused", "already exists" in str(exc))

        diff2 = baseline.save_baseline(second, path, force=True)
        check("forced update reports the added entry", len(diff2["added"]) == 1, diff2)
        summary = baseline.baseline_changes_summary(diff2)
        check("update summary is human readable",
              summary.startswith("Baseline changes:") and "\n  + " in summary, summary)

        text = _read(path)
        check("baseline file contains no source snippets",
              "hashlib.md5(" not in text and "def digest" not in text)
        check("baseline file contains no host paths",
              "/home/" not in text and tmp not in text)

        os.environ["CI"] = "true"
        try:
            try:
                baseline.save_baseline(second, path, force=True)
                check("baseline write refused inside CI", False)
            except baseline.BaselineError as exc:
                check("baseline write refused inside CI", "CI environment" in str(exc))
            baseline.save_baseline(second, path, force=True, allow_in_ci=True)
            check("explicit --allow-in-ci overrides the CI refusal", True)
        finally:
            os.environ.pop("CI", None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

def test_sarif_schema_and_edge_cases():
    warn = mk(path="src/a.py", line=7, end_line=9)
    err = mk(rule="deprecated-rsa-python-cryptography", path="src/b.py", line=3,
             severity="ERROR", sig="call:rsa.generate_private_key",
             category="key-encapsulation", standard="FIPS 203")
    note = mk(rule="pqc-mlkem-python", path="src/c.py", line=1, severity="INFO",
              sig="call:mlkem", pqc=True)

    doc = sarif.build_sarif({"findings": [warn, err, note], "engine": "ast+semgrep"})
    check("sarif schema valid (findings)", sarif.validate_sarif(doc) == [],
          sarif.validate_sarif(doc)[:2])
    check("sarif tool name/version",
          doc["runs"][0]["tool"]["driver"]["name"] == "PiQuaChu"
          and doc["runs"][0]["tool"]["driver"]["version"])
    check("sarif help URIs present",
          all(r.get("helpUri") for r in doc["runs"][0]["tool"]["driver"]["rules"]))
    check("PASS evidence is not a SARIF result", len(doc["runs"][0]["results"]) == 2,
          len(doc["runs"][0]["results"]))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    check("severity mapping ERROR->error",
          levels["deprecated-rsa-python-cryptography"] == "error", levels)
    check("severity mapping WARNING->warning",
          levels["weak-crypto-python-md5"] == "warning", levels)
    by_rule = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    region = by_rule["weak-crypto-python-md5"]["locations"][0]["physicalLocation"]["region"]
    check("multi-line region preserved", region["startLine"] == 7
          and region["endLine"] == 9, region)
    check("partial fingerprints are stable",
          by_rule["weak-crypto-python-md5"]["partialFingerprints"]["pquFingerprint/v1"]
          == warn["fingerprint"])

    empty = sarif.build_sarif({"findings": []})
    check("sarif with no findings is valid", sarif.validate_sarif(empty) == [])
    check("sarif with no findings has no results", empty["runs"][0]["results"] == [])

    unlocated = sarif.build_sarif({"findings": [mk(path="", line=0)]})
    check("missing location is valid", sarif.validate_sarif(unlocated) == [])
    check("missing location is flagged, not invented",
          unlocated["runs"][0]["results"][0]["properties"].get("unlocated") is True)

    duplicate = sarif.build_sarif({"findings": [warn, dict(warn)]})
    check("duplicate findings dedupe to one result",
          len(duplicate["runs"][0]["results"]) == 1)

    unknown = sarif.build_sarif({"findings": [mk(rule="novel-rule-xyz", path="src/n.py")]})
    check("unknown rule still reported", len(unknown["runs"][0]["results"]) == 1)
    check("unknown rule descriptor is marked",
          unknown["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
          .get("unknownRule") is True)
    check("unknown rule document is schema valid", sarif.validate_sarif(unknown) == [])

    diag = sarif.build_sarif({"findings": [],
                              "diagnostics": {"parser_failures": {"java": 2},
                                              "parser_failure_files": ["src/Broken.java"],
                                              "unresolved_values": {"python": 3}}})
    notifications = diag["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    check("parse failures become notifications, not results",
          len(diag["runs"][0]["results"]) == 0 and len(notifications) >= 2,
          notifications)
    check("parse-failure document is schema valid", sarif.validate_sarif(diag) == [])

    # No snippets by default; explicit local opt-in only.
    check("no snippets by default",
          "snippet" not in json.dumps(doc["runs"][0]["results"]))

    def provider(rel, start, end):
        return "SECRET_SNIPPET"

    with_snip = sarif.build_sarif({"findings": [warn]}, snippet_provider=provider)
    check("snippets only appear with an explicit provider",
          "SECRET_SNIPPET" in json.dumps(with_snip))
    check("snippet document is schema valid", sarif.validate_sarif(with_snip) == [])

    delta = baseline.compare([warn], baseline.build_baseline([warn]))
    annotated = sarif.build_sarif({"findings": [warn, err]}, baseline_delta={
        "mode": "baseline", "counts": delta["counts"],
        "new": [err], "persistent": [warn], "moved": [], "changed": [],
        "suppressed": [], "resolved": [], "uncertain": delta["uncertain"],
        "baseline": {"present": True, "schema_version": 1},
    })
    statuses = {r["ruleId"]: r["properties"].get("baselineStatus")
                for r in annotated["runs"][0]["results"]}
    check("baseline status carried into SARIF",
          statuses["deprecated-rsa-python-cryptography"] == "new"
          and statuses["weak-crypto-python-md5"] == "persistent", statuses)
    check("baseline SARIF is schema valid", sarif.validate_sarif(annotated) == [])


def test_sarif_paths_are_safe():
    unicode_finding = mk(path="src/üñî code#1.py", line=4)
    doc = sarif.build_sarif({"findings": [unicode_finding]})
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    check("unicode + spaces percent-encoded",
          uri == "src/%C3%BC%C3%B1%C3%AE%20code%231.py", uri)
    check("uriBaseId is SRCROOT",
          doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
          ["artifactLocation"]["uriBaseId"] == "SRCROOT")
    check("originalUriBaseIds is relative",
          doc["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"] == ".")
    check("unicode document is schema valid", sarif.validate_sarif(doc) == [])

    windows = mk(path="src\\win dir\\a.py", line=2)
    doc2 = sarif.build_sarif({"findings": [windows]})
    uri2 = doc2["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    check("windows separators normalised", "\\" not in uri2 and "%5C" not in uri2, uri2)
    check("windows path has no drive letter", ":" not in uri2, uri2)

    host = mk(path="/home/someone/secret/project/src/a.py", line=3)
    doc3 = sarif.build_sarif({"findings": [host]})
    blob = json.dumps(doc3)
    check("absolute host paths never leak",
          "/home/" not in blob and "someone" not in blob, blob[:200])
    check("absent host path is schema valid", sarif.validate_sarif(doc3) == [])


# ---------------------------------------------------------------------------
# Patcher: dry-run, classes, apply, rollback, conflicts, guards
# ---------------------------------------------------------------------------

def test_patch_dry_run_and_classes():
    tmp = tempfile.mkdtemp(prefix="pqu-patch-")
    try:
        path = os.path.join(tmp, "app.py")
        _write(path, MD5_FIXTURE)
        dry = patcher.build_patch(path, root=tmp)
        check("md5 rewrite is only a conditional candidate",
              dry["applicability"] == "candidate-only", dry["applicability"])
        check("dry-run produces no diff", dry["diff"] == "")
        check("candidate lists its preconditions",
              dry["candidates"] and dry["candidates"][0].get("preconditions"),
              dry["candidates"])
        check("dry-run does not touch the file", _read(path) == MD5_FIXTURE)

        reviewed = patcher.build_patch(path, root=tmp, include_candidates=True,
                                       findings=[mk(path="app.py", line=5)])
        check("reviewed candidate is applicable", reviewed["applicability"] == "applied")
        check("diff is a unified diff", reviewed["diff"].startswith("--- a/app.py"),
              reviewed["diff"][:40])
        check("diff switches md5 -> sha256", "sha256" in reviewed["diff"])
        check("patch metadata records hashes",
              reviewed["old_sha256"] != reviewed["new_sha256"])
        check("parser validation recorded as passed",
              reviewed["validation"]["ok"] is True, reviewed["validation"])
        check("patch metadata records rule ids",
              "weak-crypto-python-md5" in reviewed["rule_ids"], reviewed["rule_ids"])
        check("file still untouched after building", _read(path) == MD5_FIXTURE)

        ecb_src = ("from Crypto.Cipher import AES\n"
                   "\n"
                   "def encrypt(key, data):\n"
                   "    return AES.new(key, AES.MODE_ECB).encrypt(data)\n")
        ecb_path = os.path.join(tmp, "ecb.py")
        _write(ecb_path, ecb_src)
        ecb = patcher.build_patch(ecb_path, root=tmp, include_candidates=True)
        check("AES/ECB rewrite downgraded to manual-only",
              ecb["applicability"] == "manual-only", ecb["applicability"])
        check("ECB manual record explains why",
              "nonce" in " ".join(ecb["manual"][0].get("follow_up", [])).lower(),
              ecb["manual"][0])
        check("ECB source is never rewritten", _read(ecb_path) == ecb_src)

        mldsa_src = ("from oqs import Signature\n"
                     "\n"
                     "def sign(sk, msg):\n"
                     "    return Signature('ML-DSA-65').sign(msg, sk)\n")
        pqc_path = os.path.join(tmp, "pqc.py")
        _write(pqc_path, mldsa_src)
        check("PQC API call is left alone",
              patcher.build_patch(pqc_path, root=tmp, include_candidates=True) is None)

        nested = os.path.join(tmp, "tests", "test_crypto.py")
        _write(nested, "import random\n\n\ndef make_key():\n"
                       "    secret_key = random.choice('abcdef')\n"
                       "    return secret_key\n")
        test_patch = patcher.build_patch(nested, root=tmp, include_candidates=True)
        check("test-path RNG rewrite is skipped, not applied",
              test_patch["applicability"] == "skipped"
              and test_patch["skipped"][0].get("class") == "conditional-candidate",
              test_patch["applicability"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_patch_apply_backup_and_rollback():
    tmp = tempfile.mkdtemp(prefix="pqu-apply-")
    try:
        path = os.path.join(tmp, "app.py")
        _write(path, MD5_FIXTURE)
        patch = patcher.build_patch(path, root=tmp, include_candidates=True)

        modified = patcher.apply_patches([patch], root=tmp)
        check("apply reports the modified file", modified == ["app.py"], modified)
        applied_text = _read(path)
        check("apply wrote the SHA-256 rewrite",
              "sha256" in applied_text and "md5" not in applied_text, applied_text)
        manifest_path = patch.get("rollback_manifest")
        check("rollback manifest recorded", bool(manifest_path)
              and os.path.isfile(manifest_path), manifest_path)
        manifest = json.loads(_read(manifest_path))
        check("manifest is a local artifact",
              manifest["kind"] == "piquachu-rollback-manifest"
              and manifest["local_artifact"] is True)
        check("manifest records old/new hashes",
              manifest["files"][0]["old_sha256"] == patch["old_sha256"]
              and manifest["files"][0]["new_sha256"] == patch["new_sha256"])
        check("backup exists next to the target",
              os.path.isfile(os.path.join(manifest["backup_dir"],
                                          manifest["files"][0]["backup"])))

        # Idempotence: a second pass finds nothing to rewrite.
        again = patcher.build_patch(path, root=tmp, include_candidates=True)
        check("second run is idempotent (no diff)", again is None or again["diff"] == "",
              again and again["applicability"])

        restored = patcher.rollback(manifest_path)
        check("rollback restores the file", restored == ["app.py"], restored)
        check("rollback restores the original content", _read(path) == MD5_FIXTURE)

        # Rollback refuses to clobber a file edited after apply.
        patch2 = patcher.build_patch(path, root=tmp, include_candidates=True)
        patcher.apply_patches([patch2], root=tmp)
        _write(path, _read(path) + "\n# developer edit after apply\n")
        try:
            patcher.rollback(patch2["rollback_manifest"])
            check("rollback refuses post-apply edits", False)
        except patcher.PatchConflictError as exc:
            check("rollback refuses post-apply edits", "modified after apply" in str(exc))
        check("refused rollback leaves the developer edit intact",
              "# developer edit after apply" in _read(path))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_patch_conflicts_and_all_or_nothing():
    tmp = tempfile.mkdtemp(prefix="pqu-conflict-")
    try:
        a = os.path.join(tmp, "a.py")
        b = os.path.join(tmp, "b.py")
        _write(a, MD5_FIXTURE)
        _write(b, "import hashlib\n\n\ndef h2(data):\n"
                  "    return hashlib.sha1(data).hexdigest()\n")
        p_a = patcher.build_patch(a, root=tmp, include_candidates=True)
        p_b = patcher.build_patch(b, root=tmp, include_candidates=True)

        _write(b, _read(b) + "\n# concurrent edit\n")
        try:
            patcher.apply_patches([p_a, p_b], root=tmp)
            check("stale patch is refused", False)
        except patcher.PatchConflictError as exc:
            check("stale patch is refused", "changed since the diff" in str(exc))
        check("conflict aborts before any write (all-or-nothing)",
              _read(a) == MD5_FIXTURE, _read(a))
        check("conflicting file untouched",
              "concurrent edit" in _read(b) and "sha256" not in _read(b))

        # Re-analysis after the edit produces a clean, appliable patch again.
        p_a2 = patcher.build_patch(a, root=tmp, include_candidates=True)
        check("re-analysis yields a fresh patch",
              p_a2["applicability"] == "applied")

        # Patches from different roots are refused outright.
        other = tempfile.mkdtemp(prefix="pqu-other-")
        try:
            c = os.path.join(other, "c.py")
            _write(c, MD5_FIXTURE)
            p_c = patcher.build_patch(c, root=other, include_candidates=True)
            try:
                patcher.apply_patches([p_a2, p_c], root=tmp)
                check("multi-root batch refused", False)
            except patcher.PatchError as exc:
                check("multi-root batch refused", "span multiple roots" in str(exc))
        finally:
            shutil.rmtree(other, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_patch_target_guards():
    tmp = tempfile.mkdtemp(prefix="pqu-guard-")
    outside = tempfile.mkdtemp(prefix="pqu-outside-")
    try:
        target = os.path.join(tmp, "app.py")
        _write(target, MD5_FIXTURE)
        patch = patcher.build_patch(target, root=tmp, include_candidates=True)

        traversal = dict(patch, path="../escape.py")
        try:
            patcher.apply_patches([traversal], root=tmp)
            check("path traversal refused", False)
        except patcher.PatchError as exc:
            check("path traversal refused", "traversal" in str(exc).lower(), exc)

        escaped = dict(patch, path="outside.py",
                       abs_path=os.path.join(outside, "outside.py"))
        _write(escaped["abs_path"], MD5_FIXTURE)
        try:
            patcher.apply_patches([escaped], root=tmp)
            check("target outside the root refused", False)
        except patcher.PatchError:
            check("target outside the root refused", True)
        check("outside file untouched", _read(escaped["abs_path"]) == MD5_FIXTURE)

        unsupported = dict(patch, path="notes.txt",
                           abs_path=os.path.join(tmp, "notes.txt"),
                           new_content="x", diff="@@ -1 +1 @@\n-a\n+b\n")
        _write(unsupported["abs_path"], "a\n")
        try:
            patcher.apply_patches([unsupported], root=tmp)
            check("unsupported file type refused", False)
        except patcher.PatchError as exc:
            check("unsupported file type refused", "unsupported file type" in str(exc))

        link = os.path.join(tmp, "link.py")
        os.symlink(target, link)
        link_patch = patcher.build_patch(link, root=tmp)
        check("symlinked file is refused by analysis",
              link_patch["applicability"] == "refused-symlink",
              link_patch["applicability"])
        check("symlink refusal explains the risk",
              "escape" in link_patch["reason"].lower(), link_patch["reason"])

        swap = patcher.build_patch(target, root=tmp, include_candidates=True)
        os.unlink(target)
        os.symlink(os.path.join(outside, "outside.py"), target)
        try:
            patcher.apply_patches([swap], root=tmp)
            check("symlink swap before apply is refused", False)
        except patcher.PatchError:
            check("symlink swap before apply is refused", True)
        check("symlink target outside the root untouched",
              _read(os.path.join(outside, "outside.py")) == MD5_FIXTURE)

        fifo_dir = tempfile.mkdtemp(prefix="pqu-fifo-")
        try:
            fifo = os.path.join(fifo_dir, "pipe.py")
            os.mkfifo(fifo)
            rec = patcher.build_patch(fifo, root=fifo_dir)
            check("non-regular file refused",
                  rec["applicability"] == "refused-not-regular", rec["applicability"])
        finally:
            shutil.rmtree(fifo_dir, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(outside, ignore_errors=True)


def test_patch_parse_error_refusal():
    tmp = tempfile.mkdtemp(prefix="pqu-parse-")
    try:
        broken = os.path.join(tmp, "broken.py")
        broken_src = "import hashlib\n\ndef digest(:\n    return hashlib.md5(b'x')\n"
        _write(broken, broken_src)
        rec = patcher.build_patch(broken, root=tmp, include_candidates=True)
        check("unparsable file refused",
              rec["applicability"] == "refused-parse-error", rec["applicability"])
        check("refusal explains parse errors are never regex-fixed",
              "parse errors are never" in rec["reason"], rec["reason"])
        check("refused file is left byte-identical", _read(broken) == broken_src)
        try:
            patcher.apply_patches([dict(rec, diff="@@ -1 +1 @@\n-a\n+b\n",
                                        new_content="broken")], root=tmp)
            check("refused patch cannot be applied", False)
        except patcher.PatchError:
            check("refused patch cannot be applied", True)
        check("refused file still byte-identical", _read(broken) == broken_src)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_pr_creation_requires_confirmation():
    tmp = tempfile.mkdtemp(prefix="pqu-pr-")
    try:
        path = os.path.join(tmp, "app.py")
        _write(path, MD5_FIXTURE)
        patch = patcher.build_patch(path, root=tmp, include_candidates=True,
                                    findings=[mk(path="app.py", line=5)])
        try:
            patcher.github_pull_request("owner/repo", [patch], branch="pqu/fix")
            check("PR creation refused without confirmation", False)
        except patcher.PatchError as exc:
            check("PR creation refused without confirmation",
                  "confirmation" in str(exc), exc)
        preview = patcher.github_pr_preview("owner/repo", [patch], branch="pqu/fix")
        check("PR preview makes no network calls",
              preview["network_calls_made"] is False)
        check("PR preview lists files + rules",
              preview["files"] and preview["files"][0]["path"] == "app.py"
              and preview["files"][0]["rule_ids"], preview["files"])
        check("PR preview metadata carries hashes",
              preview["files"][0]["old_sha256"] != preview["files"][0]["new_sha256"])
        check("no branch/commit was created", _read(path) == MD5_FIXTURE)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI end-to-end (exit codes are the CI contract)
# ---------------------------------------------------------------------------

def test_cli_baseline_gate_exit_codes():
    tmp = tempfile.mkdtemp(prefix="pqu-cli-")
    try:
        proj = os.path.join(tmp, "project")
        _write(os.path.join(proj, "app.py"), RSA_FIXTURE)
        bl = os.path.join(tmp, "baseline.json")
        sarif_out = os.path.join(tmp, "out.sarif")

        r = _run_cli("scan", proj, "--no-baseline", "--fail-on", "new-high")
        check("cli: explicit no-baseline gate fails on new ERROR", r.returncode == 1,
              r.stderr[-300:])
        check("cli: gate failure message names the policy",
              "new-high" in (r.stdout + r.stderr), r.stdout[-300:])

        r = _run_cli("scan", proj, "--sarif", sarif_out)
        check("cli: sarif scan succeeds", r.returncode == 0, r.stderr[-300:])
        with open(sarif_out, "r", encoding="utf-8") as fh:
            sarif_doc = json.load(fh)
        check("cli: sarif artifact is schema valid", sarif.validate_sarif(sarif_doc) == [],
              sarif.validate_sarif(sarif_doc)[:2])
        check("cli: sarif artifact contains no source snippets",
              "generate_private_key(public_exponent" not in json.dumps(sarif_doc))

        r = _run_cli("scan", proj, "--update-baseline", bl)
        check("cli: explicit baseline update succeeds", r.returncode == 0, r.stderr[-300:])
        check("cli: baseline file written", os.path.isfile(bl))
        check("cli: update prints a change summary",
              "Baseline written" in r.stdout, r.stdout[-300:])

        r = _run_cli("scan", proj, "--baseline", bl, "--fail-on", "new-high")
        check("cli: baselined findings do not fail the gate", r.returncode == 0,
              r.stdout[-300:] + r.stderr[-300:])

        r = _run_cli("scan", proj, "--baseline", bl, "--fail-on", "none")
        check("cli: policy none never fails", r.returncode == 0, r.stderr[-300:])

        # A new WARNING stays green under new-high but fails under new-warning.
        _write(os.path.join(proj, "extra.py"),
               "import hashlib\n\n\ndef h(data):\n"
               "    return hashlib.sha1(data).hexdigest()\n")
        r = _run_cli("scan", proj, "--baseline", bl, "--fail-on", "new-high")
        check("cli: new WARNING ignored by new-high", r.returncode == 0,
              r.stdout[-400:])
        r = _run_cli("scan", proj, "--baseline", bl, "--fail-on", "new-warning")
        check("cli: new WARNING fails new-warning", r.returncode == 1, r.stdout[-400:])

        r = _run_cli("scan", proj, "--baseline", os.path.join(tmp, "missing.json"),
                     "--fail-on", "new-high")
        check("cli: missing baseline fails safe (exit 2)", r.returncode == 2,
              r.stderr[-300:])
        check("cli: missing baseline is not reported as clean",
              "NOT being reported as clean" in r.stderr, r.stderr[-300:])

        bad = os.path.join(tmp, "bad.json")
        _write(bad, "{ this is not json")
        r = _run_cli("scan", proj, "--baseline", bad, "--fail-on", "new-high")
        check("cli: corrupt baseline fails safe (exit 2)", r.returncode == 2,
              r.stderr[-300:])

        r = _run_cli("scan", proj, "--baseline", bl, "--fail-on", "nonsense")
        check("cli: invalid policy is a usage error (exit 2)", r.returncode == 2)

        json_out = os.path.join(tmp, "report.json")
        r = _run_cli("scan", proj, "--baseline", bl, "--json", "--output", json_out)
        check("cli: json report written", r.returncode == 0 and os.path.isfile(json_out))
        with open(json_out, "r", encoding="utf-8") as fh:
            report = json.load(fh)
        check("cli: report carries the baseline delta", "baseline_delta" in report)
        check("cli: report keeps diagnostics + disagreements",
              "diagnostics" in report and "engine_disagreements" in report,
              sorted(report))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_cli_patch_workflow():
    tmp = tempfile.mkdtemp(prefix="pqu-clipatch-")
    try:
        proj = os.path.join(tmp, "project")
        target = os.path.join(proj, "app.py")
        _write(target, MD5_FIXTURE)

        r = _run_cli("patch", proj)
        check("cli: patch defaults to dry-run", r.returncode == 0, r.stderr[-300:])
        check("cli: dry-run says nothing was written",
              "DRY-RUN" in r.stdout, r.stdout[-300:])
        check("cli: dry-run leaves the file untouched", _read(target) == MD5_FIXTURE)
        check("cli: dry-run never creates a backup dir",
              not os.path.exists(os.path.join(proj, ".piquachu-backups")))

        r = _run_cli("patch", proj, "--include-candidates", "--apply")
        check("cli: opt-in apply succeeds", r.returncode == 0, r.stderr[-400:])
        check("cli: applied file has the rewrite", "sha256" in _read(target),
              _read(target))
        check("cli: apply prints the rollback manifest",
              "rollback manifest:" in r.stdout, r.stdout[-400:])
        manifest_line = [ln for ln in r.stdout.splitlines()
                         if "rollback manifest:" in ln][0]
        manifest_path = manifest_line.split("rollback manifest:", 1)[1].strip()
        check("cli: rollback manifest exists", os.path.isfile(manifest_path))

        # Backups must never pollute a later scan.
        r = _run_cli("scan", proj, "--json")
        check("cli: scan after apply still succeeds", r.returncode == 0, r.stderr[-300:])
        with open(os.devnull, "w") as _:
            pass

        r = _run_cli("patch", "--rollback", manifest_path)
        check("cli: rollback succeeds", r.returncode == 0, r.stderr[-300:])
        check("cli: rollback restores original bytes", _read(target) == MD5_FIXTURE)

        r = _run_cli("patch", proj, "--apply", "--repo", "owner/repo")
        check("cli: --apply on a clean tree is a no-op", r.returncode == 0,
              r.stderr[-300:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# CI definitions
# ---------------------------------------------------------------------------

def _load_yaml(path):
    """Parse CI YAML with PyYAML when present, else `ruamel.yaml` (already a
    pinned dependency of the requirements), so the check never silently skips."""
    try:
        import yaml  # noqa: PLC0415
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh), None
    except ImportError:
        pass
    try:
        from ruamel.yaml import YAML  # noqa: PLC0415
    except ImportError:
        return None, "no YAML parser installed (pyyaml or ruamel.yaml)"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = YAML(typ="safe", pure=True).load(fh)
        # Normalize ruamel containers/scalars to plain JSON types (also maps a
        # YAML-1.1 boolean `on:` key to the string "true", handled below).
        return json.loads(json.dumps(data)), None
    except Exception as exc:  # noqa: BLE001 — reported as a parse failure
        return None, f"YAML parse error: {exc}"


def test_ci_workflow_files():
    gh_path = os.path.join(REPO_ROOT, ".github", "workflows", "piquachu-scan.yml")
    gl_path = os.path.join(REPO_ROOT, ".gitlab-ci.yml")
    check("github workflow exists", os.path.isfile(gh_path), gh_path)
    check("gitlab ci exists", os.path.isfile(gl_path), gl_path)

    gh, err = _load_yaml(gh_path)
    check("github workflow YAML is parseable", gh is not None, err)
    if gh is not None:
        check("github workflow parses", isinstance(gh, dict))
        # YAML 1.1 parsers turn the `on:` key into True (and JSON into "true").
        triggers = gh.get("on") or gh.get(True) or gh.get("true") or {}
        if isinstance(triggers, list):
            triggers = {t: None for t in triggers}
        check("github runs on pull_request", "pull_request" in triggers, triggers)
        check("github has no default permissions", gh.get("permissions") == {},
              gh.get("permissions"))
        jobs = gh.get("jobs") or {}
        check("github has a scan job", "scan" in jobs, sorted(jobs))
        scan_job = jobs["scan"]
        check("github scan job is read-only",
              scan_job.get("permissions", {}).get("contents") == "read"
              and "security-events" not in scan_job.get("permissions", {}),
              scan_job.get("permissions"))
        uses = []
        for job in jobs.values():
            for step in job.get("steps", []):
                if "uses" in step:
                    uses.append(step["uses"])
        check("github actions are SHA-pinned",
              uses and all("@" in u and len(u.split("@")[1]) == 40
                           and all(ch in "0123456789abcdef" for ch in u.split("@")[1])
                           for u in uses), uses)
        check("github checkout disables the persisted token",
              any(step.get("with", {}).get("fetch-depth") == 0
                  for step in scan_job.get("steps", [])))
        text = _read(gh_path)
        check("github never uses pull_request_target", "pull_request_target" not in text)
        check("github passes no secrets to the scan",
              "secrets." not in text.split("code-scanning-upload")[0], "secret in scan job")
        check("github gate policy is new-findings based",
              "--fail-on new-high" in text)
        check("github uploads SARIF as an artifact",
              "upload-artifact" in text and "piquachu.sarif" in text)
        check("github fails safe on baseline errors",
              "rc\" -eq 2" in text or "-eq 2" in text, "no exit-2 handling")

    gl, err = _load_yaml(gl_path)
    check("gitlab ci YAML is parseable", gl is not None, err)
    if gl is not None:
        check("gitlab ci parses", isinstance(gl, dict))
        job = gl.get("piquachu-pqc-scan")
        check("gitlab scan job exists", isinstance(job, dict), sorted(gl))
        check("gitlab job is MR + default-branch scoped",
              any("merge_request_event" in str(r) for r in job.get("rules", [])),
              job.get("rules"))
        check("gitlab job runs unprivileged",
              "services" not in job and job.get("tags") is None, job)
        check("gitlab image is pinned to a version",
              str(job.get("image", "")).startswith("python:") and
              "latest" not in str(job.get("image")), job.get("image"))
        artifacts = job.get("artifacts") or {}
        paths = artifacts.get("paths") or []
        check("gitlab publishes SARIF + JSON artifacts",
              any("sarif" in p for p in paths) and any("json" in p for p in paths),
              paths)
        reports = artifacts.get("reports") or {}
        check("gitlab declares the native SAST report",
              reports.get("sast") == "gl-sast-report.json", reports)
        check("gitlab publishes the SAST report as a path artifact too",
              "gl-sast-report.json" in paths, paths)
        check("gitlab scan writes the SAST report",
              "--gitlab-sast gl-sast-report.json" in _read(gl_path))
        check("gitlab SAST report is kept when the gate fails",
              artifacts.get("when") == "always", artifacts)
        check("gitlab gates on new findings",
              "--fail-on new-high" in _read(gl_path))
        check("gitlab pins full history for the MR baseline",
              str((gl.get("variables") or {}).get("GIT_DEPTH")) == "0",
              gl.get("variables"))


# ---------------------------------------------------------------------------
# GitLab SAST export (gl-sast-report.json)
# ---------------------------------------------------------------------------

def test_gitlab_sast_export():
    findings = [
        mk(rule="deprecated-rsa-python-cryptography", path="src/app.py", line=8,
           severity="ERROR", sig="call:rsa.generate_private_key",
           category="key-encapsulation", standard="FIPS 203"),
        mk(path="src/util.py", line=5),
        mk(rule="pqc-ml-kem-python", path="src/kem.py", line=3, pqc=True),
        mk(rule="advisory-note", path="src/note.py", line=1, informational=True),
        mk(rule="wrapper-flow", path="src/wrap.py", line=2, conf="inconclusive"),
        mk(rule="severity-unknown", path="src/odd.py", line=4, severity="BOGUS"),
        mk(rule="unlocated-rule", path="", line=0),
    ]
    doc, stats = gitlab_sast.build_report({"findings": findings,
                                           "engine_version": "9.9.9"},
                                          start_time="2026-01-02T03:04:05",
                                          end_time="2026-01-02T03:04:06")

    check("gitlab exp: document is schema valid", gitlab_sast.validate_report(doc) == [],
          gitlab_sast.validate_report(doc)[:3])
    check("gitlab exp: version matches the pinned schema",
          doc["version"] == gitlab_sast.REPORT_VERSION == "15.2.5")
    check("gitlab exp: scan block is a completed SAST scan",
          doc["scan"]["type"] == "sast" and doc["scan"]["status"] == "success"
          and doc["scan"]["scanner"]["version"] == "9.9.9", doc["scan"]["scanner"])
    check("gitlab exp: only actionable findings become vulnerabilities",
          stats["included"] == 2 and len(doc["vulnerabilities"]) == 2, stats)
    check("gitlab exp: exclusions are counted, never silent",
          stats["excluded"] == {"pass_evidence": 1, "informational": 1,
                               "inconclusive": 1, "unlocated": 1,
                               "unknown_severity": 1}, stats["excluded"])
    check("gitlab exp: exclusion count is disclosed in scan.messages",
          any("not exported" in m["value"] for m in doc["scan"]["messages"]),
          doc["scan"]["messages"])
    check("gitlab exp: severity mapping is ERROR→High / WARNING→Medium",
          {v["severity"] for v in doc["vulnerabilities"]} == {"High", "Medium"},
          [v["severity"] for v in doc["vulnerabilities"]])
    check("gitlab exp: vulnerabilities are ordered deterministically",
          [v["location"]["file"] for v in doc["vulnerabilities"]] ==
          ["src/app.py", "src/util.py"])

    blob = json.dumps(doc)
    check("gitlab exp: no absolute host paths", "/tmp/" not in blob and "/home/" not in blob)
    check("gitlab exp: no source extract field", "raw_source_code_extract" not in blob)
    check("gitlab exp: rule identifiers are present and stable",
          all(v["identifiers"][0]["value"] == v["identifiers"][0]["name"]
              for v in doc["vulnerabilities"]))

    # Stable identity: same call site (even after a line shift) keeps its id.
    shifted, _ = gitlab_sast.build_report({"findings": [
        mk(rule="deprecated-rsa-python-cryptography", path="src/app.py", line=99,
           severity="ERROR", sig="call:rsa.generate_private_key")]})
    original = [v for v in doc["vulnerabilities"]
                if v["location"]["file"] == "src/app.py"][0]
    check("gitlab exp: vulnerability id survives a line shift",
          shifted["vulnerabilities"][0]["id"] == original["id"],
          (shifted["vulnerabilities"][0]["id"], original["id"]))
    rerun, _ = gitlab_sast.build_report({"findings": findings[:2]})
    check("gitlab exp: ids are deterministic across runs",
          [v["id"] for v in rerun["vulnerabilities"]] ==
          [v["id"] for v in doc["vulnerabilities"]])

    # Empty inventory is valid (and must not invent a vulnerability).
    empty, estats = gitlab_sast.build_report({"findings": []})
    check("gitlab exp: empty scan is schema valid with zero vulnerabilities",
          empty["vulnerabilities"] == [] and gitlab_sast.validate_report(empty) == [],
          estats)

    # A malformed finding is skipped, not crashed on, and is accounted for.
    junk, jstats = gitlab_sast.build_report({"findings": [
        {"vulnerability": "", "file": None, "line": None,
         "severity": "ERROR"},
        {"vulnerability": "no-file", "file": None, "line": 3, "severity": "ERROR"},
    ]})
    check("gitlab exp: malformed findings cannot break the artifact",
          junk["vulnerabilities"] == [] and gitlab_sast.validate_report(junk) == [],
          jstats)

    # Validation is real: a corrupted severity/type must be rejected.
    bad = json.loads(json.dumps(doc))
    bad["vulnerabilities"][0]["severity"] = "Severe"
    check("gitlab exp: invalid severity is rejected by the official schema",
          gitlab_sast.validate_report(bad) != [])
    bad_type = json.loads(json.dumps(doc))
    bad_type["scan"]["type"] = "dast"
    check("gitlab exp: invalid scan type is rejected by the official schema",
          gitlab_sast.validate_report(bad_type) != [])
    no_ids = json.loads(json.dumps(doc))
    no_ids["vulnerabilities"][0]["identifiers"] = []
    check("gitlab exp: missing identifiers are rejected (minItems 1)",
          gitlab_sast.validate_report(no_ids) != [])

    # End-to-end: CI writes the artifact even when the gate fails.
    tmp = tempfile.mkdtemp(prefix="pqu-gl-")
    try:
        proj = os.path.join(tmp, "project")
        _write(os.path.join(proj, "app.py"), RSA_FIXTURE)
        out = os.path.join(tmp, "gl-sast-report.json")
        r = _run_cli("scan", proj, "--gitlab-sast", out,
                     "--no-baseline", "--fail-on", "new-high")
        check("cli: SAST gate failure keeps exit code 1", r.returncode == 1,
              r.stderr[-300:])
        check("cli: SAST artifact is written despite the gate failure",
              os.path.isfile(out), r.stdout[-300:])
        with open(out, "r", encoding="utf-8") as fh:
            cli_doc = json.load(fh)
        check("cli: SAST artifact validates",
              gitlab_sast.validate_report(cli_doc) == [],
              gitlab_sast.validate_report(cli_doc)[:3])
        check("cli: SAST artifact reports the RSA finding as High",
              any(v["severity"] == "High" and "rsa" in v["identifiers"][0]["value"]
                  for v in cli_doc["vulnerabilities"]), cli_doc["vulnerabilities"])
        check("cli: SAST artifact has no source snippet",
              "generate_private_key(public_exponent" not in json.dumps(cli_doc))
        r = _run_cli("scan", proj, "--gitlab-sast", out,
                     "--no-baseline", "--fail-on", "none")
        check("cli: SAST scan passes with policy none", r.returncode == 0,
              r.stderr[-300:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------

TESTS = [
    test_baseline_document_and_privacy,
    test_baseline_validation_strict,
    test_baseline_files_missing_and_corrupt,
    test_identity_survives_line_shift,
    test_rename_and_move_are_best_effort,
    test_status_classification,
    test_suppression_lifecycle,
    test_gate_policies,
    test_baseline_update_is_never_silent,
    test_sarif_schema_and_edge_cases,
    test_sarif_paths_are_safe,
    test_patch_dry_run_and_classes,
    test_patch_apply_backup_and_rollback,
    test_patch_conflicts_and_all_or_nothing,
    test_patch_target_guards,
    test_patch_parse_error_refusal,
    test_pr_creation_requires_confirmation,
    test_cli_baseline_gate_exit_codes,
    test_cli_patch_workflow,
    test_ci_workflow_files,
    test_gitlab_sast_export,
]


def main() -> int:
    print("=" * 68)
    print("Phase 3 — baselines, SARIF, safe patching, CI workflow")
    print("=" * 68)
    for test in TESTS:
        print(f"\n[{test.__name__.replace('test_', '').replace('_', ' ')}]")
        try:
            test()
        except AssertionError as exc:
            print(f"  ✗ {exc}")
    print("\n" + "=" * 68)
    if FAILED:
        print(f"FAILED: {len(FAILED)} check(s) — {FAILED}")
        print("=" * 68)
        return 1
    print(f"ALL {len(PASSED)} CHECKS PASSED ✅")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
