"""
runner.py — Reliability benchmark runner
========================================
Executes the scanner over the labeled corpus and computes detection metrics:

    Accuracy  = (TP + TN) / N
    Precision = TP / (TP + FP)        (false-positive control)
    Recall    = TP / (TP + FN)        (false-negative control)
    F1        = 2 * P * R / (P + R)   (harmonic mean)

Label mapping
-------------
A corpus item is a *risk case* (should be flagged) iff its expected label is in
POSITIVE_EXPECTED. The scanner's prediction is "risk present" iff it produced
at least one non-PQC finding OR the project verdict is in the risk set
(non_compliant / at_risk / transitional).

Entry points:
    python -m benchmark.runner              (print report)
    python -m benchmark.runner --json       (machine-readable)
    cipher_cli.py benchmark
"""

import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import metrics  # noqa: E402
import scanner  # noqa: E402

from .corpus import TESTS, build_case_dir  # noqa: E402

POSITIVE_EXPECTED = {
    "NON_COMPLIANT", "NON_COMPLIANT_UNREACHABLE", "NON_COMPLIANT_SEMANTIC",
    "MIXED", "TRANSITIONAL_COMPLIANT", "NO_CODE_USAGE_DEPENDENCY_RISK",
}
NEGATIVE_EXPECTED = {
    "COMPLIANT", "COMPLIANT_SYMMETRIC_ONLY", "NO_CRYPTO_DETECTED",
    "NO_FILES_ERROR_HANDLING",
}
# Cases whose correct outcome is "a human must look": the evidence is genuinely
# unresolved (env/config/dynamic value). They are scored separately and never
# forced into TP/FP/FN/TN, because doing so would invent ground truth.
UNCERTAIN_EXPECTED = {"UNDERTERMINED"}

# Documented, reviewed misses. A miss that is *not* listed here fails the
# hermetic release gate (see metrics.release_gates).
KNOWN_MISSES = {
    "34_minified_js_rsa": (
        "Known FN: RSA key generation inside minified JavaScript that the "
        "current semgrep rules do not match; documented in the Phase 1 report."
    ),
}

RISK_VERDICTS = {"non_compliant", "at_risk", "transitional"}


def expected_risk(expected: str) -> bool:
    if expected in POSITIVE_EXPECTED:
        return True
    if expected in NEGATIVE_EXPECTED:
        return False
    raise ValueError(f"Unknown expected label: {expected!r}")


def actual_risk(result: dict) -> tuple[bool, str]:
    """(risk_present, verdict) from a scan_directory() result."""
    matrix = result.get("compliance", {}) or {}
    findings = result.get("findings", []) or []
    verdict = matrix.get("verdict", "compliant")
    # Inconclusive/informational evidence is displayed but must not change the
    # risk classification (it is explicitly excluded from compliance scoring).
    legacy = [f for f in findings
              if not f.get("pqc_compliant") and not f.get("informational")]
    return (bool(legacy) or verdict in RISK_VERDICTS), verdict


def confusion_label(expected_risk: bool, actual: bool) -> str:
    if expected_risk and actual:
        return "TP"
    if not expected_risk and actual:
        return "FP"
    if expected_risk and not actual:
        return "FN"
    return "TN"


def compute_metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    n = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "accuracy": round((tp + tn) / n, 4) if n else 0.0,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "count": n,
    }


def run_single(case_name: str, spec: dict, workdir: str) -> dict:
    """Scan one corpus case and return the outcome record."""
    case_dir = build_case_dir(case_name, spec, workdir)
    started = time.monotonic()
    result = scanner.scan_directory(case_dir)
    elapsed = round(time.monotonic() - started, 2)

    expected = spec["expected"]
    act_risk, verdict = actual_risk(result)
    findings = result.get("findings", []) or []
    rules = sorted({f.get("vulnerability") for f in findings})
    confidence = sorted({f.get("confidence_tier") for f in findings
                         if f.get("confidence_tier")})

    if expected in UNCERTAIN_EXPECTED:
        exp_risk = None
        label = "UNCERTAIN"
    else:
        exp_risk = expected_risk(expected)
        label = confusion_label(exp_risk, act_risk)

    return {
        "name": case_name,
        "category": spec.get("category", "?"),
        "expected": expected,
        "desc": spec.get("desc", ""),
        "rationale": spec.get("rationale", ""),
        "label_source": spec.get("label_source", "bundled corpus"),
        "kind": spec.get("kind", "synthetic-corpus"),
        "expectation": check_expectations(spec, findings, result),
        "expected_risk": exp_risk,
        "actual_risk": act_risk,
        "actual_verdict": verdict,
        "engine": result.get("engine", "?"),
        "findings": len(findings),
        "rules": rules,
        "confidence_tiers": confidence,
        "parser_failures": (result.get("diagnostics") or {})
                            .get("parser_failures", {}),
        "elapsed_s": elapsed,
        "label": label,
    }


def check_expectations(spec: dict, findings: list, result: dict) -> dict:
    """Verify the per-case rule/confidence/absence assertions.

    The confusion matrix only sees *risk present/absent*. These checks keep the
    corpus honest about which rule fired and which must not fire, so a case
    cannot pass by accidentally matching an unrelated rule.
    """
    problems: list[str] = []
    rules = {str(f.get("vulnerability") or "") for f in findings}
    tiers = {str(f.get("confidence_tier") or "") for f in findings}

    for rule in spec.get("expect_rules", []) or []:
        if rule not in rules:
            problems.append(f"missing expected rule {rule}")
    for rule in spec.get("forbid_rules", []) or []:
        if rule in rules:
            problems.append(f"unexpected rule {rule}")
    for tier in spec.get("expect_confidence", []) or []:
        if tier not in tiers:
            problems.append(f"missing confidence tier {tier}")
    min_parse_failures = spec.get("expect_parser_failures")
    if min_parse_failures:
        got = int((result.get("diagnostics") or {})
                  .get("parser_failures", {}).get("python", 0))
        got += int((result.get("diagnostics") or {})
                   .get("parser_failures", {}).get("java", 0))
        if got < int(min_parse_failures):
            problems.append(f"expected >= {min_parse_failures} parser "
                            f"failure(s), saw {got}")

    return {"ok": not problems, "problems": problems}


def run_all(corpus_dir: str | None = None, tests: dict | None = None) -> dict:
    """Run the full corpus. `tests` overrides the bundled TESTS (used by tests)."""
    tests = tests if tests is not None else TESTS
    workdir = corpus_dir or tempfile.mkdtemp(prefix="piquachu-bench-")
    os.makedirs(workdir, exist_ok=True)

    results = []
    for name in sorted(tests):
        spec = tests[name]
        try:
            results.append(run_single(name, spec, workdir))
        except Exception as exc:  # never let one bad case sink the report
            try:
                exp_risk = expected_risk(spec.get("expected", "NO_CRYPTO_DETECTED"))
            except ValueError:
                exp_risk = None
            results.append({
                "name": name, "category": spec.get("category", "?"),
                "expected": spec.get("expected", "?"), "desc": spec.get("desc", ""),
                "rationale": spec.get("rationale", ""),
                "label_source": spec.get("label_source", "bundled corpus"),
                "kind": spec.get("kind", "synthetic-corpus"),
                "expectation": {"ok": False, "problems": ["case raised"]},
                "expected_risk": exp_risk,
                "actual_risk": False, "actual_verdict": "error",
                "engine": "error", "findings": 0, "rules": [],
                "confidence_tiers": [], "parser_failures": {},
                "elapsed_s": 0.0, "label": "ERROR", "error": str(exc),
            })

    tp = sum(r["label"] == "TP" for r in results)
    fp = sum(r["label"] == "FP" for r in results)
    fn = sum(r["label"] == "FN" for r in results)
    tn = sum(r["label"] == "TN" for r in results)
    uncertain = [r for r in results if r["label"] == "UNCERTAIN"]
    errors = [r for r in results if r["label"] == "ERROR"]
    expectation_failures = [r["name"] for r in results
                            if not (r.get("expectation") or {}).get("ok", True)]
    misses = [r["name"] for r in results
              if r["label"] in ("FP", "FN", "ERROR")]
    unexpected_misses = [name for name in misses if name not in KNOWN_MISSES]

    by_category: dict[str, dict] = {}
    for r in results:
        cat = r["category"]
        bucket = by_category.setdefault(
            cat, {"total": 0, "TP": 0, "FP": 0, "FN": 0, "TN": 0,
                  "UNCERTAIN": 0})
        bucket["total"] += 1
        if r["label"] in ("TP", "FP", "FN", "TN", "UNCERTAIN"):
            bucket[r["label"]] += 1
        else:  # ERROR counts as a miss, never as a pass
            bucket["FN"] += 1

    for cat, bucket in by_category.items():
        bucket["detection_rate"] = round(
            bucket["TP"] / (bucket["TP"] + bucket["FN"]), 4
        ) if (bucket["TP"] + bucket["FN"]) else None

    return metrics.annotate({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "suite": "hermetic-synthetic-corpus",
        "metric_source": "hermetic",
        "engine": _engine_badge(results),
        "corpus_size": len(results),
        "binary_cases": len(results) - len(uncertain) - len(errors),
        "uncertain_cases": [
            {"name": r["name"], "expected": r["expected"],
             "actual_verdict": r["actual_verdict"], "rules": r["rules"]}
            for r in uncertain
        ],
        "errors": [r["name"] for r in errors],
        "expectation_failures": expectation_failures,
        "known_misses": {k: v for k, v in KNOWN_MISSES.items() if k in misses},
        "unexpected_misses": unexpected_misses,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "metrics": compute_metrics(tp, fp, fn, tn),
        "by_category": by_category,
        "results": results,
        "release_gates": metrics.release_gates({
            "confusion": {"fp": fp, "fn": fn},
            "metrics": compute_metrics(tp, fp, fn, tn),
            "errors": [r["name"] for r in errors],
            "expectation_failures": expectation_failures,
            "unexpected_misses": unexpected_misses,
            "corpus_size": len(results),
        }, known_misses=KNOWN_MISSES),
    }, metric_source=metrics.HERMETIC)


def _engine_badge(results: list) -> str:
    from collections import Counter
    engines = [r.get("engine") for r in results if r.get("engine") not in (None, "error")]
    if not engines:
        return "unknown"
    return Counter(engines).most_common(1)[0][0]


def print_report(report: dict) -> None:
    m = report["metrics"]
    c = report["confusion"]
    print("=" * 72)
    print("PiQuaChu reliability benchmark (detection metrics)")
    print("=" * 72)
    print(f"Engine      : {report['engine']}")
    print(f"Suite       : {report.get('suite', 'corpus')} "
          f"({report.get('metric_source', 'hermetic')})")
    print(f"Corpus      : {report['corpus_size']} labeled cases "
          f"({report.get('binary_cases', report['corpus_size'])} binary, "
          f"{len(report.get('uncertain_cases') or [])} uncertain)")
    print(f"Confusion   : TP={c['tp']}  FP={c['fp']}  FN={c['fn']}  TN={c['tn']}")
    print(f"Accuracy    : {m['accuracy']:.4f}")
    print(f"Precision   : {m['precision']:.4f}  (false positives: {c['fp']})")
    print(f"Recall      : {m['recall']:.4f}  (false negatives: {c['fn']})")
    print(f"F1 score    : {m['f1']:.4f}")
    print("-" * 72)
    print("Per-category detection rates:")
    for cat, bucket in report["by_category"].items():
        rate = bucket["detection_rate"]
        rate_s = f"{rate:.2f}" if rate is not None else " n/a"
        print(f"  {cat:<38} {bucket['total']:>2} cases  TP={bucket['TP']} "
              f"FP={bucket['FP']} FN={bucket['FN']}  rate={rate_s}")
    print("-" * 72)
    misses = [r for r in report["results"] if r["label"] in ("FP", "FN", "ERROR")]
    if misses:
        print("Review:")
        for r in misses:
            print(f"  [{r['label']}] {r['name']}: expected={r['expected']} "
                  f"verdict={r['actual_verdict']} findings={r['findings']} "
                  f"rules={r.get('rules', [])}")
    else:
        print("All binary corpus cases classified correctly.")
    if report.get("uncertain_cases"):
        print("Uncertain (excluded from the confusion matrix by design):")
        for r in report["uncertain_cases"]:
            print(f"  [UNCERTAIN] {r['name']}: expected={r['expected']} "
                  f"verdict={r['actual_verdict']} rules={r['rules']}")
    if report.get("expectation_failures"):
        print("Per-case rule/confidence assertions failed:")
        for r in report["results"]:
            exp = r.get("expectation") or {}
            if exp.get("ok", True):
                continue
            print(f"  [{r['name']}] {', '.join(exp.get('problems') or [])}")
    prov = report.get("ruleset") or {}
    corpus = report.get("corpus") or {}
    print("-" * 72)
    print(f"Ruleset     : {prov.get('version')} "
          f"sha256={(prov.get('sha256') or '?')[:12]} rules={prov.get('rules')}")
    print(f"Corpus      : {corpus.get('version')} "
          f"sha256={(corpus.get('sha256') or '?')[:12]} cases={corpus.get('cases')}")
    print(f"Generated   : {report.get('generated_at')}")
    gates = report.get("release_gates") or {}
    if gates:
        shown = {k: v for k, v in gates.items() if k != "details"}
        print("Release gates: " + "  ".join(f"{k}={v}" for k, v in shown.items()))


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="PiQuaChu reliability benchmark")
    parser.add_argument("--json", action="store_true", help="print raw JSON report")
    parser.add_argument("--output", help="write report JSON to a file")
    parser.add_argument("--corpus-dir", help="override corpus directory")
    args = parser.parse_args(argv)

    report = run_all(corpus_dir=args.corpus_dir)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nReport written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
