#!/usr/bin/env python3
# backend/report_counts.py
"""
report_counts.py — canonical, executable project counts
=======================================================
Documentation must not hard-code rule / corpus / test counts that drift from
the code.  This script is the single source for those numbers:

    python report_counts.py            # human-readable
    python report_counts.py --json     # machine-readable
    python report_counts.py --markdown # paste into README/reports

It executes the script-style suites with the current interpreter and reports
their collected "checks" (assertions), which are not the same thing as pytest
test functions.  It never claims a suite passed when it did not.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import compliance  # noqa: E402
import standards  # noqa: E402
from benchmark.corpus import TESTS as CORPUS  # noqa: E402

SUITES = [
    "test_compliance.py",
    "test_standards.py",
    "test_cbom.py",
    "test_extras.py",
    "test_dataflow.py",
    "test_api.py",
    "test_phase3.py",
    "test_phase4.py",
    "test_docs.py",
]

# Suites that need a real service (Redis broker + Celery worker).  They are
# reported separately: a missing service is BLOCKED (never counted as a
# pass), but it does not make the mandatory suites look broken.
OPTIONAL_SUITES = [
    "test_celery_integration.py",
    # Needs a JDK (java/javac/jcmd) for the real-JVM loaded-class checks.
    "test_runtime_java.py",
]

# Committed external-validation report (written by benchmark.external_eval).
EXTERNAL_REPORT = os.path.join(
    os.path.dirname(HERE), "docs", "engineering", "data",
    "phase-2-external-validation.json")
_CHECK_RE = re.compile(r"ALL (\d+) CHECKS PASSED")


def _corpus_count() -> int:
    return len(CORPUS)


def _external_summary() -> dict | None:
    """Summary of the committed external ground-truth run, or None."""
    if not os.path.isfile(EXTERNAL_REPORT):
        return None
    try:
        with open(EXTERNAL_REPORT, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return {
        "report": os.path.relpath(EXTERNAL_REPORT, os.path.dirname(HERE)),
        "metric_source": data.get("metric_source"),
        "generated_at": data.get("generated_at"),
        "targets": data.get("targets"),
        "confusion": data.get("confusion"),
        "metrics": data.get("metrics"),
    }


def _fixture_count() -> int:
    fixture_dir = os.path.join(HERE, "cbom_fixtures")
    if not os.path.isdir(fixture_dir):
        return 0
    return len([f for f in os.listdir(fixture_dir) if f.endswith(".json")])


def run_suite(filename: str) -> dict:
    env = dict(os.environ)
    env["PATH"] = os.path.join(HERE, "venv", "bin") + os.pathsep + env.get("PATH", "")
    proc = subprocess.run(
        [sys.executable, filename],
        cwd=HERE,
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
    )
    output = proc.stdout + proc.stderr
    match = _CHECK_RE.search(output)
    if proc.returncode == 0 and match:
        status = "passed"
    elif proc.returncode == 0 and "BLOCKED:" in output:
        status = "blocked"
    else:
        status = "failed"
    return {
        "suite": filename,
        "exit_code": proc.returncode,
        "checks": int(match.group(1)) if match else None,
        "status": status,
    }


def collect(with_suites: bool = True) -> dict:
    rules = compliance.load_rule_metadata()
    suites = [run_suite(name) for name in SUITES] if with_suites else []
    optional = [run_suite(name) for name in OPTIONAL_SUITES] if with_suites else []
    return {
        "registry_reviewed": standards.REGISTRY_REVIEWED,
        "standards": standards.registry_metadata(),
        "rules": {
            "total": len(rules),
            "by_standard": {
                std: sum(1 for m in rules.values()
                         if m.get("nist_standard") == std)
                for std in standards.standard_ids()
            },
            "advisory_or_other": sum(
                1 for m in rules.values()
                if m.get("nist_standard") not in standards.standard_ids()
            ),
        },
        "corpus_cases": _corpus_count(),
        "cbom_fixtures": _fixture_count(),
        "external_validation": _external_summary(),
        "suites": suites,
        "optional_suites": optional,
        "checks_total": sum(s["checks"] or 0 for s in suites),
        "all_suites_passed": all(s["status"] == "passed" for s in suites) if suites else None,
        # A service-backed suite that RAN and failed is a real failure; one
        # that could not run (BLOCKED) is reported but does not flip the flag.
        "optional_suites_ok": all(s["status"] != "failed" for s in optional)
        if optional else None,
    }


def print_human(counts: dict) -> None:
    print("PiQuaChu canonical counts")
    print("=" * 56)
    print(f"Standards registry reviewed : {counts['registry_reviewed']}")
    print(f"Rules loaded                : {counts['rules']['total']}")
    for std, n in counts["rules"]["by_standard"].items():
        lifecycle = counts["standards"]["lifecycle"][std]
        print(f"  {std:<9} {n:>3} rule(s)  [{lifecycle}]")
    print(f"  Advisory/other           : {counts['rules']['advisory_or_other']}")
    print(f"Labeled corpus cases        : {counts['corpus_cases']}")
    print(f"Committed CBOM fixtures     : {counts['cbom_fixtures']}")
    external = counts.get("external_validation")
    if external:
        ext_metrics = external.get("metrics") or {}
        micro = ext_metrics.get("micro") or ext_metrics
        print(f"External ground truth       : {', '.join(external.get('targets') or [])}"
              f" — precision={micro.get('precision')} recall={micro.get('recall')}"
              f" f1={micro.get('f1')} ({external.get('metric_source')})")
    else:
        print("External ground truth       : not published")
    if counts["suites"]:
        print("-" * 56)
        for suite in counts["suites"]:
            print(f"{suite['suite']:<24} {suite['status']:<8} "
                  f"exit={suite['exit_code']} checks={suite['checks']}")
        print(f"Checks total                : {counts['checks_total']}")
        print(f"All suites passed           : {counts['all_suites_passed']}")
    if counts.get("optional_suites"):
        print("-" * 56)
        for suite in counts["optional_suites"]:
            print(f"{suite['suite']:<24} {suite['status']:<8} "
                  f"exit={suite['exit_code']} checks={suite['checks']} "
                  f"(needs a real service)")
        print(f"Optional suites ok          : {counts['optional_suites_ok']}")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    counts = collect(with_suites="--no-suites" not in argv)
    if "--json" in argv:
        print(json.dumps(counts, indent=2))
    elif "--markdown" in argv:
        print(f"| Metric | Value |\n|---|---|")
        print(f"| Standards registry reviewed | {counts['registry_reviewed']} |")
        print(f"| Rules loaded | {counts['rules']['total']} |")
        print(f"| Labeled corpus cases | {counts['corpus_cases']} |")
        print(f"| Committed CBOM fixtures | {counts['cbom_fixtures']} |")
        if counts["suites"]:
            print(f"| Checks executed (all suites) | {counts['checks_total']} |")
            print(f"| Suites passed | {counts['all_suites_passed']} |")
    else:
        print_human(counts)
    return 0 if (counts["all_suites_passed"] is not False
                 and counts.get("optional_suites_ok") is not False) else 1


if __name__ == "__main__":
    sys.exit(main())
