"""
external.py — External validation against real-world applications
=================================================================
Implements the E1 roadmap item from the Experiment Plan: run the production
scanner over a real, known-vulnerable application (OWASP Juice Shop) and emit
a metrics report in the SAME JSON shape as `worker.py benchmark` (G4 format),
so external results are directly comparable with corpus results.

External validation is *observational*, not labeled-corpus grading: Juice Shop
is a real application, so there is no per-case ground truth to score a
confusion matrix against. The report therefore records detection surface —
per-file findings, verdict, scores, rules fired — plus the benchmark-shaped
metric fields (corpus_size, confusion, metrics) so downstream tooling can
consume both reports identically.

Usage
-----
    # 1. Clone (or reuse a previous clone):
    git clone --depth 1 https://github.com/juice-shop/juice-shop.git /tmp/juice-shop

    # 2. Run the external validation:
    cd backend
    python3 worker.py external --repo /tmp/juice-shop --output external_report.json

    # shorthand (clones automatically into --workdir):
    python3 worker.py external --clone --output external_report.json

Privacy: everything runs locally; the repo never leaves the machine.
"""

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner  # noqa: E402

JUICE_SHOP_URL = "https://github.com/juice-shop/juice-shop.git"
JUICE_SHOP_REF = "master"  # keep pinned for reproducible reports

# Common false-positive sources when scanning a Node.js application.
SKIP_DIRS = {"node_modules", "dist", "build", ".git", "coverage", "vendor",
             "__pycache__", "venv", ".venv", "frontend/node_modules"}


def _log(msg: str) -> None:
    print(msg, flush=True)


def _engine_badge(findings: list) -> str:
    engines = sorted({f.get("engine") for f in findings if f.get("engine")})
    return engines[0] if len(engines) == 1 else ("mixed" if engines else "unknown")


def _count_dir(root: str) -> tuple[int, int]:
    """(#files, #bytes) of scannable content, respecting SKIP_DIRS."""
    n = 0
    b = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = os.path.join(dirpath, name)
            try:
                b += os.path.getsize(p)
                n += 1
            except OSError:
                continue
    return n, b


def _scan(repo: str, logger) -> dict:
    """Full production scan — same pipeline as the corpus benchmark."""
    started = time.monotonic()
    result = scanner.scan_directory(repo, logger=logger)
    elapsed = round(time.monotonic() - started, 2)
    result["_elapsed_s"] = elapsed
    return result


def run_external(repo: str, output: str | None = None, logger=None) -> dict:
    """Scan an external repo and build the benchmark-shaped report."""
    log = logger or _log
    repo = os.path.abspath(repo)
    if not os.path.isdir(repo):
        raise FileNotFoundError(f"repository not found: {repo}")

    log(f"[external] scanning {repo} …")
    result = _scan(repo, log)
    findings = result.get("findings", []) or []
    matrix = result.get("compliance", {}) or {}

    legacy = [f for f in findings if not f.get("pqc_compliant")]
    files = sorted({f.get("file", "?") for f in findings})

    n_files, n_bytes = _count_dir(repo)

    # Verdict normalization: scan_directory returns 'at_risk' spelling.
    verdict = matrix.get("verdict", "not_detected")

    # Benchmark-shaped fields (identical keys to worker.py benchmark output).
    # External runs are observational (no per-case ground truth), so confusion
    # is reported as detection surface rather than TP/FP/FN/TN.
    report = {
        "mode": "external-validation",
        "target": {
            "name": os.path.basename(repo),
            "path": repo,
            "kind": "owasp-juice-shop" if "juice-shop" in repo.lower() else "repository",
            "ref": JUICE_SHOP_REF if "juice-shop" in repo.lower() else None,
            "scannable_files": n_files,
            "scannable_bytes": n_bytes,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engine": result.get("engine", "unknown"),
        "corpus_size": len(findings),
        "confusion": {
            "tp": len(legacy), "fp": None, "fn": None, "tn": None,
            "note": ("external run is observational — no per-case ground truth; "
                     "tp = legacy findings detected, fp/fn/tn undefined"),
        },
        "metrics": {
            "accuracy": None, "precision": None, "recall": None, "f1": None,
            "count": len(findings),
        },
        "by_category": {},
        "results": [],
        "compliance": {
            "pqc_score": matrix.get("pqc_score"),
            "risk_score": matrix.get("risk_score"),
            "risk_level": matrix.get("risk_level"),
            "verdict": verdict,
            "standards": {std: info.get("status") for std, info in (matrix.get("standards") or {}).items()},
            "advisory_total": (matrix.get("advisory") or {}).get("total", 0),
        },
        "detections": [
            {
                "file": f.get("file"),
                "line": f.get("line"),
                "rule": f.get("vulnerability"),
                "severity": f.get("severity"),
                "category": f.get("category"),
                "pqc_compliant": f.get("pqc_compliant"),
                "nist_standard": f.get("nist_standard"),
                "target_algorithm": f.get("target_algorithm"),
                "engine": f.get("engine"),
            }
            for f in findings
        ],
        "affected_files": files[:200],
        "elapsed_s": result.get("_elapsed_s"),
    }

    # Group by category, mirroring the benchmark's by_category buckets.
    by_cat: dict[str, dict] = {}
    for f in findings:
        cat = f.get("category") or "unknown"
        bucket = by_cat.setdefault(cat, {"total": 0, "ERROR": 0, "WARNING": 0, "INFO": 0})
        bucket["total"] += 1
        sev = str(f.get("severity", "INFO")).upper()
        if sev in bucket:
            bucket[sev] += 1
    report["by_category"] = by_cat

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        log(f"[external] report written to {output}")

    return report


def print_report(report: dict) -> None:
    """Human-readable summary in the benchmark's visual language."""
    comp = report.get("compliance", {})
    c = report.get("confusion", {})
    print("=" * 72)
    print(f"PiQuaChu external validation — {report['target']['name']}")
    print("=" * 72)
    print(f"Engine       : {report['engine']}")
    print(f"Files scanned: {report['target']['scannable_files']} "
          f"({report['target']['scannable_bytes']} bytes)")
    print(f"Findings     : {report['corpus_size']} "
          f"(legacy: {c.get('tp')}, PQC-compliant: {report['corpus_size'] - (c.get('tp') or 0)})")
    print(f"Verdict      : {comp.get('verdict')} · pqc_score={comp.get('pqc_score')} "
          f"risk_score={comp.get('risk_score')} ({comp.get('risk_level')})")
    print(f"Elapsed      : {report.get('elapsed_s')}s")
    print("-" * 72)
    print("By category:")
    for cat, bucket in report.get("by_category", {}).items():
        print(f"  {cat:<24} {bucket['total']:>4} findings "
              f"(ERROR={bucket['ERROR']} WARN={bucket['WARNING']} INFO={bucket['INFO']})")
    print("-" * 72)
    print("Top affected files:")
    per_file: dict[str, int] = {}
    for d in report.get("detections", []):
        per_file[d["file"]] = per_file.get(d["file"], 0) + 1
    for f, n in sorted(per_file.items(), key=lambda kv: -kv[1])[:10]:
        print(f"  {n:>4}  {f}")


def clone_juice_shop(workdir: str, logger=None) -> str:
    """Clone OWASP Juice Shop (shallow) into workdir and return the path."""
    log = logger or _log
    dest = os.path.join(workdir, "juice-shop")
    if os.path.isdir(dest) and os.path.isdir(os.path.join(dest, ".git")):
        log(f"[external] reusing existing clone at {dest}")
        return dest
    os.makedirs(workdir, exist_ok=True)
    log(f"[external] cloning {JUICE_SHOP_URL} (shallow, ref={JUICE_SHOP_REF}) …")
    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", JUICE_SHOP_REF,
         JUICE_SHOP_URL, dest],
        check=True,
    )
    return dest


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="external",
        description="Run the scanner against a real-world application and emit a benchmark-shaped report",
    )
    parser.add_argument("--repo", help="path to a local clone of the target repo")
    parser.add_argument("--clone", action="store_true",
                        help=f"clone {JUICE_SHOP_URL} into --workdir first")
    parser.add_argument("--workdir", default="/tmp/piquachu-external",
                        help="where to place the clone (default /tmp/piquachu-external)")
    parser.add_argument("--output", help="write the JSON report to a file")
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    parser.add_argument("--no-scan", action="store_true",
                        help="print an existing report file instead of scanning")
    args = parser.parse_args(argv)

    if args.no_scan:
        if not args.output:
            parser.error("--no-scan requires --output <report.json>")
        with open(args.output, encoding="utf-8") as fh:
            report = json.load(fh)
        print_report(report)
        return 0

    repo = args.repo
    if args.clone:
        repo = clone_juice_shop(args.workdir)
    if not repo:
        parser.error("either --repo <path> or --clone is required")

    report = run_external(repo, output=args.output, logger=_log)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
