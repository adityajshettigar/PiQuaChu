#!/usr/bin/env python3
# backend/worker.py
"""
worker.py — PiQuaChu ops worker
=====================================
Utility entry points for operational tasks:

    python worker.py benchmark [--output metrics.json] [--json]
        Run the reliability benchmark (F1 / Accuracy / Precision / Recall)
        over the labeled corpus — used by CI gates and dashboards.

    python worker.py external --repo /path/to/repo [--output report.json]
    python worker.py external --clone [--output report.json]
        Observational run against a real application (OWASP Juice Shop) with a
        benchmark-shaped report. NOT graded — there is no ground truth in it.

    python worker.py external-ground-truth --all --workdir /tmp/pqc-ext
        Graded external validation: score the scanner against the manually
        reviewed, pinned ground truth (see benchmark/external_ground_truth.py).

    python worker.py selfcheck
        Engine health check (alias for `cipher_cli.py selfcheck`).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def cmd_benchmark(args) -> int:
    from benchmark import runner
    report = runner.run_all(corpus_dir=args.corpus_dir)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        runner.print_report(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nMetrics written to {args.output}")
    return 0


def cmd_selfcheck(args) -> int:
    import cipher_cli
    return cipher_cli.main(["selfcheck"])


def cmd_external_ground_truth(args) -> int:
    from benchmark import external_eval
    argv = []
    if args.all:
        argv += ["--all", "--workdir", args.workdir]
    else:
        argv += ["--target", args.target, "--repo", args.repo]
    if args.output:
        argv += ["--output", args.output]
    if args.json:
        argv += ["--json"]
    if args.allow_unpinned:
        argv += ["--allow-unpinned"]
    return external_eval.main(argv)


def cmd_external(args) -> int:
    from benchmark import external

    if args.no_scan:
        if not args.output:
            print("ERROR: --no-scan requires --output <report.json>", file=sys.stderr)
            return 2
        with open(args.output, encoding="utf-8") as fh:
            report = json.load(fh)
        external.print_report(report)
        return 0

    repo = args.repo
    if args.clone:
        repo = external.clone_juice_shop(args.workdir)
    if not repo:
        print("ERROR: either --repo <path> or --clone is required", file=sys.stderr)
        return 2

    report = external.run_external(repo, output=args.output)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        external.print_report(report)
    return 0


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="worker", description="PiQuaChu ops worker")
    sub = parser.add_subparsers(dest="command", required=True)

    p_bench = sub.add_parser("benchmark", help="Run the reliability benchmark")
    p_bench.add_argument("--json", action="store_true", help="print raw JSON report")
    p_bench.add_argument("--output", help="write metrics JSON to a file")
    p_bench.add_argument("--corpus-dir", help="override corpus directory")
    p_bench.set_defaults(func=cmd_benchmark)

    p_self = sub.add_parser("selfcheck", help="Engine health check")
    p_self.set_defaults(func=cmd_selfcheck)

    p_gt = sub.add_parser(
        "external-ground-truth",
        help="Graded external validation against manually reviewed ground truth")
    p_gt.add_argument("--all", action="store_true",
                      help="evaluate every target under --workdir")
    p_gt.add_argument("--target", help="single target name (with --repo)")
    p_gt.add_argument("--repo", help="local checkout of --target")
    p_gt.add_argument("--workdir", default="/tmp/pqc-ext",
                      help="directory holding the checkouts (default /tmp/pqc-ext)")
    p_gt.add_argument("--output", help="write the JSON report here")
    p_gt.add_argument("--json", action="store_true", help="print raw JSON report")
    p_gt.add_argument("--allow-unpinned", action="store_true",
                      help="allow a checkout that is not at the pinned commit")
    p_gt.set_defaults(func=cmd_external_ground_truth)

    p_ext = sub.add_parser("external", help="External validation (e.g. OWASP Juice Shop)")
    p_ext.add_argument("--repo", help="path to a local clone of the target repo")
    p_ext.add_argument("--clone", action="store_true",
                       help="clone OWASP Juice Shop into --workdir first")
    p_ext.add_argument("--workdir", default="/tmp/piquachu-external",
                       help="where to place the clone (default /tmp/piquachu-external)")
    p_ext.add_argument("--output", help="write the JSON report to a file")
    p_ext.add_argument("--json", action="store_true", help="print raw JSON report")
    p_ext.add_argument("--no-scan", action="store_true",
                       help="re-print an existing report file (with --output)")
    p_ext.set_defaults(func=cmd_external)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
