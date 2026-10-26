#!/usr/bin/env python3
# backend/benchmark/external_eval.py
"""
external_eval.py — score the scanner against manually reviewed ground truth
==========================================================================
Static analysis only. The target repository is never executed, its dependencies
are never installed, and nothing is uploaded. Reports contain identifiers and
locations (file, line, rule id) — never source text.

Usage
-----
    cd backend
    python -m benchmark.external_eval --target paramiko --repo /tmp/pqc-ext/paramiko
    python -m benchmark.external_eval --all --workdir /tmp/pqc-ext --output /tmp/ext.json

Scoring model
-------------
Per reviewed call site:
  * TP — a risk site with at least one *scored* (non-informational) finding
         within ``MATCH_TOLERANCE_LINES`` on the same file.
  * FN — a risk site without one (an inconclusive-only match is reported as a
         miss with ``inconclusive_only: true``).
  * FP — any scored finding that does not match a risk site.
  * TN — a benign site with no scored finding.
Uncertain sites are listed with their outcome and excluded from the matrix.

Micro metrics pool sites across targets; macro metrics average per-target
values. Both are reported; they are never blended into one number.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import metrics as metrics_provenance  # noqa: E402
import scanner  # noqa: E402

from . import external_ground_truth as gt  # noqa: E402

ENGINE_VERSION = "2.3.0"


def _git_commit(repo: str) -> str | None:
    try:
        out = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def _scan_scope(repo: str, target: dict) -> dict:
    """Run the production scanner over each in-scope directory."""
    scopes = target.get("scope") or ["."]
    findings: list = []
    per_scope: list = []
    diagnostics: dict = {"parser_failures": {}, "files_analyzed": {},
                         "parser_failure_files": [], "unresolved_values": {}}
    engine_parts: list = []
    for rel in scopes:
        path = repo if rel in (".", "") else os.path.join(repo, rel)
        if not os.path.isdir(path):
            raise FileNotFoundError(f"scope directory missing: {rel!r} in {repo}")
        result = scanner.scan_directory(path)
        engine_parts.append(result.get("engine", "?"))
        scoped = []
        for finding in result.get("findings", []) or []:
            item = dict(finding)
            item["_scope"] = rel
            scoped.append(item)
        findings.extend(scoped)
        per_scope.append({"scope": rel, "findings": len(scoped),
                          "engine": result.get("engine")})
        merged = result.get("diagnostics") or {}
        for key in ("parser_failures", "files_analyzed", "unresolved_values"):
            for lang, count in (merged.get(key) or {}).items():
                diagnostics[key][lang] = diagnostics[key].get(lang, 0) + int(count)
        diagnostics["parser_failure_files"].extend(merged.get("parser_failure_files", []))
    return {"findings": findings, "per_scope": per_scope,
            "diagnostics": diagnostics,
            "engine": "+".join(sorted(set(engine_parts)))}


def _normalized_file(finding: dict, scope: str) -> str:
    rel = str(finding.get("file") or "").replace("\\", "/").lstrip("./")
    if scope in (".", ""):
        return rel
    prefix = scope.rstrip("/") + "/"
    return rel[len(prefix):] if rel.startswith(prefix) else rel


def _candidates(finding: dict, scope: str, sites: list) -> list:
    """(distance, site) candidates within tolerance on the same file."""
    rel = _normalized_file(finding, scope)
    line = finding.get("line_start") or finding.get("line")
    if not isinstance(line, int):
        return []
    out = []
    for site in sites:
        if site["file"] != rel:
            continue
        distance = abs(line - site["line"])
        if distance <= gt.MATCH_TOLERANCE_LINES:
            out.append((distance, site))
    return out


def _assign(finding: dict, scope: str, risk_sites: list,
            benign_sites: list) -> tuple:
    """Attribute one finding to a single site (nearest line wins).

    Two reviewed sites can be one line apart (a hash call and the HMAC next to
    it), so a finding is attributed to exactly one site — never counted for
    two — otherwise an adjacent benign site would silently absorb a real false
    positive. Ties are recorded as ambiguous.
    """
    candidates = ([(d, s, "risk") for d, s in _candidates(finding, scope, risk_sites)]
                  + [(d, s, "benign") for d, s in
                     _candidates(finding, scope, benign_sites)])
    if not candidates:
        return None, None, False
    candidates.sort(key=lambda c: (c[0], 0 if c[2] == "risk" else 1))
    best = candidates[0]
    ambiguous = any(c[0] == best[0] and c[2] != best[2] for c in candidates)
    return best[2], best[1], ambiguous


def evaluate(target: dict, repo: str, *, allow_unpinned: bool = False) -> dict:
    commit = _git_commit(repo)
    pinned_ok = commit == target["commit"]
    if not pinned_ok and not allow_unpinned:
        raise SystemExit(
            f"REFUSING: {target['name']} at {repo} is at {commit or 'unknown'}, "
            f"expected pinned {target['commit']}. Use --allow-unpinned to "
            f"override (report will be marked unpinned)."
        )

    scan = _scan_scope(repo, target)
    # Paths inside a scoped directory come back relative to that directory,
    # which is exactly how the ground truth is written (e.g. "dsskey.py",
    # "lib/insecurity.ts").
    scope_of = scan["per_scope"][0]["scope"] if scan["per_scope"] else "."
    findings = scan["findings"]
    risk_sites = gt.sites(target, "risk")
    benign_sites = gt.sites(target, "benign")
    uncertain_sites = gt.sites(target, "uncertain")

    matched_site_ids: set = set()
    scored_findings = [f for f in findings if not f.get("informational")]
    informational = [f for f in findings if f.get("informational")]

    attribution: dict = {}   # id(finding) -> (label, site_id, ambiguous)
    for finding in findings:
        label, site, ambiguous = _assign(finding, scope_of, risk_sites, benign_sites)
        attribution[id(finding)] = (label, site["id"] if site else None, ambiguous)

    def hits_for(site: dict, label: str, pool: list) -> list:
        return [f for f in pool
                if attribution.get(id(f), (None, None, False))[:2] == (label, site["id"])]

    site_results: list = []
    for site in risk_sites:
        hits = hits_for(site, "risk", scored_findings)
        soft = hits_for(site, "risk", informational)
        site_results.append({
            "id": site["id"], "file": site["file"], "line": site["line"],
            "category": site["category"], "label": "risk",
            "observed": site["observed"],
            "detected": bool(hits),
            "inconclusive_only": bool(soft) and not hits,
            "rules": sorted({f.get("rule_id") or f.get("vulnerability")
                             for f in hits if f.get("rule_id") or f.get("vulnerability")}),
            "engines": sorted({f.get("engine") for f in hits if f.get("engine")}),
            "confidence_tiers": sorted({f.get("confidence_tier") for f in hits
                                        if f.get("confidence_tier")}),
        })
        if hits:
            matched_site_ids.add(site["id"])

    for site in benign_sites:
        hits = hits_for(site, "benign", scored_findings)
        site_results.append({
            "id": site["id"], "file": site["file"], "line": site["line"],
            "category": site["category"], "label": "benign",
            "observed": site["observed"],
            "detected": bool(hits),
            "rules": sorted({f.get("rule_id") or f.get("vulnerability")
                             for f in hits if f.get("rule_id") or f.get("vulnerability")}),
            "engines": sorted({f.get("engine") for f in hits if f.get("engine")}),
            "confidence_tiers": sorted({f.get("confidence_tier") for f in hits
                                        if f.get("confidence_tier")}),
        })

    uncertain_results = []
    for site in uncertain_sites:
        hits = [f for f in findings if _candidates(f, scope_of, [site])]
        uncertain_results.append({
            "id": site["id"], "file": site["file"], "line": site["line"],
            "category": site["category"], "label": "uncertain",
            "observed": site["observed"],
            "flagged": bool(hits),
            "rules": sorted({f.get("rule_id") or f.get("vulnerability")
                             for f in hits if f.get("rule_id") or f.get("vulnerability")}),
            "note": "excluded from the confusion matrix (no binary truth)",
        })

    false_positives = []
    ambiguous_count = 0
    for finding in scored_findings:
        label, site_id, ambiguous = attribution[id(finding)]
        if ambiguous:
            ambiguous_count += 1
        if label == "risk":
            continue
        false_positives.append({
            "file": _normalized_file(finding, scope_of),
            "line": finding.get("line_start") or finding.get("line"),
            "rule": finding.get("rule_id") or finding.get("vulnerability"),
            "engine": finding.get("engine"),
            "confidence_tier": finding.get("confidence_tier"),
            "evidence_type": finding.get("evidence_type"),
            "matches_benign_site": site_id,
            "ambiguous_attribution": ambiguous,
            "matches_uncertain_site": bool(
                _candidates(finding, scope_of, uncertain_sites)),
        })

    tp = sum(1 for s in site_results if s["label"] == "risk" and s["detected"])
    fn = sum(1 for s in site_results if s["label"] == "risk" and not s["detected"])
    tn = sum(1 for s in site_results if s["label"] == "benign" and not s["detected"])
    fp = len(false_positives)

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall else None)

    by_category: dict = {}
    for site in site_results:
        if site["label"] != "risk":
            continue
        bucket = by_category.setdefault(site["category"],
                                        {"sites": 0, "detected": 0})
        bucket["sites"] += 1
        bucket["detected"] += int(site["detected"])
    for bucket in by_category.values():
        bucket["recall"] = round(bucket["detected"] / bucket["sites"], 4) \
            if bucket["sites"] else None

    tiers: dict = {}
    for site in site_results:
        if site["label"] == "risk" and site["detected"]:
            for tier in site["confidence_tiers"] or ["none"]:
                tiers[tier] = tiers.get(tier, 0) + 1

    files_seen = {f.get("file") for f in findings}
    return {
        "target": {
            "name": target["name"], "url": target["url"], "ref": target["ref"],
            "commit": commit, "pinned_commit": target["commit"],
            "pinned_verified": pinned_ok, "license": target["license"],
            "languages": target["languages"], "scope": target["scope"],
            "exclusions": target["exclusions"], "note": target["note"],
            "known_blind_spots": target["known_blind_spots"],
        },
        "scan": {
            "engine": scan["engine"],
            "scopes": scan["per_scope"],
            "findings": len(findings),
            "scored_findings": len(scored_findings),
            "inconclusive_findings": len(informational),
            "files_with_findings": len(files_seen),
            "files_analyzed": scan["diagnostics"]["files_analyzed"],
            "parser_failures": scan["diagnostics"]["parser_failures"],
            "parser_failure_files": sorted(
                set(scan["diagnostics"]["parser_failure_files"]))[:50],
        },
        "ground_truth": {
            "reviewer": gt.REVIEWER, "review_date": gt.REVIEW_DATE,
            "rubric": gt.LABELING_RUBRIC,
            "match_tolerance_lines": gt.MATCH_TOLERANCE_LINES,
            "counts": gt.counts(target),
        },
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                      "uncertain": len(uncertain_results),
                      "ambiguous_attributions": ambiguous_count},
        "metrics": {"precision": round(precision, 4) if precision is not None else None,
                    "recall": round(recall, 4) if recall is not None else None,
                    "f1": round(f1, 4) if f1 is not None else None,
                    "aggregation": "micro (per reviewed call site)"},
        "by_category": by_category,
        "confidence_tiers_of_true_positives": tiers,
        "sites": site_results,
        "uncertain_sites": uncertain_results,
        "false_positives": false_positives,
        "false_negatives": [s["id"] for s in site_results
                            if s["label"] == "risk" and not s["detected"]],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metric_source": metrics_provenance.EXTERNAL,
        "ruleset": metrics_provenance.ruleset_fingerprint(),
        "engine_version": ENGINE_VERSION,
        "reproduce": [
            f"git clone --depth 1 --branch {target['ref']} {target['url']} "
            f"/tmp/pqc-ext/{target['name']}",
            f"python -m benchmark.external_eval --target {target['name']} "
            f"--repo /tmp/pqc-ext/{target['name']}",
        ],
    }


def aggregate(reports: list) -> dict:
    """Micro (pooled sites) + macro (mean of per-target) aggregation."""
    tp = sum(r["confusion"]["tp"] for r in reports)
    fp = sum(r["confusion"]["fp"] for r in reports)
    fn = sum(r["confusion"]["fn"] for r in reports)
    tn = sum(r["confusion"]["tn"] for r in reports)
    micro_p = tp / (tp + fp) if (tp + fp) else None
    micro_r = tp / (tp + fn) if (tp + fn) else None
    micro_f1 = (2 * micro_p * micro_r / (micro_p + micro_r)
                if micro_p and micro_r else None)
    per_target = [r["metrics"] for r in reports]
    macro = {}
    for key in ("precision", "recall", "f1"):
        values = [m[key] for m in per_target if m.get(key) is not None]
        macro[key] = round(sum(values) / len(values), 4) if values else None
    return {
        "targets": [r["target"]["name"] for r in reports],
        "metric_source": metrics_provenance.EXTERNAL,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                      "uncertain": sum(r["confusion"]["uncertain"] for r in reports)},
        "metrics": {
            "micro": {"precision": round(micro_p, 4) if micro_p is not None else None,
                      "recall": round(micro_r, 4) if micro_r is not None else None,
                      "f1": round(micro_f1, 4) if micro_f1 is not None else None,
                      "definition": "pooled over all reviewed call sites"},
            "macro": {**macro,
                      "definition": "unweighted mean of per-target metrics"},
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "per_target": [
            {"name": r["target"]["name"], "commit": r["target"]["commit"],
             "sites": sum(r["ground_truth"]["counts"].values()),
             "confusion": r["confusion"], "metrics": r["metrics"],
             "parser_failures": r["scan"]["parser_failures"]}
            for r in reports
        ],
    }


def print_report(report: dict) -> None:
    t = report["target"]
    c = report["confusion"]
    m = report["metrics"]
    print("=" * 74)
    print(f"External validation — {t['name']} @ {str(t['commit'])[:12]} "
          f"({'pinned' if t['pinned_verified'] else 'UNPINNED'})")
    print("=" * 74)
    print(f"Scope        : {', '.join(t['scope'])}  license={t['license']}")
    print(f"Engine       : {report['scan']['engine']} (v{report['engine_version']})")
    print(f"Findings     : {report['scan']['findings']} "
          f"({report['scan']['inconclusive_findings']} inconclusive)")
    print(f"Ground truth : {report['ground_truth']['counts']}")
    print(f"Confusion    : TP={c['tp']} FP={c['fp']} FN={c['fn']} TN={c['tn']} "
          f"(uncertain={c['uncertain']})")
    print(f"Metrics      : precision={m['precision']} recall={m['recall']} "
          f"f1={m['f1']}  [{m['aggregation']}]")
    print(f"Parse fails  : {report['scan']['parser_failures']}")
    print("-" * 74)
    print("Per-category recall:")
    for cat, bucket in sorted(report["by_category"].items()):
        print(f"  {cat:<24} {bucket['detected']}/{bucket['sites']} "
              f"recall={bucket['recall']}")
    if report["false_negatives"]:
        print("-" * 74)
        print(f"Missed risk sites: {', '.join(report['false_negatives'])}")
    if report["false_positives"]:
        print("-" * 74)
        print(f"False positives ({len(report['false_positives'])}):")
        for fp in report["false_positives"][:15]:
            print(f"  {fp['file']}:{fp['line']} {fp['rule']} "
                  f"[{fp['engine']}/{fp['confidence_tier']}]")
    if report["uncertain_sites"]:
        print("-" * 74)
        print("Uncertain sites (excluded from the matrix):")
        for site in report["uncertain_sites"]:
            print(f"  {site['id']} {site['file']}:{site['line']} "
                  f"flagged={site['flagged']}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="PiQuaChu external validation")
    parser.add_argument("--target", choices=sorted(gt.TARGETS),
                        help="ground-truth target to evaluate")
    parser.add_argument("--repo", help="local checkout of the target")
    parser.add_argument("--all", action="store_true",
                        help="evaluate every target under --workdir")
    parser.add_argument("--workdir", default="/tmp/pqc-ext",
                        help="directory holding the checkouts (default /tmp/pqc-ext)")
    parser.add_argument("--output", help="write the JSON report here")
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    parser.add_argument("--allow-unpinned", action="store_true",
                        help="evaluate a checkout that is not at the pinned commit")
    args = parser.parse_args(argv)

    reports = []
    if args.all:
        for name, target in sorted(gt.TARGETS.items()):
            repo = os.path.join(args.workdir, name)
            if not os.path.isdir(repo):
                print(f"[skip] {name}: no checkout at {repo} "
                      f"(clone {target['url']} @ {target['ref']})")
                continue
            print(f"[eval] {name} …", flush=True)
            reports.append(evaluate(target, repo,
                                    allow_unpinned=args.allow_unpinned))
    else:
        if not args.target or not args.repo:
            parser.error("--target and --repo are required without --all")
        target = gt.TARGETS[args.target]
        reports.append(evaluate(target, args.repo,
                               allow_unpinned=args.allow_unpinned))

    if not args.json:
        for report in reports:
            print_report(report)
            print()

    summary = aggregate(reports)
    payload = {
        "metric_source": metrics_provenance.EXTERNAL,
        "generated_at": summary["generated_at"],
        "targets": summary["targets"],
        "confusion": summary["confusion"],
        "metrics": summary["metrics"],
        "per_target": summary["per_target"],
        "details": reports,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
