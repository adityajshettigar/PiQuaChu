#!/usr/bin/env python3
# backend/cipher_cli.py
"""
cipher_cli.py — PiQuaChu Local PQC Compliance Agent
==========================================================
Zero-trust CLI that analyzes source code (zip archive or directory) against
the authoritative standards registry (FIPS 203 ML-KEM, FIPS 204 ML-DSA and
FIPS 205 SLH-DSA are finalized; FIPS 206 / FN-DSA is still in development)
using AST-based engines. Results are discovery evidence, not a compliance
certificate.

    python cipher_cli.py scan <archive.zip|dir> [--json] [--output report.json]
                            [--sarif out.sarif]
                            [--baseline base.json [--fail-on new-high]]
                            [--update-baseline base.json [--force]]
    python cipher_cli.py telemetry <archive.zip|dir>        # anonymized only
    python cipher_cli.py remediate <archive.zip|dir>        # migration plans
    python cipher_cli.py patch <dir> [--output patches/] [--apply]  # DRY-RUN by default
                            [--include-candidates] [--rollback manifest.json]
                            [--pr --repo o/n --branch b (--yes | interactive)]
    python cipher_cli.py runtime --enable [--pid N] [--json]  # READ-ONLY, opt-in
                            [--live-tls host:port --allow-live-probe]
    python cipher_cli.py selfcheck                          # engine health check

Exit codes (scan with a baseline / policy):
    0 = pass, 1 = gate policy triggered, 2 = baseline/usage error (fail safe).

Privacy guarantee: this agent NEVER uploads source code. The `telemetry`
subcommand prints exactly the anonymized payload (algorithm, standard,
severity, verdict) that is permitted to leave the machine.
"""

import argparse
import atexit
import json
import os
import shutil
import sys
import tempfile
import zipfile

import audit
import cbom
import compliance
import baseline
import evidence
import gitlab_sast
import metrics
import patcher
import remediation
import runtime_probe
import sarif
import scanner

# Track temp dirs created for zip targets and always clean them up at exit.
_TEMP_DIRS = []


def _cleanup_temp_dirs():
    for d in _TEMP_DIRS:
        shutil.rmtree(d, ignore_errors=True)


atexit.register(_cleanup_temp_dirs)

_AUDIT_READY = False


def _audit_connect():
    """CLI audit sink: the local DB (migrated once) + the audit JSONL file."""
    global _AUDIT_READY
    import sqlite3
    import migrations
    path = os.environ.get("PIQUACHU_DB_PATH") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "piquachu.db")
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    if not _AUDIT_READY:
        migrations.migrate(conn, db_path=path)
        _AUDIT_READY = True
    return conn


def _audit(action: str, **fields) -> None:
    """Audit a local security action; never lets audit failure break the CLI."""
    try:
        audit.set_connection_provider(_audit_connect)
        audit.record(action, actor_type="cli", **fields)
    except Exception as exc:  # noqa: BLE001
        print(f"warning: audit event '{action}' not recorded ({type(exc).__name__})",
              file=sys.stderr)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _prepare_target(target: str) -> str:
    """Return a directory path to scan. Unpacks .zip archives into a temp dir
    with zip-slip / zip-bomb protections applied."""
    if target.lower().endswith(".zip"):
        tmp = tempfile.mkdtemp(prefix="piquachu-")
        _TEMP_DIRS.append(tmp)
        with zipfile.ZipFile(target, "r") as zf:
            try:
                scanner.safe_extract_zip(
                    zf, tmp,
                    max_entries=5000,
                    max_bytes=250 * 1024 * 1024,
                    max_file_bytes=scanner.MAX_FILE_BYTES,
                    max_compression_ratio=scanner.MAX_COMPRESSION_RATIO,
                )
            except scanner.ZipExtractionError as exc:
                print(f"ERROR: unsafe archive rejected: {exc}", file=sys.stderr)
                sys.exit(1)
        return tmp
    return target


def _print_matrix(compliance_matrix: dict) -> None:
    print("=" * 72)
    print("NIST PQC DISCOVERY MATRIX")
    print("=" * 72)
    print(f"Readiness score : {compliance_matrix.get('pqc_score')}/100  "
          f"(verdict: {compliance_matrix.get('verdict')})")
    for std, info in compliance_matrix.get("standards", {}).items():
        print(f"  {std:<9} {info['algorithm']:<9} {info['status']:<16} "
              f"compliant={info['compliant_count']} legacy={info['legacy_count']}")
    advisory = compliance_matrix.get("advisory", {})
    print(f"  Advisory     (hashing={advisory.get('hashing', 0)}, "
          f"symmetric={advisory.get('symmetric', 0)}, tls={advisory.get('tls', 0)})")
    print("-" * 72)
    print(compliance_matrix.get("summary", ""))


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def _snippet_provider(root: str):
    """Opt-in local snippet reader for SARIF artifacts. Reads only inside the
    scan root (realpath-checked), never follows symlinks, caps the region.
    CI workflows never pass --sarif-include-snippets."""
    root_real = os.path.realpath(root)

    def provider(rel, start, end):
        try:
            start, end = int(start), int(end)
        except (TypeError, ValueError):
            return None
        if end < start or end - start > 200:
            return None
        path = os.path.realpath(os.path.join(root_real, str(rel)))
        if path != root_real and not path.startswith(root_real + os.sep):
            return None
        if os.path.islink(path) or not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        return "\n".join(lines[max(0, start - 1):end])

    return provider


def _update_baseline(args, findings, ruleset_meta) -> int:
    """Explicit baseline update: show what changes, never clobber silently,
    never run by default (and not in CI without --allow-in-ci)."""
    path = args.update_baseline
    old = None
    if os.path.exists(path):
        try:
            old = baseline.load_baseline(path)
        except baseline.BaselineError as exc:
            if not getattr(args, "force", False):
                print(f"ERROR: existing baseline cannot be read: {exc}",
                      file=sys.stderr)
                print("ERROR: --update-baseline never silently overwrites a "
                      "baseline — inspect/fix it, or pass --force to replace "
                      "it (its suppressions cannot be carried over).",
                      file=sys.stderr)
                return 2
            print(f"WARNING: replacing unreadable baseline ({exc}); its "
                  f"suppressions cannot be carried over.", file=sys.stderr)
            old = None
    carry = list(old.get("suppressions", [])) if old else []
    # Expired suppressions (old['expired_suppressions']) are dropped on update
    # and shown as removed in the change summary below.
    try:
        new_bl = baseline.build_baseline(
            findings,
            ruleset=ruleset_meta,
            scanner_version=evidence.ENGINE_VERSION,
            engine_version=evidence.ENGINE_VERSION,
            model_version=evidence.MODEL_VERSION,
            suppressions=carry,
        )
        diff = baseline.save_baseline(
            new_bl, path,
            force=bool(getattr(args, "force", False)),
            allow_in_ci=bool(getattr(args, "allow_in_ci", False)))
    except baseline.BaselineError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(baseline.baseline_changes_summary(diff))
    print(f"Baseline written: {path}")
    if carry:
        print(f"  ({len(carry)} active suppression(s) carried over)")
    return 0


def cmd_scan(args) -> int:
    target_dir = _prepare_target(args.target)
    result = scanner.scan_directory(target_dir)
    if "error" in result:
        print(f"ERROR: {result['error']}", file=sys.stderr)
        return 1

    findings = result.get("findings", [])
    matrix = result.get("compliance", {})
    engine = result.get("engine", "?")

    # ---- Phase 3: baseline delta + gate policy ------------------------------
    baseline_path = getattr(args, "baseline", None)
    no_baseline = bool(getattr(args, "no_baseline", False))
    fail_on = getattr(args, "fail_on", None)
    delta = gate = None
    try:
        fp = metrics.ruleset_fingerprint()
        ruleset_sha = fp.get("sha256")
        ruleset_meta = {"sha256": fp.get("sha256"),
                        "rule_count": fp.get("rules"),
                        "version": fp.get("version")}
    except Exception:
        ruleset_sha, ruleset_meta = None, None

    if getattr(args, "update_baseline", None):
        rc = _update_baseline(args, findings, ruleset_meta)
        if rc != 0:
            return rc

    if baseline_path and not no_baseline:
        try:
            bl = baseline.load_baseline(baseline_path)
        except baseline.BaselineError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            print("ERROR: baseline unusable — failing safe (exit 2); the scan "
                  "is NOT being reported as clean. Only an explicit "
                  "--no-baseline accepts baseline-free gating.", file=sys.stderr)
            return 2
        delta = baseline.compare(findings, bl, baseline_path=baseline_path,
                                 ruleset_sha256=ruleset_sha)
    elif no_baseline or fail_on:
        delta = baseline.compare(findings, None, ruleset_sha256=ruleset_sha)

    if delta is not None and (fail_on or baseline_path):
        try:
            policy = baseline.parse_policy(fail_on or "new-error")
        except baseline.BaselineError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        gate = baseline.evaluate_gate(
            delta, policy,
            gate_inconclusive=bool(getattr(args, "gate_inconclusive", False)))

    # ---- SARIF (official-schema validated) ---------------------------------
    sarif_path = getattr(args, "sarif", None)
    if sarif_path:
        provider = None
        if getattr(args, "sarif_include_snippets", False):
            provider = _snippet_provider(target_dir)
        doc = sarif.build_sarif(result, baseline_delta=delta, gate=gate,
                                snippet_provider=provider)
        errs = sarif.validate_sarif(doc)
        fatal = [e for e in errs if not any(
            token in e for token in ("not installed", "schema missing",
                                     "schema unreadable"))]
        if fatal:
            print(f"ERROR: SARIF failed official schema validation "
                  f"({len(fatal)} error(s)):", file=sys.stderr)
            for e in fatal[:10]:
                print(f"  {e}", file=sys.stderr)
            return 2
        if errs:
            print(f"WARNING: official SARIF validation unavailable: {errs[0]}",
                  file=sys.stderr)
        sarif.write_sarif(doc, sarif_path)
        print(f"\nSARIF written to {sarif_path} "
              f"({len(doc['runs'][0]['results'])} result(s); validated against "
              f"the official SARIF 2.1.0 schema)")

    # ---- GitLab SAST (official-schema validated) ---------------------------
    gitlab_path = getattr(args, "gitlab_sast", None)
    if gitlab_path:
        gitlab_doc, gitlab_stats = gitlab_sast.build_report(result)
        errs = gitlab_sast.validate_report(gitlab_doc)
        fatal = [e for e in errs if not any(
            token in e for token in ("not installed", "schema missing",
                                     "schema unreadable"))]
        if fatal:
            print(f"ERROR: GitLab SAST report failed official schema "
                  f"validation ({len(fatal)} error(s)):", file=sys.stderr)
            for e in fatal[:10]:
                print(f"  {e}", file=sys.stderr)
            return 2
        if errs:
            print(f"WARNING: official GitLab SAST validation unavailable: "
                  f"{errs[0]}", file=sys.stderr)
        gitlab_sast.write_report(gitlab_doc, gitlab_path)
        excluded = sum(gitlab_stats["excluded"].values())
        print(f"\nGitLab SAST written to {gitlab_path} "
              f"({gitlab_stats['included']} vulnerabilit"
              f"{'y' if gitlab_stats['included'] == 1 else 'ies'}, "
              f"{excluded} finding(s) kept out of the SAST view; validated "
              f"against the official GitLab schema {gitlab_sast.REPORT_VERSION})")

    # ---- Report -------------------------------------------------------------
    # Start from the full scanner result so no key (diagnostics,
    # engine_disagreements, …) is ever dropped for --json/--output consumers.
    report = dict(result)
    report["telemetry"] = compliance.build_telemetry(findings)
    if delta is not None:
        report["baseline_delta"] = delta
    if gate is not None:
        report["gate"] = gate
    if sarif_path:
        report["sarif"] = sarif_path
    if gitlab_path:
        report["gitlab_sast"] = gitlab_path

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _print_matrix(matrix)
        if delta is not None:
            print()
            baseline.print_delta(delta, gate)
        print(f"\nEngine: {engine} | {len(findings)} finding(s):")
        for f in findings:
            marker = "✓" if f.get("pqc_compliant") else "✗"
            print(f"  {marker} [{f.get('severity','?'):<7}] {f.get('file')}:"
                  f"{f.get('line')} {f.get('vulnerability')} -> "
                  f"{f.get('target_algorithm') or 'migrate'}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        if not args.json:
            print(f"\nReport written to {args.output}")

    if gate is not None and gate["triggered"]:
        print(f"\nGATE: FAIL — policy {gate['policy']}: "
              f"{len(gate['failures'])} finding(s) matched "
              f"(scope '{gate['scope']}', severity ≥ {gate['min_severity']})",
              file=sys.stderr)
        return 1
    return 0


def cmd_telemetry(args) -> int:
    """Print ONLY the anonymized telemetry payload (no source code, no paths)."""
    target_dir = _prepare_target(args.target)
    result = scanner.scan_directory(target_dir)
    if "error" in result:
        print(f"ERROR: {result['error']}", file=sys.stderr)
        return 1
    payload = compliance.build_telemetry(result.get("findings", []))
    print(json.dumps(payload, indent=2))
    print("\n# Privacy: algorithm-level telemetry only. No source code leaves the host.")
    return 0


def cmd_remediate(args) -> int:
    target_dir = _prepare_target(args.target)
    result = scanner.scan_directory(target_dir)
    if "error" in result:
        print(f"ERROR: {result['error']}", file=sys.stderr)
        return 1

    plans = []
    for f in result.get("findings", []):
        if f.get("pqc_compliant"):
            continue  # no remediation needed for compliant usage
        plans.append({"finding": {k: f.get(k) for k in
                                  ("file", "line", "vulnerability", "severity",
                                   "nist_standard", "category", "target_algorithm")},
                      "plan": remediation.build_plan(f)})

    print("=" * 72)
    print(f"MIGRATION PLANS ({len(plans)} finding(s))")
    print("=" * 72)
    for item in plans:
        p = item["plan"]
        print(f"\n▶ {item['finding']['file']}:{item['finding']['line']} "
              f"[{item['finding']['vulnerability']}] (source: {p.get('source')})")
        print(f"  Risk: {p.get('risk')}")
        print(f"  Dependencies: {p.get('dependencies')}")
        print("  Replacement:")
        for line in p.get("replacement_code", "").splitlines():
            print(f"    {line}")
        print(f"  Justification: {p.get('justification', '')[:200]}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(plans, fh, indent=2)
        print(f"\nPlans written to {args.output}")
    return 0


def cmd_patch(args) -> int:
    """Remediation patches: DRY-RUN by default (unified diff), opt-in apply
    (atomic + backup + conflict-checked), opt-in confirmed GitHub PR."""
    if getattr(args, "rollback", None):
        try:
            restored = patcher.rollback(args.rollback)
        except patcher.PatchError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(f"Rolled back {len(restored)} file(s):")
        for rel in restored:
            print(f"  restored {rel}")
        _audit("patch.rollback", object_type="patch_manifest",
               object_id=os.path.basename(args.rollback),
               detail={"files": len(restored)})
        return 0

    if not getattr(args, "target", None):
        print("ERROR: patch requires a target directory "
              "(or --rollback <manifest.json>)", file=sys.stderr)
        return 2
    if args.apply and args.target.lower().endswith(".zip"):
        print("ERROR: --apply on a .zip target would write into a temporary "
              "extraction that is discarded afterwards. Extract the archive "
              "and patch the directory instead — refusing.", file=sys.stderr)
        return 2

    target_dir = _prepare_target(args.target)
    result = scanner.scan_directory(target_dir)
    if "error" in result:
        print(f"ERROR: {result['error']}", file=sys.stderr)
        return 1

    patches = patcher.patch_directory(target_dir, result.get("findings", []),
                                      include_candidates=bool(args.include_candidates))
    if not patches:
        print("No remediation records found (review remaining findings "
              "manually — see `cipher_cli.py remediate`).")
        if args.pr:
            print("ERROR: --pr has nothing to push.", file=sys.stderr)
            return 1
        return 0

    applied_p = [p for p in patches if p.get("diff")]
    cand_p = [p for p in patches if not p.get("diff") and p.get("candidates")]
    manual_p = [p for p in patches if not p.get("diff") and p.get("manual")
                and not p.get("candidates")]
    refused_p = [p for p in patches
                 if str(p.get("applicability", "")).startswith(("refused", "skipped"))
                 and not p.get("diff")]

    print("=" * 72)
    print(f"REMEDIATION RECORDS ({len(patches)} file(s) | "
          f"{len(applied_p)} applicable, {len(cand_p)} candidate-only, "
          f"{len(manual_p)} manual-only, {len(refused_p)} refused/skipped)")
    print("=" * 72)
    for p in patches:
        print(f"\n▶ {p['path']}  [{p['applicability']}] "
              f"confidence={p.get('confidence')}"
              + (f"  rules={','.join(p['rule_ids'])}" if p.get("rule_ids") else ""))
        for c in p.get("changes", []):
            print(f"    APPLY L{c['line']}: {c['what']} [{c.get('class')}]")
        for c in p.get("candidates", []):
            print(f"    CANDIDATE L{c.get('line')}: {c.get('what')} "
                  f"[{c.get('class')}] — not applied by default")
            for pre in (c.get("preconditions") or [])[:3]:
                print(f"        precondition: {pre}")
        for c in p.get("manual", []):
            print(f"    MANUAL L{c.get('line')}: {c.get('what')} "
                  f"[{c.get('class')}] — never auto-applied")
            for step in (c.get("follow_up") or [])[:3]:
                print(f"        follow-up: {step}")
        for note in (p.get("notes") or []):
            print(f"    note: {note}")
        if p.get("diff"):
            print("    validation: "
                  f"{p['validation'].get('command')} -> "
                  f"{'ok' if p['validation'].get('ok') else 'FAILED'}")

    if args.output:
        written = patcher.write_patches(patches, args.output)
        for w in written:
            print(f"  patch written: {w}")
        print(f"  manifest written: "
              f"{os.path.join(args.output, 'patch-manifest.json')}")
        _audit("patch.generate", object_type="patch_batch",
               detail={"files": len(applied_p),
                       "candidate_only": len(cand_p),
                       "apply_requested": bool(args.apply)})

    if not applied_p:
        if args.apply:
            print("\nNothing to apply (candidates are opt-in via "
                  "--include-candidates; manual-only rewrites are never "
                  "applied).")
        else:
            print("\nDRY-RUN — nothing was written. Candidates are opt-in via "
                  "--include-candidates; manual-only rewrites are never "
                  "applied. Review the preconditions above first.")
    elif args.apply:
        try:
            modified = patcher.apply_patches(patches, root=target_dir,
                                             backup_dir=args.backup_dir)
        except patcher.PatchError as exc:
            print(f"\nERROR: {exc}", file=sys.stderr)
            return 1
        print(f"\nApplied {len(modified)} file(s) in place (atomic writes).")
        for rel in modified:
            print(f"  modified {rel}")
        _audit("patch.apply", object_type="patch_batch",
               detail={"files": len(modified), "target": os.path.basename(
                   os.path.abspath(target_dir))})
        manifests = {p.get("rollback_manifest") for p in patches
                     if p.get("rollback_manifest")}
        for m in sorted(manifests):
            print(f"  rollback manifest: {m}")
            print(f"  undo with: python cipher_cli.py patch --rollback {m}")
    else:
        print("\nDRY-RUN — nothing was written. Review the diffs above, then "
              "re-run with --apply to apply (backups + rollback manifest are "
              "created automatically).")

    if args.pr:
        repo = args.repo or os.environ.get("GITHUB_REPOSITORY")
        if not repo:
            print("ERROR: --pr requires --repo owner/name (or "
                  "GITHUB_REPOSITORY env).", file=sys.stderr)
            return 1
        if not args.branch:
            print("ERROR: --pr requires an explicit --branch — the branch "
                  "name is yours to choose; nothing was sent.", file=sys.stderr)
            return 2
        if not applied_p:
            print("ERROR: --pr has no applicable patches to push.", file=sys.stderr)
            return 1
        preview = patcher.github_pr_preview(repo, applied_p, branch=args.branch)
        print("\n" + "=" * 72)
        print("PR PREVIEW (no network calls made yet)")
        print("=" * 72)
        print(f"Repository : {preview['repo']}")
        print(f"Branch     : {preview['branch']}")
        print(f"Title      : {preview['title']}")
        print("Body       :")
        for line in preview["body"].splitlines():
            print(f"  {line}")
        print("Files      :")
        for f in preview["files"]:
            print(f"  {f['path']} ({f['changes']} change(s), "
                  f"{','.join(f['classes'])})")
        excerpt = []
        for p in applied_p:
            excerpt.extend((p.get("diff") or "").splitlines())
        for line in excerpt[:60]:
            print(line)
        if len(excerpt) > 60:
            print(f"… {len(excerpt) - 60} more diff line(s) omitted")

        confirmed = False
        if args.yes:
            confirmed = True
        elif sys.stdin.isatty():
            answer = input("\nType 'yes' to create this PR (anything else "
                           "aborts, no network used): ")
            confirmed = answer.strip().lower() == "yes"
        if not confirmed:
            print("PR aborted — no network call was made (pass --yes to "
                  "confirm non-interactively).")
            return 2
        try:
            url = patcher.github_pull_request(repo, applied_p,
                                              branch=args.branch, confirm=True)
        except patcher.PatchError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"ERROR: PR creation failed: {exc}", file=sys.stderr)
            return 1
        print(f"\nPull request opened: {url}")
    return 0


def cmd_cbom(args) -> int:
    """Emit a CycloneDX-format Cryptographic Bill of Materials."""
    target_dir = _prepare_target(args.target)
    result = scanner.scan_directory(target_dir)
    if "error" in result:
        print(f"ERROR: {result['error']}", file=sys.stderr)
        return 1

    bom = cbom.build_cbom(result.get("compliance", {}), result.get("findings", []),
                          filename=args.target)
    text = json.dumps(bom, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"CBOM written to {args.output} "
              f"(CycloneDX {bom.get('specVersion')}: "
              f"{len(bom.get('components', []))} cryptographic-asset components, "
              f"{len(bom.get('vulnerabilities', []))} CVE vulnerabilities)")
    else:
        print(text)
    return 0


def cmd_benchmark(args) -> int:
    """Run the reliability benchmark (Accuracy / Precision / Recall / F1)."""
    try:
        from benchmark import runner
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            from benchmark import runner
        except ImportError as exc:
            print(f"ERROR: benchmark module unavailable: {exc}", file=sys.stderr)
            return 1
    report = runner.run_all(corpus_dir=args.corpus_dir)
    runner.print_report(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nMetrics written to {args.output}")
    return 0


def cmd_runtime(args) -> int:
    """Read-only runtime evidence — opt-in, local, no memory/secret access."""
    if not args.enable:
        print("Runtime discovery is opt-in. It inspects only this process or an "
              "explicit same-user PID, read-only, with no network calls unless "
              "--allow-live-probe and a target are given.\n"
              "Re-run with --enable to acknowledge and collect.", file=sys.stderr)
        return 2
    try:
        report = runtime_probe.collect(
            enable=True, pid=args.pid,
            live_tls_target=args.live_tls,
            allow_live_probe=bool(args.allow_live_probe),
        )
    except runtime_probe.RuntimeProbeDenied as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except runtime_probe.RuntimeProbeDisabled as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    _audit("runtime.probe", result="ok", object_type="runtime_evidence",
           detail={"pid": args.pid, "network_used": report.get("network_used"),
                   "collected": (report.get("summary") or {}).get("collected")})
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print("=" * 72)
    print("RUNTIME EVIDENCE (read-only, opt-in)")
    print("=" * 72)
    print(f"Source        : {report['evidence_source']}  (static findings are separate)")
    print(f"Collected at  : {report['collected_at']}")
    print(f"Memory read   : {report['memory_inspected']}   Network: {report['network_used']}")
    summary = report.get("summary") or {}
    print(f"Items         : {summary.get('collected')} collected, "
          f"{summary.get('not_collected')} not collected, {summary.get('errors')} errors")
    print("-" * 72)
    for item in report["items"]:
        print(f"  [{item['status']}] {item['name']} ({item['evidence_type']})")
        if item.get("version"):
            print(f"      version: {item['version']}")
        if item.get("detail") and item["status"] != "collected":
            print(f"      detail: {item['detail']}")
        if item.get("limitations"):
            print(f"      note: {item['limitations']}")
    if args.output:
        print(f"\nEvidence written to {args.output}")
    print("\nMissing permission/coverage is reported as 'not_collected' — it is "
          "not evidence that no crypto is present.")
    return 0


def cmd_selfcheck(args) -> int:
    print("PiQuaChu agent self-check")
    print("=" * 72)
    try:
        import scanner, compliance, remediation, standards  # noqa: F401
        print("✓ modules importable")
    except Exception as exc:
        print(f"✗ module import failed: {exc}")
        return 1
    try:
        standards.validate_registry()
        print(f"✓ standards registry valid ({standards.REGISTRY_REVIEWED})")
    except standards.RegistryError as exc:
        print(f"✗ standards registry invalid: {exc}")
        return 1
    meta = compliance.load_rule_metadata()
    print(f"✓ {len(meta)} rule(s) loaded from rules.yaml")
    for std in compliance.STANDARDS:
        rules = [r for r in meta.values() if r.get("nist_standard") == std]
        pos = [r for r in rules if r.get("pqc_compliant")]
        lifecycle = standards.lifecycle_of(std)
        print(f"  {std:<9} {len(rules):>3} rule(s)  ({len(pos)} positive / {len(rules) - len(pos)} negative)"
              f"  [{lifecycle}]")
    for std in standards.STANDARDS:
        if std["lifecycle"] != standards.LIFECYCLE_FINAL:
            print(f"  note: {std['id']} ({std['algorithm']}) is {std['lifecycle']} — "
                  f"detection is algorithm evidence, not a finalized pass")
    matrix = compliance.analyze_compliance([])
    print(f"✓ empty-scan matrix ok (verdict {matrix['verdict']}, "
          f"score {matrix['pqc_score']} — no evidence is not a pass)")
    print("✓ self-check passed")
    return 0


# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="cipher_cli",
        description=("PiQuaChu local PQC discovery agent "
                     "(FIPS 203/204/205 finalized; FIPS 206 in development)."),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan code and print the NIST PQC compliance matrix")
    p_scan.add_argument("target", help=".zip archive or directory of source code")
    p_scan.add_argument("--json", action="store_true", help="print raw JSON report")
    p_scan.add_argument("--output", help="write JSON report to a file")
    # Phase 3: baseline / gate / SARIF
    p_scan.add_argument("--baseline", metavar="FILE",
                        help="compare against this committed baseline and gate")
    p_scan.add_argument("--no-baseline", action="store_true",
                        help="explicitly proceed WITHOUT a baseline (every "
                             "actionable finding then counts as new)")
    p_scan.add_argument("--fail-on", metavar="POLICY",
                        help="gate policy <scope>-<level>: new|changed|any x "
                             "info|warning|error (aliases low/medium/high/"
                             "critical), or 'none'. Default with --baseline: "
                             "new-error")
    p_scan.add_argument("--gate-inconclusive", action="store_true",
                        help="let inconclusive/informational findings fail the "
                             "gate too (default: annotations only)")
    p_scan.add_argument("--update-baseline", metavar="FILE",
                        help="EXPLICIT baseline update: show changes, then "
                             "write FILE (never silent; needs --force to "
                             "replace an existing file)")
    p_scan.add_argument("--force", action="store_true",
                        help="allow --update-baseline to replace an existing file")
    p_scan.add_argument("--allow-in-ci", action="store_true",
                        help="permit --update-baseline while CI env vars are set")
    p_scan.add_argument("--sarif", metavar="FILE",
                        help="write SARIF 2.1.0 output (official-schema "
                             "validated before writing)")
    p_scan.add_argument("--gitlab-sast", metavar="FILE",
                        help="write a GitLab SAST (gl-sast-report) JSON "
                             "artifact, validated against the pinned "
                             "official schema before writing")
    p_scan.add_argument("--sarif-include-snippets", action="store_true",
                        help="LOCAL OPT-IN ONLY: include source snippets in "
                             "the SARIF artifact (never set this in CI)")
    p_scan.set_defaults(func=cmd_scan)

    p_tel = sub.add_parser("telemetry", help="Print only the anonymized telemetry payload")
    p_tel.add_argument("target", help=".zip archive or directory of source code")
    p_tel.set_defaults(func=cmd_telemetry)

    p_rem = sub.add_parser("remediate", help="Generate migration plans for every finding")
    p_rem.add_argument("target", help=".zip archive or directory of source code")
    p_rem.add_argument("--output", help="write plans JSON to a file")
    p_rem.set_defaults(func=cmd_remediate)

    p_patch = sub.add_parser("patch", help="Generate remediation patches "
                                            "(DRY-RUN by default)")
    p_patch.add_argument("target", nargs="?",
                         help="directory of source code (zip targets cannot be "
                              "applied in place)")
    p_patch.add_argument("--output", help="write unified diff(s) + manifest to this directory")
    p_patch.add_argument("--apply", action="store_true",
                         help="apply changes in place (atomic, backed up, "
                              "conflict-checked) — dry-run is the default")
    p_patch.add_argument("--backup-dir",
                         help="where to store apply backups (default: "
                              "<target>/.piquachu-backups/<timestamp>)")
    p_patch.add_argument("--include-candidates", action="store_true",
                         help="include conditional candidates in the diff/apply "
                              "(review the preconditions first)")
    p_patch.add_argument("--rollback", metavar="MANIFEST",
                         help="restore files from a rollback manifest.json")
    p_patch.add_argument("--pr", action="store_true",
                         help="opt-in GitHub PR: prints a preview, requires "
                              "--repo, --branch and confirmation "
                              "(--yes or interactive); validates token scopes "
                              "before any write")
    p_patch.add_argument("--repo", help="GitHub repo owner/name for --pr mode")
    p_patch.add_argument("--branch", help="branch name for --pr mode (required with --pr)")
    p_patch.add_argument("--yes", action="store_true",
                         help="confirm PR creation non-interactively")
    p_patch.set_defaults(func=cmd_patch)

    p_cbom = sub.add_parser("cbom", help="Export a CycloneDX Cryptographic Bill of Materials")
    p_cbom.add_argument("target", help=".zip archive or directory of source code")
    p_cbom.add_argument("--output", help="write CBOM JSON to a file")
    p_cbom.set_defaults(func=cmd_cbom)

    p_bench = sub.add_parser("benchmark", help="Run the reliability benchmark (F1 / accuracy metrics)")
    p_bench.add_argument("--output", help="write metrics JSON to a file")
    p_bench.add_argument("--corpus-dir", help="override corpus directory (default: bundled corpus)")
    p_bench.set_defaults(func=cmd_benchmark)

    p_rt = sub.add_parser(
        "runtime",
        help="Read-only runtime evidence (OPT-IN: requires --enable)")
    p_rt.add_argument("--enable", action="store_true",
                      help="explicit opt-in acknowledgement (required)")
    p_rt.add_argument("--pid", type=int,
                      help="explicit same-user process to inspect (read-only)")
    p_rt.add_argument("--live-tls", metavar="HOST:PORT",
                      help="optional single explicit TLS target")
    p_rt.add_argument("--allow-live-probe", action="store_true",
                      help="allow the single explicit TLS handshake")
    p_rt.add_argument("--json", action="store_true", help="print raw JSON evidence")
    p_rt.add_argument("--output", help="write the evidence JSON to this file")
    p_rt.set_defaults(func=cmd_runtime)

    p_self = sub.add_parser("selfcheck", help="Verify engine health")
    p_self.set_defaults(func=cmd_selfcheck)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
