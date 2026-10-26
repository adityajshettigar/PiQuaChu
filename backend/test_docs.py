#!/usr/bin/env python3
# backend/test_docs.py
"""
test_docs.py — documentation claim consistency checks.

Run:  venv/bin/python test_docs.py

This is deliberately a small, deterministic guard against the Phase 1 failure
mode: docs drifting from the registry and serialized CBOM version.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark.corpus import TESTS as CORPUS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSED = []

FORBIDDEN = [
    "four NIST-finalized",
    "four finalized NIST",
    "published as FIPS 206",
    "FIPS 206 published",
    "FIPS 206 (May 2025)",
    "CycloneDX 1.5",
    "ALL FOUR NIST-finalized",
    "47-case",
    "47 labeled",
    "106 rules loaded",
]


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ✓ {name}")


def read(rel: str) -> str:
    path = os.path.join(ROOT, rel)
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def test_readme_claims():
    print("README claims:")
    readme = read("README.md")
    lowered = readme.lower()
    for phrase in FORBIDDEN:
        check(f"README omits stale phrase: {phrase}", phrase.lower() not in lowered)
    check("README names CycloneDX 1.7", "CycloneDX 1.7" in readme)
    check("README marks FIPS 206 in development", "in development" in lowered)
    check("README has scope/limitations section", "Scope and limitations" in readme)
    check("README documents not_assessed", "not_assessed" in readme)
    check("README says static evidence is not compliance",
          "not proof of" in lowered and "compliance" in lowered)
    check("README points to report_counts.py", "report_counts.py" in readme)

    # If the README states a corpus count, it must match the code.
    match = re.search(r"\*\*(\d+) labeled cases\*\*", readme)
    check("README corpus count present", match is not None)
    if match:
        check("README corpus count matches corpus.py",
              int(match.group(1)) == len(CORPUS),
              f"{match.group(1)} vs {len(CORPUS)}")


def test_source_docs():
    print("Source/docstring claims:")
    for rel in ("backend/compliance.py", "backend/cbom.py", "backend/standards.py",
                "backend/cipher_cli.py", "backend/scanner.py"):
        text = read(rel).lower()
        for phrase in FORBIDDEN:
            check(f"{rel} omits stale phrase: {phrase}", phrase.lower() not in text)
    standards_src = read("backend/standards.py")
    check("registry marks FIPS 206 in development",
          '"lifecycle": LIFECYCLE_IN_DEVELOPMENT' in standards_src)
    check("registry does not claim a FIPS 206 publication date",
          '"publication_date": None' in standards_src)
    check("CBOM native spec is 1.7", 'CBOM_SPEC_VERSION = "1.7"' in read("backend/cbom.py"))


def test_generated_docs():
    print("Supporting docs:")
    for rel in ("need-to-know/PRD.md", "need-to-know/01 Problem Statement.md",
                "need-to-know/03 Domain Notes.md",
                "need-to-know/04 Data Dictionary.md",
                "need-to-know/07 Model Architecture.md",
                "need-to-know/08 Experiment Plan.md",
                "need-to-know/09 Validation Protocol.md",
                "need-to-know/10 Product Architecture.md",
                "summary.txt"):
        text = read(rel).lower()
        for phrase in FORBIDDEN:
            check(f"{rel} omits stale phrase: {phrase}", phrase.lower() not in text)


def main():
    print("=" * 68)
    print("PiQuaChu documentation consistency checks")
    print("=" * 68)
    test_readme_claims()
    test_source_docs()
    test_generated_docs()
    print("=" * 68)
    print(f"ALL {len(PASSED)} CHECKS PASSED ✅")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
