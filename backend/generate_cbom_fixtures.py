#!/usr/bin/env python3
# backend/generate_cbom_fixtures.py
"""
generate_cbom_fixtures.py — regenerate committed CBOM fixture artifacts.

Run:  venv/bin/python generate_cbom_fixtures.py

The fixtures are schema-validated by test_cbom.py.  They exist so reviewers can
inspect representative serialized BOMs without running the scanner.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbom
import cbom_cases

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cbom_fixtures")


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, bom in cbom_cases.build_all().items():
        cbom.validate_cbom(bom)
        path = os.path.join(OUT_DIR, f"{name}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(bom, fh, indent=2)
            fh.write("\n")
        print(f"wrote {path}")
    print(f"{len(cbom_cases.CASES)} schema-valid fixture BOM(s) in {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
