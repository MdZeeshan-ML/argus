# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""Runs every adversarial test_*.py in this directory as its own subprocess (matching
each file's `python tests/adversarial/test_X.py` self-execution contract) and prints
one combined summary. See _fixtures.py module docstring for the full framing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_DIR = Path(__file__).resolve().parent


def main() -> int:
    modules = sorted(p for p in _DIR.glob("test_*.py"))
    overall_rc = 0
    totals = {"passed": 0, "failed": 0}
    for mod in modules:
        proc = subprocess.run([sys.executable, str(mod)], capture_output=True, text=True)
        print(proc.stdout)
        if proc.stderr.strip():
            print(proc.stderr, file=sys.stderr)
        overall_rc = overall_rc or proc.returncode
        for line in proc.stdout.splitlines():
            if line.strip().endswith("total") and "passed" in line:
                # e.g. "7 passed, 0 failed — 7 total"
                parts = line.replace("—", ",").split(",")
                for part in parts:
                    part = part.strip()
                    for key in totals:
                        if key in part:
                            digits = "".join(c for c in part if c.isdigit())
                            if digits:
                                totals[key] += int(digits)

    print("=" * 60)
    print(
        f"GRAND TOTAL: {totals['passed']} passed, {totals['failed']} failed "
        f"across {len(modules)} files"
    )
    return overall_rc


if __name__ == "__main__":
    sys.exit(main())
