# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""Tiny assert-based test runner — mirrors the __main__ self-test convention already
used in every argus/*.py module. No pytest: it is not in pyproject.toml's approved
dependency list and CLAUDE.md requires explicit approval before adding one (Hard Rule 6).
These files are still pytest-collectible for free (plain `test_*` functions + bare
`assert` — pytest needs no import to discover/run them), so nothing is lost if pytest
is approved later.
"""

from __future__ import annotations

import sys
import traceback


def run_tests(namespace: dict, *, module_name: str = "") -> int:
    """Run every test_* callable in namespace; print PASS/FAIL; return exit code."""
    tests = {
        k: v for k, v in sorted(namespace.items())
        if k.startswith("test_") and callable(v)
    }
    passed = failed = 0
    label = module_name or "adversarial suite"
    print(f"=== {label} ({len(tests)} cases) ===")
    for name, fn in tests.items():
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL {name}: {exc}")
        except Exception:
            failed += 1
            print(f"  ERROR {name}:")
            traceback.print_exc()
        else:
            passed += 1
            print(f"  PASS {name}")
    print(f"\n{passed} passed, {failed} failed — {passed + failed} total\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(0)
