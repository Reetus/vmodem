#!/usr/bin/env python3
"""Test FOSSIL status word (THRE set, DCD low when no connection)."""

from testenv import run_log_only_test


def test_fossil_status():
    return run_log_only_test("test_fossil_status", "FOSSIL_STATUS", min_results=2)


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_fossil_status() else 1)
