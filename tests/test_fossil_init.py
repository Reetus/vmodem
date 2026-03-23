#!/usr/bin/env python3
"""Test FOSSIL init returns signature 0x1954."""

from testenv import run_log_only_test


def test_fossil_init():
    return run_log_only_test("test_fossil_init", "FOSSIL_INIT")


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_fossil_init() else 1)
