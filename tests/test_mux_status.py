#!/usr/bin/env python3
"""Test MUX INT 2Fh installation check."""

from testenv import run_log_only_test


def test_mux_status():
    return run_log_only_test("test_mux_status", "MUX_STATUS")


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_mux_status() else 1)
