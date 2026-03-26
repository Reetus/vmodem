#!/usr/bin/env python3
"""
VMODEM automated test runner.

Launches DOSBox-X with a minimal DOS environment containing only VMODEM,
packet drivers, mTCP, and COMTEST.EXE.  Orchestrates test scenarios by:
  1. Starting DOSBox-X with a test-specific AUTOEXEC.BAT
  2. Connecting via TCP (telnet) from the Python side
  3. Reading COMTEST.LOG from the guest to verify results

Prerequisites:
  - DOSBox-X binary (dosbox-x)
  - Xvfb for headless mode (optional, falls back to visible window)
  - VMODEM.EXE, COMTEST.EXE built in ../src/
  - Packet drivers and mTCP in ../../dosenv/

Usage:
  python3 test_vmodem.py                   # run all tests
  python3 test_vmodem.py test_fossil_init  # run one test
  python3 test_vmodem.py -v                # verbose output
"""

import argparse
import os
import shutil
import sys
import tempfile

from testenv import SRC_DIR, find_dosbox, set_verbose

from test_fossil_init import test_fossil_init
from test_fossil_status import test_fossil_status
from test_mux_status import test_mux_status
from test_echo import test_echo
from test_full_cycle import test_full_cycle
from test_send_text import test_send_text
from test_hunt_group import test_hunt_group
from test_idle_timeout import test_idle_timeout
from test_dtr_disconnect import test_dtr_disconnect
from test_eager_listen import test_eager_listen
from test_mux_port_status import test_mux_port_status
from test_s0_register import test_s0_register
from test_hunt_full import test_hunt_full
from test_reconnect import test_reconnect
from test_hunt_ring_timeout import test_hunt_ring_timeout
from test_tcp_out import test_tcp_out
from test_relay import test_relay
from test_single_busy import test_single_busy
from test_naws import test_naws
from test_ttype import test_ttype
from test_tls_irc import test_tls_irc
from test_vping import test_vping
from test_vtracert import test_vtracert


ALL_TESTS = {
    "test_fossil_init": test_fossil_init,
    "test_fossil_status": test_fossil_status,
    "test_mux_status": test_mux_status,
    "test_echo": test_echo,
    "test_full_cycle": test_full_cycle,
    "test_send_text": test_send_text,
    "test_hunt_group": test_hunt_group,
    "test_idle_timeout": test_idle_timeout,
    "test_dtr_disconnect": test_dtr_disconnect,
    "test_eager_listen": test_eager_listen,
    "test_mux_port_status": test_mux_port_status,
    "test_s0_register": test_s0_register,
    "test_hunt_full": test_hunt_full,
    "test_reconnect": test_reconnect,
    "test_hunt_ring_timeout": test_hunt_ring_timeout,
    "test_tcp_out": test_tcp_out,
    "test_relay": test_relay,
    "test_single_busy": test_single_busy,
    "test_naws": test_naws,
    "test_ttype": test_ttype,
    "test_tls_irc": test_tls_irc,
    "test_vping": test_vping,
    "test_vtracert": test_vtracert,
}


def main():
    parser = argparse.ArgumentParser(description="VMODEM automated test runner")
    parser.add_argument("tests", nargs="*", help="Specific tests to run")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-l", "--list", action="store_true", help="List available tests")
    args = parser.parse_args()

    verbose = args.verbose or os.environ.get("VERBOSE", "0") != "0"
    set_verbose(verbose)

    if args.list:
        print("Available tests:")
        for name in ALL_TESTS:
            print(f"  {name}")
        return 0

    # Kill stale DOSBox-X processes from previous test runs
    import subprocess, signal
    try:
        result = subprocess.run(["pgrep", "-f", "dosbox-x.*vmodem_test"],
                                capture_output=True, text=True)
        for pid in result.stdout.strip().split("\n"):
            if pid:
                os.kill(int(pid), signal.SIGKILL)
    except (ProcessLookupError, ValueError, FileNotFoundError):
        pass

    # Clean up stale test temp directories
    import glob as glob_mod
    for old_dir in glob_mod.glob(os.path.join(tempfile.gettempdir(), "vmodem_test_*")):
        try:
            shutil.rmtree(old_dir, ignore_errors=True)
        except OSError:
            pass

    # Verify prerequisites
    try:
        find_dosbox()
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        return 1

    for exe in ["vmodem.exe", "comtest.exe"]:
        if not os.path.exists(os.path.join(SRC_DIR, exe)):
            print(f"ERROR: {exe} not found in {SRC_DIR} — run wmake first")
            return 1

    tests_to_run = args.tests if args.tests else list(ALL_TESTS.keys())
    passed = 0
    failed = 0
    errors = []

    for name in tests_to_run:
        if name not in ALL_TESTS:
            print(f"Unknown test: {name}")
            errors.append(name)
            continue

        print(f"\n{'='*60}")
        print(f"TEST: {name}")
        print(f"{'='*60}")

        try:
            if ALL_TESTS[name]():
                print(f">> PASS: {name}")
                passed += 1
            else:
                print(f">> FAIL: {name}")
                failed += 1
                errors.append(name)
        except Exception as e:
            print(f">> ERROR: {name}: {e}")
            failed += 1
            errors.append(name)
            if verbose:
                import traceback
                traceback.print_exc()

    print(f"\n{'='*60}")
    print(f"RESULTS: {passed} passed, {failed} failed out of {passed + failed}")
    if errors:
        print(f"FAILED: {', '.join(errors)}")
    print(f"{'='*60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
