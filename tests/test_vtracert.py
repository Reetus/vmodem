#!/usr/bin/env python3
"""Test ICMP traceroute via VMODEM's MUX ICMP API.

Loads VMODEM TSR in DOSBox-X, runs VTRACERT to trace the route to the
SLIRP gateway (10.0.2.2) and verifies that the trace completes.
Note: SLIRP is 1 hop — real multi-hop traces only work on real networks.
"""

import os
import re

from testenv import DOSBoxTestEnv, is_verbose, vlog

# SLIRP gateway — 1 hop from guest, always responds to ICMP
TRACE_TARGET = "10.0.2.2"


def test_vtracert():
    env = DOSBoxTestEnv()
    try:
        bbs_utils = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "bbs-utils")
        vtracert_src = os.path.join(bbs_utils, "vtracert", "vtracert.exe")
        if not os.path.exists(vtracert_src):
            print(f"FAIL: test_vtracert - VTRACERT.EXE not found at {vtracert_src}")
            return False

        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            f"VTRACERT {TRACE_TARGET} > VTRACE.OUT",
            "EXIT",
        ])

        vm_dir = os.path.join(env.drive_c, "vmodem")
        import shutil
        shutil.copy2(vtracert_src, os.path.join(vm_dir, "VTRACERT.EXE"))

        env.start()

        # SLIRP gateway is 1 hop — trace should complete quickly.
        # 60s timeout covers DHCP + mTCP init + ARP + the trace itself.
        env.wait_for_exit(timeout=60)

        out_path = os.path.join(env.drive_c, "vmodem", "VTRACE.OUT")
        if not os.path.exists(out_path):
            print("FAIL: test_vtracert - VTRACE.OUT not found (vtracert may not have run)")
            return False

        with open(out_path, "r") as f:
            output = f.read()

        if is_verbose():
            print(f"  VTRACERT output:\n{output}")

        # Check for key markers
        has_header = "tracing route" in output.lower()
        has_complete = "trace complete" in output.lower()

        # Count hop lines (lines starting with whitespace + number)
        hop_lines = re.findall(r"^\s*\d+\s+", output, re.MULTILINE)
        hop_count = len(hop_lines)

        # Check that destination IP appears in the output (header or final hop)
        has_target = TRACE_TARGET in output

        # Check for ms timing values (at least one probe got a reply)
        has_timing = "ms" in output.lower()

        print(f"  Hops: {hop_count}, Header: {has_header}, "
              f"Complete: {has_complete}, Target: {has_target}")

        # Pass if header present, at least 1 hop responded, and trace completed
        ok = has_header and has_complete and hop_count >= 1 and has_timing
        print(f"  {'PASS' if ok else 'FAIL'}: VTRACERT "
              f"({hop_count} hop(s) to {TRACE_TARGET})")

        if is_verbose():
            vmodem_log = os.path.join(env.drive_c, "vmodem", "VMODEM.LOG")
            if os.path.exists(vmodem_log):
                with open(vmodem_log, "r") as f:
                    print(f"  VMODEM.LOG:\n{f.read()[:2000]}")

        return ok
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    from testenv import set_verbose
    if "-v" in sys.argv or "--verbose" in sys.argv:
        set_verbose(True)
    sys.exit(0 if test_vtracert() else 1)
