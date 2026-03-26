#!/usr/bin/env python3
"""Test ICMP ping via VMODEM's MUX ICMP API.

Loads VMODEM TSR in DOSBox-X, runs VPING to ping the SLIRP gateway
(10.0.2.2), and verifies that replies are received.

No COMTEST or TCP interaction needed — VPING is a standalone utility
that uses vsocket's ICMP MUX calls through the resident VMODEM TSR.
"""

import os
import time

from testenv import DOSBoxTestEnv, is_verbose, vlog

# SLIRP gateway — always responds to ICMP echo from the guest
PING_TARGET = "10.0.2.2"


def test_vping():
    env = DOSBoxTestEnv()
    try:
        # Copy VPING.EXE into the test environment
        bbs_utils = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "bbs-utils")
        vping_src = os.path.join(bbs_utils, "vping", "vping.exe")
        if not os.path.exists(vping_src):
            print(f"FAIL: test_vping - VPING.EXE not found at {vping_src}")
            return False

        env.setup([
            # VMODEM must be loaded for the mTCP stack + ICMP MUX
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            # Run vping, redirect output to file for host-side checking
            f"VPING -c 4 {PING_TARGET} > VPING.OUT",
            "EXIT",
        ])

        # Copy VPING.EXE into guest C:\VMODEM
        vm_dir = os.path.join(env.drive_c, "vmodem")
        import shutil
        shutil.copy2(vping_src, os.path.join(vm_dir, "VPING.EXE"))

        env.start()

        # VPING sends 4 pings with ~1s between each, plus DHCP/init overhead.
        # 60s is generous but safe.
        env.wait_for_exit(timeout=60)

        # Read VPING.OUT from guest drive
        out_path = os.path.join(env.drive_c, "vmodem", "VPING.OUT")
        if not os.path.exists(out_path):
            print("FAIL: test_vping - VPING.OUT not found (vping may not have run)")
            return False

        with open(out_path, "r") as f:
            output = f.read()

        if is_verbose():
            print(f"  VPING output:\n{output}")

        # Check for successful replies
        reply_count = output.lower().count("reply from")
        timeout_count = output.lower().count("timed out")
        has_stats = "packets:" in output.lower()

        # Parse loss percentage from stats line
        loss_pct = 100
        for line in output.split("\n"):
            if "loss" in line.lower():
                # "Lost = 0 (0% loss)"
                try:
                    pct_str = line.split("(")[1].split("%")[0].strip()
                    loss_pct = int(pct_str)
                except (IndexError, ValueError):
                    pass

        print(f"  Replies: {reply_count}, Timeouts: {timeout_count}, "
              f"Loss: {loss_pct}%")

        # Pass if we got at least 1 reply
        ok = reply_count >= 1 and has_stats
        print(f"  {'PASS' if ok else 'FAIL'}: VPING "
              f"({reply_count}/4 replies from {PING_TARGET})")

        # Also dump VMODEM.LOG in verbose mode for debugging
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
    sys.exit(0 if test_vping() else 1)
