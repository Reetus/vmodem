#!/usr/bin/env python3
"""Test NAWS (Negotiate About Window Size) negotiation.

Flow:
  1. Start DOSBox-X with VMODEM + COMTEST NAWS_QUERY
  2. Connect via TCP as a telnet client
  3. VMODEM sends DO NAWS during IAC negotiation
  4. We respond WILL NAWS + SB NAWS 132x37 SE
  5. COMTEST queries MUX_PORT_NAWS and verifies 132x37
"""

import socket
import struct
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, vlog, wait_for_rdy)

# Telnet protocol bytes
IAC  = 0xFF
WILL = 0xFB
WONT = 0xFC
DO   = 0xFD
DONT = 0xFE
SB   = 0xFA
SE   = 0xF0

TELOPT_NAWS = 31

# Test values — intentionally non-standard to prove they came through
TEST_COLS = 132
TEST_ROWS = 37


def handle_telnet_negotiation(sock, timeout=10):
    """Read IAC negotiation from VMODEM and respond.

    Specifically:
      - Reply DO to any WILL offers
      - Reply WILL NAWS + subneg when we see DO NAWS
      - Reply WONT to any other DO requests
      - Drain until we've handled all initial negotiation
    """
    buf = b""
    naws_sent = False
    deadline = time.time() + timeout

    while time.time() < deadline:
        sock.settimeout(max(0.2, deadline - time.time()))
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            # If we've already sent NAWS and no more data, we're done
            if naws_sent:
                break
            continue

        # Process IAC sequences in buffer
        while len(buf) >= 3:
            if buf[0] != IAC:
                # Skip non-IAC data (RING, CONNECT messages, etc.)
                buf = buf[1:]
                continue

            cmd = buf[1]

            if cmd == IAC:
                # IAC IAC = literal 0xFF
                buf = buf[2:]
                continue

            if cmd in (WILL, WONT, DO, DONT):
                if len(buf) < 3:
                    break  # need more data
                opt = buf[2]
                buf = buf[3:]

                if cmd == WILL:
                    # Server offers an option — accept it
                    vlog(f"Server WILL {opt}, responding DO")
                    sock.sendall(bytes([IAC, DO, opt]))
                elif cmd == DO:
                    if opt == TELOPT_NAWS:
                        # Server requests NAWS — accept and send size
                        vlog(f"Server DO NAWS, sending WILL + subneg {TEST_COLS}x{TEST_ROWS}")
                        sock.sendall(bytes([IAC, WILL, TELOPT_NAWS]))
                        # Send SB NAWS <cols_hi> <cols_lo> <rows_hi> <rows_lo> SE
                        sb_data = struct.pack(">HH", TEST_COLS, TEST_ROWS)
                        sock.sendall(bytes([IAC, SB, TELOPT_NAWS])
                                     + sb_data
                                     + bytes([IAC, SE]))
                        naws_sent = True
                        vlog("NAWS subneg sent")
                    else:
                        # Refuse other DO requests
                        vlog(f"Server DO {opt}, responding WONT")
                        sock.sendall(bytes([IAC, WONT, opt]))
                elif cmd == DONT or cmd == WONT:
                    pass  # ignore
            else:
                # Other IAC command (NOP, etc.)
                buf = buf[2:]

        # If nothing left to process and NAWS was sent, give a little time
        # for any remaining negotiation then break
        if naws_sent and len(buf) < 3:
            time.sleep(0.3)
            # One more drain
            sock.settimeout(0.5)
            try:
                extra = sock.recv(4096)
                buf += extra
            except socket.timeout:
                pass
            break

    return naws_sent


def test_naws():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST NAWS_QUERY",
            "EXIT",
        ])
        env.start()

        # Wait for COMTEST to be ready for connection
        if not wait_for_rdy(env, "NAWS_WAITING_DCD"):
            print("FAIL: test_naws - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        # Connect to VMODEM
        sock = connect_with_retries()
        if sock is None:
            print("FAIL: test_naws - could not connect")
            env.wait_for_exit(timeout=10)
            return False

        # Handle telnet negotiation — send NAWS
        naws_ok = handle_telnet_negotiation(sock)
        if not naws_ok:
            print("FAIL: test_naws - VMODEM did not send DO NAWS")
            sock.close()
            env.wait_for_exit(timeout=10)
            return False

        vlog("NAWS negotiation complete, waiting for COMTEST to query...")

        # Wait for COMTEST to finish its MUX query
        if not wait_for_rdy(env, "NAWS_DONE", timeout=30):
            print("FAIL: test_naws - COMTEST did not finish query")
            sock.close()
            env.wait_for_exit(timeout=10)
            return False

        # Disconnect
        sock.close()

        # Wait for DOSBox to exit
        env.wait_for_exit(timeout=45)

        # Read and report results
        log_text = env.read_comtest_log()
        results = parse_comtest_log(log_text) if log_text else []
        if is_verbose() and log_text:
            print(f"  LOG:\n{log_text}")

        passed = True
        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")
            if status == "FAIL":
                passed = False

        if not results:
            print("FAIL: test_naws - no COMTEST.LOG results")
            return False

        return passed
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_naws() else 1)
