#!/usr/bin/env python3
"""Test Telnet BINARY mode negotiation (RFC 856).

Flow:
  1. Start DOSBox-X with VMODEM + COMTEST ECHO_BACK
  2. Connect via TCP as a telnet client
  3. Verify VMODEM sends WILL BINARY and DO BINARY during negotiation
  4. Respond with DO BINARY and WILL BINARY
  5. Send a test payload containing CR (0x0D) bytes
  6. Verify the data round-trips without CR->CR+NUL corruption

Without BINARY mode, telnet inserts NUL (0x00) after every CR (0x0D),
which corrupts ZMODEM and other binary protocols.
"""

import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, strip_telnet_iac, vlog)

# Telnet protocol bytes
IAC  = 0xFF
WILL = 0xFB
WONT = 0xFC
DO   = 0xFD
DONT = 0xFE
SB   = 0xFA
SE   = 0xF0

TELOPT_BINARY = 0
TELOPT_ECHO   = 1
TELOPT_SGA    = 3
TELOPT_NAWS   = 31
TELOPT_TTYPE  = 24

OPT_NAMES = {0: "BINARY", 1: "ECHO", 3: "SGA", 24: "TTYPE", 31: "NAWS"}
CMD_NAMES = {WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT"}


def handle_negotiation(sock, timeout=10):
    """Read IAC negotiation from VMODEM, track BINARY offers.

    Returns dict of negotiated options with their state.
    """
    buf = b""
    deadline = time.time() + timeout
    saw_will_binary = False
    saw_do_binary = False
    options_seen = []

    while time.time() < deadline:
        sock.settimeout(max(0.2, deadline - time.time()))
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            if saw_will_binary and saw_do_binary:
                break
            continue

        # Process IAC sequences
        while len(buf) >= 3:
            if buf[0] != IAC:
                buf = buf[1:]
                continue

            cmd = buf[1]

            if cmd == IAC:
                buf = buf[2:]
                continue

            if cmd in (WILL, WONT, DO, DONT):
                if len(buf) < 3:
                    break
                opt = buf[2]
                buf = buf[3:]

                oname = OPT_NAMES.get(opt, f"0x{opt:02x}")
                cname = CMD_NAMES.get(cmd, f"0x{cmd:02x}")
                vlog(f"Server {cname} {oname}")
                options_seen.append((cmd, opt))

                if cmd == WILL:
                    if opt == TELOPT_BINARY:
                        saw_will_binary = True
                        vlog("  -> Responding DO BINARY")
                        sock.sendall(bytes([IAC, DO, TELOPT_BINARY]))
                    else:
                        sock.sendall(bytes([IAC, DO, opt]))
                elif cmd == DO:
                    if opt == TELOPT_BINARY:
                        saw_do_binary = True
                        vlog("  -> Responding WILL BINARY")
                        sock.sendall(bytes([IAC, WILL, TELOPT_BINARY]))
                    elif opt == TELOPT_NAWS or opt == TELOPT_TTYPE:
                        sock.sendall(bytes([IAC, WONT, opt]))
                    else:
                        sock.sendall(bytes([IAC, WONT, opt]))
                elif cmd == DONT or cmd == WONT:
                    pass
            elif cmd == SB:
                # Skip subnegotiation
                se_idx = buf.find(bytes([IAC, SE]), 2)
                if se_idx < 0:
                    break
                buf = buf[se_idx+2:]
            else:
                buf = buf[2:]

        # Short break to allow all negotiation to arrive
        if saw_will_binary and saw_do_binary:
            time.sleep(0.3)
            # Drain any remaining
            sock.settimeout(0.3)
            try:
                extra = sock.recv(4096)
                buf += extra
            except socket.timeout:
                pass
            # Process remaining
            while len(buf) >= 3 and buf[0] == IAC:
                cmd = buf[1]
                if cmd in (WILL, WONT, DO, DONT):
                    opt = buf[2]
                    buf = buf[3:]
                    oname = OPT_NAMES.get(opt, f"0x{opt:02x}")
                    cname = CMD_NAMES.get(cmd, f"0x{cmd:02x}")
                    vlog(f"Server {cname} {oname} (late)")
                    if cmd == WILL:
                        sock.sendall(bytes([IAC, DO, opt]))
                    elif cmd == DO:
                        sock.sendall(bytes([IAC, WONT, opt]))
                else:
                    break
            break

    return {
        'will_binary': saw_will_binary,
        'do_binary': saw_do_binary,
        'options': options_seen,
    }


def test_binary(env):
    """Test BINARY negotiation and data integrity in a single connection.

    1. Verify VMODEM sends WILL BINARY and DO BINARY
    2. Send CR-containing payload through FOSSIL echo
    3. Verify round-trip without NUL insertion
    """
    print("test_binary:")

    sock = connect_with_retries(env.host, env.port)
    if sock is None:
        print("  FAIL: could not connect")
        return False
    try:
        result = handle_negotiation(sock)

        # Check WILL BINARY (server says it will send binary)
        if result['will_binary']:
            print("  PASS: Server sent WILL BINARY")
        else:
            print("  FAIL: Server did NOT send WILL BINARY")
            opts = [(CMD_NAMES.get(c, '?'), OPT_NAMES.get(o, f'{o}'))
                    for c, o in result['options']]
            print(f"    Options seen: {opts}")
            return False

        # Check DO BINARY (server requests we send binary)
        if result['do_binary']:
            print("  PASS: Server sent DO BINARY")
        else:
            print("  FAIL: Server did NOT send DO BINARY")
            return False

        # Wait for CONNECT message (AT modem emulation sends RING + CONNECT)
        # COMTEST won't echo data until the modem layer establishes the call
        pre_buf = b""
        deadline = time.time() + 15
        got_connect = False
        while time.time() < deadline:
            sock.settimeout(max(0.5, deadline - time.time()))
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                pre_buf += chunk
                clean = strip_telnet_iac(pre_buf)
                if b"onnect" in clean.lower():
                    vlog(f"Got CONNECT indication")
                    got_connect = True
                    break
            except socket.timeout:
                continue

        if not got_connect:
            print("  FAIL: No CONNECT message received")
            vlog(f"Pre-data received: {pre_buf!r}")
            return False

        # Drain remaining CONNECT text + small delay for COMTEST echo loop
        time.sleep(1)
        sock.settimeout(0.5)
        try:
            while True:
                extra = sock.recv(4096)
                if not extra:
                    break
                vlog(f"Drained post-CONNECT: {strip_telnet_iac(extra)!r}")
        except socket.timeout:
            pass

        # Test payload: bytes that would be corrupted without BINARY mode
        # CR (0x0D) followed by non-NUL byte — in text mode, telnet inserts
        # NUL after CR, turning 0D 41 into 0D 00 41
        test_data = bytes([
            0x0D, 0x41,           # CR + 'A'
            0x0D, 0x0A,           # CR + LF (normal line ending)
            0x0D, 0x0D,           # CR + CR
            0x0D, 0x42,           # CR + 'B'
            0x48, 0x0D, 0x49,     # 'H' + CR + 'I'
        ])

        vlog(f"Sending {len(test_data)} test bytes with embedded CRs")

        # Send through the telnet connection — need to escape any 0xFF
        escaped = b""
        for b in test_data:
            if b == 0xFF:
                escaped += b"\xFF\xFF"
            else:
                escaped += bytes([b])

        sock.sendall(escaped)

        # Read back echoed data (COMTEST ECHO_BACK echoes all FOSSIL input)
        # Allow time for round-trip through FOSSIL + VMODEM
        time.sleep(2)

        sock.settimeout(5)
        received = b""
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                received += chunk
                # Keep reading until we have enough or timeout
                if len(received) >= len(test_data):
                    # Small extra wait for any trailing bytes
                    time.sleep(0.5)
                    sock.settimeout(0.3)
                    try:
                        received += sock.recv(4096)
                    except socket.timeout:
                        pass
                    break
            except socket.timeout:
                continue

        # Strip any telnet IAC sequences from received data
        clean = b""
        i = 0
        while i < len(received):
            if received[i] == 0xFF and i + 1 < len(received):
                if received[i+1] == 0xFF:
                    clean += b"\xFF"
                    i += 2
                    continue
                elif received[i+1] in (WILL, WONT, DO, DONT):
                    i += 3  # skip IAC cmd opt
                    continue
                elif received[i+1] == SB:
                    se = received.find(bytes([IAC, SE]), i+2)
                    i = se + 2 if se >= 0 else len(received)
                    continue
                else:
                    i += 2
                    continue
            clean += bytes([received[i]])
            i += 1

        vlog(f"Sent:     {test_data.hex()}")
        vlog(f"Received: {clean.hex()}")
        vlog(f"Raw recv: {received.hex()}")

        if clean == test_data:
            print(f"  PASS: {len(test_data)} bytes with CRs round-tripped intact")
            return True
        elif len(clean) > len(test_data):
            # Check for NUL insertion after CR
            extra_nuls = 0
            j = 0
            for b in clean:
                if j < len(test_data) and b == test_data[j]:
                    j += 1
                elif b == 0x00:
                    extra_nuls += 1
                else:
                    break
            if extra_nuls > 0:
                print(f"  FAIL: {extra_nuls} extra NUL bytes inserted after CR "
                      f"(BINARY mode not working)")
            else:
                print(f"  FAIL: received {len(clean)} bytes, expected {len(test_data)}")
                print(f"    sent: {test_data.hex()}")
                print(f"    got:  {clean.hex()}")
            return False
        else:
            print(f"  FAIL: received {len(clean)} bytes, expected {len(test_data)}")
            print(f"    sent: {test_data.hex()}")
            print(f"    got:  {clean.hex()}")
            return False
    finally:
        sock.close()


def test_bulk_binary(env, size=2048):
    """Test bulk data transfer including 0xFF bytes.

    Sends a large payload through FOSSIL echo and verifies round-trip.
    This simulates ZMODEM-like transfer volumes.
    """
    print(f"test_bulk_binary ({size} bytes):")

    sock = connect_with_retries(env.host, env.port)
    if sock is None:
        print("  FAIL: could not connect")
        return False
    try:
        result = handle_negotiation(sock)
        if not result['will_binary'] or not result['do_binary']:
            print("  FAIL: BINARY mode not negotiated")
            return False

        # Wait for CONNECT
        pre_buf = b""
        deadline = time.time() + 15
        got_connect = False
        while time.time() < deadline:
            sock.settimeout(max(0.5, deadline - time.time()))
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                pre_buf += chunk
                clean = strip_telnet_iac(pre_buf)
                if b"onnect" in clean.lower():
                    got_connect = True
                    break
            except socket.timeout:
                continue

        if not got_connect:
            print("  FAIL: No CONNECT message")
            return False

        # Drain CONNECT text
        time.sleep(1)
        sock.settimeout(0.5)
        try:
            while True:
                extra = sock.recv(4096)
                if not extra:
                    break
        except socket.timeout:
            pass

        # Build test payload: all byte values 0x00-0xFF repeated
        test_data = bytes(range(256)) * (size // 256)
        if len(test_data) < size:
            test_data += bytes(range(size - len(test_data)))

        vlog(f"Sending {len(test_data)} bytes (includes 0xFF, 0x0D, etc.)")

        # Telnet-escape 0xFF as IAC IAC
        escaped = b""
        for b in test_data:
            if b == 0xFF:
                escaped += b"\xFF\xFF"
            else:
                escaped += bytes([b])

        # Send all at once (burst) — simulates how SyncTERM sends ZMODEM data
        sock.sendall(escaped)

        # Read back echoed data
        received = b""
        deadline = time.time() + 30
        while time.time() < deadline:
            sock.settimeout(max(0.5, deadline - time.time()))
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                received += chunk
                clean_len = len(strip_telnet_iac(received))
                if clean_len >= len(test_data):
                    time.sleep(0.5)
                    sock.settimeout(0.3)
                    try:
                        received += sock.recv(4096)
                    except socket.timeout:
                        pass
                    break
            except socket.timeout:
                continue

        clean = strip_telnet_iac(received)
        vlog(f"Sent {len(test_data)} bytes, received {len(clean)} bytes")

        if clean == test_data:
            print(f"  PASS: {len(test_data)} bytes round-tripped intact")
            return True
        else:
            # Find first mismatch
            for i in range(min(len(clean), len(test_data))):
                if clean[i] != test_data[i]:
                    print(f"  FAIL: first mismatch at byte {i}: "
                          f"expected 0x{test_data[i]:02x}, got 0x{clean[i]:02x}")
                    # Show context
                    start = max(0, i - 4)
                    end = min(len(test_data), i + 8)
                    print(f"    expected[{start}:{end}]: {test_data[start:end].hex()}")
                    cend = min(len(clean), i + 8)
                    print(f"    received[{start}:{cend}]: {clean[start:cend].hex()}")
                    break
            else:
                print(f"  FAIL: length mismatch: sent {len(test_data)}, "
                      f"got {len(clean)}")
            return False
    finally:
        sock.close()


class BinaryTestEnv:
    """Wraps DOSBoxTestEnv with ECHO mode for binary tests."""

    def __init__(self):
        self.env = DOSBoxTestEnv()
        self.host = "127.0.0.1"
        self.port = 2323

    def start(self):
        self.env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST ECHO",
            "EXIT",
        ])
        self.env.start()
        if not self.env.wait_for_comtest_ready():
            raise RuntimeError("COMTEST did not reach ready state")

    def cleanup(self):
        self.env.cleanup()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Test BINARY mode negotiation")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--bulk-size", type=int, default=2048,
                        help="Bulk test payload size (default 2048)")
    args = parser.parse_args()

    from testenv import set_verbose
    set_verbose(args.verbose)

    env = BinaryTestEnv()
    try:
        env.start()

        # Only run one test at a time since COMTEST ECHO handles one connection
        if args.bulk_size > 11:
            passed = test_bulk_binary(env, args.bulk_size)
        else:
            passed = test_binary(env)

        if passed:
            print("\nBINARY mode test PASSED")
            return 0
        else:
            print("\nBINARY mode test FAILED")
            return 1
    finally:
        env.cleanup()


if __name__ == "__main__":
    exit(main())
