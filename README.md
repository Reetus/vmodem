# VMODEM

A DOS TSR (Terminate and Stay Resident) virtual serial port driver that bridges FOSSIL INT 14h to TCP/IP via the [mTCP](http://www.brutman.com/mTCP/) stack. It lets legacy DOS BBS software accept telnet connections over a real network — no physical modem required. Also provides a BSD socket library (`vsocket.lib`) so DOS programs can make outgoing TCP connections through the TSR.

Yes, we're writing DOS TSR drivers in 2026. The mass psychosis is real, but at least our BBS still answers the phone.

## What It Does

VMODEM hooks INT 14h to present a standard FOSSIL driver interface (the same API that RemoteAccess, Synchronet, Maximus, and other BBS packages expect). Behind the scenes, it translates serial I/O into TCP socket operations using mTCP's packet driver stack.

**Key features:**

- **FOSSIL-compatible** — drop-in replacement for a physical modem + FOSSIL driver
- **Multi-port** — supports COM1–COM4 simultaneously
- **Hunt groups** — multiple COM ports share a single TCP listen port; incoming connections are dispatched to the first free port (like a modem hunt group)
- **Telnet IAC** — handles telnet protocol negotiation (WILL/WONT/DO/DONT, IAC escaping, NOP keepalives)
- **AT command emulation** — RING, auto-answer (S0 register), CONNECT/NO CARRIER responses
- **Door support** — AT&D0 ignores DTR drops so BBS door programs can launch without losing the connection
- **Outgoing TCP** — BSD socket API (`vsocket.lib`) lets DOS programs make outgoing TCP connections through the TSR
- **Idle timeout** — automatically disconnects stale sessions
- **Stays resident** — installs as a TSR, controlled at runtime via `VMODCTL.EXE`

## Executables

| Program | Size | Description |
|---------|------|-------------|
| `VMODEM.EXE` | ~60 KB | Main TSR driver (hooks INT 14h, INT 28h, INT 2Fh) |
| `VMODCTL.EXE` | ~13 KB | Runtime control utility (no mTCP dependency) |
| `COMDIAG.EXE` | — | Real-time COM port status monitor (diagnostic) |
| `FOSSCHK.EXE` | — | FOSSIL driver detection and info checker (diagnostic) |
| `COMTEST.EXE` | — | Automated test helper (used by Python test harness) |

## Usage

### VMODEM.EXE — TSR Driver

```
VMODEM [options]

  /L:n:port         Listen on COM n for Telnet on TCP port
  /L:n-m:port       Hunt group: share TCP port across COM n through m
  /E                Eager listen (open sockets immediately, don't wait for FOSSIL init)
  /D:file           Write debug log to file (e.g. /D:VMODEM.LOG)
```

**Examples:**

```bash
# Load packet driver first (e.g., NE2000, PCAP, etc.)
# Then set up mTCP environment:
SET MTCPCFG=C:\MTCP\TCP.CFG

# COM1 listens for telnet on port 23
VMODEM /L:1:23

# Same, but start accepting connections immediately (no BBS needed)
VMODEM /L:1:23 /E

# Hunt group: COM1-4 share port 2323 (first free port answers)
VMODEM /L:1-4:2323

# Enable debug logging
VMODEM /L:1:23 /D:VMODEM.LOG

```

Once loaded, any BBS software that uses FOSSIL INT 14h will see VMODEM as a standard serial port driver. The BBS initializes FOSSIL (AH=04h), and VMODEM begins accepting TCP connections.

### VMODCTL.EXE — Control Utility

Controls the resident TSR without unloading it. Communicates via INT 2Fh (Multiplex Interrupt).

```
VMODCTL [options]

  /I:n              FOSSIL init COM n (activates listen socket)
  /U:n              FOSSIL deinit COM n
  /L:n:port         Set COM n to listen on TCP port
  /D:n              Disconnect COM n
  /S                Show status of all ports
  /G                Dump debug log
  /H or /?          Help
```

**Examples:**

```bash
# Initialize COM1 FOSSIL and show status
VMODCTL /I:1 /S

# Output:
# VMODEM Status
# Port   Mode        LocalTCP RemoteIP:Port        RxBuf
# ------------------------------------------------------------
# COM1   LISTEN      2323     -                    0
# COM2   CONN        2323     10.0.2.2:54321       12
# COM3   LISTEN      2323     -                    0
# COM4   not managed

# Disconnect COM2
VMODCTL /D:2

# Change COM1 to listen on a different port
VMODCTL /L:1:2300
```

### COMDIAG.EXE — Diagnostic Monitor

Real-time display of COM port status (LSR/MSR bits) and VMODEM port states. Refreshes every second. Press ESC to exit. Useful for watching connection state transitions on real hardware.

### FOSSCHK.EXE — FOSSIL Checker

Verifies FOSSIL driver presence by reading the INT 14h vector, checking the signature word (0x1954) at offset +6, and querying driver info via AH=1Bh.

## Building

### Prerequisites

- **Open Watcom 2.0** (C/C++ 16-bit compiler, linker, assembler)
  - Download: [open-watcom-v2](https://github.com/open-watcom/open-watcom-v2)
  - Linux host cross-compiling to DOS is fully supported
- **mTCP source** (TCP/IP stack for DOS)
  - Expected at `../../mtcp/mTCP-src_2025-01-10/` relative to the `src/` directory
  - Download: [brutman.com/mTCP](http://www.brutman.com/mTCP/)

### Build Instructions

```bash
# Set up Open Watcom environment
export WATCOM=/opt/watcom
export PATH=$WATCOM/binl64:$PATH
export INCLUDE=$WATCOM/h

# Build everything
cd src/
wmake

# Debug build (with symbols)
wmake debug=1

# Install to dosenv
wmake install

# Clean
wmake clean
```

All source files are compiled with `wpp` (C++ mode) to link against mTCP's C++ objects. Small memory model (`-ms`) is used to keep near pointers in DGROUP so the TSR stays compact after `_dos_keep()`.

### Linux Cross-Compilation Notes

The build system is designed to run on Linux targeting DOS:

- Case-sensitive filenames: mTCP source files use uppercase (`PACKET.CPP`); the Makefile references them in lowercase via symlinks
- `-fo=.obj` is required on all compile rules — Linux Watcom defaults to ELF `.o` instead of DOS OMF `.obj`
- `wasm` needs explicit `-fo=ipasm.obj` for the same reason
- `clean` target uses `rm -f` instead of DOS `del`

## Testing

### Prerequisites

- **Python 3** (3.8+)
- **DOSBox-X** — DOS emulator with slirp networking support
  - Build from source or use a binary with `-slirp` network support
  - Expected at `../../dosbox-x-src/src/dosbox-x` or on system PATH
- **Xvfb** — X virtual framebuffer for headless testing (optional; falls back to visible window)

### Running Tests

```bash
cd tests/

# Run all tests
python3 test_vmodem.py

# Run a specific test
python3 test_vmodem.py test_echo

# Verbose output
python3 test_vmodem.py -v

# List available tests
python3 test_vmodem.py -l
```

### Test Suite

| Test | Description |
|------|-------------|
| `test_fossil_init` | FOSSIL init returns signature 0x1954 |
| `test_fossil_status` | Status bits correct (THRE set, DCD low when idle) |
| `test_mux_status` | INT 2Fh MUX installation check works |
| `test_echo` | Connect via TCP, send data, verify echo |
| `test_full_cycle` | Full lifecycle: connect, exchange greeting, disconnect |
| `test_send_text` | DOS sends text via FOSSIL TX, Python receives it |
| `test_hunt_group` | Two connections dispatched to COM1 and COM2 via shared port |
| `test_idle_timeout` | Idle timeout disconnects and port returns to LISTEN |
| `test_dtr_disconnect` | FOSSIL deinit triggers disconnect, port returns to LISTEN |
| `test_eager_listen` | /E flag: connections accepted without FOSSIL init |
| `test_mux_port_status` | MUX_STATUS shows CONN mode and correct remote IP:port |
| `test_s0_register` | S0 auto-answer register: S0=0 prevents answer, S0=1 enables |
| `test_hunt_full` | Hunt group rejects 3rd connection when all ports busy |
| `test_reconnect` | Connect, disconnect, connect again on same port |
| `test_hunt_ring_timeout` | Hunt mode /E: ring timeout returns ports to LISTEN |
| `test_tcp_out` | Outgoing TCP connection via MUX socket API |
| `test_relay` | Bidirectional relay: FOSSIL incoming ↔ MUX socket outgoing |

Tests run inside DOSBox-X with slirp networking. The Python harness launches DOSBox-X, waits for VMODEM to start listening, connects via TCP, and communicates with `COMTEST.EXE` running inside the VM. Results are read from `COMTEST.LOG` written to a shared directory.

## Technical Details

### Architecture

```
  Telnet Client
       |
   TCP/IP (mTCP)
       |
  +-----------+     +----------+
  | poll.c    |<--->| telnet.c |   IAC FSM, byte escaping
  | (INT 28h) |     +----------+
  +-----------+
       |
  +-----------+     +----------+
  | int14.c   |<--->| ringbuf.c|   512-byte circular buffer
  | (INT 14h) |     +----------+
  +-----------+     +----------+
       |       <--->| atcmd.c  |   AT command / modem emulation
       |            +----------+
   BBS Software
  (RemoteAccess, etc.)
```

### Interrupt Hooks

| Interrupt | Purpose |
|-----------|---------|
| **INT 14h** | FOSSIL driver interface — AH=00h–1Bh serial port functions |
| **INT 28h** | DOS idle hook — drives mTCP polling (stack switch to private 16 KB stack) |
| **INT 2Fh** | Multiplex — AH=C3h for runtime control (listen, connect, disconnect, status) |

INT 28h is used for polling instead of INT 8 (timer tick) because mTCP already hooks INT 1Ch via INT 8. The private stack switch is necessary because the TSR's DGROUP stack is too small for mTCP's processing.

### FOSSIL Interface

VMODEM implements the standard FOSSIL INT 14h functions that BBS software expects:

| AH | Function | Description |
|----|----------|-------------|
| 00h | Set baud | Accepted but ignored (TCP has no baud rate) |
| 01h | TX char | Write byte to TCP send buffer |
| 02h | RX char | Read byte from ring buffer |
| 03h | Status | Return LSR/MSR-style status word |
| 04h | Init | Initialize port, create listen socket, return 0x1954 |
| 05h | Deinit | Close connections, release port (respects AT&D0) |
| 06h | DTR | DTR drop triggers disconnect (ignored if AT&D0 set) |
| 08h | Flush TX | Drain TX ring to TCP socket |
| 09h | Purge TX | Discard pending TX data |
| 0Ah | Purge RX | Discard pending RX data |
| 1Bh | Info | Return driver info block |

### Multiplex Interface (INT 2Fh, AH=C3h)

Runtime control and external socket API. Subcommands 00h–07h control the TSR; 10h–18h provide the outgoing socket API used by `vsocket.lib`.

| AL | Function | Registers |
|----|----------|-----------|
| 00h | Install check | Returns AL=FFh, ES:BX→VModemState |
| 01h | Listen | CX=port(0–3), DX=TCP port |
| 03h | Disconnect | CX=port(0–3) |
| 04h | Status | ES:BX→StatusBlock (108 bytes) |
| 05h | Poll | Trigger one mTCP poll cycle |
| 06h | Debug log | ES:BX→buffer, CX=size |
| 07h | Hunt listen | CL=port mask, DX=TCP port |
| 10h | Sock alloc | Returns AL=handle (0–3) or 0xFF |
| 11h | Sock connect | CL=handle, DX=port, ES:BX→4-byte IP |
| 12h | Sock status | CL=handle; returns AL=state |
| 13h | Sock send | CL=handle, DX=len, ES:BX→data |
| 14h | Sock recv | CL=handle, DX=bufsz, ES:BX→buffer |
| 15h | Sock close | CL=handle |
| 16h | Sock result | Returns AX=last operation result |
| 17h | DNS resolve | ES:BX→hostname; initiates async DNS query |
| 18h | DNS result | ES:BX→4-byte IP buf; returns AL=state |
| FFh | Unload | Restore vectors, free TSR memory |

### Port State Machine

```
  PORT_DISC ──(AH=04h init)──> PORT_LISTEN
       ^                            |
       |                     (TCP accept)
       |                            v
       +───(disconnect)────── PORT_CONN
       |                            |
       +───(idle timeout)───────────+
```

When a listen socket exists, disconnects return to `PORT_LISTEN` instead of `PORT_DISC`, allowing the port to accept new connections without requiring another FOSSIL init.

### Hunt Groups

Multiple COM ports can share a single TCP listen port. When a connection arrives, it's dispatched to the first free port in the group. If all ports are busy, the caller receives a "line engaged" message and is disconnected. This emulates a telephone hunt group / rotary line.

```
VMODEM /L:1-4:2323    Four COM ports share TCP port 2323
```

### Memory Model

Small model (`-ms`) with near data pointers. All mTCP buffers are allocated from `near malloc` to stay within the 64 KB DGROUP segment. The TSR footprint is kept minimal so `_dos_keep()` only reserves what's needed.

### mTCP Configuration

Tuned for the 64 KB DGROUP constraint:

- 4 packet buffers
- 8 TCP sockets (4 ports × 2: data + listen)
- 6 TCP transmit buffers
- 1 DNS cache entry
- `TCP_LISTEN_CODE` enabled (required for `TcpSocket::listen()`)

## BSD Socket Library (vsocket.lib)

VMODEM includes a BSD-style socket library that lets DOS programs make outgoing TCP connections through the resident TSR. Link your program against `VSOCKET.LIB` and include `VSOCKET.H`.

```c
#include "vsocket.h"

int main(void)
{
    struct sockaddr_in addr;
    int s;

    if (vsock_init() != 0) return 1;  /* verify TSR loaded */

    s = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(6667);
    addr.sin_addr.s_addr = inet_addr("10.0.2.2");
    connect(s, (struct sockaddr *)&addr, sizeof(addr));

    send(s, "NICK dos\r\n", 10, 0);
    /* ... */
    closesocket(s);
    return 0;
}
```

**Limitations:**
- AF_INET + SOCK_STREAM only (TCP); no UDP
- Max 4 simultaneous sockets
- `gethostbyname()` supports DNS resolution and dotted-decimal IPs
- `connect()` blocks with a 30-second timeout

**This library is published in case it's useful to someone, but is not supported. Use at your own risk.**

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE) — the same license as [mTCP](http://www.brutman.com/mTCP/), which VMODEM links against.
