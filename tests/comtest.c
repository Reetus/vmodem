/*
 * comtest.c - DOS test helper for VMODEM
 *
 * Runs inside DOSBox-X.  Exercises the FOSSIL (INT 14h) and MUX (INT 2Fh)
 * interfaces, writing pass/fail results to COMTEST.LOG.
 *
 * The Python test runner reads COMTEST.LOG after DOSBox-X exits to check
 * results.  The Python side handles TCP connections (telnet client) while
 * this program handles the DOS/FOSSIL side.
 *
 * Usage: COMTEST <test_name> [args...]
 *
 * Tests:
 *   FOSSIL_INIT    - Init FOSSIL on COM1, check signature 1954h
 *   FOSSIL_STATUS  - Check status word (DCD, THRE, etc.)
 *   ECHO           - Init FOSSIL, wait for data, echo it back, deinit
 *   WAIT_DCD       - Wait for DCD (connection), report when seen
 *   SEND_TEXT      - Send a text string via FOSSIL TX
 *   MUX_STATUS     - Check VMODEM MUX status block
 *   MUX_DISCONNECT - Send disconnect via MUX, verify
 *   FULL_CYCLE     - Init, wait for connect, echo, wait for disconnect
 *
 * Compile: wpp comtest -0 -ms -fo=.obj -zp2 -zpw -ei -s -we
 *          wlink system dos name comtest.exe file comtest.obj
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include <i86.h>
#include <conio.h>

/* FOSSIL INT 14h functions */
#define FOSSIL_INIT      0x04
#define FOSSIL_DEINIT    0x05
#define FOSSIL_SET_BAUD  0x00
#define FOSSIL_TX_CHAR   0x01
#define FOSSIL_RX_CHAR   0x02
#define FOSSIL_STATUS    0x03
#define FOSSIL_DTR       0x06
#define FOSSIL_FLUSH_OUT 0x08
#define FOSSIL_PURGE_OUT 0x09
#define FOSSIL_PURGE_IN  0x0A
#define FOSSIL_INFO      0x1B

/* MUX defines — use shared header for StatusBlock struct */
#include "../src/vmodem_mux.h"

/* BSD socket API wrapping VMODEM's MUX socket interface */
#include "lib/vsocket.h"

/* Status word bits */
#define STATUS_RDA       0x0100  /* AH bit 0: receive data available */
#define STATUS_THRE      0x2000  /* AH bit 5: TX holding register empty */
#define STATUS_TSRE      0x4000  /* AH bit 6: TX shift register empty */
#define STATUS_DCD       0x0080  /* AL bit 7: carrier detect */

static FILE *logfile;
static int pass_count = 0;
static int fail_count = 0;

static void log_result(const char *test, int passed, const char *detail)
{
    const char *status = passed ? "PASS" : "FAIL";
    printf("%s: %s %s\n", status, test, detail);
    fprintf(logfile, "%s: %s %s\n", status, test, detail);
    fflush(logfile);
    if (passed) pass_count++;
    else fail_count++;
}

static void log_info(const char *msg)
{
    printf("INFO: %s\n", msg);
    fprintf(logfile, "INFO: %s\n", msg);
    fflush(logfile);
}

/* Write a flag file that is immediately closed so the host can detect it.
 * DOSBox-X caches file writes; fflush alone doesn't update the host FS.
 * By opening+writing+closing a separate file, DOSBox-X flushes to host. */
static void write_ready_flag(const char *marker)
{
    /* DOSBox-X directory mounts flush new file creation to the host FS
     * immediately, but overwriting an existing file's content may not
     * be visible until DOSBox-X exits.  Delete first so fopen always
     * creates a fresh file that the host can see. */
    remove("COMTEST.RDY");
    {
        FILE *f = fopen("COMTEST.RDY", "w");
        if (f) {
            fprintf(f, "%s\n", marker);
            fclose(f);
        }
    }
}

/* ---- FOSSIL helpers ---- */

static unsigned short fossil_call(unsigned char func, unsigned short dx_val,
                                  unsigned short ax_val)
{
    union REGS r;
    r.h.ah = func;
    r.h.al = (unsigned char)(ax_val & 0xFF);
    r.x.dx = dx_val;
    int86(0x14, &r, &r);
    return r.x.ax;
}

static unsigned short fossil_init(int port)
{
    return fossil_call(FOSSIL_INIT, (unsigned short)port, 0);
}

static void fossil_deinit(int port)
{
    fossil_call(FOSSIL_DEINIT, (unsigned short)port, 0);
}

static unsigned short fossil_status(int port)
{
    return fossil_call(FOSSIL_STATUS, (unsigned short)port, 0);
}

static void fossil_tx(int port, unsigned char ch)
{
    fossil_call(FOSSIL_TX_CHAR, (unsigned short)port, (unsigned short)ch);
}

static int fossil_rx(int port)
{
    unsigned short ax = fossil_call(FOSSIL_RX_CHAR, (unsigned short)port, 0);
    if (ax & 0x8000) return -1;  /* timeout / no data */
    return (int)(ax & 0xFF);
}

static void fossil_tx_string(int port, const char *s)
{
    while (*s)
        fossil_tx(port, (unsigned char)*s++);
}

/* Init FOSSIL and enable auto-answer on first ring.
 * s0 defaults to 0 after init; most tests need auto-answer enabled. */
static unsigned short fossil_init_answer(int port)
{
    unsigned short ax = fossil_init(port);
    if (ax == 0x1954) {
        fossil_tx_string(port, "ATS0=1\r");
        {
            unsigned long t;
            t = *(volatile unsigned long far *)MK_FP(0x0040, 0x006C) + 18UL;
            while (*(volatile unsigned long far *)MK_FP(0x0040, 0x006C) < t) {
                union REGS r;
                r.h.ah = 0x0B;
                int86(0x21, &r, &r);
            }
        }
    }
    return ax;
}

/* ---- Wait helpers ---- */

static unsigned long get_tick(void)
{
    return *(volatile unsigned long far *)MK_FP(0x0040, 0x006C);
}

/* Yield CPU to DOSBox-X so it can process host events (slirp networking).
 * A tight busy-loop starves the emulator's event loop and prevents
 * incoming TCP connections from reaching the virtual NE2000.
 * INT 28h alone isn't enough — DOSBox-X needs an actual idle signal.
 * INT 21h AH=0Bh (check keyboard) triggers DOS's internal idle loop. */
static void dos_idle(void)
{
    union REGS r;
    /* INT 21h AH=0Bh: check standard input status.
     * DOS calls INT 28h internally during this, triggering DOSBox-X
     * idle detection (which yields CPU to host event processing). */
    r.h.ah = 0x0B;
    int86(0x21, &r, &r);
}

static int wait_for_dcd(int port, int timeout_secs)
{
    unsigned long deadline = get_tick() + (unsigned long)timeout_secs * 18UL;
    while (get_tick() < deadline) {
        unsigned short st = fossil_status(port);
        if (st & STATUS_DCD) return 1;
        dos_idle();
    }
    return 0;
}

static int wait_for_no_dcd(int port, int timeout_secs)
{
    unsigned long deadline = get_tick() + (unsigned long)timeout_secs * 18UL;
    while (get_tick() < deadline) {
        unsigned short st = fossil_status(port);
        if (!(st & STATUS_DCD)) return 1;
        dos_idle();
    }
    return 0;
}

static int wait_for_data(int port, int timeout_secs)
{
    unsigned long deadline = get_tick() + (unsigned long)timeout_secs * 18UL;
    while (get_tick() < deadline) {
        unsigned short st = fossil_status(port);
        if (st & STATUS_RDA) return 1;
        dos_idle();
    }
    return 0;
}

/* ---- MUX helpers ---- */

static int mux_installed(void)
{
    union REGS r;
    r.h.ah = MUX_ID;
    r.h.al = MUX_INSTALL_CHK;
    int86(0x2F, &r, &r);
    return (r.h.al == 0xFF) ? 1 : 0;
}

/* ---- Test implementations ---- */

static void test_fossil_init(void)
{
    unsigned short ax = fossil_init(0);
    log_result("FOSSIL_INIT_SIG", ax == 0x1954,
               ax == 0x1954 ? "(AX=1954h)" : "(AX != 1954h)");
    fossil_deinit(0);
}

static void test_fossil_status(void)
{
    unsigned short st;
    fossil_init(0);

    st = fossil_status(0);

    /* THRE should be set (output buffer empty) */
    log_result("STATUS_THRE", (st & STATUS_THRE) != 0,
               "(TX ready)");

    /* DCD should be low (no connection yet) */
    log_result("STATUS_DCD_LOW", (st & STATUS_DCD) == 0,
               "(no carrier)");

    fossil_deinit(0);
}

static void test_mux_status(void)
{
    log_result("MUX_INSTALLED", mux_installed(),
               mux_installed() ? "(found)" : "(not found)");
}

static void test_echo(void)
{
    /* Init FOSSIL, wait for DCD (Python connects), echo data back */
    unsigned long deadline;
    int got_data = 0;
    char buf[128];
    int buf_len = 0;

    fossil_init_answer(0);
    log_info("ECHO: waiting for DCD (connection)...");
    write_ready_flag("ECHO_WAITING_DCD");

    if (!wait_for_dcd(0, 120)) {
        log_result("ECHO_DCD", 0, "(timeout waiting for connection)");
        fossil_deinit(0);
        return;
    }
    log_result("ECHO_DCD", 1, "(connection detected)");

    /* Read data for up to 10 seconds — check DCD to avoid AT echo storm */
    log_info("ECHO: reading data...");
    deadline = get_tick() + 10UL * 18UL;
    while (get_tick() < deadline) {
        unsigned short st;
        int ch;
        st = fossil_status(0);
        if (!(st & STATUS_DCD)) break;
        ch = fossil_rx(0);
        if (ch >= 0) {
            if (buf_len < 127) {
                buf[buf_len++] = (char)ch;
            }
            /* Echo it back */
            fossil_tx(0, (unsigned char)ch);
            got_data = 1;
            /* Reset deadline on each byte received */
            deadline = get_tick() + 3UL * 18UL;
        }
    }
    buf[buf_len] = '\0';

    log_result("ECHO_DATA", got_data,
               got_data ? buf : "(no data received)");

    /* Wait for disconnect or timeout */
    log_info("ECHO: waiting for disconnect...");
    if (wait_for_no_dcd(0, 30)) {
        log_result("ECHO_DISCONNECT", 1, "(DCD dropped)");
    } else {
        log_result("ECHO_DISCONNECT", 0, "(still connected after 15s)");
    }

    fossil_deinit(0);
}

static void test_full_cycle(void)
{
    /* Full lifecycle: init, wait connect, exchange data, wait disconnect */
    unsigned short ax;
    char buf[128];
    int buf_len = 0;
    unsigned long deadline;

    /* Step 1: Init */
    ax = fossil_init_answer(0);
    log_result("CYCLE_INIT", ax == 0x1954, "(FOSSIL init)");

    /* Step 2: Wait for connection */
    log_info("CYCLE: waiting for connection...");
    write_ready_flag("CYCLE_WAITING_DCD");
    if (!wait_for_dcd(0, 120)) {
        log_result("CYCLE_CONNECT", 0, "(timeout)");
        fossil_deinit(0);
        return;
    }
    log_result("CYCLE_CONNECT", 1, "(DCD high)");

    /* Step 3: Send greeting */
    fossil_tx_string(0, "HELLO_FROM_DOS\r\n");
    log_info("CYCLE: sent greeting");

    /* Step 4: Wait for response */
    deadline = get_tick() + 10UL * 18UL;
    while (get_tick() < deadline) {
        unsigned short st;
        int ch;
        st = fossil_status(0);
        if (!(st & STATUS_DCD)) break;
        ch = fossil_rx(0);
        if (ch >= 0) {
            if (buf_len < 127) buf[buf_len++] = (char)ch;
            deadline = get_tick() + 3UL * 18UL;
        }
    }
    buf[buf_len] = '\0';
    log_result("CYCLE_RECV", buf_len > 0, buf);

    /* Step 5: Wait for disconnect */
    log_info("CYCLE: waiting for disconnect...");
    if (wait_for_no_dcd(0, 30)) {
        log_result("CYCLE_DISCONNECT", 1, "(clean disconnect)");
    } else {
        log_result("CYCLE_DISCONNECT", 0, "(still connected)");
    }

    fossil_deinit(0);
}

static void test_send_text(const char *text)
{
    fossil_init_answer(0);
    log_info("SEND_TEXT: waiting for DCD...");
    write_ready_flag("SEND_WAITING_DCD");

    if (!wait_for_dcd(0, 120)) {
        log_result("SEND_DCD", 0, "(timeout)");
        fossil_deinit(0);
        return;
    }
    log_result("SEND_DCD", 1, "(connected)");

    fossil_tx_string(0, text);
    fossil_tx_string(0, "\r\n");
    /* Flush TX buffer: AH=08h forces VMODEM to drain TX ring to TCP.
     * Then poll status (AH=03h) which triggers full mTCP poll cycle
     * including Tcp::drivePackets() to actually transmit. */
    fossil_call(FOSSIL_FLUSH_OUT, 0, 0);
    fossil_status(0);  /* triggers poll_on_priv_stack → drivePackets */
    log_result("SEND_TEXT", 1, text);

    /* Keep polling to ensure TCP packets are delivered */
    {
        unsigned long t = get_tick() + 36UL;
        while (get_tick() < t) {
            fossil_status(0);
            dos_idle();
        }
    }
    fossil_deinit(0);
}

static void test_hunt_group(void)
{
    /* Hunt group test: init FOSSIL on COM1 and COM2, wait for connections
     * on both, echo data on whichever port gets data.
     *
     * Python connects twice to the same TCP port.  VMODEM dispatches
     * the first connection to COM1 and the second to COM2.
     *
     * Flow:
     *   1. Init FOSSIL on COM1 (port 0) and COM2 (port 1)
     *   2. Write ready flag
     *   3. Wait for DCD on COM1 (first connection)
     *   4. Write second ready flag
     *   5. Wait for DCD on COM2 (second connection)
     *   6. Echo data on both ports for a while
     *   7. Wait for disconnects
     */
    unsigned short ax;
    unsigned long deadline;
    int got1 = 0, got2 = 0;
    char buf1[64], buf2[64];
    int len1 = 0, len2 = 0;

    /* Step 1: Init both ports */
    ax = fossil_init_answer(0);
    log_result("HUNT_INIT_COM1", ax == 0x1954, "(FOSSIL init COM1)");

    ax = fossil_init_answer(1);
    log_result("HUNT_INIT_COM2", ax == 0x1954, "(FOSSIL init COM2)");

    /* Step 2: Signal ready for first connection */
    log_info("HUNT: waiting for first connection on COM1...");
    write_ready_flag("HUNT_WAITING_DCD1");

    /* Step 3: Wait for DCD on COM1 */
    if (!wait_for_dcd(0, 120)) {
        log_result("HUNT_DCD1", 0, "(timeout waiting for COM1 connection)");
        fossil_deinit(0);
        fossil_deinit(1);
        return;
    }
    log_result("HUNT_DCD1", 1, "(COM1 connected)");

    /* Step 4: Signal ready for second connection */
    log_info("HUNT: waiting for second connection on COM2...");
    write_ready_flag("HUNT_WAITING_DCD2");

    /* Step 5: Wait for DCD on COM2 */
    if (!wait_for_dcd(1, 120)) {
        log_result("HUNT_DCD2", 0, "(timeout waiting for COM2 connection)");
        fossil_deinit(0);
        fossil_deinit(1);
        return;
    }
    log_result("HUNT_DCD2", 1, "(COM2 connected)");

    /* Step 6: Echo data on both ports.
     * Read from each port and echo back.  Collect received data
     * to verify port isolation (each port gets different data).
     * Check DCD on both ports to avoid AT echo storm on disconnect. */
    log_info("HUNT: echoing data on both ports...");
    deadline = get_tick() + 10UL * 18UL;
    while (get_tick() < deadline) {
        unsigned short st0, st1;
        int ch;

        st0 = fossil_status(0);
        st1 = fossil_status(1);
        if (!(st0 & STATUS_DCD) && !(st1 & STATUS_DCD)) break;

        /* Echo on COM1 */
        if (st0 & STATUS_DCD) {
            ch = fossil_rx(0);
            if (ch >= 0) {
                if (len1 < 63) buf1[len1++] = (char)ch;
                fossil_tx(0, (unsigned char)ch);
                got1 = 1;
                deadline = get_tick() + 3UL * 18UL;
            }
        }

        /* Echo on COM2 */
        if (st1 & STATUS_DCD) {
            ch = fossil_rx(1);
            if (ch >= 0) {
                if (len2 < 63) buf2[len2++] = (char)ch;
                fossil_tx(1, (unsigned char)ch);
                got2 = 1;
                deadline = get_tick() + 3UL * 18UL;
            }
        }
    }
    buf1[len1] = '\0';
    buf2[len2] = '\0';

    log_result("HUNT_ECHO1", got1, got1 ? buf1 : "(no data on COM1)");
    log_result("HUNT_ECHO2", got2, got2 ? buf2 : "(no data on COM2)");

    /* Step 7: Wait for disconnects */
    log_info("HUNT: waiting for disconnects...");
    if (wait_for_no_dcd(0, 30))
        log_result("HUNT_DISC1", 1, "(COM1 disconnected)");
    else
        log_result("HUNT_DISC1", 0, "(COM1 still connected)");

    if (wait_for_no_dcd(1, 30))
        log_result("HUNT_DISC2", 1, "(COM2 disconnected)");
    else
        log_result("HUNT_DISC2", 0, "(COM2 still connected)");

    fossil_deinit(0);
    fossil_deinit(1);
}

/* ---- MUX status helper ---- */

static void mux_get_status(unsigned char *mode_out, unsigned short *remotePort_out,
                           unsigned char *remoteIP_out)
{
    /* Read StatusBlock via INT 2Fh MUX_STATUS — use the shared struct */
    union REGS r;
    struct SREGS sr;
    static StatusBlock sb;

    memset(&sb, 0, sizeof(sb));
    segread(&sr);
    sr.es = FP_SEG(&sb);
    r.h.ah = MUX_ID;
    r.h.al = MUX_STATUS;
    r.x.bx = FP_OFF(&sb);
    int86x(0x2F, &r, &r, &sr);

    if (mode_out) *mode_out = sb.ports[0].mode;
    if (remotePort_out) *remotePort_out = sb.ports[0].remotePort;
    if (remoteIP_out) memcpy(remoteIP_out, sb.ports[0].remoteIP, 4);
}

/* ---- New test implementations ---- */

static void test_idle_timeout(void)
{
    /* Init FOSSIL, wait for TCP connection, then do NOTHING.
     * After the idle timeout (30s), VMODEM should disconnect.
     * Verify DCD drops and port returns to PORT_LISTEN (mode=1). */
    unsigned char mode;

    fossil_init_answer(0);
    log_info("IDLE_TIMEOUT: waiting for connection...");
    write_ready_flag("IDLE_WAITING_DCD");

    if (!wait_for_dcd(0, 120)) {
        log_result("IDLE_DCD", 0, "(timeout waiting for connection)");
        fossil_deinit(0);
        return;
    }
    log_result("IDLE_DCD", 1, "(connected)");

    /* Now do nothing — just idle poll for up to 45 seconds.
     * The 30s idle timeout should fire and disconnect us. */
    log_info("IDLE_TIMEOUT: idling for 45s, expecting disconnect...");
    if (wait_for_no_dcd(0, 45)) {
        log_result("IDLE_DISCONNECT", 1, "(DCD dropped after idle)");
    } else {
        log_result("IDLE_DISCONNECT", 0, "(still connected after 45s)");
        fossil_deinit(0);
        return;
    }

    /* Check port mode via MUX_STATUS — should be PORT_LISTEN (1) */
    mux_get_status(&mode, NULL, NULL);
    log_result("IDLE_PORT_LISTEN", mode == 1,
               mode == 1 ? "(port returned to LISTEN)" : "(port NOT in LISTEN)");

    fossil_deinit(0);
}

static void test_dtr_disconnect(void)
{
    /* Init FOSSIL, wait for TCP connection, drop DTR (AH=06h AL=00h).
     * This triggers pending_close → disconnect.
     * Verify port returns to PORT_LISTEN. */
    unsigned char mode;

    fossil_init_answer(0);
    log_info("DTR_DISC: waiting for connection...");
    write_ready_flag("DTR_WAITING_DCD");

    if (!wait_for_dcd(0, 120)) {
        log_result("DTR_DCD", 0, "(timeout waiting for connection)");
        fossil_deinit(0);
        return;
    }
    log_result("DTR_DCD", 1, "(connected)");

    /* Small delay to let connection stabilise */
    {
        unsigned long t = get_tick() + 36UL; /* ~2 seconds */
        while (get_tick() < t) dos_idle();
    }

    /* Drop DTR (AH=06h AL=00h) — should trigger disconnect */
    log_info("DTR_DISC: dropping DTR...");
    fossil_call(0x06, 0, 0);  /* AH=06h, DX=0 (COM1), AL=00h (lower DTR) */

    /* pending_close is processed on next poll cycle (INT 28h).
     * Poll via AH=03h (status) to drive mTCP polling from INT 14h context. */
    {
        unsigned long deadline = get_tick() + 10UL * 18UL; /* 10 seconds */
        while (get_tick() < deadline) {
            fossil_status(0);  /* drives poll_on_priv_stack → pending_close */
            mux_get_status(&mode, NULL, NULL);
            if (mode == 1) break;  /* PORT_LISTEN */
            dos_idle();
        }
    }

    /* Check port mode — should be PORT_LISTEN (1) since listenSock still exists */
    mux_get_status(&mode, NULL, NULL);
    {
        char mbuf[40];
        sprintf(mbuf, "(mode=%u, expected 1)", (unsigned)mode);
        log_result("DTR_PORT_LISTEN", mode == 1, mbuf);
    }
    fossil_deinit(0);
}

static void test_eager_listen(void)
{
    /* With /E flag, VMODEM should accept connections WITHOUT FOSSIL init.
     * We do NOT call fossil_init() — just wait for mode=PORT_CONN.
     *
     * p->initialized is set by cmd_listen (/L:1:2323), so AH=03h
     * still goes through VMODEM's handler and drives mTCP polling. */
    unsigned char mode;
    unsigned long deadline;

    log_info("EAGER: NOT calling FOSSIL init, waiting for connection...");
    write_ready_flag("EAGER_WAITING");

    /* Poll MUX_STATUS for PORT_CONN (mode=2) on COM1.
     * Also call fossil_status to drive mTCP polling from INT 14h context. */
    deadline = get_tick() + 120UL * 18UL;
    while (get_tick() < deadline) {
        fossil_status(0);  /* drives poll_on_priv_stack if not busy */
        mux_get_status(&mode, NULL, NULL);
        if (mode == 2) break;
        dos_idle();
    }

    log_result("EAGER_CONN", mode == 2,
               mode == 2 ? "(connection accepted without FOSSIL init)"
                         : "(no connection detected)");
}

static void test_mux_port_status(void)
{
    /* Init FOSSIL, wait for TCP connection, then read MUX_STATUS.
     * Verify mode=CONN (2), remotePort>0, remoteIP!=0.0.0.0. */
    unsigned char mode, rip[4];
    unsigned short rport;

    fossil_init_answer(0);
    log_info("MUX_PORT: waiting for connection...");
    write_ready_flag("MUX_PORT_WAITING_DCD");

    if (!wait_for_dcd(0, 120)) {
        log_result("MUX_PORT_DCD", 0, "(timeout)");
        fossil_deinit(0);
        return;
    }
    log_result("MUX_PORT_DCD", 1, "(connected)");

    /* Small delay for status to populate */
    {
        unsigned long t = get_tick() + 18UL;
        while (get_tick() < t) dos_idle();
    }

    /* Read MUX_STATUS */
    mux_get_status(&mode, &rport, rip);

    log_result("MUX_PORT_MODE", mode == 2,
               mode == 2 ? "(mode=CONN)" : "(mode!=CONN)");
    log_result("MUX_PORT_RPORT", rport > 0,
               rport > 0 ? "(remotePort > 0)" : "(remotePort = 0)");
    {
        int ip_nonzero = (rip[0] | rip[1] | rip[2] | rip[3]) != 0;
        char ipbuf[20];
        sprintf(ipbuf, "(%u.%u.%u.%u)", rip[0], rip[1], rip[2], rip[3]);
        log_result("MUX_PORT_RIP", ip_nonzero, ipbuf);
    }

    /* Keep alive briefly so Python can verify, then clean up */
    {
        unsigned long t = get_tick() + 36UL;
        while (get_tick() < t) dos_idle();
    }

    fossil_deinit(0);
}

static void test_s0_register(void)
{
    /* Test S0 auto-answer register:
     *   Phase 1: Set S0=0 (no auto-answer), connect, verify no CONNECT after 15s.
     *   Phase 2: Send ATS0=1 to re-enable, verify CONNECT.
     *
     * AT commands are sent via FOSSIL TX (AH=01h) while in command mode
     * (no active connection). */
    unsigned short ax;

    ax = fossil_init(0);
    log_result("S0_INIT", ax == 0x1954, "(FOSSIL init)");

    /* Set S0=0 — disable auto-answer */
    log_info("S0: setting ATS0=0 (disable auto-answer)...");
    fossil_tx_string(0, "ATS0=0\r");
    /* Small delay for command to process */
    {
        unsigned long t = get_tick() + 18UL;
        while (get_tick() < t) dos_idle();
    }

    /* Signal Python to connect */
    write_ready_flag("S0_PHASE1_WAITING");

    /* Wait up to 20s — DCD should NOT go high (no auto-answer) */
    log_info("S0: waiting 20s, should NOT get DCD (S0=0)...");
    if (wait_for_dcd(0, 20)) {
        log_result("S0_NO_ANSWER", 0, "(DCD went high — auto-answered despite S0=0!)");
        fossil_deinit(0);
        return;
    }
    log_result("S0_NO_ANSWER", 1, "(no auto-answer with S0=0)");

    /* Now set S0=1 — enable auto-answer */
    log_info("S0: setting ATS0=1 (enable auto-answer)...");
    fossil_tx_string(0, "ATS0=1\r");

    /* Signal Python (it's still connected, should now get answered) */
    write_ready_flag("S0_PHASE2_WAITING");

    /* DCD should go high within ~15s (ring + answer) */
    if (wait_for_dcd(0, 20)) {
        log_result("S0_AUTO_ANSWER", 1, "(connected after S0=1)");
    } else {
        log_result("S0_AUTO_ANSWER", 0, "(no connection after S0=1)");
    }

    fossil_deinit(0);
}

static void test_hunt_full(void)
{
    /* Hunt group test: init FOSSIL on COM1 and COM2, fill both,
     * then the Python side connects a third time and expects rejection.
     * COMTEST just inits and echoes — Python verifies the 3rd rejection. */
    unsigned short ax;

    ax = fossil_init_answer(0);
    log_result("HUNTFULL_INIT_COM1", ax == 0x1954, "(FOSSIL init COM1)");
    ax = fossil_init_answer(1);
    log_result("HUNTFULL_INIT_COM2", ax == 0x1954, "(FOSSIL init COM2)");

    log_info("HUNTFULL: waiting for first connection on COM1...");
    write_ready_flag("HUNTFULL_WAITING_DCD1");

    if (!wait_for_dcd(0, 120)) {
        log_result("HUNTFULL_DCD1", 0, "(timeout)");
        fossil_deinit(0); fossil_deinit(1);
        return;
    }
    log_result("HUNTFULL_DCD1", 1, "(COM1 connected)");

    log_info("HUNTFULL: waiting for second connection on COM2...");
    write_ready_flag("HUNTFULL_WAITING_DCD2");

    if (!wait_for_dcd(1, 120)) {
        log_result("HUNTFULL_DCD2", 0, "(timeout)");
        fossil_deinit(0); fossil_deinit(1);
        return;
    }
    log_result("HUNTFULL_DCD2", 1, "(COM2 connected)");

    /* Signal Python to try a 3rd connection (should be rejected) */
    write_ready_flag("HUNTFULL_BOTH_BUSY");

    /* Keep connections alive for 15 seconds while Python tests 3rd */
    {
        unsigned long deadline = get_tick() + 15UL * 18UL;
        while (get_tick() < deadline) {
            fossil_status(0);
            fossil_status(1);
            dos_idle();
        }
    }

    fossil_deinit(0);
    fossil_deinit(1);
}

static void test_reconnect(void)
{
    /* Init FOSSIL, wait for connect, exchange data, wait for disconnect,
     * then wait for a SECOND connection on the same port. */
    unsigned short ax;
    unsigned long deadline;

    ax = fossil_init_answer(0);
    log_result("RECONN_INIT", ax == 0x1954, "(FOSSIL init)");

    /* First connection */
    log_info("RECONN: waiting for first connection...");
    write_ready_flag("RECONN_WAITING_DCD1");

    if (!wait_for_dcd(0, 120)) {
        log_result("RECONN_DCD1", 0, "(timeout)");
        fossil_deinit(0);
        return;
    }
    log_result("RECONN_DCD1", 1, "(first connection)");

    /* Echo data until DCD drops or idle timeout.
     * Use fossil_status() instead of dos_idle() — AH=03h drives mTCP
     * polling AND yields properly under DOSBox-X emulation.
     * MUST check DCD: when remote disconnects, VMODEM sends "NO CARRIER"
     * text which comtest would echo back as AT commands, creating an
     * infinite echo loop that prevents the deadline from expiring. */
    deadline = get_tick() + 5UL * 18UL;
    while (get_tick() < deadline) {
        unsigned short st;
        int ch;
        st = fossil_status(0);
        if (!(st & STATUS_DCD)) break;  /* DCD dropped — stop echoing */
        ch = fossil_rx(0);
        if (ch >= 0) {
            fossil_tx(0, (unsigned char)ch);
            deadline = get_tick() + 3UL * 18UL;
        }
    }

    /* Wait for disconnect — idle timeout is 30s + echo period (~5s) */
    log_info("RECONN: waiting for first disconnect...");
    write_ready_flag("RECONN_ECHO_DONE");
    if (!wait_for_no_dcd(0, 45)) {
        log_result("RECONN_DISC1", 0, "(still connected)");
        fossil_deinit(0);
        return;
    }
    log_result("RECONN_DISC1", 1, "(first disconnect)");

    /* Signal ready for second connection */
    write_ready_flag("RECONN_WAITING_DCD2");

    /* Wait for second connection */
    if (!wait_for_dcd(0, 120)) {
        log_result("RECONN_DCD2", 0, "(timeout on second connection)");
        fossil_deinit(0);
        return;
    }
    log_result("RECONN_DCD2", 1, "(second connection)");

    /* Echo data again — check DCD to avoid AT echo storm on disconnect */
    deadline = get_tick() + 5UL * 18UL;
    while (get_tick() < deadline) {
        unsigned short st;
        int ch;
        st = fossil_status(0);
        if (!(st & STATUS_DCD)) break;
        ch = fossil_rx(0);
        if (ch >= 0) {
            fossil_tx(0, (unsigned char)ch);
            deadline = get_tick() + 3UL * 18UL;
        }
    }

    /* Wait for second disconnect */
    if (wait_for_no_dcd(0, 30)) {
        log_result("RECONN_DISC2", 1, "(second disconnect)");
    } else {
        log_result("RECONN_DISC2", 0, "(still connected)");
    }

    fossil_deinit(0);
}

static void test_hunt_ring_timeout(void)
{
    /* Hunt mode with /E: connect 2 clients, let ring timeout fire
     * (host doesn't answer — no FOSSIL init).  After timeout, both
     * ports should return to PORT_LISTEN so new connections are accepted.
     * Verifies the ring timeout handler correctly handles hunt group ports. */
    unsigned char mode;
    unsigned long deadline;

    log_info("HUNT_RT: NOT calling FOSSIL init, waiting for connections...");
    write_ready_flag("HUNT_RT_WAITING");

    /* Wait for COM1 to accept first connection (mode=2) */
    deadline = get_tick() + 120UL * 18UL;
    while (get_tick() < deadline) {
        fossil_status(0);  /* drive mTCP polling */
        mux_get_status(&mode, NULL, NULL);
        if (mode == 2) break;
        dos_idle();
    }
    log_result("HUNT_RT_CONN1", mode == 2, "(first connection on COM1)");

    if (mode != 2) return;

    /* Signal Python to connect second client */
    write_ready_flag("HUNT_RT_CONN1_OK");

    /* Wait for COM2 to accept second connection */
    {
        unsigned char mode2;
        StatusBlock sb;
        union REGS r;
        struct SREGS sr;

        deadline = get_tick() + 120UL * 18UL;
        while (get_tick() < deadline) {
            fossil_status(0);
            memset(&sb, 0, sizeof(sb));
            segread(&sr);
            sr.es = FP_SEG(&sb);
            r.h.ah = MUX_ID;
            r.h.al = MUX_STATUS;
            r.x.bx = FP_OFF(&sb);
            int86x(0x2F, &r, &r, &sr);
            mode2 = sb.ports[1].mode;
            if (mode2 == 2) break;
            dos_idle();
        }
        log_result("HUNT_RT_CONN2", mode2 == 2, "(second connection on COM2)");
        if (mode2 != 2) return;
    }

    /* Now wait for ring timeout (~60 seconds: 10 rings * 6s interval).
     * Neither port has FOSSIL init, so no one answers.
     * After timeout, both ports should return to PORT_LISTEN. */
    log_info("HUNT_RT: waiting for ring timeout (up to 90s)...");
    {
        StatusBlock sb;
        union REGS r;
        struct SREGS sr;
        unsigned char m1, m2;

        deadline = get_tick() + 90UL * 18UL;
        while (get_tick() < deadline) {
            fossil_status(0);
            memset(&sb, 0, sizeof(sb));
            segread(&sr);
            sr.es = FP_SEG(&sb);
            r.h.ah = MUX_ID;
            r.h.al = MUX_STATUS;
            r.x.bx = FP_OFF(&sb);
            int86x(0x2F, &r, &r, &sr);
            m1 = sb.ports[0].mode;
            m2 = sb.ports[1].mode;
            /* Both ports should return to LISTEN after ring timeout */
            if (m1 == 1 && m2 == 1) break;
            dos_idle();
        }

        {
            char mbuf[60];
            sprintf(mbuf, "(COM1 mode=%u, COM2 mode=%u, expected both=1)",
                    (unsigned)m1, (unsigned)m2);
            log_result("HUNT_RT_RELISTEN", m1 == 1 && m2 == 1, mbuf);
        }
    }

    /* Signal Python that ring timeout test is complete */
    write_ready_flag("HUNT_RT_DONE");

    /* Wait briefly then verify ports can accept NEW connections */
    {
        unsigned long t = get_tick() + 36UL;
        while (get_tick() < t) { fossil_status(0); dos_idle(); }
    }
}

/* -----------------------------------------------------------------------
 * test_dns_resolve — DNS hostname resolution via gethostbyname()
 *
 * Usage: COMTEST DNS_RESOLVE [hostname]
 * Resolves a hostname and logs the IP address.
 * Default hostname: one.one.one.one (Cloudflare, A records 1.1.1.1, 1.0.0.1)
 * ----------------------------------------------------------------------- */

static void test_dns_resolve(const char *hostname)
{
    struct hostent *he;
    unsigned char *ip;

    if (vsock_init() != 0) {
        log_result("DNS_INIT", 0, "(VMODEM not loaded)");
        write_ready_flag("DNS_FAIL");
        return;
    }
    log_result("DNS_INIT", 1, "(VMODEM present)");

    log_info("DNS_RESOLVE: resolving...");

    he = gethostbyname(hostname);
    if (he == (struct hostent *)0) {
        log_result("DNS_RESOLVE", 0, "(gethostbyname returned NULL)");
        write_ready_flag("DNS_FAIL");
        return;
    }

    if (he->h_length != 4 || he->h_addr_list[0] == (char *)0) {
        log_result("DNS_RESOLVE", 0, "(bad hostent)");
        write_ready_flag("DNS_FAIL");
        return;
    }

    ip = (unsigned char *)he->h_addr;
    {
        char detail[80];
        sprintf(detail, "(host=%s ip=%u.%u.%u.%u)",
                hostname, ip[0], ip[1], ip[2], ip[3]);
        log_result("DNS_RESOLVE", 1, detail);
    }

    /* Verify resolved IP is not 0.0.0.0 */
    {
        int nonzero = (ip[0] | ip[1] | ip[2] | ip[3]) != 0;
        log_result("DNS_NONZERO", nonzero,
                   nonzero ? "(valid IP)" : "(got 0.0.0.0)");
    }

    write_ready_flag("DNS_PASS");
}

/* -----------------------------------------------------------------------
 * test_tcp_out — outgoing TCP connection via BSD socket API (vsocket.lib)
 *
 * Usage: COMTEST TCP_OUT <ip0> <ip1> <ip2> <ip3> <port>
 * Connects to the given IP:port, sends HELLO_FROM_DOS, receives response.
 * ----------------------------------------------------------------------- */

static void test_tcp_out(unsigned char ip0, unsigned char ip1,
                         unsigned char ip2, unsigned char ip3,
                         unsigned short port)
{
    int sock;
    int n;
    struct sockaddr_in addr;
    static unsigned char recvbuf[256];
    int recv_total = 0;
    unsigned long deadline;

    if (vsock_init() != 0) {
        log_result("TCPOUT_ALLOC", 0, "(VMODEM not loaded)");
        return;
    }

    log_info("TCP_OUT: allocating socket...");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    log_result("TCPOUT_ALLOC", sock >= 0,
               sock >= 0 ? "(got socket)" : "(alloc failed)");
    if (sock < 0) return;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    {
        unsigned char *p = (unsigned char *)&addr.sin_addr.s_addr;
        p[0] = ip0; p[1] = ip1; p[2] = ip2; p[3] = ip3;
    }

    log_info("TCP_OUT: connecting...");
    n = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    log_result("TCPOUT_ESTABLISHED", n == 0,
               n == 0 ? "(connected)" : "(timeout/error)");
    if (n != 0) { closesocket(sock); return; }

    /* Send greeting */
    {
        const char *msg = "HELLO_FROM_DOS\n";
        n = send(sock, msg, (int)strlen(msg), 0);
    }
    log_result("TCPOUT_SEND", n > 0, n > 0 ? "(sent)" : "(send failed)");

    vsock_poll();

    /* Receive response (10 second timeout). */
    deadline = get_tick() + 182UL;
    while (get_tick() < deadline) {
        dos_idle();
        n = recv(sock, recvbuf + recv_total,
                 (int)(sizeof(recvbuf) - 1 - recv_total), 0);
        if (n > 0) {
            recv_total += n;
            recvbuf[recv_total] = '\0';
            if (strstr((char *)recvbuf, "HELLO_FROM_HOST") != NULL)
                break;
        }
    }
    log_result("TCPOUT_RECV", recv_total > 0 &&
               strstr((char *)recvbuf, "HELLO_FROM_HOST") != NULL,
               recv_total > 0 ? "(data received)" : "(no data)");

    closesocket(sock);
    log_result("TCPOUT_CLOSE", 1, "(closed)");

    if (recv_total > 0 && strstr((char *)recvbuf, "HELLO_FROM_HOST") != NULL)
        write_ready_flag("TCPOUT_PASS");
    else
        write_ready_flag("TCPOUT_FAIL");
}

/* -----------------------------------------------------------------------
 * test_relay — bidirectional relay: FOSSIL (incoming) <-> MUX (outgoing)
 *
 * Flow:
 *   1. Init FOSSIL on COM1, wait for Python client to connect (DCD high)
 *   2. MUX_SOCK_ALLOC + CONNECT to Python server at IP:port
 *   3. Bidirectional relay loop:
 *      - FOSSIL RX -> MUX send  (Python client -> Python server)
 *      - MUX recv -> FOSSIL TX  (Python server -> Python client)
 *   4. Stop after both directions have relayed data (+2s flush)
 *   5. Close both connections
 * --------------------------------------------------------------------- */
static void test_relay(unsigned char ip0, unsigned char ip1,
                       unsigned char ip2, unsigned char ip3,
                       unsigned short port)
{
    int sock;
    int n;
    struct sockaddr_in addr;
    unsigned long deadline, done_tick;
    static unsigned char relaybuf[256];
    int f2m_total = 0;  /* fossil-to-socket bytes relayed */
    int m2f_total = 0;  /* socket-to-fossil bytes relayed */

    /* Step 1: Init FOSSIL on COM1 (port 0, matches /L:1:2323) */
    fossil_init_answer(0);
    log_info("RELAY: waiting for incoming connection on COM1...");
    write_ready_flag("RELAY_WAITING_DCD");

    if (!wait_for_dcd(0, 120)) {
        log_result("RELAY_DCD", 0, "(timeout)");
        fossil_deinit(0);
        write_ready_flag("RELAY_FAIL");
        return;
    }
    log_result("RELAY_DCD", 1, "(connected)");

    /* Step 2: Allocate socket and connect outgoing */
    if (vsock_init() != 0) {
        log_result("RELAY_ALLOC", 0, "(VMODEM not loaded)");
        fossil_deinit(0);
        write_ready_flag("RELAY_FAIL");
        return;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    log_result("RELAY_ALLOC", sock >= 0,
               sock >= 0 ? "(got socket)" : "(alloc failed)");
    if (sock < 0) {
        fossil_deinit(0);
        write_ready_flag("RELAY_FAIL");
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    {
        unsigned char *p = (unsigned char *)&addr.sin_addr.s_addr;
        p[0] = ip0; p[1] = ip1; p[2] = ip2; p[3] = ip3;
    }

    n = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    log_result("RELAY_ESTABLISHED", n == 0,
               n == 0 ? "(connected)" : "(timeout/error)");
    if (n != 0) {
        closesocket(sock);
        fossil_deinit(0);
        write_ready_flag("RELAY_FAIL");
        return;
    }

    /* Purge FOSSIL RX to clear RING/CONNECT modem responses so they
     * don't get relayed and trigger done_tick prematurely. */
    fossil_call(FOSSIL_PURGE_IN, 0, 0);

    /* Step 3: Bidirectional relay loop (30s max) */
    deadline = get_tick() + 546UL;
    done_tick = 0;
    while (get_tick() < deadline) {
        unsigned short fst;

        dos_idle();
        fst = fossil_status(0);  /* drives mTCP polling */

        /* FOSSIL RX -> socket send (batch available bytes) */
        {
            int count = 0;
            while (count < (int)sizeof(relaybuf) && (fst & STATUS_RDA)) {
                int ch = fossil_rx(0);
                if (ch < 0) break;
                relaybuf[count++] = (unsigned char)ch;
                fst = fossil_status(0);
            }
            if (count > 0) {
                n = send(sock, relaybuf, count, 0);
                if (n > 0) f2m_total += n;
            }
        }

        /* Socket recv -> FOSSIL TX */
        n = recv(sock, relaybuf, (int)sizeof(relaybuf), 0);
        if (n > 0) {
            int i;
            for (i = 0; i < n; i++)
                fossil_tx(0, relaybuf[i]);
            m2f_total += n;
        }

        /* Once both directions have data, relay 2 more seconds then stop */
        if (f2m_total > 0 && m2f_total > 0 && done_tick == 0)
            done_tick = get_tick() + 36UL;
        if (done_tick != 0 && get_tick() >= done_tick)
            break;
    }

    /* Flush FOSSIL TX buffer */
    fossil_call(FOSSIL_FLUSH_OUT, 0, 0);
    {
        unsigned long flush_end = get_tick() + 36UL;
        while (get_tick() < flush_end)
            fossil_status(0);
    }

    {
        char detail[64];
        sprintf(detail, "(f2m=%d m2f=%d)", f2m_total, m2f_total);
        log_result("RELAY_F2M", f2m_total > 0, detail);
        log_result("RELAY_M2F", m2f_total > 0, detail);
    }

    /* Step 4: Close */
    closesocket(sock);
    fossil_deinit(0);
    log_result("RELAY_CLOSE", 1, "(done)");

    if (f2m_total > 0 && m2f_total > 0)
        write_ready_flag("RELAY_PASS");
    else
        write_ready_flag("RELAY_FAIL");
}

/* ---- Main ---- */

int main(int argc, char *argv[])
{
    const char *test_name;

    if (argc < 2) {
        printf("Usage: COMTEST <test_name> [args...]\n");
        printf("Tests: FOSSIL_INIT FOSSIL_STATUS MUX_STATUS ECHO\n");
        printf("       FULL_CYCLE SEND_TEXT HUNT_GROUP\n");
        printf("       IDLE_TIMEOUT DTR_DISCONNECT EAGER_LISTEN\n");
        printf("       MUX_PORT_STATUS S0_REGISTER HUNT_FULL RECONNECT\n");
        printf("       HUNT_RING_TIMEOUT\n");
        return 1;
    }

    logfile = fopen("COMTEST.LOG", "w");
    if (!logfile) {
        printf("ERROR: cannot create COMTEST.LOG\n");
        return 1;
    }

    test_name = argv[1];

    /* Convert to uppercase for comparison */
    {
        char upper[32];
        int i;
        for (i = 0; i < 31 && test_name[i]; i++)
            upper[i] = (test_name[i] >= 'a' && test_name[i] <= 'z')
                      ? test_name[i] - 32 : test_name[i];
        upper[i] = '\0';

        fprintf(logfile, "TEST: %s\n", upper);
        fflush(logfile);

        if (strcmp(upper, "FOSSIL_INIT") == 0)
            test_fossil_init();
        else if (strcmp(upper, "FOSSIL_STATUS") == 0)
            test_fossil_status();
        else if (strcmp(upper, "MUX_STATUS") == 0)
            test_mux_status();
        else if (strcmp(upper, "ECHO") == 0)
            test_echo();
        else if (strcmp(upper, "FULL_CYCLE") == 0)
            test_full_cycle();
        else if (strcmp(upper, "SEND_TEXT") == 0)
            test_send_text(argc > 2 ? argv[2] : "TEST_DATA");
        else if (strcmp(upper, "HUNT_GROUP") == 0)
            test_hunt_group();
        else if (strcmp(upper, "IDLE_TIMEOUT") == 0)
            test_idle_timeout();
        else if (strcmp(upper, "DTR_DISCONNECT") == 0)
            test_dtr_disconnect();
        else if (strcmp(upper, "EAGER_LISTEN") == 0)
            test_eager_listen();
        else if (strcmp(upper, "MUX_PORT_STATUS") == 0)
            test_mux_port_status();
        else if (strcmp(upper, "S0_REGISTER") == 0)
            test_s0_register();
        else if (strcmp(upper, "HUNT_FULL") == 0)
            test_hunt_full();
        else if (strcmp(upper, "RECONNECT") == 0)
            test_reconnect();
        else if (strcmp(upper, "HUNT_RING_TIMEOUT") == 0)
            test_hunt_ring_timeout();
        else if (strcmp(upper, "TCP_OUT") == 0) {
            unsigned char ip0 = argc > 2 ? (unsigned char)atoi(argv[2]) : 10;
            unsigned char ip1 = argc > 3 ? (unsigned char)atoi(argv[3]) : 0;
            unsigned char ip2 = argc > 4 ? (unsigned char)atoi(argv[4]) : 2;
            unsigned char ip3 = argc > 5 ? (unsigned char)atoi(argv[5]) : 2;
            unsigned short port = argc > 6 ? (unsigned short)atoi(argv[6]) : 9999;
            test_tcp_out(ip0, ip1, ip2, ip3, port);
        }
        else if (strcmp(upper, "RELAY") == 0) {
            unsigned char ip0 = argc > 2 ? (unsigned char)atoi(argv[2]) : 10;
            unsigned char ip1 = argc > 3 ? (unsigned char)atoi(argv[3]) : 0;
            unsigned char ip2 = argc > 4 ? (unsigned char)atoi(argv[4]) : 2;
            unsigned char ip3 = argc > 5 ? (unsigned char)atoi(argv[5]) : 2;
            unsigned short port = argc > 6 ? (unsigned short)atoi(argv[6]) : 9998;
            test_relay(ip0, ip1, ip2, ip3, port);
        }
        else if (strcmp(upper, "DNS_RESOLVE") == 0) {
            const char *host = argc > 2 ? argv[2] : "one.one.one.one";
            test_dns_resolve(host);
        }
        else {
            printf("Unknown test: %s\n", upper);
            fprintf(logfile, "FAIL: UNKNOWN_TEST %s\n", upper);
        }
    }

    fprintf(logfile, "SUMMARY: %d passed, %d failed\n", pass_count, fail_count);
    fflush(logfile);
    fclose(logfile);

    printf("\nResults: %d passed, %d failed\n", pass_count, fail_count);
    return fail_count > 0 ? 1 : 0;
}
