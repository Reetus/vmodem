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

/* MUX defines */
#define MUX_ID           0xC3
#define MUX_INSTALL_CHK  0x00
#define MUX_STATUS       0x04
#define MUX_DISCONNECT   0x03

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
    FILE *f = fopen("COMTEST.RDY", "w");
    if (f) {
        fprintf(f, "%s\n", marker);
        fclose(f);
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

    fossil_init(0);
    log_info("ECHO: waiting for DCD (connection)...");
    write_ready_flag("ECHO_WAITING_DCD");

    if (!wait_for_dcd(0, 120)) {
        log_result("ECHO_DCD", 0, "(timeout waiting for connection)");
        fossil_deinit(0);
        return;
    }
    log_result("ECHO_DCD", 1, "(connection detected)");

    /* Read data for up to 10 seconds */
    log_info("ECHO: reading data...");
    deadline = get_tick() + 10UL * 18UL;
    while (get_tick() < deadline) {
        int ch = fossil_rx(0);
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
    ax = fossil_init(0);
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
        int ch = fossil_rx(0);
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
    fossil_init(0);
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
    ax = fossil_init(0);
    log_result("HUNT_INIT_COM1", ax == 0x1954, "(FOSSIL init COM1)");

    ax = fossil_init(1);
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
     * to verify port isolation (each port gets different data). */
    log_info("HUNT: echoing data on both ports...");
    deadline = get_tick() + 10UL * 18UL;
    while (get_tick() < deadline) {
        int ch;

        /* Echo on COM1 */
        ch = fossil_rx(0);
        if (ch >= 0) {
            if (len1 < 63) buf1[len1++] = (char)ch;
            fossil_tx(0, (unsigned char)ch);
            got1 = 1;
            deadline = get_tick() + 3UL * 18UL;
        }

        /* Echo on COM2 */
        ch = fossil_rx(1);
        if (ch >= 0) {
            if (len2 < 63) buf2[len2++] = (char)ch;
            fossil_tx(1, (unsigned char)ch);
            got2 = 1;
            deadline = get_tick() + 3UL * 18UL;
        }

        dos_idle();
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

/* ---- Main ---- */

int main(int argc, char *argv[])
{
    const char *test_name;

    if (argc < 2) {
        printf("Usage: COMTEST <test_name> [args...]\n");
        printf("Tests: FOSSIL_INIT FOSSIL_STATUS MUX_STATUS ECHO\n");
        printf("       FULL_CYCLE SEND_TEXT HUNT_GROUP\n");
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
