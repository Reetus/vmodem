/*
 * vmodtest.c - VMODEM COM port test utility
 *
 * Provides an INT 14h echo server on COM1 for automated host-side testing.
 * All COM port I/O goes through INT 14h so VMODEM intercepts it.
 *
 * Usage:
 *   VMODTEST /ECHO   - echo everything received on COM1 back to sender,
 *                      prefixed with "OK:" so the host can verify both
 *                      directions.  Exits when "QUIT\r\n" is received or
 *                      after 60 seconds with no connection.
 *   VMODTEST /STATUS - print VMODEM port status via INT 2Fh (same as
 *                      VMODCTL /S but usable from within a test autoexec
 *                      to confirm VMODEM loaded correctly).
 *
 * INT 14h calling convention:
 *   AH=00h  init port (AL = baud/parity config, ignored by VMODEM)
 *   AH=01h  send byte (AL = byte)
 *   AH=02h  recv byte; returns AH=LSR, AL=byte (AH bit7=timeout/no data)
 *   AH=03h  status;  returns AH=LSR, AL=MSR (MSR bit7=DCD)
 *
 * Compile with: wpp vmodtest -0 -ms -fo=.obj -zp2 -zpw -ei -s -we
 */

#include <stdio.h>
#include <string.h>
#include <dos.h>
#include <i86.h>
#include <conio.h>

#define COM1 0
#define MUX_ID          0xC3
#define MUX_INSTALL_CHK 0x00
#define MUX_STATUS      0x04
#define MUX_POLL        0x05
#define STATUS_BLOCK_MAGIC 0xA55A

/* ---- BIOS timer ---- */

/* BIOS tick counter at 0040:006C, incremented at ~18.2 Hz */
static unsigned long bios_ticks(void)
{
    return *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
}

/* ---- INT 14h helpers ---- */

static void com_init(int port)
{
    union REGS r;

    /* FOSSIL init (AH=04h) — returns AX=1954h if FOSSIL present */
    r.h.ah = 0x04;
    r.w.dx = (unsigned short)port;
    r.w.bx = 0;  /* no ^C flag */
    int86(0x14, &r, &r);
    if (r.w.ax == 0x1954)
        printf("FOSSIL driver detected (rev %d, max func 0x%02X)\n",
               r.h.bh, r.h.bl);
    else
        printf("Warning: No FOSSIL driver (AX=0x%04X)\n", r.w.ax);
}

/* Returns byte received, or -1 if no data (timeout bit set) */
static int com_recv(int port)
{
    union REGS r;
    r.h.ah = 0x02;
    r.w.dx = (unsigned short)port;
    int86(0x14, &r, &r);
    if (r.h.ah & 0x80) return -1;
    return (unsigned char)r.h.al;
}

static void com_send(int port, unsigned char c)
{
    union REGS r;
    r.h.ah = 0x01;
    r.h.al = c;
    r.w.dx = (unsigned short)port;
    int86(0x14, &r, &r);
}

static void com_send_str(int port, const char *s)
{
    while (*s)
        com_send(port, (unsigned char)*s++);
}

/* Returns non-zero if DCD (Data Carrier Detect) is set — i.e. connected */
static int com_dcd(int port)
{
    union REGS r;
    r.h.ah = 0x03;
    r.w.dx = (unsigned short)port;
    int86(0x14, &r, &r);
    return (r.h.al & 0x80) ? 1 : 0;  /* MSR bit 7 = DCD */
}

/* ---- Status block matching vmodem.h ---- */

typedef struct {
    unsigned short magic;
    unsigned long  poll_count;
    unsigned long  pkt_count;
    unsigned short arp_count;
    unsigned short ip_count;
    unsigned long  arp_req_recv;
    unsigned long  arp_rep_sent;
    unsigned long  arp_req_sent;
    unsigned long  arp_rep_recv;
    unsigned char  buf_low_free;
    unsigned char  buf_first;
    unsigned char  buf_next;
    unsigned char  _pad0;
    unsigned long  pkts_recv;
    unsigned long  pkts_sent;
    unsigned long  pkts_send_errs;
    unsigned long  pkts_dropped;
    unsigned long  unhandled_count;
    unsigned short first_unhandled_et;
    unsigned short tcp_pend_sent;
    unsigned short tcp_pend_outgoing;
    unsigned char  active_sockets;
    unsigned char  poll_phase;
    struct {
        unsigned char  mode;
        unsigned char  initialized;
        unsigned short localPort;
        unsigned short remotePort;
        unsigned char  remoteIP[4];
        unsigned short rxCount;
    } ports[4];
} StatusBlock;

static const char *mode_name(unsigned char m)
{
    switch (m) {
    case 0: return "DISC";
    case 1: return "LISTEN";
    case 2: return "CONN";
    default: return "?";
    }
}

/* ---- Commands ---- */

static void cmd_status(void)
{
    union REGS  r;
    union REGS  or2;
    struct SREGS sr;
    StatusBlock sb;
    int i;

    memset(&sb, 0, sizeof(sb));

    /* FOSSIL signature check (same method BBS software uses) */
    {
        void (__interrupt __far *vec14)(void) = _dos_getvect(0x14);
        unsigned char __far *bptr = (unsigned char __far *)vec14;
        unsigned short sig = *(unsigned short __far *)(bptr + 6);

        printf("FOSSIL check: INT 14h -> %04X:%04X\n",
               FP_SEG(vec14), FP_OFF(vec14));
        printf("  Bytes: %02X %02X %02X %02X %02X %02X [%02X %02X] %02X\n",
               bptr[0], bptr[1], bptr[2], bptr[3], bptr[4], bptr[5],
               bptr[6], bptr[7], bptr[8]);
        printf("  Sig at +6: 0x%04X %s\n",
               sig, (sig == 0x1954) ? "FOSSIL OK" : "NOT FOSSIL");

        /* Try AH=04h init */
        r.h.ah = 0x04;
        r.w.dx = 0;
        r.w.bx = 0;
        int86(0x14, &r, &r);
        printf("  Init: AX=0x%04X BH=%d BL=0x%02X\n",
               r.w.ax, r.h.bh, r.h.bl);
    }

    /* Call INT 2Fh MUX_INSTALL_CHK to detect VMODEM */
    r.h.ah = MUX_ID;
    r.h.al = MUX_INSTALL_CHK;
    int86(0x2F, &r, &r);
    if (r.h.al != 0xFF) {
        printf("VMODEM not installed.\n");
        return;
    }

    /* Call INT 2Fh MUX_STATUS: ES:BX -> StatusBlock buffer */
    segread(&sr);
    sr.es  = FP_SEG(&sb);
    r.h.ah = MUX_ID;
    r.h.al = MUX_STATUS;
    r.w.bx = FP_OFF(&sb);
    int86x(0x2F, &r, &or2, &sr);

    if (sb.magic != STATUS_BLOCK_MAGIC) {
        printf("Bad status block magic.\n");
        return;
    }

    printf("VMODEM status (polls=%lu pkts=%lu arp=%u ip=%u)\n",
           sb.poll_count, sb.pkt_count, sb.arp_count, sb.ip_count);
    printf("  mTCP ARP: req_recv=%lu rep_sent=%lu req_sent=%lu rep_recv=%lu\n",
           sb.arp_req_recv, sb.arp_rep_sent, sb.arp_req_sent, sb.arp_rep_recv);
    printf("  Buffers: low_free=%u first=%u next=%u\n",
           (unsigned)sb.buf_low_free, (unsigned)sb.buf_first, (unsigned)sb.buf_next);
    printf("  PktDrv: recv=%lu sent=%lu send_errs=%lu dropped=%lu\n",
           sb.pkts_recv, sb.pkts_sent, sb.pkts_send_errs, sb.pkts_dropped);
    printf("  Unhandled: count=%lu first_et=0x%04X\n",
           sb.unhandled_count, sb.first_unhandled_et);
    printf("  TCP: Pending_Sent=%u Pending_Outgoing=%u ActiveSockets=%u\n",
           sb.tcp_pend_sent, sb.tcp_pend_outgoing, (unsigned)sb.active_sockets);
    for (i = 0; i < 4; i++) {
        if (!sb.ports[i].initialized) continue;
        printf("  COM%d: %-10s port=%u rx=%u",
               i + 1,
               mode_name(sb.ports[i].mode),
               sb.ports[i].localPort,
               sb.ports[i].rxCount);
        if (sb.ports[i].mode >= 2) {
            printf(" remote=%u.%u.%u.%u:%u",
                   sb.ports[i].remoteIP[0], sb.ports[i].remoteIP[1],
                   sb.ports[i].remoteIP[2], sb.ports[i].remoteIP[3],
                   sb.ports[i].remotePort);
        }
        printf("\n");
    }
    /* PIC diagnostics */
    {
        unsigned char imr = inp(0x21);
        printf("  PIC IMR: 0x%02X (IRQ3 %s)\n",
               (unsigned)imr,
               (imr & 0x08) ? "MASKED" : "unmasked");
    }

    /* NE2000 register diagnostics (I/O base 0x300) */
    {
        unsigned char cr, isr, cntr2, rsr, bnry, curr;
        void (__interrupt __far *irq3_vec)(void);

        /* Check INT 0x0B vector (IRQ 3) */
        irq3_vec = _dos_getvect(0x0B);
        printf("  INT 0Bh (IRQ3) vector: %04X:%04X\n",
               (unsigned)FP_SEG(irq3_vec), (unsigned)FP_OFF(irq3_vec));

        /* Read NE2000 registers (read CR first for diagnostics) */
        cr = inp(0x300);
        outp(0x300, 0x22);                 /* page 0, started, abort DMA */
        isr    = inp(0x307);  /* Interrupt Status Register */
        cntr2  = inp(0x30F);  /* CNTR2 (missed pkts) - NOT IMR (write-only) */
        rsr    = inp(0x30C);  /* Receive Status Register */
        bnry   = inp(0x303);  /* Boundary Pointer */
        /* Switch to page 1 to read CURR */
        outp(0x300, 0x62);                 /* page 1, started, abort DMA */
        curr = inp(0x307);    /* Current Page register */
        /* Back to page 0, clean state */
        outp(0x300, 0x22);
        printf("  NE2000: CR=0x%02X ISR=0x%02X CNTR2=%u RSR=0x%02X BNRY=0x%02X CURR=0x%02X\n",
               (unsigned)cr, (unsigned)isr, (unsigned)cntr2,
               (unsigned)rsr, (unsigned)bnry, (unsigned)curr);
        if (bnry != curr)
            printf("  NE2000: PACKETS WAITING (BNRY != CURR)\n");

        /* Write IMR directly and clear ISR */
        outp(0x300, 0x22);     /* page 0, started */
        outp(0x307, 0xFF);     /* clear all ISR bits */
        outp(0x30F, 0x1F);     /* IMR: enable PRX+PTX+RXE+TXE+OVW */
        printf("  NE2000: Wrote IMR=0x1F, ISR cleared\n");
    }

    fflush(stdout);
}

static void cmd_echo(void)
{
    char   rxbuf[64];
    int    rxlen = 0;
    int    b;
    unsigned long start_tick, last_dot, now;
    unsigned long timeout_ticks = 18UL * 120;  /* ~120 seconds at 18.2 Hz */

    com_init(COM1);

    printf("Waiting for connection on COM1...\n");
    fflush(stdout);

    start_tick = bios_ticks();
    last_dot   = start_tick;

    {
        unsigned long last_diag = start_tick;
        unsigned long iter = 0;
        unsigned long last_iter_diag = 0;
        while (!com_dcd(COM1)) {
            now = bios_ticks();
            iter++;

            /* Poll mTCP via VMODEM */
            {
                union REGS pr;
                pr.h.ah = MUX_ID;
                pr.h.al = MUX_POLL;
                int86(0x2F, &pr, &pr);
            }

            /* Write heartbeat every 10000 iterations with TCP diagnostics */
            if (iter - last_iter_diag >= 10000UL) {
                StatusBlock dsb;
                union REGS dr;
                union REGS dor;
                struct SREGS dsr;

                memset(&dsb, 0, sizeof(dsb));
                segread(&dsr);
                dsr.es = FP_SEG(&dsb);
                dr.h.ah = MUX_ID;
                dr.h.al = MUX_STATUS;
                dr.w.bx = FP_OFF(&dsb);
                int86x(0x2F, &dr, &dor, &dsr);

                {
                    FILE *df = fopen("C:\\NE_DIAG.TXT", "w");
                    if (df) {
                        fprintf(df, "iter=%lu t=%lu polls=%lu pkts=%lu\n",
                                iter, now - start_tick,
                                dsb.poll_count, dsb.pkt_count);
                        fprintf(df, "PS=%u PO=%u AS=%u PH=%u\n",
                                dsb.tcp_pend_sent, dsb.tcp_pend_outgoing,
                                (unsigned)dsb.active_sockets,
                                (unsigned)dsb.poll_phase);
                        fprintf(df, "send=%lu serr=%lu recv=%lu\n",
                                dsb.pkts_sent, dsb.pkts_send_errs,
                                dsb.pkts_recv);
                        fclose(df);
                    }
                }
                last_iter_diag = iter;
            }

            /* Print a dot every ~1 second */
            if (now - last_dot >= 18UL) {
                union REGS r;
                r.h.ah = 0x02;
                r.h.dl = '.';
                int86(0x21, &r, &r);
                last_dot = now;
            }

            if (now - start_tick > timeout_ticks) {
                FILE *tf = fopen("C:\\NE_DIAG.TXT", "w");
                if (tf) {
                    fprintf(tf, "TIMEOUT iter=%lu t=%lu\n",
                            iter, now - start_tick);
                    fclose(tf);
                }
                printf("\nTimeout waiting for connection.\n");
                fflush(stdout);
                return;
            }
        }
    }

    printf("\nConnected.  Echoing (send QUIT to exit)...\n");
    com_send_str(COM1, "VMODTEST READY\r\n");

    for (;;) {
        /* Poll mTCP so drivePackets() flushes TX data */
        {
            union REGS pr;
            pr.h.ah = MUX_ID;
            pr.h.al = MUX_POLL;
            int86(0x2F, &pr, &pr);
        }

        b = com_recv(COM1);
        if (b < 0) {
            /* No data — check if still connected */
            if (!com_dcd(COM1)) {
                printf("Disconnected.\n");
                break;
            }
            continue;
        }

        /* Echo byte back */
        com_send(COM1, (unsigned char)b);

        /* Accumulate into line buffer to detect "QUIT" */
        if (b == '\r' || b == '\n') {
            rxbuf[rxlen] = '\0';
            if (strncmp(rxbuf, "QUIT", 4) == 0) {
                com_send_str(COM1, "BYE\r\n");
                printf("QUIT received — exiting.\n");
                break;
            }
            rxlen = 0;
        } else {
            if (rxlen < (int)sizeof(rxbuf) - 1)
                rxbuf[rxlen++] = (char)b;
        }
    }
}

/* Returns full FOSSIL status AX (AH=LSR, AL=MSR) */
static unsigned short com_status(int port)
{
    union REGS r;
    r.h.ah = 0x03;
    r.w.dx = (unsigned short)port;
    int86(0x14, &r, &r);
    return r.w.ax;
}

static void com_dtr(int port, int raise)
{
    union REGS r;
    r.h.ah = 0x06;
    r.h.al = raise ? 0x01 : 0x00;
    r.w.dx = (unsigned short)port;
    int86(0x14, &r, &r);
}

static void poll_mtcp(void)
{
    union REGS r;
    r.h.ah = MUX_ID;
    r.h.al = MUX_POLL;
    int86(0x2F, &r, &r);
}

static void delay_ticks(unsigned long ticks)
{
    unsigned long start = bios_ticks();
    while (bios_ticks() - start < ticks) {
        poll_mtcp();
    }
}

static void dump_debuglog(void)
{
    union REGS r;
    struct SREGS sr;
    char dbgbuf[2048];
    unsigned short got, k;

    segread(&sr);
    sr.es = FP_SEG(dbgbuf);
    r.h.ah = MUX_ID;
    r.h.al = 0x06;  /* MUX_DEBUGLOG */
    r.w.bx = FP_OFF(dbgbuf);
    r.w.cx = sizeof(dbgbuf);
    int86x(0x2F, &r, &r, &sr);
    got = r.w.ax;

    printf("  Debug log (%u bytes): [", got);
    for (k = 0; k < got; k++) {
        unsigned char c = (unsigned char)dbgbuf[k];
        if (c >= 0x20 && c < 0x7F)
            putchar(c);
        else
            printf("\\x%02X", c);
    }
    printf("]\n");
}

static void cmd_hangup(void)
{
    unsigned short st;
    int pass;

    printf("\n=== HANGUP TEST ===\n");
    printf("Tests: FOSSIL init, wait for connect, +++, ATH, verify disconnect\n\n");

    /* Step 1: FOSSIL init */
    printf("[1] FOSSIL init (AH=04h)...\n");
    com_init(COM1);

    /* Step 2: Check initial status */
    st = com_status(COM1);
    printf("[2] Initial status: AH=0x%02X AL=0x%02X (DCD=%s)\n",
           (st >> 8) & 0xFF, st & 0xFF,
           (st & 0x80) ? "ON" : "off");

    /* Step 3: Wait for connection (DCD high) */
    printf("[3] Waiting for TCP connection (DCD)...\n");
    fflush(stdout);
    {
        unsigned long start = bios_ticks();
        unsigned long timeout = 18UL * 30;  /* 30 seconds */
        while (!com_dcd(COM1)) {
            poll_mtcp();
            if (bios_ticks() - start > timeout) {
                printf("    TIMEOUT - no connection after 30s\n");
                dump_debuglog();
                return;
            }
        }
    }

    st = com_status(COM1);
    printf("    Connected! Status: AH=0x%02X AL=0x%02X\n",
           (st >> 8) & 0xFF, st & 0xFF);

    /* Drain any pending RX data (CONNECT response etc.) */
    {
        int b, count = 0;
        while ((b = com_recv(COM1)) >= 0) count++;
        printf("    Drained %d RX bytes\n", count);
    }

    /* Step 4: Send some data to establish last_tx_tick */
    printf("[4] Sending test data 'HELLO'...\n");
    com_send_str(COM1, "HELLO\r\n");
    poll_mtcp();

    /* Step 5: Guard time silence (~1 second) */
    printf("[5] Guard time silence (1s)...\n");
    fflush(stdout);
    delay_ticks(20);  /* ~1.1 seconds */

    /* Step 6: Send +++ escape sequence */
    printf("[6] Sending +++ escape...\n");
    com_send(COM1, '+');
    com_send(COM1, '+');
    com_send(COM1, '+');

    /* Wait a moment for OK response */
    delay_ticks(5);

    /* Check if we got OK response */
    {
        char resp[32];
        int rlen = 0, b;
        while ((b = com_recv(COM1)) >= 0 && rlen < 30) {
            resp[rlen++] = (char)b;
        }
        resp[rlen] = '\0';
        printf("    Response (%d bytes): '", rlen);
        {
            int j;
            for (j = 0; j < rlen; j++) {
                if (resp[j] >= 0x20 && resp[j] < 0x7F)
                    putchar(resp[j]);
                else
                    printf("\\x%02X", (unsigned char)resp[j]);
            }
        }
        printf("'\n");

        if (rlen == 0) {
            printf("    WARNING: No response to +++ (not in command mode?)\n");
        }
    }

    st = com_status(COM1);
    printf("    Status after +++: AH=0x%02X AL=0x%02X (DCD=%s)\n",
           (st >> 8) & 0xFF, st & 0xFF,
           (st & 0x80) ? "ON" : "off");

    /* Step 7: Send ATH to hangup */
    printf("[7] Sending ATH0\\r...\n");
    com_send_str(COM1, "ATH0\r");
    delay_ticks(5);

    /* Read response */
    {
        char resp[64];
        int rlen = 0, b;
        while ((b = com_recv(COM1)) >= 0 && rlen < 60) {
            resp[rlen++] = (char)b;
        }
        resp[rlen] = '\0';
        printf("    Response (%d bytes): '", rlen);
        {
            int j;
            for (j = 0; j < rlen; j++) {
                if (resp[j] >= 0x20 && resp[j] < 0x7F)
                    putchar(resp[j]);
                else
                    printf("\\x%02X", (unsigned char)resp[j]);
            }
        }
        printf("'\n");
    }

    /* Step 8: Verify DCD is now low */
    poll_mtcp();
    st = com_status(COM1);
    pass = !(st & 0x80);
    printf("[8] Final status: AH=0x%02X AL=0x%02X (DCD=%s)\n",
           (st >> 8) & 0xFF, st & 0xFF,
           (st & 0x80) ? "ON" : "off");
    printf("    %s: DCD is %s after ATH\n",
           pass ? "PASS" : "FAIL",
           pass ? "LOW (disconnected)" : "still HIGH (connection NOT closed!)");

    /* Step 9: Also test DTR drop disconnect */
    if (pass) {
        printf("\n[9] Skipping DTR test (already disconnected).\n");
    } else {
        printf("\n[9] ATH failed. Trying DTR drop (AH=06h AL=00h)...\n");
        com_dtr(COM1, 0);  /* lower DTR */
        delay_ticks(5);
        poll_mtcp();

        st = com_status(COM1);
        pass = !(st & 0x80);
        printf("    Status after DTR drop: AH=0x%02X AL=0x%02X (DCD=%s)\n",
               (st >> 8) & 0xFF, st & 0xFF,
               (st & 0x80) ? "ON" : "off");
        printf("    %s: DTR drop %s\n",
               pass ? "PASS" : "FAIL",
               pass ? "disconnected" : "also FAILED");

        /* Raise DTR again for clean state */
        com_dtr(COM1, 1);
    }

    /* Dump debug log */
    printf("\n[10] Debug log:\n");
    dump_debuglog();
}

static void cmd_fosslog(void)
{
    union REGS r;
    struct SREGS sr;
    char dbgbuf[2048];
    unsigned short got;
    int found_f = 0;
    unsigned short k;

    /* Step 1: Drain the existing debug log */
    segread(&sr);
    sr.es = FP_SEG(dbgbuf);
    r.h.ah = MUX_ID;
    r.h.al = 0x06;  /* MUX_DEBUGLOG */
    r.w.bx = FP_OFF(dbgbuf);
    r.w.cx = sizeof(dbgbuf);
    int86x(0x2F, &r, &r, &sr);
    printf("Drained %u bytes from old log.\n", r.w.ax);

    /* Step 2: Send FOSSIL AH=04h (init) on COM1 */
    printf("Sending FOSSIL AH=04h init on COM1...\n");
    r.h.ah = 0x04;
    r.w.dx = 0;  /* COM1 */
    r.w.bx = 0;
    int86(0x14, &r, &r);
    printf("  AH=04h returned AX=0x%04X (expect 0x1954)\n", r.w.ax);

    /* Step 3: Send FOSSIL AH=03h (status) on COM1 */
    printf("Sending FOSSIL AH=03h status on COM1...\n");
    r.h.ah = 0x03;
    r.w.dx = 0;
    int86(0x14, &r, &r);
    printf("  AH=03h returned AX=0x%04X (AH=LSR AL=MSR)\n", r.w.ax);

    /* Step 4: Send FOSSIL AH=06h (DTR raise) on COM1 */
    printf("Sending FOSSIL AH=06h DTR raise on COM1...\n");
    r.h.ah = 0x06;
    r.h.al = 0x01;  /* raise DTR */
    r.w.dx = 0;
    int86(0x14, &r, &r);

    /* Step 5: Send a TX byte (AH=01h) - letter 'X' */
    printf("Sending FOSSIL AH=01h TX 'X' on COM1...\n");
    r.h.ah = 0x01;
    r.h.al = 'X';
    r.w.dx = 0;
    int86(0x14, &r, &r);

    /* Step 6: Read the debug log */
    memset(dbgbuf, 0, sizeof(dbgbuf));
    segread(&sr);
    sr.es = FP_SEG(dbgbuf);
    r.h.ah = MUX_ID;
    r.h.al = 0x06;  /* MUX_DEBUGLOG */
    r.w.bx = FP_OFF(dbgbuf);
    r.w.cx = sizeof(dbgbuf);
    int86x(0x2F, &r, &r, &sr);
    got = r.w.ax;

    printf("\nDebug log (%u bytes):\n", got);
    if (got == 0) {
        printf("  (EMPTY - no log data at all!)\n");
        return;
    }

    /* Print the log, replacing non-printable chars */
    printf("  [");
    for (k = 0; k < got; k++) {
        unsigned char c = (unsigned char)dbgbuf[k];
        if (c >= 0x20 && c < 0x7F)
            putchar(c);
        else
            printf("\\x%02X", c);
    }
    printf("]\n\n");

    /* Check for F: entries */
    for (k = 0; k + 1 < got; k++) {
        if (dbgbuf[k] == 'F' && dbgbuf[k+1] == ':') {
            found_f = 1;
            break;
        }
    }

    if (found_f)
        printf("PASS: Found F: entries in debug log.\n");
    else
        printf("FAIL: No F: entries found! FOSSIL logging is broken.\n");
}

int main(int argc, char *argv[])
{
    printf("VMODTEST - VMODEM COM port test utility\n");

    /* FOSSIL detection disabled for now */

    if (argc < 2) {
        printf("Usage: VMODTEST /ECHO | /STATUS | /FOSSLOG | /HANGUP\n");
        return 1;
    }

    if (_fstricmp(argv[1], "/ECHO") == 0) {
        cmd_echo();
    } else if (_fstricmp(argv[1], "/STATUS") == 0) {
        cmd_status();
    } else if (_fstricmp(argv[1], "/FOSSLOG") == 0) {
        cmd_fosslog();
    } else if (_fstricmp(argv[1], "/HANGUP") == 0) {
        cmd_hangup();
    } else {
        printf("Unknown option: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
