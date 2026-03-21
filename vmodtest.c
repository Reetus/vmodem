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
 *                      VMODEMCTL /S but usable from within a test autoexec
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
    r.h.ah = 0x00;
    r.h.al = 0xE3;   /* 9600 baud, 8N1 — VMODEM ignores this */
    r.w.dx = (unsigned short)port;
    int86(0x14, &r, &r);
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
    case 3: return "RESOLVING";
    case 4: return "CONNECTING";
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

int main(int argc, char *argv[])
{
    printf("VMODTEST - VMODEM COM port test utility\n");

    if (argc < 2) {
        printf("Usage: VMODTEST /ECHO | /STATUS\n");
        return 1;
    }

    if (_fstricmp(argv[1], "/ECHO") == 0) {
        cmd_echo();
    } else if (_fstricmp(argv[1], "/STATUS") == 0) {
        cmd_status();
    } else {
        printf("Unknown option: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
