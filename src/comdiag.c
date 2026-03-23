/*
 * comdiag.c - COM Port Diagnostic Utility
 *
 * Displays real-time status of COM1-COM4 via INT 14h AH=03h, showing
 * parsed LSR and MSR bits with human-readable labels.  If VMODEM is
 * installed, also shows VMODEM port states via INT 2Fh MUX_STATUS.
 *
 * Refreshes every ~1 second using the BIOS timer tick counter.
 * Press ESC to exit.
 *
 * Compile with: wpp comdiag -0 -ms -fo=.obj -zp2 -zpw -ei -s -we
 */

#include <stdio.h>
#include <string.h>
#include <dos.h>
#include <i86.h>
#include <conio.h>

#include "vmodem_mux.h"

#define ESC_KEY             0x1B

/* ---- BIOS timer ---- */

static unsigned long bios_ticks(void)
{
    return *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
}

/* ---- DOS idle ---- */

static void dos_idle(void)
{
    union REGS r;
    r.h.ah = 0;
    int86(0x28, &r, &r);
}

/* ---- Mode name table ---- */

static const char *mode_name(unsigned char m)
{
    switch (m) {
    case 0: return "DISC";
    case 1: return "LISTEN";
    case 2: return "CONN";
    default: return "?";
    }
}

/* ---- Set cursor position via INT 10h AH=02h ---- */

static void goto_xy(unsigned char col, unsigned char row)
{
    union REGS r;
    r.h.ah = 0x02;
    r.h.bh = 0;       /* page 0 */
    r.h.dh = row;
    r.h.dl = col;
    int86(0x10, &r, &r);
}

/* ---- Clear screen: scroll entire window, then home cursor ---- */

static void clear_screen(void)
{
    union REGS r;
    /* INT 10h AH=06h: scroll up, AL=0 = clear */
    r.h.ah = 0x06;
    r.h.al = 0;       /* clear entire window */
    r.h.bh = 0x07;    /* attribute: white on black */
    r.h.ch = 0;       /* top-left row */
    r.h.cl = 0;       /* top-left col */
    r.h.dh = 24;      /* bottom-right row */
    r.h.dl = 79;      /* bottom-right col */
    int86(0x10, &r, &r);
    goto_xy(0, 0);
}

/* ---- INT 14h AH=03h: get port status ---- */

static void com_status(int port, unsigned char *lsr, unsigned char *msr)
{
    union REGS r;
    r.h.ah = 0x03;
    r.w.dx = (unsigned short)port;
    int86(0x14, &r, &r);
    *lsr = r.h.ah;
    *msr = r.h.al;
}

/* ---- Check if VMODEM is installed ---- */

static int vmodem_installed(void)
{
    union REGS r;
    struct SREGS sr;
    memset(&r, 0, sizeof(r));
    memset(&sr, 0, sizeof(sr));
    r.h.ah = MUX_ID;
    r.h.al = MUX_INSTALL_CHK;
    int86x(0x2F, &r, &r, &sr);
    return (r.h.al == 0xFF) ? 1 : 0;
}

/* ---- Get VMODEM status block ---- */

static int vmodem_get_status(StatusBlock *sb)
{
    union REGS   r;
    struct SREGS sr;

    memset(sb, 0, sizeof(*sb));
    memset(&r, 0, sizeof(r));
    memset(&sr, 0, sizeof(sr));
    sr.es  = FP_SEG(sb);
    r.h.ah = MUX_ID;
    r.h.al = MUX_STATUS;
    r.w.bx = FP_OFF(sb);
    int86x(0x2F, &r, &r, &sr);

    return (sb->magic == STATUS_BLOCK_MAGIC) ? 1 : 0;
}

/* ---- Main display loop ---- */

int main(void)
{
    unsigned long last_tick;
    int           i;

    clear_screen();
    printf("COMDIAG - COM Port Diagnostic Utility\n");
    printf("Press ESC to exit.\n\n");

    last_tick = 0;  /* force immediate first display */

    for (;;) {
        unsigned long now = bios_ticks();

        /* Check for ESC key */
        if (kbhit()) {
            int k = getch();
            if (k == ESC_KEY) break;
        }

        /* Refresh every ~18 ticks (~1 second) */
        if (now - last_tick < 18UL && last_tick != 0) {
            dos_idle();
            continue;
        }
        last_tick = now;

        /* Home cursor and overwrite in place */
        goto_xy(0, 0);

        printf("COMDIAG - COM Port Diagnostic Utility    [ESC to exit]   \n");
        printf("========================================================\n\n");

        /* Query and display each COM port */
        for (i = 0; i < 4; i++) {
            unsigned char lsr, msr;
            com_status(i, &lsr, &msr);

            printf("COM%d:  TX-%s  RX-%s  DCD=%s  DSR=%s  CTS=%s  RI=%s   \n",
                   i + 1,
                   (lsr & 0x20) ? "READY" : "BUSY ",
                   (lsr & 0x01) ? "DATA " : "EMPTY",
                   (msr & 0x80) ? "ON " : "OFF",
                   (msr & 0x20) ? "ON " : "OFF",
                   (msr & 0x10) ? "ON " : "OFF",
                   (msr & 0x40) ? "ON " : "OFF");
        }

        printf("\n");

        /* FOSSIL detection */
        {
            void (__interrupt __far *vec14)(void) = _dos_getvect(0x14);
            unsigned short __far *sigptr = (unsigned short __far *)vec14;
            unsigned short sig = sigptr[3];  /* word at offset +6 */

            printf("FOSSIL: INT 14h -> %04X:%04X  sig=0x%04X %s   \n",
                   FP_SEG(vec14), FP_OFF(vec14),
                   sig, (sig == 0x1954) ? "FOUND" : "NOT FOUND");
        }

        printf("\n");

        /* VMODEM status section */
        if (vmodem_installed()) {
            StatusBlock sb;

            printf("VMODEM Status:                                          \n");
            printf("%-6s %-11s %-8s %-20s %s\n",
                   "Port", "Mode", "LocalTCP", "RemoteIP:Port", "RxBuf");
            printf("----------------------------------------------------\n");

            if (vmodem_get_status(&sb)) {
                for (i = 0; i < MAX_PORTS; i++) {
                    if (!sb.ports[i].initialized) {
                        printf("COM%d   not managed                                  \n",
                               i + 1);
                        continue;
                    }
                    if (sb.ports[i].mode == 2) {
                        printf("COM%d   %-11s %-8u %u.%u.%u.%u:%-5u  %u   \n",
                               i + 1,
                               mode_name(sb.ports[i].mode),
                               sb.ports[i].localPort,
                               sb.ports[i].remoteIP[0],
                               sb.ports[i].remoteIP[1],
                               sb.ports[i].remoteIP[2],
                               sb.ports[i].remoteIP[3],
                               sb.ports[i].remotePort,
                               sb.ports[i].rxCount);
                    } else {
                        printf("COM%d   %-11s %-8u %-20s %u   \n",
                               i + 1,
                               mode_name(sb.ports[i].mode),
                               sb.ports[i].localPort,
                               "-",
                               sb.ports[i].rxCount);
                    }
                }
            } else {
                printf("  (bad status block)                                \n");
            }
        } else {
            printf("VMODEM: not installed                               \n");
        }

        /* Pad remaining lines to avoid leftover text from previous frame */
        printf("                                                        \n");
        printf("                                                        \n");
    }

    printf("\nCOMDIAG exiting.\n");
    return 0;
}
