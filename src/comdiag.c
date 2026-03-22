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

#define MUX_ID              0xC3
#define MUX_INSTALL_CHK     0x00
#define MUX_STATUS          0x04
#define STATUS_BLOCK_MAGIC  0xA55A

#define ESC_KEY             0x1B

/* ---- StatusBlock matching vmodem.h ---- */

typedef struct {
    unsigned short magic;
    struct {
        unsigned char  mode;
        unsigned char  initialized;
        unsigned short localPort;
        unsigned short remotePort;
        unsigned char  remoteIP[4];
        unsigned short rxCount;
    } ports[4];
} StatusBlock;

/* ---- BIOS timer ---- */

static unsigned long bios_ticks(void)
{
    return *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
}

/* ---- Mode name table ---- */

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

/* ---- Clear screen via INT 10h AH=00h (set video mode, clears screen) ---- */

static void clear_screen(void)
{
    union REGS r;
    /* Read current video mode */
    r.h.ah = 0x0F;
    int86(0x10, &r, &r);
    /* Re-set it to clear the screen */
    r.h.ah = 0x00;
    /* r.h.al already has current mode from AH=0Fh */
    int86(0x10, &r, &r);
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
    r.h.ah = MUX_ID;
    r.h.al = MUX_INSTALL_CHK;
    int86(0x2F, &r, &r);
    return (r.h.al == 0xFF) ? 1 : 0;
}

/* ---- Get VMODEM status block ---- */

static int vmodem_get_status(StatusBlock *sb)
{
    union REGS   r;
    union REGS   or2;
    struct SREGS sr;

    memset(sb, 0, sizeof(*sb));
    segread(&sr);
    sr.es  = FP_SEG(sb);
    r.h.ah = MUX_ID;
    r.h.al = MUX_STATUS;
    r.w.bx = FP_OFF(sb);
    int86x(0x2F, &r, &or2, &sr);

    return (sb->magic == STATUS_BLOCK_MAGIC) ? 1 : 0;
}

/* ---- Print LSR bits ---- */

static void print_lsr(unsigned char lsr)
{
    printf("  LSR (0x%02X):", lsr);
    if (lsr & 0x80) printf(" TIMEOUT");
    if (lsr & 0x40) printf(" TSRE");       /* TX shift register empty */
    if (lsr & 0x20) printf(" THRE");       /* TX holding register empty */
    if (lsr & 0x10) printf(" BREAK");      /* break interrupt */
    if (lsr & 0x08) printf(" FRAME-ERR");  /* framing error */
    if (lsr & 0x04) printf(" PARITY-ERR"); /* parity error */
    if (lsr & 0x02) printf(" OVERRUN");    /* overrun error */
    if (lsr & 0x01) printf(" RX-READY");   /* data ready */
    if (lsr == 0)   printf(" (none)");
    printf("\n");
}

/* ---- Print MSR bits ---- */

static void print_msr(unsigned char msr)
{
    printf("  MSR (0x%02X):", msr);
    if (msr & 0x80) printf(" DCD");        /* Data Carrier Detect */
    if (msr & 0x40) printf(" RI");         /* Ring Indicator */
    if (msr & 0x20) printf(" DSR");        /* Data Set Ready */
    if (msr & 0x10) printf(" CTS");        /* Clear To Send */
    if (msr & 0x08) printf(" dDCD");       /* delta DCD */
    if (msr & 0x04) printf(" dRI");        /* trailing edge RI */
    if (msr & 0x02) printf(" dDSR");       /* delta DSR */
    if (msr & 0x01) printf(" dCTS");       /* delta CTS */
    if (msr == 0)   printf(" (none)");
    printf("\n");
}

/* ---- Print one-line summary for a port ---- */

static void print_port_summary(int port, unsigned char lsr, unsigned char msr)
{
    printf("  Status: TX-%s  RX-%s  DCD=%s  DSR=%s  CTS=%s  RI=%s\n",
           (lsr & 0x20) ? "READY" : "BUSY",
           (lsr & 0x01) ? "DATA"  : "EMPTY",
           (msr & 0x80) ? "ON"  : "OFF",
           (msr & 0x20) ? "ON"  : "OFF",
           (msr & 0x10) ? "ON"  : "OFF",
           (msr & 0x40) ? "ON"  : "OFF");
    if (lsr & 0x80) printf("  ** TIMEOUT **\n");
}

/* ---- Main display loop ---- */

int main(void)
{
    unsigned long last_tick;
    int           has_vmodem;
    int           i;

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
        if (now - last_tick < 18UL && last_tick != 0)
            continue;
        last_tick = now;

        clear_screen();

        printf("COMDIAG - COM Port Diagnostic Utility    [ESC to exit]\n");
        printf("========================================================\n\n");

        /* Query and display each COM port */
        for (i = 0; i < 4; i++) {
            unsigned char lsr, msr;
            com_status(i, &lsr, &msr);

            printf("COM%d:\n", i + 1);
            print_port_summary(i, lsr, msr);
            print_lsr(lsr);
            print_msr(msr);
            printf("\n");
        }

        /* FOSSIL detection (same method BBS software uses) */
        {
            void (__interrupt __far *vec14)(void) = _dos_getvect(0x14);
            unsigned short __far *sigptr = (unsigned short __far *)vec14;
            unsigned char __far *bptr = (unsigned char __far *)vec14;
            unsigned short sig = sigptr[3];  /* word at offset +6 */
            unsigned char maxf = bptr[8];    /* byte at offset +8 */

            printf("--------------------------------------------------------\n");
            printf("FOSSIL check: INT 14h -> %04X:%04X\n",
                   FP_SEG(vec14), FP_OFF(vec14));
            printf("  Bytes at vector: %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   bptr[0], bptr[1], bptr[2], bptr[3], bptr[4], bptr[5],
                   bptr[6], bptr[7], bptr[8]);
            printf("  Signature at +6: 0x%04X (%s)\n",
                   sig, (sig == 0x1954) ? "FOSSIL FOUND" : "NOT FOSSIL");
            if (sig == 0x1954)
                printf("  Max function: 0x%02X\n", maxf);

            /* Also try AH=04h init */
            {
                union REGS r;
                r.h.ah = 0x04;
                r.w.dx = 0;
                r.w.bx = 0;
                int86(0x14, &r, &r);
                printf("  AH=04h init: AX=0x%04X BH=%d BL=0x%02X (%s)\n",
                       r.w.ax, r.h.bh, r.h.bl,
                       (r.w.ax == 0x1954) ? "OK" : "FAIL");
            }
            printf("\n");
        }

        /* VMODEM status section */
        has_vmodem = vmodem_installed();
        if (has_vmodem) {
            StatusBlock sb;
            printf("--------------------------------------------------------\n");
            printf("VMODEM Status:\n\n");
            if (vmodem_get_status(&sb)) {
                for (i = 0; i < 4; i++) {
                    if (!sb.ports[i].initialized) continue;
                    printf("  COM%d: %-10s  localPort=%u  rxBuf=%u",
                           i + 1,
                           mode_name(sb.ports[i].mode),
                           sb.ports[i].localPort,
                           sb.ports[i].rxCount);
                    if (sb.ports[i].mode >= 2) {
                        printf("  remote=%u.%u.%u.%u:%u",
                               sb.ports[i].remoteIP[0],
                               sb.ports[i].remoteIP[1],
                               sb.ports[i].remoteIP[2],
                               sb.ports[i].remoteIP[3],
                               sb.ports[i].remotePort);
                    }
                    printf("\n");
                }
            } else {
                printf("  (bad status block)\n");
            }
        } else {
            printf("VMODEM: not installed\n");
        }
    }

    printf("\nCOMDIAG exiting.\n");
    return 0;
}
