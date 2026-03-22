/*
 * vmodemctl.c - VMODEM Control Utility (VMODEMCTL.EXE)
 *
 * A lightweight companion to VMODEM.EXE that communicates with the
 * resident TSR via INT 2Fh (Multiplex Interrupt) to:
 *   - Add or change listen/connect settings without unloading the TSR
 *   - Disconnect individual COM ports
 *   - Show current status
 *
 * This utility does NOT link against mTCP — it only uses standard
 * DOS interrupt calls.  Compiled as a small model EXE.
 *
 * Usage:
 *   VMODEMCTL /L:n:port            Set COM n to listen on TCP port
 *   VMODEMCTL /C:n:host:port       Connect COM n outbound
 *   VMODEMCTL /D:n                 Disconnect COM n
 *   VMODEMCTL /S                   Show status
 *   VMODEMCTL /H                   Help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include <i86.h>

/* Replicate only the constants we need from vmodem.h
 * (we do not include vmodem.h because it pulls in mTCP headers) */

#define VMODEM_SIG       "VMODEM10"
#define VMODEM_SIG_LEN   8
#define MAX_PORTS        4
#define MUX_ID           0xC3
#define MUX_INSTALL_CHK  0x00
#define MUX_LISTEN       0x01
#define MUX_CONNECT      0x02
#define MUX_DISCONNECT   0x03
#define MUX_STATUS       0x04
#define MUX_DEBUGLOG     0x06
#define MUX_UNLOAD       0xFF

#define STATUS_BLOCK_MAGIC 0xA55A

/* Minimal StatusBlock mirroring vmodem.h */
typedef struct {
    unsigned short magic;
    struct {
        unsigned char  mode;
        unsigned char  initialized;
        unsigned short localPort;
        unsigned short remotePort;
        unsigned char  remoteIP[4];
        unsigned short rxCount;
    } ports[MAX_PORTS];
} StatusBlock;

static const char *mode_names[] = {
    "DISC", "LISTEN", "CONN", "RESOLVING", "CONNECTING", "???"
};

/* -----------------------------------------------------------------------
 * check_installed
 *
 * Returns a far pointer to the resident VModemState if VMODEM is loaded,
 * otherwise NULL.  We do NOT dereference the pointer here — it's just
 * used to confirm presence and to pass ES:BX back for the STATUS call.
 * --------------------------------------------------------------------- */

static int check_installed(unsigned short *seg_out, unsigned short *off_out)
{
    union REGS  r;
    struct SREGS sr;

    memset(&r, 0, sizeof(r));
    memset(&sr, 0, sizeof(sr));

    r.h.ah = MUX_ID;
    r.h.al = MUX_INSTALL_CHK;
    int86x(0x2F, &r, &r, &sr);

    if (r.h.al != 0xFF)
        return 0;

    if (seg_out) *seg_out = sr.es;
    if (off_out) *off_out = (unsigned short)r.x.bx;
    return 1;
}

/* -----------------------------------------------------------------------
 * parse_ipaddr — simple dotted-decimal IPv4 parser
 * --------------------------------------------------------------------- */

static int parse_ipaddr(const char *str, unsigned char ip[4])
{
    int parts = 0;
    const char *p = str;

    while (parts < 4) {
        int octet = 0, digits = 0;
        while (*p >= '0' && *p <= '9') { octet = octet*10 + (*p-'0'); p++; digits++; }
        if (!digits || octet > 255) return -1;
        ip[parts++] = (unsigned char)octet;
        if (parts < 4) { if (*p != '.') return -1; p++; }
    }
    return (*p == '\0') ? 0 : -1;
}

/* -----------------------------------------------------------------------
 * show_status — display status from the StatusBlock
 * --------------------------------------------------------------------- */

static void show_status(void)
{
    unsigned short seg, off;
    StatusBlock sb;
    union REGS  r;
    struct SREGS sr;
    int i;

    if (!check_installed(&seg, &off)) {
        printf("VMODEM is not installed.\n");
        return;
    }

    memset(&sb, 0, sizeof(sb));
    memset(&r, 0, sizeof(r));
    memset(&sr, 0, sizeof(sr));

    r.h.ah  = MUX_ID;
    r.h.al  = MUX_STATUS;
    sr.es   = FP_SEG(&sb);
    r.x.bx  = FP_OFF(&sb);
    int86x(0x2F, &r, &r, &sr);

    if (sb.magic != STATUS_BLOCK_MAGIC) {
        printf("VMODEM: bad status block magic.\n");
        return;
    }

    printf("\nVMODEM Status\n");
    printf("%-6s %-11s %-8s %-20s %s\n",
           "Port", "Mode", "LocalTCP", "RemoteIP:Port", "RxBuf");
    printf("------------------------------------------------------------\n");

    for (i = 0; i < MAX_PORTS; i++) {
        unsigned char mode = sb.ports[i].mode;
        if (!sb.ports[i].initialized) {
            printf("COM%d   not managed\n", i + 1);
            continue;
        }
        if (mode > 4) mode = 5;
        printf("COM%d   %-11s %-8u %u.%u.%u.%u:%-5u  %u\n",
               i + 1,
               mode_names[mode],
               sb.ports[i].localPort,
               sb.ports[i].remoteIP[0], sb.ports[i].remoteIP[1],
               sb.ports[i].remoteIP[2], sb.ports[i].remoteIP[3],
               sb.ports[i].remotePort,
               sb.ports[i].rxCount);
    }
    printf("\n");
}

/* -----------------------------------------------------------------------
 * do_listen — send MUX_LISTEN to the TSR
 * --------------------------------------------------------------------- */

static void do_listen(int com_idx, unsigned short tcp_port)
{
    union REGS  r;
    struct SREGS sr;

    memset(&r, 0, sizeof(r));
    memset(&sr, 0, sizeof(sr));

    r.h.ah = MUX_ID;
    r.h.al = MUX_LISTEN;
    r.x.cx = (unsigned short)com_idx;
    r.x.dx = tcp_port;
    int86x(0x2F, &r, &r, &sr);

    printf("COM%d: listening on TCP port %u\n", com_idx + 1, tcp_port);
}

/* -----------------------------------------------------------------------
 * do_connect — send MUX_CONNECT to the TSR
 * --------------------------------------------------------------------- */

static void do_connect(int com_idx, unsigned short tcp_port,
                       const char *hostname)
{
    union REGS  r;
    struct SREGS sr;

    memset(&r, 0, sizeof(r));
    memset(&sr, 0, sizeof(sr));

    r.h.ah = MUX_ID;
    r.h.al = MUX_CONNECT;
    r.x.cx = (unsigned short)com_idx;
    r.x.dx = tcp_port;
    sr.es  = FP_SEG(hostname);
    r.x.si = FP_OFF(hostname);
    int86x(0x2F, &r, &r, &sr);

    printf("COM%d: connecting to %s:%u\n", com_idx + 1, hostname, tcp_port);
}

/* -----------------------------------------------------------------------
 * do_disconnect — send MUX_DISCONNECT to the TSR
 * --------------------------------------------------------------------- */

static void do_disconnect(int com_idx)
{
    union REGS  r;
    struct SREGS sr;

    memset(&r, 0, sizeof(r));
    memset(&sr, 0, sizeof(sr));

    r.h.ah = MUX_ID;
    r.h.al = MUX_DISCONNECT;
    r.x.cx = (unsigned short)com_idx;
    int86x(0x2F, &r, &r, &sr);

    printf("COM%d: disconnected.\n", com_idx + 1);
}

/* -----------------------------------------------------------------------
 * print_help
 * --------------------------------------------------------------------- */

static void print_help(void)
{
    printf(
        "VMODEMCTL - Control utility for the VMODEM TSR\n"
        "\n"
        "Usage: VMODEMCTL [options]\n"
        "\n"
        "  /L:n:port         Set COM n to listen on TCP port\n"
        "  /C:n:host:port    Connect COM n outbound to host:port\n"
        "  /D:n              Disconnect COM n\n"
        "  /S                Show status of all ports\n"
        "  /H or /?          This help\n"
        "\n"
        "Examples:\n"
        "  VMODEMCTL /L:1:23        COM1 listens on Telnet port 23\n"
        "  VMODEMCTL /C:2:bbs.example.com:23   COM2 connects outbound\n"
        "  VMODEMCTL /D:1           Disconnect COM1\n"
        "  VMODEMCTL /S             Show status\n"
    );
}

/* -----------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    int i;
    int did_something = 0;

    if (argc < 2) {
        print_help();
        return 0;
    }

    for (i = 1; i < argc; i++) {
        char *arg = argv[i];
        char  c;
        unsigned short seg, off;

        if (arg[0] != '/' && arg[0] != '-') continue;

        c = arg[1];
        if (c >= 'a' && c <= 'z') c -= 32;

        if (c == 'H' || c == '?') { print_help(); return 0; }

        if (c == 'S') {
            show_status();
            did_something = 1;
            continue;
        }

        /* All other options require VMODEM to be installed */
        if (!check_installed(&seg, &off)) {
            printf("VMODEM is not installed.\n");
            return 1;
        }

        if (c == 'L' && arg[2] == ':') {
            /* /L:n:port */
            char *p = arg + 3;
            int comn = *p - '0';
            unsigned short port;
            if (comn < 1 || comn > 4 || p[1] != ':') {
                printf("Bad /L: %s\n", arg); return 1;
            }
            port = (unsigned short)atoi(p + 2);
            if (!port) { printf("Bad port: %s\n", arg); return 1; }
            do_listen(comn - 1, port);
            did_something = 1;
            continue;
        }

        if (c == 'C' && arg[2] == ':') {
            /* /C:n:host:port */
            char *p = arg + 3;
            int   comn = *p - '0';
            char *colon1, *colon2, *q;
            char  host[64];
            unsigned short port;
            int hlen;

            if (comn < 1 || comn > 4 || p[1] != ':') {
                printf("Bad /C: %s\n", arg); return 1;
            }
            colon1 = p + 2;
            colon2 = NULL;
            for (q = colon1; *q; q++) if (*q == ':') colon2 = q;
            if (!colon2) { printf("Missing port: %s\n", arg); return 1; }

            port  = (unsigned short)atoi(colon2 + 1);
            hlen  = (int)(colon2 - colon1);
            if (!port || hlen <= 0 || hlen >= 63) {
                printf("Bad host/port: %s\n", arg); return 1;
            }
            memcpy(host, colon1, (unsigned)hlen);
            host[hlen] = '\0';

            do_connect(comn - 1, port, host);
            did_something = 1;
            continue;
        }

        if (c == 'D' && arg[2] == ':') {
            /* /D:n */
            int comn = arg[3] - '0';
            if (comn < 1 || comn > 4) {
                printf("Bad /D: %s\n", arg); return 1;
            }
            do_disconnect(comn - 1);
            did_something = 1;
            continue;
        }

        if (c == 'G') {
            /* /G — dump debug log */
            union REGS r;
            struct SREGS sr;
            static char dbgbuf[2048];
            unsigned short got;

            segread(&sr);
            sr.es = FP_SEG(dbgbuf);
            r.h.ah = MUX_ID;
            r.h.al = MUX_DEBUGLOG;
            r.w.bx = FP_OFF(dbgbuf);
            r.w.cx = sizeof(dbgbuf);
            int86x(0x2F, &r, &r, &sr);
            got = r.w.ax;
            if (got > 0) {
                unsigned short k;
                for (k = 0; k < got; k++)
                    putchar(dbgbuf[k]);
                putchar('\n');
            } else {
                printf("(debug log empty)\n");
            }
            did_something = 1;
            continue;
        }

        printf("Unknown option: %s  (use /H for help)\n", arg);
        return 1;
    }

    if (!did_something) {
        show_status();
    }

    return 0;
}
