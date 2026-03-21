/*
 * vmodem.c - VMODEM TSR main entry point
 *
 * Responsibilities:
 *   1. Parse command-line arguments (/L /C /U /S /H)
 *   2. Detect whether the TSR is already loaded (via INT 2Fh)
 *   3. If loaded: route /L, /C commands to the resident TSR
 *   4. If not loaded: initialise mTCP, hook interrupts, go TSR
 *   5. Provide cmd_* implementations callable from the INT 2Fh handler
 *
 * Resident size (small model .EXE):
 *   paras = (DS_segment - _psp) + 0x1000
 *   This covers PSP + code segment + full 64KB DGROUP (data + near heap).
 */

#include CFG_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include <i86.h>
#include <conio.h>
#include "vmodem.h"
#include "tcp.h"
#include "tcpsockm.h"
#include "dns.h"
#include "utils.h"
#include "arp.h"
#include "ip.h"
#include "packet.h"

/* -----------------------------------------------------------------------
 * Resident global data (in DGROUP)
 * --------------------------------------------------------------------- */

VModemState  g_state;

/* InDOS flag pointer — obtained via INT 21h AH=34h at startup.
 * When *g_indos_ptr == 0, DOS is not in a system call and file I/O is safe. */
unsigned char __far *g_indos_ptr = NULL;

/* Debug: unhandled packet counter and first EtherType seen */
static unsigned long  g_unhandled_count = 0;
static unsigned short g_first_unhandled_et = 0;

static void unhandled_pkt_handler(unsigned char *packet, unsigned short len)
{
    g_unhandled_count++;
    if (g_unhandled_count == 1 && len >= 14) {
        /* Save the EtherType (bytes 12-13 in network byte order) */
        g_first_unhandled_et = ((unsigned short)packet[12] << 8) | packet[13];
    }
    Buffer_free(packet);
}

/* Ctrl-Break / Ctrl-C stubs — required by Utils::initStack() */
static void __interrupt __far ctrl_break_handler(void) {}
static void __interrupt __far ctrl_c_handler(void)     {}

/* -----------------------------------------------------------------------
 * parse_ipaddr — parse dotted-decimal IPv4 string
 * Returns 0 on success, -1 if not a valid IPv4 literal.
 * --------------------------------------------------------------------- */

int parse_ipaddr(const char *str, IpAddr_t ip)
{
    int parts = 0;
    const char *p = str;

    while (parts < 4) {
        int octet = 0, digits = 0;
        while (*p >= '0' && *p <= '9') {
            octet = octet * 10 + (*p - '0');
            p++;
            digits++;
        }
        if (!digits || octet > 255)
            return -1;
        ip[parts++] = (unsigned char)octet;
        if (parts < 4) {
            if (*p != '.') return -1;
            p++;
        }
    }
    return (*p == '\0') ? 0 : -1;
}

/* -----------------------------------------------------------------------
 * check_installed — probe INT 2Fh for VMODEM
 * Returns far pointer to VModemState, or NULL if not installed.
 * --------------------------------------------------------------------- */

static VModemState __far *check_installed(void)
{
    union REGS  r;
    struct SREGS sr;
    memset(&r,  0, sizeof(r));
    memset(&sr, 0, sizeof(sr));
    r.h.ah = MUX_ID;
    r.h.al = MUX_INSTALL_CHK;
    int86x(0x2F, &r, &r, &sr);
    if (r.h.al != 0xFF)
        return NULL;
    return (VModemState __far *)MK_FP(sr.es, r.x.bx);
}

/* -----------------------------------------------------------------------
 * Debug log helpers
 * --------------------------------------------------------------------- */

void dbg(const char *msg)
{
    while (*msg) {
        g_state.dbglog[g_state.dbglog_head] = *msg;
        g_state.dbglog_head = (g_state.dbglog_head + 1) % DBGLOG_SIZE;
        if (g_state.dbglog_count < DBGLOG_SIZE)
            g_state.dbglog_count++;
        msg++;
    }
}

static const char hex_chars[] = "0123456789ABCDEF";

void dbg_hex(const char *prefix, unsigned char val)
{
    char buf[8];
    int i = 0;
    const char *p = prefix;
    while (*p && i < 4) buf[i++] = *p++;
    buf[i++] = hex_chars[(val >> 4) & 0x0F];
    buf[i++] = hex_chars[val & 0x0F];
    buf[i++] = ' ';
    buf[i] = '\0';
    dbg(buf);
}

/* -----------------------------------------------------------------------
 * cmd_listen — put a COM port into TCP listen mode
 * --------------------------------------------------------------------- */

void cmd_listen(int port_idx, unsigned short tcp_port)
{
    PortState *p;
    TcpSocket *ls;

    if (port_idx < 0 || port_idx >= MAX_PORTS)
        return;
    p = &g_state.ports[port_idx];
    cmd_disconnect(port_idx);

    ls = TcpSocketMgr::getSocket();
    if (!ls) {
        printf("VMODEM: no free socket for COM%d\n", port_idx + 1);
        return;
    }
    if (ls->listen(tcp_port, 2048) != 0) {
        printf("VMODEM: listen() failed for COM%d port %u\n",
               port_idx + 1, tcp_port);
        TcpSocketMgr::freeSocket(ls);
        return;
    }
    p->listenSock  = ls;
    p->sock        = NULL;
    p->localPort   = tcp_port;
    p->mode        = PORT_LISTEN;
    p->initialized = 1;
    ring_init(&p->rx);
}

/* -----------------------------------------------------------------------
 * cmd_connect — initiate outbound connection for a COM port
 * --------------------------------------------------------------------- */

void cmd_connect(int port_idx, unsigned short tcp_port,
                 char __far *hostname)
{
    PortState *p;
    IpAddr_t   ip;
    char       local[64];
    int        i;

    if (port_idx < 0 || port_idx >= MAX_PORTS || !hostname)
        return;
    p = &g_state.ports[port_idx];

    /* Copy far hostname to near buffer */
    for (i = 0; i < 63 && hostname[i]; i++)
        local[i] = hostname[i];
    local[i] = '\0';

    strncpy(p->hostname, local, sizeof(p->hostname) - 1);
    p->hostname[sizeof(p->hostname) - 1] = '\0';
    p->remotePort  = tcp_port;
    p->listenSock  = NULL;
    p->initialized = 1;
    cmd_disconnect(port_idx);

    if (parse_ipaddr(local, ip) == 0) {
        /* Direct IP connect (non-blocking) */
        TcpSocket *s = TcpSocketMgr::getSocket();
        if (!s) {
            printf("VMODEM: no free socket for COM%d\n", port_idx + 1);
            return;
        }
        s->setRecvBuffer(2048);
        {
            static unsigned short src_port = 1025;
            if (src_port > 65000) src_port = 1025;
            s->connectNonBlocking(src_port++, ip, tcp_port);
        }
        memcpy(p->remoteIP, ip, 4);
        p->sock = s;
        p->mode = PORT_CONNECTING;
    } else {
        /* Need DNS resolution */
        IpAddr_t dummy;
        int8_t rc = Dns::resolve(local, dummy, 1);
        if (rc == 0) {
            /* Already cached */
            TcpSocket *s = TcpSocketMgr::getSocket();
            if (s) {
                s->setRecvBuffer(2048);
                static unsigned short sp2 = 2000;
                if (sp2 > 65000) sp2 = 2000;
                s->connectNonBlocking(sp2++, dummy, tcp_port);
                memcpy(p->remoteIP, dummy, 4);
                p->sock = s;
                p->mode = PORT_CONNECTING;
            }
        } else {
            p->sock = NULL;
            p->mode = PORT_RESOLVING;
        }
    }
    ring_init(&p->rx);
}

/* -----------------------------------------------------------------------
 * cmd_disconnect — close socket(s) for a COM port
 * --------------------------------------------------------------------- */

void cmd_disconnect(int port_idx)
{
    PortState *p;
    if (port_idx < 0 || port_idx >= MAX_PORTS)
        return;
    p = &g_state.ports[port_idx];
    if (p->sock) {
        p->sock->close();
        TcpSocketMgr::freeSocket(p->sock);
        p->sock = NULL;
    }
    if (p->listenSock) {
        p->listenSock->close();
        TcpSocketMgr::freeSocket(p->listenSock);
        p->listenSock = NULL;
    }
    p->mode = PORT_DISC;
    ring_init(&p->rx);
}

/* -----------------------------------------------------------------------
 * cmd_status — fill a StatusBlock for the caller
 * --------------------------------------------------------------------- */

void cmd_status(StatusBlock __far *sb)
{
    int i;
    if (!sb) return;
    sb->magic = STATUS_BLOCK_MAGIC;
    sb->poll_count = g_state.poll_count;
    sb->pkt_count  = g_state.pkt_count;
    sb->arp_count  = g_state.arp_count;
    sb->ip_count   = g_state.ip_count;
    sb->arp_req_recv = Arp::RequestsReceived;
    sb->arp_rep_sent = Arp::RepliesSent;
    sb->arp_req_sent = Arp::RequestsSent;
    sb->arp_rep_recv = Arp::RepliesReceived;
    sb->buf_low_free = Buffer_lowFreeCount;
    sb->buf_first    = Buffer_first;
    sb->buf_next     = Buffer_next;
    sb->_pad0        = 0;
    sb->pkts_recv      = Packets_received;
    sb->pkts_sent      = Packets_sent;
    sb->pkts_send_errs = Packets_send_errs;
    sb->pkts_dropped   = Packets_dropped;
    sb->unhandled_count     = g_unhandled_count;
    sb->first_unhandled_et  = g_first_unhandled_et;
    sb->tcp_pend_sent       = g_state.tcp_pend_sent;
    sb->tcp_pend_outgoing   = g_state.tcp_pend_outgoing;
    sb->active_sockets      = g_state.active_sockets;
    sb->poll_phase          = g_state.poll_phase;
    for (i = 0; i < MAX_PORTS; i++) {
        PortState *p = &g_state.ports[i];
        sb->ports[i].mode        = (unsigned char)p->mode;
        sb->ports[i].initialized = p->initialized;
        sb->ports[i].localPort   = p->localPort;
        sb->ports[i].remotePort  = p->remotePort;
        sb->ports[i].remoteIP[0] = p->remoteIP[0];
        sb->ports[i].remoteIP[1] = p->remoteIP[1];
        sb->ports[i].remoteIP[2] = p->remoteIP[2];
        sb->ports[i].remoteIP[3] = p->remoteIP[3];
        sb->ports[i].rxCount     = (unsigned short)ring_count(&p->rx);
    }
}

/* -----------------------------------------------------------------------
 * print_status — print port table to stdout
 * --------------------------------------------------------------------- */

static void print_status(VModemState __far *rs)
{
    int i;
    static const char *mnames[] = {
        "DISC","LISTEN","CONN","RESOLVING","CONNECTING"
    };

    printf("\nVMODEM v%s  Status\n", VMODEM_VER_STR);
    printf("%-6s %-11s %-8s %-20s %s\n",
           "Port","Mode","LocalTCP","RemoteIP:Port","RxBuf");
    printf("--------------------------------------------------------------\n");

    for (i = 0; i < MAX_PORTS; i++) {
        unsigned char  mode;
        unsigned char  init;
        unsigned short lp, rp;
        unsigned char  rip[4];
        unsigned short rxc;

        if (rs) {
            mode    = (unsigned char)rs->ports[i].mode;
            init    = rs->ports[i].initialized;
            lp      = rs->ports[i].localPort;
            rp      = rs->ports[i].remotePort;
            rip[0]  = rs->ports[i].remoteIP[0];
            rip[1]  = rs->ports[i].remoteIP[1];
            rip[2]  = rs->ports[i].remoteIP[2];
            rip[3]  = rs->ports[i].remoteIP[3];
            rxc     = rs->ports[i].rx.count;   /* far access to ring count */
        } else {
            mode    = (unsigned char)g_state.ports[i].mode;
            init    = g_state.ports[i].initialized;
            lp      = g_state.ports[i].localPort;
            rp      = g_state.ports[i].remotePort;
            rip[0]  = g_state.ports[i].remoteIP[0];
            rip[1]  = g_state.ports[i].remoteIP[1];
            rip[2]  = g_state.ports[i].remoteIP[2];
            rip[3]  = g_state.ports[i].remoteIP[3];
            rxc     = (unsigned short)ring_count(&g_state.ports[i].rx);
        }

        if (!init) {
            printf("COM%d   not managed\n", i + 1);
            continue;
        }
        if (mode > 4) mode = 0;
        printf("COM%d   %-11s %-8u %u.%u.%u.%u:%-6u %u\n",
               i + 1, mnames[mode], lp,
               rip[0], rip[1], rip[2], rip[3], rp, rxc);
    }
    printf("\n");
}

/* -----------------------------------------------------------------------
 * do_unload — restore vectors via INT 2Fh MUX_UNLOAD
 * --------------------------------------------------------------------- */

static void do_unload(VModemState __far *rs)
{
    union REGS  r;
    struct SREGS sr;

    if (!rs) {
        printf("VMODEM: not installed.\n");
        return;
    }

    /* Verify INT 14h still points to our handler */
    {
        void (__interrupt __far *cur14)(void) = _dos_getvect(0x14);
        if (FP_SEG(cur14) != rs->our_seg) {
            printf("VMODEM: Cannot unload — INT 14h was hooked after VMODEM.\n");
            printf("        Unload later TSRs first.\n");
            return;
        }
    }

    memset(&r, 0, sizeof(r));
    memset(&sr, 0, sizeof(sr));
    r.h.ah = MUX_ID;
    r.h.al = MUX_UNLOAD;
    int86x(0x2F, &r, &r, &sr);

    if (r.h.al == 0x00)
        printf("VMODEM: unloaded (vectors restored; memory not freed — reboot for full cleanup).\n");
    else
        printf("VMODEM: unload failed.\n");
}

/* -----------------------------------------------------------------------
 * Argument parsing
 * --------------------------------------------------------------------- */

#define MAX_PORT_ARGS 4

typedef struct {
    int            type;     /* 0=listen, 1=connect */
    int            com;      /* 0-based */
    unsigned short tcp_port;
    char           host[64];
} PortArg;

static int     want_status  = 0;
static int     want_unload  = 0;
static int     want_help    = 0;
static int     num_port_args = 0;
static PortArg port_args[MAX_PORT_ARGS];

static void print_help(void)
{
    printf(
        "VMODEM v%s - Virtual Serial Port over Telnet/TCP\n\n"
        "Usage: VMODEM [options]\n\n"
        "  /L:n:port         Listen on COM n for Telnet on TCP port\n"
        "  /C:n:host:port    Connect COM n outbound to host:port\n"
        "  /S                Show status\n"
        "  /U                Unload resident copy\n"
        "  /H or /?          Help\n\n"
        "Examples:\n"
        "  VMODEM /L:1:23              COM1 listens on port 23\n"
        "  VMODEM /L:1:23 /L:2:2323   COM1 and COM2 listen\n"
        "  VMODEM /C:1:192.168.1.1:23 COM1 connects outbound\n"
        "  VMODEM /S                   Show status\n"
        "  VMODEM /U                   Unload\n\n"
        "Requires: MTCP env var and packet driver loaded.\n",
        VMODEM_VER_STR
    );
}

static int parse_args(int argc, char *argv[])
{
    int i;
    for (i = 1; i < argc; i++) {
        char *arg = argv[i];
        char  c;
        if (arg[0] != '/' && arg[0] != '-') continue;
        c = arg[1];
        if (c >= 'a' && c <= 'z') c -= 32;

        if (c == 'H' || c == '?') { want_help = 1; return 0; }
        if (c == 'S') { want_status = 1; continue; }
        if (c == 'U') { want_unload = 1; continue; }

        if (c == 'L' && arg[2] == ':') {
            char *p = arg + 3;
            int comn = *p - '0';
            unsigned short port;
            if (comn < 1 || comn > 4 || p[1] != ':') {
                printf("Bad /L: %s\n", arg); return -1;
            }
            port = (unsigned short)atoi(p + 2);
            if (!port) { printf("Bad port in: %s\n", arg); return -1; }
            if (num_port_args >= MAX_PORT_ARGS) {
                printf("Too many port args.\n"); return -1;
            }
            port_args[num_port_args].type     = 0;
            port_args[num_port_args].com      = comn - 1;
            port_args[num_port_args].tcp_port = port;
            port_args[num_port_args].host[0]  = '\0';
            num_port_args++;
            continue;
        }

        if (c == 'C' && arg[2] == ':') {
            char *p = arg + 3;
            int   comn = *p - '0';
            char *colon1, *colon2, *q;
            char  host[64];
            unsigned short port;
            int hlen;

            if (comn < 1 || comn > 4 || p[1] != ':') {
                printf("Bad /C: %s\n", arg); return -1;
            }
            colon1 = p + 2;
            colon2 = NULL;
            for (q = colon1; *q; q++) if (*q == ':') colon2 = q;
            if (!colon2) { printf("Missing port in: %s\n", arg); return -1; }

            port = (unsigned short)atoi(colon2 + 1);
            hlen = (int)(colon2 - colon1);
            if (!port || hlen <= 0 || hlen >= 63) {
                printf("Bad host/port: %s\n", arg); return -1;
            }
            memcpy(host, colon1, (unsigned)hlen);
            host[hlen] = '\0';

            if (num_port_args >= MAX_PORT_ARGS) {
                printf("Too many port args.\n"); return -1;
            }
            port_args[num_port_args].type     = 1;
            port_args[num_port_args].com      = comn - 1;
            port_args[num_port_args].tcp_port = port;
            strncpy(port_args[num_port_args].host, host, 63);
            port_args[num_port_args].host[63] = '\0';
            num_port_args++;
            continue;
        }

        printf("Unknown option: %s (use /H for help)\n", arg);
        return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    VModemState __far *installed;
    int i;

    printf("VMODEM v%s\n", VMODEM_VER_STR);

    if (parse_args(argc, argv) < 0)
        return 1;

    if (want_help) { print_help(); return 0; }

    installed = check_installed();

    if (want_unload) { do_unload(installed); return 0; }

    if (want_status) {
        if (!installed)
            printf("VMODEM is not installed.\n");
        else
            print_status(installed);
        return 0;
    }

    /* Send port commands to an already-loaded TSR */
    if (installed && num_port_args > 0) {
        printf("Sending commands to resident VMODEM...\n");
        for (i = 0; i < num_port_args; i++) {
            PortArg *pa = &port_args[i];
            union REGS r;
            struct SREGS sr;
            memset(&r, 0, sizeof(r));
            memset(&sr, 0, sizeof(sr));
            r.h.ah = MUX_ID;
            if (pa->type == 0) {
                r.h.al = MUX_LISTEN;
                r.x.cx = (unsigned short)pa->com;
                r.x.dx = pa->tcp_port;
                int86x(0x2F, &r, &r, &sr);
                printf("  COM%d: listen on TCP port %u\n",
                       pa->com + 1, pa->tcp_port);
            } else {
                r.h.al = MUX_CONNECT;
                r.x.cx = (unsigned short)pa->com;
                r.x.dx = pa->tcp_port;
                sr.es  = FP_SEG(pa->host);
                r.x.si = FP_OFF(pa->host);
                int86x(0x2F, &r, &r, &sr);
                printf("  COM%d: connecting to %s:%u\n",
                       pa->com + 1, pa->host, pa->tcp_port);
            }
        }
        return 0;
    }

    if (!num_port_args && !installed) { print_help(); return 0; }

    if (installed) {
        printf("VMODEM already installed. Use /S for status.\n");
        return 1;
    }

    /* ---- Install TSR ---- */
    printf("Initialising mTCP...\n");

    if (Utils::parseEnv() != 0) {
        printf("Error: cannot parse MTCP.CFG\n"
               "       Set the MTCP env variable to point at your config.\n");
        return 1;
    }
    if (Utils::initStack(TCP_MAX_SOCKETS, TCP_MAX_XMIT_BUFS,
                         ctrl_break_handler, ctrl_c_handler) != 0) {
        printf("Error: mTCP init failed. Check packet driver and MTCP.CFG.\n");
        return 1;
    }

    /* Register unhandled packet handler for diagnostics */
    Packet_registerDefault(unhandled_pkt_handler);

    /*
     * Foreground network test: send ARP for the gateway and poll for a
     * response.  This confirms the NE2000 can both send and receive
     * packets while we're still running in the foreground (pre-TSR).
     *
     * Also dumps NE2000 register state for diagnostics.
     */
    {
        IpAddr_t gw;
        EthAddr_t gw_eth;
        unsigned long tstart, tnow;
        unsigned char cr, bnry, curr;
        int got_reply = 0;

        /* Use gateway IP from mTCP config (parsed by Utils::initStack) */
        gw[0] = Gateway[0]; gw[1] = Gateway[1];
        gw[2] = Gateway[2]; gw[3] = Gateway[3];

        /* Dump NE2000 state BEFORE test */
        cr = inp(0x300);
        bnry = inp(0x303);
        outp(0x300, (cr & 0x3F) | 0x40);  /* page 1 */
        curr = inp(0x307);
        outp(0x300, cr);
        printf("NE2000 pre-test: CR=0x%02X BNRY=0x%02X CURR=0x%02X\n",
               (unsigned)cr, (unsigned)bnry, (unsigned)curr);
        printf("  pkts_recv=%lu pkts_sent=%lu\n",
               Packets_received, Packets_sent);

        /* Send ARP for the gateway */
        printf("ARP test: resolving gateway %u.%u.%u.%u ...\n",
               gw[0], gw[1], gw[2], gw[3]);
        Arp::resolve(gw, gw_eth);

        /* Poll for ~5 seconds */
        tstart = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
        while (1) {
            PACKET_PROCESS_SINGLE;
            Arp::driveArp();
            Tcp::drivePackets();

            if (Arp::resolve(gw, gw_eth) == 0) {
                printf("ARP test: resolved! MAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
                       gw_eth[0], gw_eth[1], gw_eth[2],
                       gw_eth[3], gw_eth[4], gw_eth[5]);
                got_reply = 1;
                break;
            }

            tnow = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
            if (tnow - tstart > 18UL * 5) break;  /* 5 seconds */
        }

        if (!got_reply)
            printf("ARP test: FAILED (no reply from gateway)\n");

        /* Dump NE2000 state AFTER test and clean up */
        outp(0x300, 0x22);    /* page 0, started, abort DMA */
        bnry = inp(0x303);
        outp(0x300, 0x62);    /* page 1 */
        curr = inp(0x307);
        outp(0x300, 0x22);    /* back to page 0 */
        printf("NE2000 post-test: BNRY=0x%02X CURR=0x%02X\n",
               (unsigned)bnry, (unsigned)curr);
        printf("  pkts_recv=%lu pkts_sent=%lu\n",
               Packets_received, Packets_sent);

        /* Advance BNRY to CURR to discard any stale packets.
         * This ensures a clean ring buffer before going TSR. */
        if (bnry != curr) {
            printf("  Discarding stale NE2000 ring packet(s)\n");
            outp(0x303, curr);  /* BNRY = CURR */
        }
        /* Clear ISR and re-enable IMR */
        outp(0x307, 0xFF);    /* clear all ISR bits */
        outp(0x30F, 0x1F);    /* IMR: enable all */
        fflush(stdout);
    }

    /* Initialise resident state */
    memset(&g_state, 0, sizeof(g_state));
    memcpy(g_state.sig, VMODEM_SIG, VMODEM_SIG_LEN);
    g_state.our_seg = FP_SEG(&g_state);
    g_state.busy    = 0;

    /* Set private stack top (near offset within DGROUP) */
    g_priv_stack_top = (unsigned short)FP_OFF(g_priv_stack) +
                       (unsigned short)(PRIV_STACK_SIZE - 4);

    /* Process port arguments */
    for (i = 0; i < num_port_args; i++) {
        PortArg *pa = &port_args[i];
        if (pa->type == 0) {
            cmd_listen(pa->com, pa->tcp_port);
            printf("  COM%d: listening on TCP port %u\n",
                   pa->com + 1, pa->tcp_port);
        } else {
            cmd_connect(pa->com, pa->tcp_port, pa->host);
            printf("  COM%d: connecting to %s:%u\n",
                   pa->com + 1, pa->host, pa->tcp_port);
        }
    }

    /*
     * Disable mTCP's sleep/idle calls.  PACKET_PROCESS_SINGLE normally
     * calls SLEEP() → dosIdleCall() → INT 28h when no packets are queued.
     * We poll from INT 8 (hardware timer, IF=0) and INT 28h contexts —
     * issuing INT 28h from there is unsafe (DOS re-entrancy, recursive
     * INT 28h).  With sleep disabled, the macro just checks the packet
     * ring buffer and returns immediately when empty.
     */
    mTCP_sleepCallEnabled = 0;
    mTCP_releaseTimesliceEnabled = 0;

    /* Hook interrupt vectors.
     * INT 1Ch (user timer tick): BIOS INT 8 calls this AFTER sending EOI,
     * so IRQ 3 (NE2000) can fire during our mTCP poll — essential for
     * receiving TCP ACKs mid-handshake.  INT 8 runs with IF=0 which
     * blocks lower-priority IRQs and also makes _chain_intr fragile.
     */
    old_int1c = _dos_getvect(0x1C);
    old_int14 = _dos_getvect(0x14);
    old_int28 = _dos_getvect(0x28);
    old_int2f = _dos_getvect(0x2F);
    _dos_setvect(0x1C, int1c_handler);
    /* Build the FOSSIL signature stub dynamically in g_state.fossil_stub[].
     * This lives in DGROUP (DS-relative), so we know exactly where it is.
     * The stub is a tiny trampoline:
     *   +0: EB 07        jmp short +9  (skip signature)
     *   +2: 90 90 90 90  nops (padding)
     *   +6: 54 19        FOSSIL signature 1954h (little-endian)
     *   +8: 1B           max function number
     *   +9: EA xx xx yy yy  jmp far yy:xx (to int14_real_handler)
     */
    {
        unsigned char *s = g_state.fossil_stub;
        unsigned short real_off = FP_OFF(int14_real_handler);
        unsigned short real_seg = FP_SEG(int14_real_handler);
        unsigned short stub_off, stub_seg;

        s[0] = 0xEB; s[1] = 0x07;              /* jmp short past_sig */
        s[2] = 0x90; s[3] = 0x90;              /* nop; nop */
        s[4] = 0x90; s[5] = 0x90;              /* nop; nop */
        s[6] = 0x54; s[7] = 0x19;              /* dw 1954h */
        s[8] = 0x1B;                            /* db 1Bh (max func) */
        s[9] = 0xEA;                            /* jmp far imm */
        s[10] = (unsigned char)(real_off & 0xFF);
        s[11] = (unsigned char)(real_off >> 8);
        s[12] = (unsigned char)(real_seg & 0xFF);
        s[13] = (unsigned char)(real_seg >> 8);

        /* The stub is in DS (DGROUP).  In small model the code segment
         * (CS) is different from DS, but the CPU just needs seg:off to
         * reach the bytes.  DS is a valid segment for execution. */
        stub_seg = FP_SEG((void __far *)s);
        stub_off = FP_OFF((void __far *)s);

        printf("FOSSIL stub at %04X:%04X -> real handler %04X:%04X\n",
               stub_seg, stub_off, real_seg, real_off);
        printf("  Bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
               s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],
               s[8],s[9],s[10],s[11],s[12],s[13]);

        _disable();
        *(unsigned short __far *)MK_FP(0x0000, 0x0050) = stub_off;
        *(unsigned short __far *)MK_FP(0x0000, 0x0052) = stub_seg;
        _enable();
    }
    _dos_setvect(0x28, int28_handler);
    _dos_setvect(0x2F, int2f_handler);

    printf("\nVMODEM v%s installed (INT 14h/1Ch/28h/2Fh hooked).\n",
           VMODEM_VER_STR);
    printf("Active:");
    for (i = 0; i < MAX_PORTS; i++)
        if (g_state.ports[i].initialized)
            printf(" COM%d", i + 1);
    printf("\n");

    /*
     * Fix NE2000 register state for packet reception.
     *
     * DOSBox-X's NE2000_Poller silently drops ALL incoming packets if:
     *   - TCR loopback bits (LB0/LB1) are non-zero, OR
     *   - DCR loopback-select (LS) bit is zero
     *
     * The standard NE2000 init sequence sets TCR=0x02 (internal loopback)
     * during setup, then TCR=0x00 after starting the NIC.  If the Crynwr
     * packet driver's set_rcv_mode does a partial re-init and leaves TCR
     * in loopback mode, no packets will ever be received.
     *
     * Fix: force TCR=0x00 (normal operation), DCR with LS=1, clear ISR,
     * and set IMR to enable receive/transmit interrupts.
     *
     * TODO: Make the NE2000 I/O base configurable instead of hardcoding.
     */
    {
        outp(0x300, 0x22);                 /* page 0, started, abort DMA */
        outp(0x30D, 0x00);                 /* TCR: normal (no loopback) */
        outp(0x30E, 0x49);                 /* DCR: WTS=1, LS=1, FT=01 */
        outp(0x307, 0xFF);                 /* clear all ISR bits */
        outp(0x30F, 0x1F);                 /* IMR: enable PRX+PTX+RXE+TXE+OVW */
        /* Leave CR=0x22 — do NOT restore a stale CR value that might
         * have a Remote DMA command in progress (e.g., CR=0x0A). */
    }

    /* Get InDOS flag address — used by poll.c to check if DOS file I/O is safe */
    {
        union REGS r;
        struct SREGS sr;
        r.h.ah = 0x34;
        int86x(0x21, &r, &r, &sr);
        g_indos_ptr = (unsigned char __far *)MK_FP(sr.es, r.x.bx);
    }

    /* Open debug log file — the handle stays valid after TSR.
     * poll.c flushes new debug content to this handle periodically. */
    {
        int fd = -1;
        g_state.dbglog_fd = -1;
        if (_dos_creat("VMODEM.LOG", 0, &fd) == 0) {
            unsigned written = 0;
            g_state.dbglog_fd = (short)fd;
            /* Verify the handle works with a test write */
            _dos_write(fd, "=== VMODEM debug log ===\r\n", 25, &written);
            _dos_commit(fd);
            printf("Debug log: VMODEM.LOG (fd=%d, wrote=%u)\n", fd, written);
        }
    }
    /* Save our PSP segment — needed by poll.c to switch PSP for file I/O.
     * File handles are per-PSP; after TSR, the active PSP belongs to
     * whatever program is running. We must switch to our PSP before
     * using our file handles. */
    g_state.our_psp = _psp;

    dbg("VMODEM loaded\n");

    /* Go TSR:
     * paras = paragraphs from PSP to end of full DGROUP (including near heap).
     * (DS - _psp) covers PSP + code segment + start of DGROUP.
     * + 0x1000 = 4096 paragraphs = 64KB for the full DGROUP.
     */
    {
        unsigned short ds_seg = FP_SEG(&g_state);
        unsigned short paras  = (unsigned short)(ds_seg - _psp) + 0x1000U;
        printf("Resident size: %u bytes\n", (unsigned)(paras * 16u));
        fflush(stdout);       /* _dos_keep() never returns — flush now */
        _dos_keep(0, paras);  /* never returns */
    }
    return 0;
}
