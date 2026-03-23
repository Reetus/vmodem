/*
 * vmodem.c - VMODEM TSR main entry point
 *
 * Responsibilities:
 *   1. Parse command-line arguments (/L /E /U /H)
 *   2. Detect whether the TSR is already loaded (via INT 2Fh)
 *   3. If loaded: route /L commands to the resident TSR
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

    if (port_idx < 0 || port_idx >= MAX_PORTS)
        return;
    p = &g_state.ports[port_idx];
    cmd_disconnect(port_idx);

    /* Don't open the listen socket yet — wait for AH=04h (FOSSIL init).
     * This prevents connections arriving before the BBS is ready. */
    p->listenSock  = NULL;
    p->sock        = NULL;
    p->localPort   = tcp_port;
    p->mode        = PORT_DISC;
    p->initialized = 1;
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
        /* Don't close directly — defer to INT 28h poll cycle where
         * the packet driver can transmit reliably. */
        dbg("[CMD-DISC]");
        p->pending_close = 1;
    }
    /* Don't tear down listenSock or change mode here —
     * the poll cycle POLL-CLOSE handler will do that. */
}

/* -----------------------------------------------------------------------
 * cmd_hunt_listen — set up a hunt group (shared listen across COM ports)
 * --------------------------------------------------------------------- */

void cmd_hunt_listen(unsigned char port_mask, unsigned short tcp_port)
{
    int i, slot = -1;

    /* Find a free hunt group slot */
    for (i = 0; i < MAX_HUNT_GROUPS; i++) {
        if (!g_state.huntGroups[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        printf("VMODEM: no free hunt group slots\n");
        return;
    }

    g_state.huntGroups[slot].portMask   = port_mask;
    g_state.huntGroups[slot].tcpPort    = tcp_port;
    g_state.huntGroups[slot].listenSock = NULL;
    g_state.huntGroups[slot].active     = 1;

    /* Initialize each member port */
    for (i = 0; i < MAX_PORTS; i++) {
        if (!(port_mask & (1 << i)))
            continue;
        PortState *p = &g_state.ports[i];
        p->listenSock    = NULL;
        p->sock          = NULL;
        p->localPort     = tcp_port;
        p->mode          = PORT_DISC;
        p->initialized   = 1;
        p->huntGroupIdx  = (signed char)slot;
        ring_init(&p->rx);
    }
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
    int            type;     /* 0=listen, 2=hunt_listen */
    int            com;      /* 0-based first port */
    int            com_last; /* 0-based last port (-1 if single) */
    unsigned short tcp_port;
} PortArg;

static int     want_unload  = 0;
static int     want_help    = 0;
static int     eager_listen = 0;
static int     num_port_args = 0;
static PortArg port_args[MAX_PORT_ARGS];
static char    log_file[64] = "";  /* debug log filename, empty = no log */

static void print_help(void)
{
    printf(
        "VMODEM v%s - Virtual Serial Port over Telnet/TCP\n\n"
        "Usage: VMODEM [options]\n\n"
        "  /L:n:port         Listen on COM n for Telnet on TCP port\n"
        "  /L:n-m:port       Hunt group: share TCP port across COM n-m\n"
        "  /E                Eager listen (don't wait for FOSSIL init)\n"
        "  /D:file           Write debug log to file (e.g. /D:VMODEM.LOG)\n"
        "  /U                Unload resident copy\n"
        "  /H or /?          Help\n\n"
        "Examples:\n"
        "  VMODEM /L:1:23              COM1 listens on port 23\n"
        "  VMODEM /L:1:23 /E           Listen immediately, no FOSSIL init needed\n"
        "  VMODEM /L:1-4:2323          Hunt group: COM1-4 share port 2323\n"
        "  VMODEM /L:1:23 /D:VMODEM.LOG  Enable debug logging to file\n"
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
        if (c == 'U') { want_unload = 1; continue; }
        if (c == 'E') { eager_listen = 1; continue; }

        if (c == 'D' && arg[2] == ':') {
            /* /D:filename — enable debug log file */
            strncpy(log_file, arg + 3, sizeof(log_file) - 1);
            log_file[sizeof(log_file) - 1] = '\0';
            if (log_file[0] == '\0') {
                printf("Bad /D: missing filename\n"); return -1;
            }
            continue;
        }

        if (c == 'L' && arg[2] == ':') {
            char *p = arg + 3;
            int comn = *p - '0';
            int comn_last = -1;
            unsigned short port;
            char *port_str;

            if (comn < 1 || comn > 4) {
                printf("Bad /L: %s\n", arg); return -1;
            }

            /* Check for range: /L:1-4:port */
            if (p[1] == '-') {
                comn_last = p[2] - '0';
                if (comn_last < 1 || comn_last > 4 || comn_last < comn || p[3] != ':') {
                    printf("Bad /L range: %s\n", arg); return -1;
                }
                port_str = p + 4;
            } else if (p[1] == ':') {
                port_str = p + 2;
            } else {
                printf("Bad /L: %s\n", arg); return -1;
            }

            port = (unsigned short)atoi(port_str);
            if (!port) { printf("Bad port in: %s\n", arg); return -1; }
            if (num_port_args >= MAX_PORT_ARGS) {
                printf("Too many port args.\n"); return -1;
            }
            port_args[num_port_args].type     = (comn_last > 0) ? 2 : 0;
            port_args[num_port_args].com      = comn - 1;
            port_args[num_port_args].com_last = (comn_last > 0) ? comn_last - 1 : -1;
            port_args[num_port_args].tcp_port = port;
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
            } else if (pa->type == 2) {
                unsigned char mask = 0;
                int j;
                for (j = pa->com; j <= pa->com_last; j++)
                    mask |= (1 << j);
                r.h.al = MUX_HUNT_LISTEN;
                r.x.cx = (unsigned short)mask;
                r.x.dx = pa->tcp_port;
                int86x(0x2F, &r, &r, &sr);
                printf("  COM%d-%d: hunt group on TCP port %u\n",
                       pa->com + 1, pa->com_last + 1, pa->tcp_port);
            }
        }
        return 0;
    }

    if (!num_port_args && !installed) { print_help(); return 0; }

    if (installed) {
        printf("VMODEM already installed. Use VMODCTL /S for status.\n");
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

    /* Foreground ARP test: confirm network is working before going TSR. */
    {
        IpAddr_t gw;
        EthAddr_t gw_eth;
        unsigned long tstart, tnow;
        int got_reply = 0;

        gw[0] = Gateway[0]; gw[1] = Gateway[1];
        gw[2] = Gateway[2]; gw[3] = Gateway[3];

        printf("ARP test: resolving gateway %u.%u.%u.%u ...\n",
               gw[0], gw[1], gw[2], gw[3]);
        Arp::resolve(gw, gw_eth);

        tstart = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
        while (1) {
            PACKET_PROCESS_SINGLE;
            Arp::driveArp();
            Tcp::drivePackets();

            if (Arp::resolve(gw, gw_eth) == 0) {
                printf("ARP test: OK\n");
                got_reply = 1;
                break;
            }

            tnow = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
            if (tnow - tstart > 18UL * 5) break;
        }

        if (!got_reply)
            printf("ARP test: FAILED (no reply from gateway)\n");

        fflush(stdout);
    }

    /* Initialise resident state */
    memset(&g_state, 0, sizeof(g_state));
    memcpy(g_state.sig, VMODEM_SIG, VMODEM_SIG_LEN);
    g_state.our_seg      = FP_SEG(&g_state);
    g_state.busy         = 0;
    g_state.eager_listen = (unsigned char)eager_listen;

    /* Set private stack top (near offset within DGROUP) */
    g_priv_stack_top = (unsigned short)FP_OFF(g_priv_stack) +
                       (unsigned short)(PRIV_STACK_SIZE - 4);

    /* Initialize huntGroupIdx for all ports */
    for (i = 0; i < MAX_PORTS; i++)
        g_state.ports[i].huntGroupIdx = -1;

    /* Process port arguments */
    for (i = 0; i < num_port_args; i++) {
        PortArg *pa = &port_args[i];
        if (pa->type == 0) {
            cmd_listen(pa->com, pa->tcp_port);
            printf("  COM%d: listening on TCP port %u\n",
                   pa->com + 1, pa->tcp_port);
        } else if (pa->type == 2) {
            unsigned char mask = 0;
            int j;
            for (j = pa->com; j <= pa->com_last; j++)
                mask |= (1 << j);
            cmd_hunt_listen(mask, pa->tcp_port);
            printf("  COM%d-%d: hunt group on TCP port %u\n",
                   pa->com + 1, pa->com_last + 1, pa->tcp_port);
        }
    }

    /* Eager listen: open listen sockets immediately instead of waiting
     * for FOSSIL init (AH=04h).  Useful for standalone/test setups. */
    if (eager_listen) {
        for (i = 0; i < MAX_PORTS; i++) {
            PortState *p = &g_state.ports[i];
            if (p->initialized && p->localPort != 0 &&
                p->listenSock == NULL && p->huntGroupIdx < 0) {
                TcpSocket *ls = TcpSocketMgr::getSocket();
                if (ls && ls->listen(p->localPort, 2048) == 0) {
                    p->listenSock = ls;
                    p->mode = PORT_LISTEN;
                    printf("  COM%d: eager listen active\n", i + 1);
                } else {
                    if (ls) TcpSocketMgr::freeSocket(ls);
                    printf("  COM%d: eager listen FAILED\n", i + 1);
                }
            }
        }
        /* Hunt groups */
        for (i = 0; i < MAX_HUNT_GROUPS; i++) {
            if (g_state.huntGroups[i].active &&
                g_state.huntGroups[i].listenSock == NULL) {
                TcpSocket *ls = TcpSocketMgr::getSocket();
                if (ls && ls->listen(g_state.huntGroups[i].tcpPort, 2048) == 0) {
                    int j;
                    g_state.huntGroups[i].listenSock = ls;
                    for (j = 0; j < MAX_PORTS; j++) {
                        if (g_state.huntGroups[i].portMask & (1 << j))
                            g_state.ports[j].mode = PORT_LISTEN;
                    }
                    printf("  Hunt group %d: eager listen active\n", i);
                } else {
                    if (ls) TcpSocketMgr::freeSocket(ls);
                    printf("  Hunt group %d: eager listen FAILED\n", i);
                }
            }
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

        /* Use DOS INT 21h AH=25h to set INT 14h vector.
         * Direct IVT writes (MK_FP(0,0x50)) are not tracked by JemmEx's
         * V86 monitor, causing corrupt dispatch under memory managers. */
        _dos_setvect(0x14,
            (void (__interrupt __far *)()) MK_FP(stub_seg, stub_off));
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

    /* Open debug log file if /D:filename was specified.
     * The handle stays valid after TSR; poll.c flushes to it periodically. */
    g_state.dbglog_fd = -1;
    if (log_file[0] != '\0') {
        int fd = -1;
        if (_dos_creat(log_file, 0, &fd) == 0) {
            unsigned written = 0;
            g_state.dbglog_fd = (short)fd;
            _dos_write(fd, "=== VMODEM debug log ===\r\n", 25, &written);
            _dos_commit(fd);
            printf("Debug log: %s (fd=%d, wrote=%u)\n", log_file, fd, written);
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
