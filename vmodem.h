/*
 * vmodem.h - VMODEM TSR: shared structures, defines, and externs
 *
 * VMODEM is a FOSSIL driver (FSC-0015) that intercepts INT 14h and
 * routes serial traffic over TCP/IP using the mTCP library.
 * Up to 4 COM ports are supported.
 *
 * Memory model: small (-ms).  All mTCP near-heap allocations live in
 * DGROUP alongside our static data, so everything stays resident in one
 * contiguous segment when we TSR.
 */

#ifndef _VMODEM_H
#define _VMODEM_H

#include CFG_H
#include "types.h"
#include "tcp.h"
#include "tcpsockm.h"
#include "utils.h"

/* -----------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */

#define VMODEM_VER_STR   "1.0"
#define VMODEM_SIG       "VMODEM10"   /* 8-byte detection signature */
#define VMODEM_SIG_LEN   8

#define MAX_PORTS        4            /* COM1-COM4 */
#define RING_SIZE        512          /* rx ring buffer size (power-of-2!) */

/* INT 2Fh (Multiplex) handler ID.  Pick an ID unlikely to conflict. */
#define MUX_ID           0xC3

/* INT 2Fh sub-function codes (placed in AL when AH = MUX_ID) */
#define MUX_INSTALL_CHK  0x00   /* AL→FFh if installed; ES:BX→VModemState */
#define MUX_LISTEN       0x01   /* CX=port(0-3), DX=TCP port             */
#define MUX_CONNECT      0x02   /* CX=port, DX=TCP port, ES:SI→host str  */
#define MUX_DISCONNECT   0x03   /* CX=port(0-3)                          */
#define MUX_STATUS       0x04   /* ES:BX→StatusBlock buffer (128 bytes)  */
#define MUX_POLL         0x05   /* trigger one do_mtcp_poll() cycle      */
#define MUX_DEBUGLOG     0x06   /* ES:BX→buffer, CX=size; returns log    */
#define MUX_UNLOAD       0xFF   /* restore vectors, mark unloaded        */

/* Telnet IAC parser states */
#define IAC_NORMAL       0   /* normal data mode */
#define IAC_SAW_FF       1   /* received 0xFF (IAC), waiting for command */
#define IAC_SAW_CMD      2   /* received command byte, waiting for option */

/* Telnet protocol bytes */
#define TEL_IAC          0xFF
#define TEL_WILL         0xFB
#define TEL_WONT         0xFC
#define TEL_DO           0xFD
#define TEL_DONT         0xFE
#define TEL_SB           0xFA   /* subnegotiation begin */
#define TEL_SE           0xF0   /* subnegotiation end   */

/* Telnet option codes */
#define TELOPT_ECHO      0x01
#define TELOPT_SGA       0x03   /* Suppress Go Ahead */

/* Private stack for INT 8h/28h handlers.  mTCP's TCP/ARP/packet processing
 * chain can easily consume 2-3 KB; 4 KB gives adequate headroom. */
#define PRIV_STACK_SIZE  16384

/* -----------------------------------------------------------------------
 * Port connection modes
 * --------------------------------------------------------------------- */

typedef enum {
    PORT_DISC       = 0,    /* disconnected, not listening */
    PORT_LISTEN     = 1,    /* listening for incoming TCP connections */
    PORT_CONN       = 2,    /* actively connected to a remote host */
    PORT_RESOLVING  = 3,    /* DNS query in flight (async connect pending) */
    PORT_CONNECTING = 4     /* TCP connect in progress (non-blocking) */
} PortMode;

/* -----------------------------------------------------------------------
 * RingBuf - simple power-of-2 circular byte buffer
 *
 * INT 14h AH=01h (TX) writes to the TCP send path directly.
 * INT 14h AH=02h (RX) reads from head (consumer).
 * INT 28h drain loop writes to tail (producer).
 * No explicit lock needed: on 16-bit DOS head/tail are atomic words.
 * --------------------------------------------------------------------- */

typedef struct {
    unsigned char  data[RING_SIZE];
    unsigned short head;    /* consumer index */
    unsigned short tail;    /* producer index */
    unsigned short count;   /* bytes available */
} RingBuf;

/* -----------------------------------------------------------------------
 * PortState - per-COM-port state (lives in resident DGROUP)
 * --------------------------------------------------------------------- */

typedef struct {
    PortMode       mode;
    TcpSocket     *sock;        /* active data socket (NULL if none) */
    TcpSocket     *listenSock;  /* listening socket for server mode  */
    RingBuf        rx;          /* received data waiting for AH=02h  */

    /* Connection parameters */
    IpAddr_t       remoteIP;
    unsigned short remotePort;
    unsigned short localPort;

    /* Async connect: hostname stored here during PORT_RESOLVING/PORT_CONNECTING */
    char           hostname[64];

    /* Flags */
    unsigned char  initialized; /* 1 = this port is managed by VMODEM */

    /* Telnet IAC parser state machine */
    unsigned char  iac_state;   /* IAC_NORMAL / IAC_SAW_FF / IAC_SAW_CMD */
    unsigned char  iac_cmd;     /* the command byte we saw (WILL/WONT/DO/DONT) */
    unsigned char  neg_echo;    /* 1 = ECHO option negotiated */
    unsigned char  neg_sga;     /* 1 = SGA option negotiated  */
    unsigned char  _pad0;       /* explicit pad: keep struct size even for -zp2 */
    unsigned long  conn_tick;   /* BIOS tick when connection entered PORT_CONN */
    unsigned long  last_rx_tick;/* BIOS tick when last TCP data was received */
    unsigned long  last_tx_tick;/* BIOS tick when last FOSSIL TX byte was sent */
    unsigned short idle_timeout;/* idle disconnect timeout in seconds (0=disabled) */
} PortState;

/* -----------------------------------------------------------------------
 * VModemState - root resident structure
 *
 * Placed at a fixed location in DGROUP so that after TSR installation the
 * companion utility (or a second VMODEM invocation) can find it through
 * the INT 2Fh installation check.
 * --------------------------------------------------------------------- */

/*
 * FOSSIL_STUB_SIZE: the FOSSIL signature stub is built dynamically at
 * runtime in g_state.fossil_stub[].  Layout:
 *   +0: EB 07        jmp short past_sig
 *   +2: 90 90 90 90  nops
 *   +6: 54 19        dw 1954h  (FOSSIL signature, little-endian)
 *   +8: 1B           db 1Bh    (max function number)
 *   +9: EA xx xx xx xx  jmp far seg:off  (to int14_real_handler)
 */
#define FOSSIL_STUB_SIZE 14

typedef struct {
    unsigned char  fossil_stub[FOSSIL_STUB_SIZE]; /* MUST be first — IVT points here */
    char           sig[VMODEM_SIG_LEN]; /* "VMODEM10" — detection sentinel */
    unsigned short our_seg;     /* DS value at install time (sanity check) */
    unsigned char  busy;        /* mTCP polling re-entrancy guard          */
    unsigned char  _pad0;       /* explicit pad: keep struct naturally aligned */
    unsigned long  poll_count;  /* debug: total do_mtcp_poll() calls       */
    unsigned long  pkt_count;   /* debug: packets processed by PACKET_PROCESS */
    unsigned short arp_count;   /* debug: ARP packets seen */
    unsigned short ip_count;    /* debug: IP packets seen  */
    unsigned short tcp_pend_sent;    /* debug: Tcp::Pending_Sent snapshot */
    unsigned short tcp_pend_outgoing; /* debug: Tcp::Pending_Outgoing snapshot */
    unsigned char  active_sockets;   /* debug: TcpSocketMgr::getActiveSockets() */
    unsigned char  poll_phase;       /* debug: which step of do_mtcp_poll we're in */

    /* Debug log — circular text buffer + optional file output */
    #define DBGLOG_SIZE 2048
    char           dbglog[DBGLOG_SIZE];
    unsigned short dbglog_head;          /* next write position */
    unsigned short dbglog_count;         /* bytes in buffer */
    short          dbglog_fd;            /* DOS file handle, -1 if none */
    unsigned short our_psp;              /* VMODEM's PSP segment (for file I/O from TSR) */

    PortState      ports[MAX_PORTS];
} VModemState;

/* -----------------------------------------------------------------------
 * StatusBlock - returned by MUX_STATUS to callers
 * --------------------------------------------------------------------- */

#define STATUS_BLOCK_MAGIC 0xA55A

typedef struct {
    unsigned short magic;               /* STATUS_BLOCK_MAGIC */
    unsigned long  poll_count;          /* debug: total poll calls */
    unsigned long  pkt_count;           /* debug: packets processed */
    unsigned short arp_count;           /* debug: ARP packets */
    unsigned short ip_count;            /* debug: IP packets  */
    /* mTCP ARP stats — read directly from Arp:: class statics */
    unsigned long  arp_req_recv;        /* Arp::RequestsReceived */
    unsigned long  arp_rep_sent;        /* Arp::RepliesSent */
    unsigned long  arp_req_sent;        /* Arp::RequestsSent */
    unsigned long  arp_rep_recv;        /* Arp::RepliesReceived */
    unsigned char  buf_low_free;        /* Buffer_lowFreeCount */
    unsigned char  buf_first;           /* Buffer_first (ring head) */
    unsigned char  buf_next;            /* Buffer_next  (ring tail) */
    unsigned char  _pad0;
    unsigned long  pkts_recv;           /* Packets_received (packet driver) */
    unsigned long  pkts_sent;           /* Packets_sent */
    unsigned long  pkts_send_errs;      /* Packets_send_errs */
    unsigned long  pkts_dropped;        /* Packets_dropped */
    unsigned long  unhandled_count;     /* packets with unknown EtherType */
    unsigned short first_unhandled_et;  /* EtherType of first unhandled pkt */
    unsigned short tcp_pend_sent;       /* Tcp::Pending_Sent */
    unsigned short tcp_pend_outgoing;   /* Tcp::Pending_Outgoing */
    unsigned char  active_sockets;      /* TcpSocketMgr active count */
    unsigned char  poll_phase;          /* which poll step we're in */
    struct {
        unsigned char mode;             /* PortMode value */
        unsigned char initialized;
        unsigned short localPort;
        unsigned short remotePort;
        unsigned char remoteIP[4];
        unsigned short rxCount;         /* bytes waiting in rx ring */
    } ports[MAX_PORTS];
} StatusBlock;

/* -----------------------------------------------------------------------
 * Global resident data (defined in vmodem.c)
 * --------------------------------------------------------------------- */

extern VModemState           g_state;
extern unsigned char         g_priv_stack[PRIV_STACK_SIZE];
extern unsigned short        g_priv_stack_top; /* near offset of top of g_priv_stack */
extern unsigned short        g_save_ss;        /* saved SS during stack switch */
extern unsigned short        g_save_sp;        /* saved SP during stack switch */

/* Saved interrupt vectors */
extern void (__interrupt __far *old_int1c)(void);
extern void (__interrupt __far *old_int14)(void);
extern void (__interrupt __far *old_int28)(void);
extern void (__interrupt __far *old_int2f)(void);

/* -----------------------------------------------------------------------
 * Function prototypes
 * --------------------------------------------------------------------- */

/* vmodem.c - debug log */
void dbg(const char *msg);
void dbg_hex(const char *prefix, unsigned char val);

/* vmodem.c - IP parsing helper */
int parse_ipaddr(const char *str, IpAddr_t ip);  /* 0=ok, -1=not an IP */

/* ringbuf.c */
void ring_init(RingBuf *r);
int  ring_put(RingBuf *r, unsigned char b);   /* 0=ok, -1=full */
int  ring_get(RingBuf *r);                    /* byte or -1=empty */
int  ring_count(RingBuf *r);

/* telnet.c */
void telnet_on_connect(int port_idx);
int  telnet_filter(PortState *p, unsigned char b);
void telnet_send_byte(PortState *p, unsigned char b);
void telnet_send_raw(PortState *p, unsigned char *buf, int len);
void telnet_send_text(int port_idx, const char *msg);

/* int14.c */
extern "C" {
    void __interrupt __far int14_real_handler(void);  /* FOSSIL INT 14h handler */
}
int fossil_flush_tx(int port_idx); /* drain TX ring to TCP socket */

/* int8.c */
void __interrupt __far int1c_handler(void);
void __interrupt __far int28_handler(void);
void __interrupt __far int2f_handler(void);
void do_mtcp_poll(void);
void poll_on_priv_stack(void);

/* atcmd.c - AT command interpreter */
void at_init(int port_idx);
int  at_input(int port_idx, unsigned char b);  /* 1=consumed, 0=pass to TCP */
void at_send_ring(int port_idx);
void at_send_connect(int port_idx);
void at_send_no_carrier(int port_idx);
unsigned char at_get_s0(int port_idx);
unsigned char at_is_ringing(int port_idx);
unsigned char at_is_connect_pending(int port_idx);
void at_check_ring(int port_idx);

/* vmodem.c - control commands (callable from INT 2Fh handler) */
void cmd_listen(int port_idx, unsigned short tcp_port);
void cmd_connect(int port_idx, unsigned short tcp_port,
                 char __far *hostname);
void cmd_disconnect(int port_idx);
void cmd_status(StatusBlock __far *sb);

#endif /* _VMODEM_H */
