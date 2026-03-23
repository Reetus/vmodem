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

#include "vmodem_mux.h"          /* StatusBlock, MUX_*, MAX_PORTS, etc. */

#define RING_SIZE        512          /* rx ring buffer size (power-of-2!) */

/* Maximum hunt groups (shared listen across multiple COM ports) */
#define MAX_HUNT_GROUPS  2

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
 * chain can easily consume 2-3 KB; 16 KB gives adequate headroom. */
#define PRIV_STACK_SIZE  16384

/* -----------------------------------------------------------------------
 * Port connection modes
 * --------------------------------------------------------------------- */

typedef enum {
    PORT_DISC       = 0,    /* disconnected, not listening */
    PORT_LISTEN     = 1,    /* listening for incoming TCP connections */
    PORT_CONN       = 2     /* actively connected to a remote host */
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

    /* Flags */
    unsigned char  initialized; /* 1 = this port is managed by VMODEM */
    signed char    huntGroupIdx; /* -1 = standalone, 0..MAX_HUNT_GROUPS-1 = group */

    /* Telnet IAC parser state machine */
    unsigned char  iac_state;   /* IAC_NORMAL / IAC_SAW_FF / IAC_SAW_CMD */
    unsigned char  iac_cmd;     /* the command byte we saw (WILL/WONT/DO/DONT) */
    unsigned char  neg_echo;    /* 1 = ECHO option negotiated */
    unsigned char  neg_sga;     /* 1 = SGA option negotiated  */
    unsigned char  pending_close;/* 1 = close socket on next poll cycle */
    unsigned char  dtr_ignore;  /* 1 = ignore DTR drops (&D0 mode) */
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
    unsigned char  eager_listen;     /* 1 = listen immediately, don't wait for AH=04h */
    unsigned char  _pad2;

    /* Debug log — circular text buffer + optional file output */
    #define DBGLOG_SIZE 2048
    char           dbglog[DBGLOG_SIZE];
    unsigned short dbglog_head;          /* next write position */
    unsigned short dbglog_count;         /* bytes in buffer */
    short          dbglog_fd;            /* DOS file handle, -1 if none */
    unsigned short our_psp;              /* VMODEM's PSP segment (for file I/O from TSR) */

    PortState      ports[MAX_PORTS];

    /* Hunt groups: shared listen socket across multiple COM ports */
    struct {
        TcpSocket     *listenSock;  /* shared listen socket (NULL = inactive) */
        unsigned short tcpPort;     /* TCP port to listen on */
        unsigned char  portMask;    /* bitmask of member COM ports (bits 0-3) */
        unsigned char  active;      /* 1 = configured */
    } huntGroups[MAX_HUNT_GROUPS];

    /* External sockets: outgoing TCP via MUX_SOCK_* API */
    struct {
        TcpSocket     *sock;
        unsigned char  state;    /* EXT_SOCK_* */
        unsigned char  pending_connect; /* 1 = poll.c should call connectNonBlocking */
        IpAddr_t       conn_ip;
        uint16_t       conn_port;
    } ext_sockets[MAX_EXT_SOCKETS];

    /* MUX_SOCK return value — written by INT 2Fh handler, read by caller
     * via MUX_SOCK_STATUS on handle 0xFE (special query).
     * Works around [bp+22] not reliably reflecting AX on return. */
    unsigned short mux_sock_result;

    /* DNS resolve state for MUX_SOCK_RESOLVE */
    unsigned char  dns_resolve_state;   /* DNS_RESOLVE_* */
    unsigned char  dns_resolve_pad;
    char           dns_hostname[64];    /* hostname being resolved */
    IpAddr_t       dns_resolved_ip;     /* result IP address */
} VModemState;

/* StatusBlock is defined in vmodem_mux.h (shared with vmodctl, comdiag) */

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
int fossil_is_init(int port_idx); /* 1 if AH=04h was called, 0 after AH=05h */
int fossil_flush_tx(int port_idx); /* drain TX ring to TCP socket */
void fossil_clear_tx(int port_idx); /* discard any buffered TX data */

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
void at_set_ringing_silent(int port_idx);
void at_set_cmd_mode(int port_idx);
unsigned char at_is_connect_pending(int port_idx);
void at_check_ring(int port_idx);

/* vmodem.c - control commands (callable from INT 2Fh handler) */
void cmd_listen(int port_idx, unsigned short tcp_port);
void cmd_disconnect(int port_idx);
void cmd_hunt_listen(unsigned char port_mask, unsigned short tcp_port);
void cmd_status(StatusBlock __far *sb);

#endif /* _VMODEM_H */
