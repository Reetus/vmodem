/*
 * vmodem_mux.h - Shared MUX interface definitions
 *
 * Defines the StatusBlock struct and MUX constants used by both the
 * VMODEM TSR and standalone utilities (VMODCTL, COMDIAG) that
 * communicate via INT 2Fh.  No mTCP headers required.
 *
 * WARNING: The StatusBlock layout MUST match cmd_status() in vmodem.c.
 * If you change this struct, update cmd_status() and rebuild everything.
 */

#ifndef VMODEM_MUX_H
#define VMODEM_MUX_H

#define MAX_PORTS        4            /* COM1-COM4 */

/* INT 2Fh (Multiplex) handler ID */
#define MUX_ID           0xC3

/* INT 2Fh sub-function codes (placed in AL when AH = MUX_ID) */
#define MUX_INSTALL_CHK  0x00   /* AL->FFh if installed; ES:BX->VModemState */
#define MUX_LISTEN       0x01   /* CX=port(0-3), DX=TCP port             */
/*      MUX 0x02 reserved (was MUX_CONNECT) */
#define MUX_DISCONNECT   0x03   /* CX=port(0-3)                          */
#define MUX_STATUS       0x04   /* ES:BX->StatusBlock buffer             */
#define MUX_POLL         0x05   /* trigger one do_mtcp_poll() cycle      */
#define MUX_DEBUGLOG     0x06   /* ES:BX->buffer, CX=size; returns log   */
#define MUX_HUNT_LISTEN  0x07   /* CL=portMask, DX=TCP port              */
#define MUX_UNLOAD       0xFF   /* restore vectors, mark unloaded        */

/* ---- External socket API (outgoing TCP via VMODEM's mTCP stack) ---- */
#define MUX_SOCK_ALLOC   0x10   /* allocate socket; ret AL=handle or 0xFF */
#define MUX_SOCK_CONNECT 0x11   /* CL=handle, DX=port, ES:BX->4-byte IP  */
#define MUX_SOCK_STATUS  0x12   /* CL=handle; ret AL=state                */
#define MUX_SOCK_SEND    0x13   /* CL=handle, DX=len, ES:BX->data         */
#define MUX_SOCK_RECV    0x14   /* CL=handle, DX=bufsz, ES:BX->buffer     */
#define MUX_SOCK_CLOSE   0x15   /* CL=handle; ret AL=0                    */
#define MUX_SOCK_RESULT  0x16   /* ret AX=last mux_sock_result            */
#define MUX_SOCK_RESOLVE 0x17   /* ES:BX->hostname; initiates DNS query   */
#define MUX_SOCK_RESOLVE_RESULT 0x18  /* ES:BX->4-byte IP buf; ret AL=state */
#define MUX_PORT_NAWS    0x19   /* CL=port(0-3); ret DX=cols, SI=rows    */
#define MUX_PORT_TTYPE   0x1A   /* CL=port(0-3), DX=bufsz, ES:BX->buf   */
#define MUX_SOCK_RECV_READY 0x1B /* CL=handle; ret AX=1 if data waiting  */

#define MAX_EXT_SOCKETS  4

/* External socket states (returned by MUX_SOCK_STATUS) */
#define EXT_SOCK_FREE          0
#define EXT_SOCK_CONNECTING    1
#define EXT_SOCK_ESTABLISHED   2
#define EXT_SOCK_REMOTE_CLOSED 3
#define EXT_SOCK_ERROR         4
#define EXT_SOCK_CLOSING       5

/* DNS resolve states (returned by MUX_SOCK_RESOLVE_RESULT) */
#define DNS_RESOLVE_IDLE       0
#define DNS_RESOLVE_PENDING    1
#define DNS_RESOLVE_OK         2
#define DNS_RESOLVE_ERROR      3

#define VMODEM_SIG       "VMODEM10"
#define VMODEM_SIG_LEN   8

#define STATUS_BLOCK_MAGIC 0xA55A

typedef struct {
    unsigned short magic;               /* STATUS_BLOCK_MAGIC */
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
    } ports[MAX_PORTS];
} StatusBlock;

#endif /* VMODEM_MUX_H */
