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
