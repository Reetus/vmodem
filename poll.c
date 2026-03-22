/*
 * poll.c - do_mtcp_poll() separated into its own translation unit
 *
 * IMPORTANT: This function MUST be in a separate .c file from int8.c.
 * Open Watcom's optimizer merges epilogues between functions in the same
 * translation unit.  When poll_on_priv_stack() (which does a stack switch)
 * and do_mtcp_poll() share epilogue code, the stack pop sequence becomes
 * incorrect because the functions have different register save sets.
 * Separating them into different TUs prevents the optimizer from merging
 * their epilogues.
 */

#include CFG_H
#include <string.h>
#include <dos.h>
#include <i86.h>
#include <conio.h>
#include "vmodem.h"
#include "packet.h"
#include "tcp.h"
#include "tcpsockm.h"
#include "arp.h"
#include "ip.h"
#include "udp.h"
#include "dns.h"
#include "utils.h"

/* From vmodem.c — InDOS flag pointer (NULL if not initialized) */
extern unsigned char __far *g_indos_ptr;
/* From int8.c — set to 1 during INT 28h context (DOS file I/O safe) */
extern unsigned char g_dos_safe;
/* From int14.c — set to 1 during INT 14h poll (software interrupt, DOS I/O safe) */
extern unsigned char g_int14_safe;

/* -----------------------------------------------------------------------
 * do_mtcp_poll
 *
 * Drives all mTCP layers, then services each port:
 *   - PORT_RESOLVING  → drive DNS, check result, start TCP connect when ready
 *   - PORT_CONNECTING → drive TCP, check if connect complete
 *   - PORT_LISTEN     → check for accepted connections
 *   - PORT_CONN       → drain TCP receive buffer into ring buffer
 *
 * Called from int28_handler on the private stack.
 * Must NOT be called re-entrantly (the busy flag in int28_handler prevents this).
 * --------------------------------------------------------------------- */

void do_mtcp_poll(void)
{
    int i;

    g_state.poll_count++;
    g_state.poll_phase = 0;  /* entering poll */

    /* Step 0: Periodic ARP keepalive for SLIRP/pcap.
     * Send ARP request every ~1 second to keep the path active. */
    {
        static unsigned long last_keepalive_tick = 0;
        unsigned long now_tick = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
        if (now_tick - last_keepalive_tick >= 18UL) {
            last_keepalive_tick = now_tick;
            Arp::sendArpRequestPacket(Gateway);
        }
    }

    g_state.poll_phase = 1;  /* packet processing */
    /* Step 1: Drive the mTCP network stack.
     * Process up to 4 packets per poll cycle to catch SLIRP-queued
     * TCP packets that arrive asynchronously after an ARP keepalive. */
    {
        int pkt_loops = 4;
        while (pkt_loops-- > 0 && Buffer_first != Buffer_next) {
            g_state.pkt_count++;
            PACKET_PROCESS_SINGLE;
        }
    }
    Arp::driveArp();

    /* Snapshot TCP pending counters for diagnostics */
    g_state.tcp_pend_sent = Tcp::Pending_Sent;
    g_state.tcp_pend_outgoing = Tcp::Pending_Outgoing;
    g_state.active_sockets = TcpSocketMgr::getActiveSockets();

    g_state.poll_phase = 3;  /* drivePackets */
    Tcp::drivePackets();
    g_state.poll_phase = 4;  /* DNS */
    Dns::drivePendingQuery();

    g_state.poll_phase = 5;  /* port servicing */
    /* Step 2: Service each port */
    for (i = 0; i < MAX_PORTS; i++) {
        PortState *p = &g_state.ports[i];

        if (!p->initialized)
            continue;

        switch (p->mode) {

        case PORT_RESOLVING:
        {
            IpAddr_t resolved;
            int8_t rc;

            if (Dns::isQueryPending())
                Dns::drivePendingQuery();

            rc = Dns::resolve(p->hostname, resolved, 0);

            if (rc == 0) {
                TcpSocket *s = TcpSocketMgr::getSocket();
                if (s == NULL)
                    break;
                s->setRecvBuffer(2048);
                {
                    static unsigned short src_port = 1025;
                    if (src_port < 1025 || src_port > 65000)
                        src_port = 1025;
                    s->connectNonBlocking(src_port++, resolved, p->remotePort);
                }
                p->sock = s;
                memcpy(p->remoteIP, resolved, 4);
                p->mode = PORT_CONNECTING;
            }
            break;
        }

        case PORT_CONNECTING:
            if (p->sock == NULL) {
                p->mode = PORT_DISC;
                break;
            }
            if (p->sock->isConnectComplete()) {
                p->mode = PORT_CONN;
                telnet_on_connect(i);
            } else if (p->sock->isClosed()) {
                TcpSocketMgr::freeSocket(p->sock);
                p->sock = NULL;
                p->mode = PORT_DISC;
            }
            break;

        case PORT_LISTEN:
        {
            TcpSocket *ns = TcpSocketMgr::accept();
            if (ns) {
                if (p->sock) {
                    p->sock->close();
                    TcpSocketMgr::freeSocket(p->sock);
                }
                p->sock = ns;
                p->mode = PORT_CONN;
                p->conn_tick = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
                p->last_rx_tick = p->conn_tick;
                p->last_tx_tick = p->conn_tick;
                ring_init(&p->rx);
                telnet_on_connect(i);

                /* Notify the telnet caller that we're ringing */
                telnet_send_text(i, "\r\nRinging the host, please wait...\r\n");

                /* Inject RING so BBS sees the incoming call.
                 * CONNECT is NOT sent here — the BBS must answer
                 * with ATA (or auto-answer via S0 register). */
                at_send_ring(i);

                /* Re-create listen socket so we can reject new
                 * connections with a "busy" message during PORT_CONN. */
                if (p->listenSock == NULL) {
                    TcpSocket *ls = TcpSocketMgr::getSocket();
                    if (ls) {
                        ls->listen(p->localPort, 2048);
                        p->listenSock = ls;
                    }
                }
            }
            break;
        }

        case PORT_CONN:
        {
            unsigned char tmp[64];
            int16_t n;

            if (p->sock == NULL) {
                p->mode = PORT_DISC;
                break;
            }

            /* Reject incoming connections while a call is active.
             * Accept, send "busy" message, then close immediately. */
            if (p->listenSock) {
                TcpSocket *ns = TcpSocketMgr::accept();
                if (ns) {
                    static unsigned char busy_msg[] =
                        "\r\nLine is engaged. Please try again later.\r\n";
                    ns->send(busy_msg, sizeof(busy_msg) - 1);
                    Tcp::drivePackets();
                    ns->close();
                    Tcp::drivePackets();
                    TcpSocketMgr::freeSocket(ns);
                }
            }

            /* Drive ring/auto-answer from the poll cycle too.
             * AH=03h also calls this, but if the BBS isn't polling
             * (e.g. not running), we still need to send RINGs and
             * eventually time out unanswered calls. */
            at_check_ring(i);
            /* at_check_ring may close the socket on ring timeout */
            if (p->sock == NULL) {
                if (p->listenSock)
                    p->mode = PORT_LISTEN;
                else
                    p->mode = PORT_DISC;
                break;
            }

            /* Pending close from INT 14h (DEINIT-DISC, INIT-DISC, DTR-DISC,
             * or CMD-DISC).  Send farewell message and close here where
             * the packet driver can transmit reliably.
             * Safe from INT 28h (g_dos_safe) or INT 14h (g_int14_safe) —
             * both are software-interrupt contexts with interrupts enabled,
             * so the packet driver IRQ can fire. */
            if (p->pending_close && (g_dos_safe || g_int14_safe)) {
                dbg("[POLL-CLOSE]");
                p->pending_close = 0;
                telnet_send_text(i, "\r\nSession finished.\r\n");
                Tcp::drivePackets();
                p->sock->close();
                Tcp::drivePackets();
                TcpSocketMgr::freeSocket(p->sock);
                p->sock = NULL;
                ring_init(&p->rx);
                at_send_no_carrier(i);
                /* Close listen socket too — don't accept new connections
                 * until AH=04h (FOSSIL init) re-creates it.  This prevents
                 * a quick reconnect arriving before RA has restarted. */
                if (p->listenSock) {
                    p->listenSock->close();
                    TcpSocketMgr::freeSocket(p->listenSock);
                    p->listenSock = NULL;
                }
                p->mode = PORT_DISC;
                break;
            }

            /* Flush any buffered TX data from the FOSSIL TX ring */
            fossil_flush_tx(i);

            while (p->sock->recvDataWaiting()) {
                n = p->sock->recv(tmp, sizeof(tmp));
                if (n > 0) {
                    int j;
                    p->last_rx_tick = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
                    for (j = 0; j < n; j++) {
                        int b = telnet_filter(p, tmp[j]);
                        if (b >= 0)
                            ring_put(&p->rx, (unsigned char)b);
                    }
                } else {
                    break;
                }
            }

            /* Keepalive: send IAC NOP every ~30s to probe connection.
             * SLIRP doesn't propagate external TCP close to the internal
             * mTCP socket, so the socket stays ESTABLISHED forever.
             * If the external client is gone, the NOP send will eventually
             * cause SLIRP to RST the internal connection. */
            {
                unsigned long now = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
                unsigned long idle = now - p->last_rx_tick;
                unsigned long age = now - p->conn_tick;

                /* Send IAC NOP keepalive every ~3 seconds of idle.
                 * Start after 2s idle (36 ticks).  Repeat every 55 ticks (~3s).
                 * This probes SLIRP quickly so it notices the dead external
                 * connection and RSTs the internal socket. */
                if (idle > 36UL && (idle % 55UL) < 2UL) {
                    static unsigned char nop[2] = { 0xFF, 0xF1 }; /* IAC NOP */
                    telnet_send_raw(p, nop, 2);
                }

                /* Idle timeout: disconnect if no TX or RX for configured period.
                 * Only from INT 28h (g_dos_safe) — not from AH=03h poll. */
                if (p->idle_timeout > 0 && g_dos_safe) {
                    unsigned long tx_idle = now - p->last_tx_tick;
                    unsigned long rx_idle = idle;  /* already computed above */
                    unsigned long timeout_ticks = (unsigned long)p->idle_timeout * 18UL;
                    /* Both TX and RX must be idle */
                    if (tx_idle > timeout_ticks && rx_idle > timeout_ticks) {
                        dbg("[IDLE-TIMEOUT]");
                        telnet_send_text(i, "\r\nClosing idle connection.\r\n");
                        p->sock->close();
                        /* Drive packets to push FIN through SLIRP */
                        Tcp::drivePackets();
                        TcpSocketMgr::freeSocket(p->sock);
                        p->sock = NULL;
                        ring_init(&p->rx);
                        at_send_no_carrier(i);
                        if (p->listenSock)
                            p->mode = PORT_LISTEN;
                        else
                            p->mode = PORT_DISC;
                        break;
                    }
                }

                /* Disconnect detection — only from INT 28h context */
                if (g_dos_safe &&
                    (p->sock->isClosed() ||
                    (age > 91UL && p->sock->isRemoteClosed() && !p->sock->recvDataWaiting()))) {
                    p->sock->close();
                    TcpSocketMgr::freeSocket(p->sock);
                    p->sock = NULL;
                    ring_init(&p->rx);
                    at_send_no_carrier(i);
                    if (p->listenSock)
                        p->mode = PORT_LISTEN;
                    else
                        p->mode = PORT_DISC;
                }
            }
            break;
        }

        case PORT_DISC:
        default:
            break;
        }
    }

    /* Flush debug log to disk if file is open and DOS I/O is safe.
     * Safe when: g_dos_safe=1 (INT 28h context — DOS is idle, file I/O OK)
     *         or InDOS=0 (no DOS call in progress, e.g. INT 14h from user code)
     *         or g_int14_safe=1 (INT 14h caller context — software interrupt,
     *            user code invoked us so DOS I/O is safe).
     * Note: during INT 28h, InDOS is typically 1 (DOS is inside a keyboard read),
     * so we must check g_dos_safe separately.
     * We're on the private stack (SS == DS) so C library calls work. */
    if (g_state.dbglog_fd >= 0 &&
        (g_dos_safe || g_int14_safe ||
         (g_indos_ptr != NULL && *g_indos_ptr == 0))) {
        static unsigned short last_h = 0;
        unsigned short h = g_state.dbglog_head;
        if (h != last_h) {
            unsigned written;
            unsigned short saved_psp;

            /* Switch to VMODEM's PSP so our file handle is valid.
             * File handles are per-PSP; after TSR, the active PSP
             * belongs to whatever program triggered this poll. */
            {
                unsigned short our_psp = g_state.our_psp;
                __asm {
                    mov ah, 51h
                    int 21h
                    mov saved_psp, bx
                    mov bx, our_psp
                    mov ah, 50h
                    int 21h
                }
            }

            if (h > last_h) {
                _dos_write(g_state.dbglog_fd,
                           &g_state.dbglog[last_h],
                           h - last_h, &written);
            } else {
                /* Buffer wrapped */
                _dos_write(g_state.dbglog_fd,
                           &g_state.dbglog[last_h],
                           DBGLOG_SIZE - last_h, &written);
                if (h > 0)
                    _dos_write(g_state.dbglog_fd,
                               g_state.dbglog,
                               h, &written);
            }
            _dos_commit(g_state.dbglog_fd);

            /* Restore original PSP */
            __asm {
                mov bx, saved_psp
                mov ah, 50h
                int 21h
            }

            last_h = h;
        }
    }
}
