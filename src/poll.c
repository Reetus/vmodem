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

    /* Step 2a: Service hunt groups — accept and dispatch to first free port */
    for (i = 0; i < MAX_HUNT_GROUPS; i++) {
        TcpSocket *ns;
        int target, j;

        if (!g_state.huntGroups[i].active || g_state.huntGroups[i].listenSock == NULL)
            continue;

        ns = TcpSocketMgr::accept();
        if (!ns)
            continue;

        /* Find first free port in the hunt group */
        target = -1;
        for (j = 0; j < MAX_PORTS; j++) {
            if (!(g_state.huntGroups[i].portMask & (1 << j)))
                continue;
            if (g_state.ports[j].mode == PORT_LISTEN && g_state.ports[j].sock == NULL) {
                target = j;
                break;
            }
        }

        if (target >= 0) {
            PortState *tp = &g_state.ports[target];
            tp->sock = ns;
            tp->mode = PORT_CONN;
            tp->remotePort = ns->dstPort;
            memcpy(tp->remoteIP, ns->dstHost, 4);
            tp->conn_tick = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
            tp->last_rx_tick = tp->conn_tick;
            tp->last_tx_tick = tp->conn_tick;
            ring_init(&tp->rx);
            fossil_clear_tx(target);
            telnet_on_connect(target);
            telnet_send_text(target, "\r\nRinging the host, please wait...\r\n");
            at_send_ring(target);
            dbg("[HUNT-ACCEPT]");
        } else {
            /* All ports busy — reject */
            static unsigned char busy_msg[] =
                "\r\nAll lines are engaged. Please try again later.\r\n";
            dbg("[HUNT-REJECT]");
            ns->send(busy_msg, sizeof(busy_msg) - 1);
            Tcp::drivePackets();
            ns->close();
            Tcp::drivePackets();
            TcpSocketMgr::freeSocket(ns);
        }
    }

    /* Step 2b: Service each port */
    for (i = 0; i < MAX_PORTS; i++) {
        PortState *p = &g_state.ports[i];

        if (!p->initialized)
            continue;

        switch (p->mode) {

        case PORT_LISTEN:
        {
            TcpSocket *ns;
            /* Hunt group members are handled by the hunt group loop above */
            if (p->huntGroupIdx >= 0)
                break;
            ns = TcpSocketMgr::accept();
            if (ns) {
                if (p->sock) {
                    p->sock->close();
                    TcpSocketMgr::freeSocket(p->sock);
                }
                p->sock = ns;
                p->mode = PORT_CONN;
                p->remotePort = ns->dstPort;
                memcpy(p->remoteIP, ns->dstHost, 4);
                p->conn_tick = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
                p->last_rx_tick = p->conn_tick;
                p->last_tx_tick = p->conn_tick;
                ring_init(&p->rx);
                fossil_clear_tx(i);  /* discard stale TX data from previous session */
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
                if (p->listenSock)
                    p->mode = PORT_LISTEN;
                else if (p->huntGroupIdx >= 0)
                    p->mode = PORT_LISTEN;
                else
                    p->mode = PORT_DISC;
                break;
            }

            /* Reject incoming connections while a call is active.
             * Hunt group members skip this — the hunt group loop
             * dispatches to other free ports or rejects if all busy. */
            if (p->huntGroupIdx < 0 && p->listenSock) {
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
            /* at_check_ring may close the socket on ring timeout.
             * Respect the mode already set by ring timeout handler;
             * only fall back to PORT_DISC if no listen capability. */
            if (p->sock == NULL) {
                if (p->mode != PORT_LISTEN) {
                    if (p->listenSock)
                        p->mode = PORT_LISTEN;
                    else if (p->huntGroupIdx >= 0)
                        p->mode = PORT_LISTEN;
                    else
                        p->mode = PORT_DISC;
                }
                break;
            }

            /* Pending close from INT 14h (DEINIT-DISC, INIT-DISC, DTR-DISC,
             * or CMD-DISC).  Send farewell message and close here where
             * the packet driver can transmit reliably.
             * Safe from INT 28h (g_dos_safe) or INT 14h (g_int14_safe) —
             * both are software-interrupt contexts with interrupts enabled,
             * so the packet driver IRQ can fire. */
            if (p->pending_close && (g_dos_safe || g_int14_safe)) {
                unsigned char silent = (p->pending_close >= 2);
                dbg(silent ? "[POLL-CLOSE-S]" : "[POLL-CLOSE]");
                p->pending_close = 0;
                if (!silent)
                    telnet_send_text(i, "\r\nSession finished.\r\n");
                Tcp::drivePackets();
                p->sock->close();
                Tcp::drivePackets();
                TcpSocketMgr::freeSocket(p->sock);
                p->sock = NULL;
                memset(p->remoteIP, 0, 4);
                p->remotePort = 0;
                ring_init(&p->rx);
                if (!silent)
                    at_send_no_carrier(i);
                /* Keep the listen socket alive — RA's batch file will
                 * loop back and restart RA, which calls AH=04h.
                 * The port goes to PORT_LISTEN so it can accept new
                 * connections once RA is ready (AH=04h ring/answer). */
                if (p->listenSock)
                    p->mode = PORT_LISTEN;
                else if (p->huntGroupIdx >= 0)
                    p->mode = PORT_LISTEN;
                else
                    p->mode = PORT_DISC;
                break;
            }

            /* Flush any buffered TX data from the FOSSIL TX ring */
            fossil_flush_tx(i);

            /* Only deliver TCP data to the RX ring after the call is
             * answered.  While ringing or during connect handshake,
             * discard application data but still process telnet IAC
             * negotiation so the connection stays healthy. */
            while (p->sock->recvDataWaiting()) {
                n = p->sock->recv(tmp, sizeof(tmp));
                if (n > 0) {
                    int j;
                    p->last_rx_tick = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
                    if (at_is_ringing(i) || at_is_connect_pending(i)) {
                        /* Pre-answer: run telnet filter (handles IAC)
                         * but drop the application bytes */
                        for (j = 0; j < n; j++)
                            telnet_filter(p, tmp[j]);
                    } else {
                        for (j = 0; j < n; j++) {
                            int b = telnet_filter(p, tmp[j]);
                            if (b >= 0)
                                ring_put(&p->rx, (unsigned char)b);
                        }
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
                if (idle > 36UL) {
                    unsigned long phase = idle / 55UL;
                    unsigned long rem   = idle - phase * 55UL;
                    if (rem < 2UL) {
                        static unsigned char nop[2] = { 0xFF, 0xF1 }; /* IAC NOP */
                        telnet_send_raw(p, nop, 2);
                    }
                }

                /* Idle timeout: disconnect if no TX or RX for configured period.
                 * Safe from INT 28h (g_dos_safe) or INT 14h (g_int14_safe). */
                if (p->idle_timeout > 0 && (g_dos_safe || g_int14_safe)) {
                    unsigned long tx_idle = now - p->last_tx_tick;
                    unsigned long rx_idle = idle;  /* already computed above */
                    unsigned long timeout_ticks = (unsigned long)p->idle_timeout * 18UL;
                    /* (IDLE-TICK debug removed — too noisy) */
                    /* Both TX and RX must be idle */
                    if (tx_idle > timeout_ticks && rx_idle > timeout_ticks) {
                        dbg("[IDLE-TIMEOUT]");
                        telnet_send_text(i, "\r\nClosing idle connection.\r\n");
                        p->sock->close();
                        Tcp::drivePackets();
                        TcpSocketMgr::freeSocket(p->sock);
                        p->sock = NULL;
                        memset(p->remoteIP, 0, 4);
                        p->remotePort = 0;
                        ring_init(&p->rx);
                        at_send_no_carrier(i);
                        if (p->listenSock)
                            p->mode = PORT_LISTEN;
                        else if (p->huntGroupIdx >= 0)
                            p->mode = PORT_LISTEN;
                        else
                            p->mode = PORT_DISC;
                        break;
                    }
                }

                /* Disconnect detection — from INT 28h or INT 14h context */
                if ((g_dos_safe || g_int14_safe) &&
                    (p->sock->isClosed() ||
                    (age > 182UL && p->sock->isRemoteClosed() && !p->sock->recvDataWaiting()))) {
                    dbg(p->sock->isClosed() ? "[DISC-CLOSED]" : "[DISC-REMOTE]");
                    p->sock->close();
                    TcpSocketMgr::freeSocket(p->sock);
                    p->sock = NULL;
                    memset(p->remoteIP, 0, 4);
                    p->remotePort = 0;
                    ring_init(&p->rx);
                    at_send_no_carrier(i);
                    /* Return to PORT_LISTEN if a listen socket exists
                     * so the port can accept new connections when the
                     * BBS restarts (RA batch loop → AH=04h). */
                    if (p->listenSock)
                        p->mode = PORT_LISTEN;
                    else if (p->huntGroupIdx >= 0)
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

    /* Step 3: Service external sockets — update state tracking.
     * Tcp::drivePackets() already drives all sockets globally;
     * we just need to track state transitions here. */
    for (i = 0; i < MAX_EXT_SOCKETS; i++) {
        TcpSocket *es = g_state.ext_sockets[i].sock;
        if (!es)
            continue;

        /* Handle deferred connect (set by MUX_SOCK_CONNECT in INT 2Fh) */
        if (g_state.ext_sockets[i].pending_connect) {
            static uint16_t ephemeral_port = 16384;
            g_state.ext_sockets[i].pending_connect = 0;
            if (++ephemeral_port > 32000) ephemeral_port = 16384;
            if (es->connectNonBlocking(ephemeral_port,
                    g_state.ext_sockets[i].conn_ip,
                    g_state.ext_sockets[i].conn_port) != 0) {
                g_state.ext_sockets[i].state = EXT_SOCK_ERROR;
                dbg("[CONN-FAIL]");
            } else {
                dbg("[CONN-OK]");
            }
        }

        /* Handle deferred close (set by MUX_SOCK_CLOSE in INT 2Fh).
         * Done here where interrupts are enabled so close() can transmit FIN. */
        if (g_state.ext_sockets[i].state == EXT_SOCK_CLOSING) {
            es->close();
            Tcp::drivePackets();
            TcpSocketMgr::freeSocket(es);
            g_state.ext_sockets[i].sock = NULL;
            g_state.ext_sockets[i].state = EXT_SOCK_FREE;
            dbg("[SOCK-CLOSE]");
            continue;
        }

        if (g_state.ext_sockets[i].state == EXT_SOCK_CONNECTING) {
            if (es->isConnectComplete())
                g_state.ext_sockets[i].state = EXT_SOCK_ESTABLISHED;
            else if (es->isClosed())
                g_state.ext_sockets[i].state = EXT_SOCK_ERROR;
        } else if (g_state.ext_sockets[i].state == EXT_SOCK_ESTABLISHED) {
            if (es->isClosed())
                g_state.ext_sockets[i].state = EXT_SOCK_ERROR;
            else if (es->isRemoteClosed() && !es->recvDataWaiting())
                g_state.ext_sockets[i].state = EXT_SOCK_REMOTE_CLOSED;
        }
    }

    /* Flush debug log to disk if file is open and DOS I/O is safe.
     * Safe when: g_dos_safe=1 (INT 28h context — DOS is idle, file I/O OK)
     *         or g_int14_safe=1 (INT 14h caller context — software interrupt,
     *            user code invoked us so DOS I/O is safe).
     * NOT safe from INT 1Ch (timer tick) — doing INT 21h file I/O from
     * hardware interrupt context crashes under JemmEx V86 mode.
     * Note: during INT 28h, InDOS is typically 1 (DOS is inside a keyboard read),
     * so we must check g_dos_safe separately.
     * We're on the private stack (SS == DS) so C library calls work. */
    if (g_state.dbglog_fd >= 0 &&
        (g_dos_safe || g_int14_safe)) {
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
