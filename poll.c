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
#include "vmodem.h"
#include "packet.h"
#include "tcp.h"
#include "tcpsockm.h"
#include "arp.h"
#include "ip.h"
#include "udp.h"
#include "dns.h"
#include "utils.h"

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
                ring_init(&p->rx);
                telnet_on_connect(i);
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

            while (p->sock->recvDataWaiting()) {
                n = p->sock->recv(tmp, sizeof(tmp));
                if (n > 0) {
                    int j;
                    for (j = 0; j < n; j++) {
                        int b = telnet_filter(p, tmp[j]);
                        if (b >= 0)
                            ring_put(&p->rx, (unsigned char)b);
                    }
                } else {
                    break;
                }
            }

            if (p->sock->isRemoteClosed() || p->sock->isClosed()) {
                p->sock->close();
                TcpSocketMgr::freeSocket(p->sock);
                p->sock = NULL;
                ring_init(&p->rx);
                if (p->listenSock)
                    p->mode = PORT_LISTEN;
                else
                    p->mode = PORT_DISC;
            }
            break;
        }

        case PORT_DISC:
        default:
            break;
        }
    }
}
