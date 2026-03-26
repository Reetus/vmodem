/*
 * int8.c - Background mTCP polling (INT 28h) and control (INT 2Fh) handlers
 *
 * INT 28h (DOS Idle Interrupt)
 * ----------------------------
 * DOS calls INT 28h from its idle loop when it has nothing to do.  This
 * is the safest place to perform mTCP work because DOS re-entrancy is
 * guaranteed — all DOS services are available.  We hook this interrupt
 * to drive packet reception and TCP state machines in the background.
 *
 * Stack switching
 * ---------------
 * INT 28h can fire when the current application's stack has very little
 * headroom.  mTCP's TCP/ARP/packet processing functions consume stack
 * space.  We therefore switch to a private 1.5KB stack in DGROUP before
 * doing any mTCP work, then restore the original stack before chaining
 * to the previous INT 28h handler.
 *
 * Stack switch safety (8086):
 * After "MOV SS, AX" the CPU automatically disables interrupts for the
 * single following instruction, giving us an atomic SS:SP update with
 * "MOV SP, [g_priv_stack_top]".  This is standard 8086 behaviour.
 *
 * Re-entrancy guard
 * -----------------
 * PACKET_PROCESS_SINGLE internally calls dosIdleCall() (INT 28h) when
 * there are no packets to process.  The g_state.busy flag prevents us
 * from recursively entering the poll function.
 *
 * INT 2Fh (Multiplex Interrupt)
 * -----------------------------
 * Provides a control interface for VMODCTL and for a second VMODEM
 * invocation after the TSR is already installed.  See vmodem.h for the
 * MUX_* sub-function codes and register conventions.
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
#include "dns.h"
#include "utils.h"

/* Saved original INT 1Ch, INT 28h and INT 2Fh vectors — set in vmodem.c */
void (__interrupt __far *old_int1c)(void) = NULL;
void (__interrupt __far *old_int28)(void) = NULL;
void (__interrupt __far *old_int2f)(void) = NULL;

/* Private stack storage (in DGROUP so it stays resident) */
unsigned char  g_priv_stack[PRIV_STACK_SIZE];
unsigned short g_priv_stack_top;    /* set in vmodem.c after all allocs  */

/* Temporary SS:SP:BP save during stack switch */
unsigned short g_save_ss;
unsigned short g_save_sp;
unsigned short g_save_bp;

/* Flag: 1 when executing from INT 28h context (DOS file I/O is safe) */
unsigned char g_dos_safe = 0;

/* -----------------------------------------------------------------------
 * poll_on_priv_stack — switch to private stack, call do_mtcp_poll, restore.
 *
 * Small model assumes SS == DS.  In interrupt handlers, SS belongs to the
 * interrupted program while DS = DGROUP.  Any C code that takes the address
 * of a local variable (including mTCP's Packet_send_pkt) will pass a near
 * pointer interpreted via DS instead of SS, causing data corruption.
 *
 * This function must have NO local variables and NO parameters so the
 * compiler doesn't generate stack-frame-relative code between the switch
 * and the call.
 *
 * Call only while g_state.busy == 1 (caller must guard).
 * --------------------------------------------------------------------- */

/* do_mtcp_poll() is in poll.c (separate TU) so the compiler can't inline it.
 * No need for volatile function pointer. */

void poll_on_priv_stack(void)
{
    __asm {
        mov  word ptr g_save_bp, bp
        mov  word ptr g_save_ss, ss
        mov  word ptr g_save_sp, sp
        mov  ax, ds
        mov  ss, ax
        mov  sp, word ptr g_priv_stack_top
    }

    do_mtcp_poll();

    __asm {
        mov  ax, word ptr g_save_ss
        mov  ss, ax
        mov  sp, word ptr g_save_sp
        mov  bp, word ptr g_save_bp
    }
}

/* do_mtcp_poll() is in poll.c (separate TU to prevent epilogue merging) */

/* -----------------------------------------------------------------------
 * int1c_handler  (INT 1Ch — User Timer Tick, ~18.2 Hz)
 *
 * The BIOS INT 8 handler calls INT 1Ch AFTER sending EOI to the PIC,
 * so interrupts of equal/lower priority (including IRQ 3 for NE2000)
 * can fire during our processing.  This is critical: it allows the
 * packet driver to receive new packets (e.g., TCP ACKs) while we are
 * processing the previous batch.
 *
 * We hook INT 1Ch instead of INT 8 because:
 *   - INT 8 runs with IF=0 and IRQ 0 in-service → IRQ 3 can't fire
 *   - Watcom's _chain_intr from INT 8 context with inline asm stack
 *     switching is fragile and can crash the timer chain
 *   - INT 1Ch is the canonical user hook point for per-tick work
 *
 * Stack switch and busy flag: identical to int28_handler.
 * --------------------------------------------------------------------- */

void __interrupt __far __loadds int1c_handler(void)
{
    _chain_intr(old_int1c);
}

/* -----------------------------------------------------------------------
 * int28_handler  (INT 28h — DOS Idle)
 *
 * Switches to the private stack, drives mTCP, then restores the original
 * stack and chains to the previous INT 28h handler.
 * --------------------------------------------------------------------- */

void __interrupt __far __loadds int28_handler(void)
{
    if (g_state.busy) {
        /* Already inside a poll — skip to avoid recursion */
        _chain_intr(old_int28);
        return;
    }

    g_state.busy = 1;
    g_dos_safe = 1;

    /*
     * Enable interrupts so IRQ 3 (NE2000 packet driver) can fire during
     * mTCP processing.  INT 28h is invoked via 'int 28h' which clears IF.
     * Without STI, no packets are received because the NE2000 ISR never
     * runs.  The busy flag prevents re-entrancy if INT 28h fires again.
     */
    _enable();

    poll_on_priv_stack();

    _disable();
    g_dos_safe = 0;
    g_state.busy = 0;

    _chain_intr(old_int28);
}

/* -----------------------------------------------------------------------
 * int2f_handler  (INT 2Fh — Multiplex Interrupt)
 *
 * Provides the control interface.  AH must equal MUX_ID; AL selects
 * the operation.  All other AH values are passed to the old handler.
 *
 * Register access uses BP-relative inline assembly.  The Watcom
 * __interrupt prologue pushes: ax,cx,dx,bx,sp,bp,si,di,ds,es,ax,ax
 * then sets bp=sp.  Offsets from BP:
 *   [bp+22] = AX (AH=mux_id, AL=subfunction or return code)
 *   [bp+20] = CX (port index)
 *   [bp+18] = DX (TCP port)
 *   [bp+16] = BX (status buffer offset for MUX_STATUS)
 *   [bp+10] = SI
 *   [bp+4]  = ES (segment for MUX_STATUS buffer)
 * --------------------------------------------------------------------- */

void __interrupt __far __loadds int2f_handler(void)
{
    unsigned short orig_ax;
    unsigned short orig_cx;
    unsigned short orig_dx;
    unsigned short orig_bx;
    unsigned short orig_si;
    unsigned short orig_es;

    /* Read all needed registers from the interrupt stack frame */
    __asm {
        mov  ax, [bp+22]
        mov  orig_ax, ax
        mov  ax, [bp+20]
        mov  orig_cx, ax
        mov  ax, [bp+18]
        mov  orig_dx, ax
        mov  ax, [bp+16]
        mov  orig_bx, ax
        mov  ax, [bp+10]
        mov  orig_si, ax
        mov  ax, [bp+4]
        mov  orig_es, ax
    }

    /* AH = MUX_ID check (high byte of orig_ax) */
    if ((unsigned char)(orig_ax >> 8) != MUX_ID) {
        _chain_intr(old_int2f);
        return;
    }

    switch ((unsigned char)(orig_ax & 0xFF)) {  /* AL = subfunction */

    case MUX_INSTALL_CHK:
    {
        /* Signal installed; return pointer to g_state in ES:BX, AL=0xFF */
        unsigned short gs_seg = FP_SEG(&g_state);
        unsigned short gs_off = FP_OFF(&g_state);
        __asm {
            /* Set AL = 0xFF, keep AH unchanged */
            mov  ax, [bp+22]
            and  ax, 0xFF00
            or   ax, 0x00FF
            mov  [bp+22], ax
            /* Set ES = segment of g_state */
            mov  ax, gs_seg
            mov  [bp+4], ax
            /* Set BX = offset of g_state */
            mov  ax, gs_off
            mov  [bp+16], ax
        }
        break;
    }

    case MUX_LISTEN:
        /* CX = COM port index (0-3), DX = TCP listen port */
        cmd_listen((int)orig_cx, (unsigned short)orig_dx);
        break;

    case MUX_DISCONNECT:
        /* CX = COM port index */
        cmd_disconnect((int)orig_cx);
        break;

    case MUX_HUNT_LISTEN:
        /* CL = port mask (bits 0-3), DX = TCP port */
        cmd_hunt_listen((unsigned char)(orig_cx & 0xFF),
                        (unsigned short)orig_dx);
        break;

    case MUX_POLL:
        /*
         * Drive one poll cycle from caller's context.
         *
         * INT 2Fh is a software interrupt, which clears IF.  We MUST re-enable
         * interrupts before polling mTCP, otherwise the NE2000 packet driver's
         * ISR (IRQ 3) can never fire and no packets are ever received.
         *
         * Also check the NE2000 ring buffer directly: if BNRY != CURR but no
         * IRQ 3 has fired (ISR.PRX clear), trigger the packet driver's ISR via
         * software INT 0x0B.  This works around NE2000 emulation issues where
         * the PIC interrupt is lost or the IMR is cleared.
         */
        if (!g_state.busy) {
            g_state.busy = 1;
            _enable();

            poll_on_priv_stack();
            _disable();
            g_state.busy = 0;
        } else {
            /* Busy — can't do a full poll, but enable interrupts briefly
             * so the packet driver IRQ can fire and process pending packets */
            _enable();
            _disable();
        }
        break;

    case MUX_STATUS:
        /* ES:BX → caller-provided StatusBlock buffer */
        cmd_status((StatusBlock __far *)MK_FP(orig_es, orig_bx));
        break;

    case MUX_DEBUGLOG:
    {
        /* ES:BX → caller buffer, CX = buffer size.
         * Copy debug log to caller's buffer, return AX = bytes copied. */
        char __far *dst = (char __far *)MK_FP(orig_es, orig_bx);
        unsigned short bufsz = orig_cx;
        unsigned short count = g_state.dbglog_count;
        unsigned short start;
        unsigned short copied = 0;

        if (count > bufsz)
            count = bufsz;
        if (count > 0) {
            start = (g_state.dbglog_head + DBGLOG_SIZE - count) % DBGLOG_SIZE;
            while (copied < count) {
                dst[copied] = g_state.dbglog[start];
                start = (start + 1) % DBGLOG_SIZE;
                copied++;
            }
        }
        /* Clear the log after reading */
        g_state.dbglog_count = 0;
        g_state.dbglog_head = 0;

        __asm {
            mov  ax, copied
            mov  [bp+22], ax
        }
        break;
    }

    /* ----------------------------------------------------------------
     * MUX_SOCK_* — External socket API
     *
     * Lets non-mTCP DOS programs make outgoing TCP connections by
     * piggybacking on VMODEM's already-running mTCP stack.
     * ---------------------------------------------------------------- */

    case MUX_SOCK_ALLOC:
    {
        TcpSocket *ns;
        int slot, j;
        slot = -1;
        for (j = 0; j < MAX_EXT_SOCKETS; j++) {
            if (g_state.ext_sockets[j].state == EXT_SOCK_FREE &&
                g_state.ext_sockets[j].sock == NULL) {
                slot = j;
                break;
            }
        }
        if (slot < 0) {
            g_state.mux_sock_result = 0xFF;
            break;
        }
        ns = TcpSocketMgr::getSocket();
        if (!ns) {
            g_state.mux_sock_result = 0xFF;
            break;
        }
        if (ns->setRecvBuffer(4096) != 0) {
            dbg("[ALLOC-NOMEM]");
            TcpSocketMgr::freeSocket(ns);
            g_state.mux_sock_result = 0xFF;
            break;
        }
        g_state.ext_sockets[slot].sock = ns;
        g_state.ext_sockets[slot].state = EXT_SOCK_FREE;
        g_state.mux_sock_result = (unsigned short)slot;
        dbg("[SOCK-ALLOC]");
        break;
    }

    case MUX_SOCK_CONNECT:
    {
        unsigned char handle;
        unsigned short dport;
        handle = (unsigned char)(orig_cx & 0xFF);
        dport = (unsigned short)orig_dx;
        if (handle >= MAX_EXT_SOCKETS || g_state.ext_sockets[handle].sock == NULL) {
            g_state.mux_sock_result = 0xFF;
            break;
        }
        {
            unsigned char __far *ipfar;
            ipfar = (unsigned char __far *)MK_FP(orig_es, orig_bx);
            /* Store connect params — poll.c does the actual connectNonBlocking */
            g_state.ext_sockets[handle].conn_ip[0] = ipfar[0];
            g_state.ext_sockets[handle].conn_ip[1] = ipfar[1];
            g_state.ext_sockets[handle].conn_ip[2] = ipfar[2];
            g_state.ext_sockets[handle].conn_ip[3] = ipfar[3];
            g_state.ext_sockets[handle].conn_port = dport;
            g_state.ext_sockets[handle].pending_connect = 1;
            g_state.ext_sockets[handle].state = EXT_SOCK_CONNECTING;
        }
        g_state.mux_sock_result = 0;
        dbg("[SOCK-CONN]");
        break;
    }

    case MUX_SOCK_STATUS:
    {
        unsigned char handle;
        unsigned char st;
        handle = (unsigned char)(orig_cx & 0xFF);
        st = EXT_SOCK_ERROR;
        if (handle < MAX_EXT_SOCKETS && g_state.ext_sockets[handle].sock != NULL) {
            TcpSocket *s;
            s = g_state.ext_sockets[handle].sock;
            if (s->isConnectComplete())
                st = EXT_SOCK_ESTABLISHED;
            else if (s->isClosed())
                st = EXT_SOCK_ERROR;
            else if (g_state.ext_sockets[handle].state == EXT_SOCK_CONNECTING)
                st = EXT_SOCK_CONNECTING;
            else
                st = g_state.ext_sockets[handle].state;

            if (st == EXT_SOCK_ESTABLISHED && s->isRemoteClosed() &&
                !s->recvDataWaiting())
                st = EXT_SOCK_REMOTE_CLOSED;

            g_state.ext_sockets[handle].state = st;
        }
        g_state.mux_sock_result = (unsigned short)st;
        break;
    }

    case MUX_SOCK_SEND:
    {
        unsigned char handle;
        unsigned short len;
        static unsigned char mux_sendbuf[256];
        unsigned short sent;
        handle = (unsigned char)(orig_cx & 0xFF);
        len = (unsigned short)orig_dx;
        sent = 0;

        if (handle < MAX_EXT_SOCKETS && g_state.ext_sockets[handle].sock != NULL
            && g_state.ext_sockets[handle].state == EXT_SOCK_ESTABLISHED) {
            unsigned char __far *src;
            unsigned short i;
            int16_t rc;
            src = (unsigned char __far *)MK_FP(orig_es, orig_bx);
            if (len > 256) len = 256;
            for (i = 0; i < len; i++)
                mux_sendbuf[i] = src[i];
            rc = g_state.ext_sockets[handle].sock->send(mux_sendbuf, len);
            if (rc > 0) sent = (unsigned short)rc;
        }
        g_state.mux_sock_result = sent;
        break;
    }

    case MUX_SOCK_RECV:
    {
        unsigned char handle;
        unsigned short bufsz;
        static unsigned char mux_recvbuf[256];
        unsigned short got;
        handle = (unsigned char)(orig_cx & 0xFF);
        bufsz = (unsigned short)orig_dx;
        got = 0;

        if (handle < MAX_EXT_SOCKETS && g_state.ext_sockets[handle].sock != NULL) {
            int16_t rc;
            if (bufsz > 256) bufsz = 256;
            if (g_state.ext_sockets[handle].sock->recvDataWaiting()) {
                rc = g_state.ext_sockets[handle].sock->recv(mux_recvbuf, bufsz);
                if (rc > 0) {
                    unsigned char __far *dst;
                    unsigned short i;
                    dst = (unsigned char __far *)MK_FP(orig_es, orig_bx);
                    got = (unsigned short)rc;
                    for (i = 0; i < got; i++)
                        dst[i] = mux_recvbuf[i];
                    dbg("[RX+]");
                }
            }
        }
        g_state.mux_sock_result = got;
        break;
    }

    case MUX_SOCK_CLOSE:
    {
        /* Mark for deferred close — the actual close()+freeSocket() happens
         * in poll.c where interrupts are enabled and drivePackets can send
         * FIN packets.  Doing close() inside INT 2Fh (IF=0) hangs because
         * mTCP's close() needs the packet driver ISR to transmit. */
        unsigned char handle;
        handle = (unsigned char)(orig_cx & 0xFF);
        if (handle < MAX_EXT_SOCKETS && g_state.ext_sockets[handle].sock != NULL) {
            g_state.ext_sockets[handle].state = EXT_SOCK_CLOSING;
            dbg("[SOCK-CLOSEREQ]");
        }
        g_state.mux_sock_result = 0;
        break;
    }

    case MUX_SOCK_RESULT:
    {
        /* Return last mux_sock_result in AX — no function calls here,
         * so [bp+22] write works reliably (unlike cases with C++ calls). */
        unsigned short res;
        res = g_state.mux_sock_result;
        __asm {
            mov  ax, res
            mov  [bp+22], ax
        }
        break;
    }

    case MUX_SOCK_RESOLVE:
    {
        /* DNS hostname resolution.  ES:BX -> hostname string (max 63 chars).
         * Copies hostname to DGROUP, initiates Dns::resolve().
         * Result retrieved via MUX_SOCK_RESOLVE_RESULT.
         * Uses two-step result protocol (see MUX_SOCK_RESULT). */
        unsigned char __far *src;
        int i;
        int8_t rc;

        __asm {
            mov  ax, [bp+4]
            mov  word ptr src+2, ax
            mov  ax, [bp+16]
            mov  word ptr src, ax
        }

        /* Copy hostname from caller's buffer to DGROUP */
        for (i = 0; i < 63 && src[i] != 0; i++)
            g_state.dns_hostname[i] = src[i];
        g_state.dns_hostname[i] = '\0';

        /* Initiate resolution */
        rc = Dns::resolve(g_state.dns_hostname, g_state.dns_resolved_ip, 1);
        if (rc == 0) {
            /* Already resolved (cached or numeric IP) */
            g_state.dns_resolve_state = DNS_RESOLVE_OK;
            g_state.mux_sock_result = DNS_RESOLVE_OK;
        } else if (rc == 1) {
            /* Query sent, pending */
            g_state.dns_resolve_state = DNS_RESOLVE_PENDING;
            g_state.mux_sock_result = DNS_RESOLVE_PENDING;
        } else {
            /* Error (name too long, no nameserver, bad input) */
            g_state.dns_resolve_state = DNS_RESOLVE_ERROR;
            g_state.mux_sock_result = DNS_RESOLVE_ERROR;
        }
        break;
    }

    case MUX_SOCK_RESOLVE_RESULT:
    {
        /* Check DNS resolve status and copy result IP.
         * If resolved: copies 4-byte IP to ES:BX, result = DNS_RESOLVE_OK.
         * If pending: tries cache lookup, result = state.
         * Uses two-step result protocol (see MUX_SOCK_RESULT). */
        if (g_state.dns_resolve_state == DNS_RESOLVE_PENDING) {
            /* Check if query completed — try cache-only lookup */
            if (!Dns::isQueryPending()) {
                int8_t rc = Dns::resolve(g_state.dns_hostname,
                                          g_state.dns_resolved_ip, 0);
                if (rc == 0) {
                    g_state.dns_resolve_state = DNS_RESOLVE_OK;
                } else {
                    g_state.dns_resolve_state = DNS_RESOLVE_ERROR;
                }
            }
        }

        if (g_state.dns_resolve_state == DNS_RESOLVE_OK) {
            /* Copy resolved IP to caller's buffer at ES:BX */
            unsigned char __far *dst;
            __asm {
                mov  ax, [bp+4]
                mov  word ptr dst+2, ax
                mov  ax, [bp+16]
                mov  word ptr dst, ax
            }
            dst[0] = g_state.dns_resolved_ip[0];
            dst[1] = g_state.dns_resolved_ip[1];
            dst[2] = g_state.dns_resolved_ip[2];
            dst[3] = g_state.dns_resolved_ip[3];
        }

        g_state.mux_sock_result = g_state.dns_resolve_state;
        break;
    }

    case MUX_PORT_NAWS:
    {
        /* Return NAWS cols/rows for a COM port.
         * CL = port index (0-3).  Returns DX = cols, SI = rows.
         * If port invalid or NAWS not negotiated, returns 0,0. */
        unsigned char port_idx;
        unsigned short cols, rows;
        port_idx = (unsigned char)(orig_cx & 0xFF);
        cols = 0;
        rows = 0;
        if (port_idx < MAX_PORTS) {
            cols = g_state.ports[port_idx].naws_cols;
            rows = g_state.ports[port_idx].naws_rows;
        }
        __asm {
            mov  ax, cols
            mov  [bp+18], ax
            mov  ax, rows
            mov  [bp+10], ax
        }
        break;
    }

    case MUX_PORT_TTYPE:
    {
        /* Copy terminal type string for a COM port to caller's buffer.
         * CL = port index (0-3), DX = buffer size, ES:BX -> destination.
         * Returns AX = string length (0 if not available). */
        unsigned char port_idx;
        unsigned char __far *dst;
        unsigned short bufsz;
        unsigned short len;

        port_idx = (unsigned char)(orig_cx & 0xFF);
        dst = (unsigned char __far *)MK_FP(orig_es, orig_bx);
        bufsz = (unsigned short)orig_dx;
        len = 0;

        if (port_idx < MAX_PORTS && bufsz > 0) {
            const char *src = g_state.ports[port_idx].ttype;
            while (src[len] && len < bufsz - 1) {
                dst[len] = src[len];
                len++;
            }
            dst[len] = '\0';
        }
        __asm {
            mov  ax, len
            mov  [bp+22], ax
        }
        break;
    }

    case MUX_SOCK_RECV_READY:
    {
        /* Check if a socket has data waiting to be read.
         * CL = handle.  Returns 1 if data waiting, 0 otherwise. */
        unsigned char handle = (unsigned char)(orig_cx & 0xFF);
        unsigned short ready = 0;
        if (handle < MAX_EXT_SOCKETS && g_state.ext_sockets[handle].sock != NULL) {
            if (g_state.ext_sockets[handle].sock->recvDataWaiting())
                ready = 1;
        }
        g_state.mux_sock_result = ready;
        break;
    }

    case MUX_SOCK_DNS_FLUSH:
    {
        /* Flush a hostname from mTCP's DNS cache so the next resolve
         * gets a fresh query.  ES:BX -> hostname string. */
        unsigned char __far *src;
        char name[64];
        int i;
        __asm {
            mov  ax, [bp+4]
            mov  word ptr src+2, ax
            mov  ax, [bp+16]
            mov  word ptr src, ax
        }
        for (i = 0; i < 63 && src[i] != 0; i++)
            name[i] = src[i];
        name[i] = '\0';
        Dns::deleteFromCache(name);
        g_state.mux_sock_result = 0;
        break;
    }

    /* ---- ICMP ping/traceroute API ---- */

    case MUX_ICMP_SEND:
    {
        /* Send ICMP echo request.  CL=TTL, DX=seq, ES:BX->4-byte dest IP.
         * Queues the request; actual send happens in do_mtcp_poll(). */
        unsigned char __far *src;
        src = (unsigned char __far *)MK_FP(orig_es, orig_bx);
        g_state.icmp_ttl = (unsigned char)(orig_cx & 0xFF);
        g_state.icmp_seq = (unsigned short)orig_dx;
        g_state.icmp_dest_ip[0] = src[0];
        g_state.icmp_dest_ip[1] = src[1];
        g_state.icmp_dest_ip[2] = src[2];
        g_state.icmp_dest_ip[3] = src[3];
        g_state.icmp_send_tick = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
        g_state.icmp_send_pending = 1;
        g_state.icmp_state = ICMP_STATE_WAITING;
        g_state.mux_sock_result = 0;
        break;
    }

    case MUX_ICMP_POLL:
    {
        /* Poll ICMP request state.  Returns ICMP_STATE_* via mux_sock_result.
         * Also checks for timeout (~5 seconds = 91 BIOS ticks). */
        if (g_state.icmp_state == ICMP_STATE_WAITING && !g_state.icmp_send_pending) {
            unsigned long now = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
            if (now - g_state.icmp_send_tick > 91UL)
                g_state.icmp_state = ICMP_STATE_TIMEOUT;
        }
        g_state.mux_sock_result = g_state.icmp_state;
        break;
    }

    case MUX_ICMP_RESULT:
    {
        /* Copy IcmpMuxResult to caller's buffer at ES:BX, then reset to IDLE. */
        unsigned char __far *dst;
        unsigned char *s;
        int n;
        dst = (unsigned char __far *)MK_FP(orig_es, orig_bx);
        s = (unsigned char *)&g_state.icmp_result;
        for (n = 0; n < (int)sizeof(IcmpMuxResult); n++)
            dst[n] = s[n];
        g_state.icmp_state = ICMP_STATE_IDLE;
        g_state.mux_sock_result = 0;
        break;
    }

    case MUX_UNLOAD:
        /*
         * Restore all hooked vectors.  We do this from inside the INT 2Fh
         * handler, which is safe:
         *   - INT 14h and INT 28h are restored first (non-reentrant)
         *   - INT 2Fh is restored last; after we return (IRET), the old
         *     INT 2Fh handler is active again.
         * Memory is NOT freed here — the caller should use DOS INT 21h
         * AH=49h if they want to reclaim the MCB.
         */
        _dos_setvect(0x1C, old_int1c);
        _dos_setvect(0x14, old_int14);
        _dos_setvect(0x28, old_int28);
        _dos_setvect(0x2F, old_int2f);

        /* Wipe signature so re-install check fails */
        g_state.sig[0] = '\0';

        /* Set AL = 0x00 (success), keep AH unchanged */
        __asm {
            mov  ax, [bp+22]
            and  ax, 0xFF00
            mov  [bp+22], ax
        }
        break;

    default:
        break;
    }
    /* INT 2Fh: do not chain — just return (IRET via __interrupt epilogue) */
}
