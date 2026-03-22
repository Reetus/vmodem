/*
 * int14.c - FOSSIL driver (INT 14h) for VMODEM
 *
 * Implements the FOSSIL specification (FSC-0015, revision 5) over TCP/IP.
 * This replaces the standard BIOS INT 14h with a full FOSSIL interface
 * that BBS software (Opus, BinkleyTerm, SEAdog, etc.) expects.
 *
 * FOSSIL detection:
 *   At offset +6 in the ISR code there must be the word 1954h followed
 *   by a byte containing the maximum supported function number.
 *   We place this signature in a naked __declspec stub that jumps to
 *   the real handler.
 *
 * FOSSIL status word (AH=03h and returned by AH=00h/01h):
 *   AH bits:
 *     bit 0 = RDA  - input data available in buffer
 *     bit 1 = OVRN - input buffer overrun
 *     bit 5 = THRE - room available in output buffer
 *     bit 6 = TSRE - output buffer is empty
 *   AL bits (null-modem compatible MSR):
 *     bits 0,1 = DCTS,DDSR always 1 (delta bits mirror state bits)
 *     bit 3 = DDCD  - delta DCD (set when DCD is high)
 *     bits 4,5 = CTS,DSR always 1
 *     bit 7 = DCD   - carrier detect (TCP connected)
 *
 * Open Watcom __interrupt __far prologue pushes:
 *   ax,cx,dx,bx,sp,bp,si,di,ds,es,ax,ax (12 words), then mov bp,sp
 *   [bp+22] = AX, [bp+20] = CX, [bp+18] = DX, [bp+16] = BX
 *   [bp+10] = SI, [bp+8] = DI, [bp+4] = ES
 */

#include CFG_H
#include <dos.h>
#include <i86.h>
#include <conio.h>
#include <string.h>
#include "vmodem.h"

/* Saved original INT 14h vector — set during TSR install in vmodem.c */
void (__interrupt __far *old_int14)(void) = NULL;

/* FOSSIL revision we conform to (spec revision 5) */
#define FOSSIL_REV       5
#define FOSSIL_MAX_FUNC  0x1B

/* TX ring buffer — FOSSIL requires buffered output with flush/purge */
#define TX_RING_SIZE     512

typedef struct {
    unsigned char  data[TX_RING_SIZE];
    unsigned short head;
    unsigned short tail;
    unsigned short count;
} TxRing;

static TxRing g_tx[MAX_PORTS];

/* Per-port FOSSIL state */
static unsigned char g_fossil_init[MAX_PORTS];  /* 1 = FOSSIL init'd on this port */
static unsigned char g_flow_ctrl[MAX_PORTS];    /* flow control flags */
static unsigned char g_overrun[MAX_PORTS];      /* overrun flag */
static unsigned char g_dtr[MAX_PORTS];          /* DTR state (1=raised) */
/* last_tx_tick is now in PortState (vmodem.h) */
static unsigned char g_purge_seen[MAX_PORTS];  /* set when AH=09h called while connected */

/* Flag: set to 1 during INT 14h poll context — DOS I/O is safe because
 * this is a software interrupt from user code, not a hardware IRQ. */
unsigned char g_int14_safe = 0;

/* FOSSIL driver info string */
static char fossil_id_str[] = "VMODEM FOSSIL driver " VMODEM_VER_STR "\0";

/* FOSSIL info structure (returned by AH=1Bh) */
#pragma pack(push, 1)
typedef struct {
    unsigned short strsiz;      /* size of this structure */
    unsigned char  majver;      /* FOSSIL spec version */
    unsigned char  minver;      /* driver revision */
    unsigned long  ident;       /* FAR pointer to ID string */
    unsigned short ibufr;       /* input buffer size */
    unsigned short ifree;       /* input buffer free bytes */
    unsigned short obufr;       /* output buffer size */
    unsigned short ofree;       /* output buffer free bytes */
    unsigned char  swidth;      /* screen width */
    unsigned char  sheight;     /* screen height */
    unsigned char  baud;        /* baud rate code */
} FossilInfo;
#pragma pack(pop)

/* -----------------------------------------------------------------------
 * TX ring helpers
 * --------------------------------------------------------------------- */

static void txring_init(TxRing *t)
{
    t->head = t->tail = t->count = 0;
}

static int txring_put(TxRing *t, unsigned char b)
{
    if (t->count >= TX_RING_SIZE)
        return -1;  /* full */
    t->data[t->tail] = b;
    t->tail = (t->tail + 1) & (TX_RING_SIZE - 1);
    t->count++;
    return 0;
}

static int txring_get(TxRing *t)
{
    unsigned char b;
    if (t->count == 0)
        return -1;
    b = t->data[t->head];
    t->head = (t->head + 1) & (TX_RING_SIZE - 1);
    t->count--;
    return (int)b;
}

/* -----------------------------------------------------------------------
 * fossil_status — build FOSSIL status word for a port
 * --------------------------------------------------------------------- */

static unsigned short fossil_status(int port_idx)
{
    PortState *p = &g_state.ports[port_idx];
    unsigned char lsr = 0;
    unsigned char msr = 0;

    /* TX status */
    if (g_tx[port_idx].count < TX_RING_SIZE)
        lsr |= 0x20;  /* THRE - room in output buffer */
    if (g_tx[port_idx].count == 0)
        lsr |= 0x40;  /* TSRE - output buffer empty */

    /* RX status */
    if (ring_count(&p->rx) > 0)
        lsr |= 0x01;  /* RDA - data available */

    /* Overrun */
    if (g_overrun[port_idx]) {
        lsr |= 0x02;  /* OVRN */
        g_overrun[port_idx] = 0;  /* cleared on read */
    }

    /* Modem status register — null-modem compatible layout.
     *
     *   8250 MSR bits:
     *     bit 0 = DCTS  (delta CTS)     bit 4 = CTS
     *     bit 1 = DDSR  (delta DSR)     bit 5 = DSR
     *     bit 2 = TERI  (trailing edge RI)  bit 6 = RI
     *     bit 3 = DDCD  (delta DCD)     bit 7 = DCD
     *
     * Many BBS programs check the delta bits (especially bit 3) to
     * detect carrier changes.  X00 and other null-modem FOSSILs set
     * the delta bits to match the state bits so software always sees
     * "carrier just detected" while connected.
     *
     * CTS + DSR are always asserted (virtual null-modem cable).
     * DCD tracks TCP connection state.
     * RI is set during ringing only. */

    /* Detect BBS waiting for DCD drop (e.g. RA "Terminating Call").
     * RA polls AH=03h in a tight loop waiting for DCD=0 but never
     * sends ATH or drops DTR.  After ~500 consecutive status polls
     * with no TX/RX activity (~1 second), close the connection. */

    /* CTS + DSR always on (null-modem), plus their delta bits */
    msr |= 0x31;  /* bit 0 DCTS + bit 4 CTS + bit 5 DSR */
    msr |= 0x02;  /* bit 1 DDSR */

    if (at_is_ringing(port_idx)) {
        msr |= 0x40;  /* RI (bit 6) */
    } else if (at_is_connect_pending(port_idx)) {
        /* Handshake in progress — DCD not yet asserted.
         * Real modems raise DCD only when CONNECT is sent. */
    } else if (p->mode == PORT_CONN && p->sock != NULL) {
        /* Drop DCD after purge+status polling (BBS "Terminating Call").
         * BBS sees DCD=0 and exits its DCD polling loop. */
        if (g_purge_seen[port_idx] < 3)
            msr |= 0x88;  /* DCD (bit 7) + DDCD (bit 3) */
    }

    /* MSR sync via MCR loopback is handled by INT 1Ch handler (int8.c).
     * This runs 18.2x/sec even when BBS is in tight loop polling MSR. */

    return ((unsigned short)lsr << 8) | (unsigned short)msr;
}

/* -----------------------------------------------------------------------
 * fossil_flush_tx — drain TX ring to TCP socket
 *
 * Called from the poll loop and from AH=08h flush.
 * Returns number of bytes sent, or 0 if nothing to do.
 * --------------------------------------------------------------------- */

int fossil_flush_tx(int port_idx)
{
    PortState *p = &g_state.ports[port_idx];
    TxRing *t = &g_tx[port_idx];
    int sent = 0;
    int b;

    /* Allow sending in ESTABLISHED or CLOSE_WAIT — in CLOSE_WAIT the
     * remote sent FIN but we can still transmit.  DOSBox-X SLIRP port
     * forwarding enters CLOSE_WAIT immediately after accept. */
    if (p->sock == NULL || p->sock->isClosed())
        return 0;

    /* Batch bytes into a static buffer and send in one chunk.
     * IAC (0xFF) bytes get doubled for telnet escaping, so the
     * output buffer needs to be 2x the ring size in the worst case. */
    {
        static unsigned char outbuf[TX_RING_SIZE * 2];
        unsigned short outpos = 0;

        while (t->count > 0) {
            b = txring_get(t);
            if (b < 0) break;
            if ((unsigned char)b == 0xFF) {
                outbuf[outpos++] = 0xFF;
                outbuf[outpos++] = 0xFF;
            } else {
                outbuf[outpos++] = (unsigned char)b;
            }
            sent++;
        }
        if (outpos > 0)
            p->sock->send(outbuf, outpos);
    }
    return sent;
}

/* -----------------------------------------------------------------------
 * int14_real_handler — FOSSIL ISR (real handler)
 *
 * The actual INT 14h vector points to int14_handler in fossil.asm,
 * which contains the FOSSIL signature (1954h at offset +6) and jumps
 * here. This function has the full Watcom __interrupt prologue/epilogue.
 * --------------------------------------------------------------------- */

void __interrupt __far int14_real_handler(void)
{
    unsigned short orig_ax;
    unsigned short orig_cx;
    unsigned short orig_dx;
    unsigned short orig_bx;
    unsigned short orig_di;
    unsigned short orig_es;
    unsigned char  port_idx;
    unsigned char  func;
    PortState     *p;
    unsigned short ret_ax;

    /* Read registers from interrupt stack frame */
    __asm {
        mov  ax, [bp+22]
        mov  orig_ax, ax
        mov  ax, [bp+20]
        mov  orig_cx, ax
        mov  ax, [bp+18]
        mov  orig_dx, ax
        mov  ax, [bp+16]
        mov  orig_bx, ax
        mov  ax, [bp+8]
        mov  orig_di, ax
        mov  ax, [bp+4]
        mov  orig_es, ax
    }

    port_idx = (unsigned char)(orig_dx & 0xFF);
    func     = (unsigned char)(orig_ax >> 8);

    /* DX=00FFh is a special case — do non-comm processing, return success */
    if (port_idx == 0xFF) {
        if (func == 0x04) {
            /* Init with DX=FFh: return success but do no comm setup */
            __asm {
                mov  ax, 1954h
                mov  [bp+22], ax
                mov  ax, 051Bh
                mov  [bp+16], ax
            }
            return;
        }
        /* Other functions with DX=FFh: just return */
        return;
    }

    /* Limit to valid port range */
    port_idx &= 0x03;

    /* If this port is not managed by us, chain to the original handler */
    if (port_idx >= MAX_PORTS || !g_state.ports[port_idx].initialized) {
        _chain_intr(old_int14);
        return;
    }

    p = &g_state.ports[port_idx];
    ret_ax = 0;

    /* Log FOSSIL function calls.  Normally log each unique func once,
     * but after AH=09h purge, log ALL calls to see what BBS does. */
    {
        static unsigned long seen_lo = 0;
        static char fb[7] = { 'F', ':', '0', '0', ' ', '\0', '\0' };
        static const char hx[] = "0123456789ABCDEF";
        if (g_purge_seen[port_idx]) {
            /* After purge: log every call */
            fb[2] = hx[(func >> 4) & 0x0F];
            fb[3] = hx[func & 0x0F];
            dbg(fb);
        } else if (func < 0x20) {
            unsigned long bit = 1UL << func;
            if (!(seen_lo & bit)) {
                seen_lo |= bit;
                fb[2] = hx[(func >> 4) & 0x0F];
                fb[3] = hx[func & 0x0F];
                dbg(fb);
            }
        }
    }

    /* Post-CONNECT trace: log transitions and interesting events.
     * Tracks: RDA transitions, all non-03h calls, and first 8 AH=03h calls. */
    {
        static unsigned char post_conn_trace = 0;
        static unsigned char last_rda = 255;  /* 255 = uninitialized */
        static unsigned short trace_events = 0;
        static unsigned char f03_count = 0;
        static const char thx[] = "0123456789ABCDEF";

        /* Start tracing once we see PORT_CONN and not ringing */
        if (p->mode == PORT_CONN && !at_is_ringing(port_idx) && !post_conn_trace) {
            post_conn_trace = 1;
            trace_events = 0;
            f03_count = 0;
            last_rda = 255;
            dbg("[TRACE-ON]");
        }

        if (post_conn_trace && trace_events < 60) {
            unsigned short st = fossil_status(port_idx);
            unsigned char rda = (st >> 8) & 0x01;

            /* Log RDA transitions */
            if (rda != last_rda) {
                static char rb[10] = { 'R', 'D', 'A', ':', '0', ' ', '\0' };
                rb[4] = rda ? '1' : '0';
                dbg(rb);
                last_rda = rda;
                trace_events++;
            }

            /* Log all non-03h calls, plus first 8 03h calls */
            if (func != 0x03 || f03_count < 8) {
                static char tb[12] = { 'P', ':', '0', '0', ',', '0', '0', '0', '0', ' ', '\0', '\0' };
                tb[2] = thx[(func >> 4) & 0x0F];
                tb[3] = thx[func & 0x0F];
                tb[5] = thx[(st >> 12) & 0x0F];
                tb[6] = thx[(st >> 8) & 0x0F];
                tb[7] = thx[(st >> 4) & 0x0F];
                tb[8] = thx[st & 0x0F];
                dbg(tb);
                if (func == 0x03) f03_count++;
                trace_events++;
            }
        }
    }

    switch (func) {

    /* ------------------------------------------------------------------
     * AH=00h  Set baud rate
     * FOSSIL: only baud rate in high 3 bits of AL. We ignore all of it
     * since TCP runs at wire speed. Return status word.
     * ------------------------------------------------------------------ */
    case 0x00:
        ret_ax = fossil_status(port_idx);
        break;

    /* ------------------------------------------------------------------
     * AH=01h  Transmit character with wait
     * FOSSIL: AL = character. Wait until buffer has room, then store.
     * Return status word in AX.
     * ------------------------------------------------------------------ */
    case 0x01:
    {
        unsigned char byte_to_send = (unsigned char)(orig_ax & 0xFF);
        int at_rc;
        p->last_tx_tick = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);

        /* Count all AH=01h calls to detect if BBS is writing after CONNECT */
        {
            static unsigned short f01_count = 0;
            f01_count++;
            if (f01_count == 1 || (f01_count & 0x3FF) == 0) {
                static const char chx[] = "0123456789ABCDEF";
                static char cbuf[9] = { 'W', ':', '0', '0', '0', '0', ' ', '\0' };
                cbuf[2] = chx[(f01_count >> 12) & 0x0F];
                cbuf[3] = chx[(f01_count >> 8) & 0x0F];
                cbuf[4] = chx[(f01_count >> 4) & 0x0F];
                cbuf[5] = chx[f01_count & 0x0F];
                dbg(cbuf);
            }
        }

        /* Try AT command parser first — it returns 1 if the byte was
         * consumed (command mode), 0 if we should send to TCP. */
        at_rc = at_input(port_idx, byte_to_send);
        if (at_rc == 0) {
            /* Data mode — send to TCP via TX ring */
            if (p->mode == PORT_CONN && p->sock != NULL) {
                static unsigned short tx_count = 0;
                if (tx_count == 0)
                    dbg("[TX+]");  /* first TX byte in data mode */
                tx_count++;
                if (txring_put(&g_tx[port_idx], byte_to_send) < 0) {
                    fossil_flush_tx(port_idx);
                    if (txring_put(&g_tx[port_idx], byte_to_send) < 0) {
                        telnet_send_byte(p, byte_to_send);
                    }
                }
            } else {
                static unsigned char tx_noconn = 0;
                if (!tx_noconn) {
                    tx_noconn = 1;
                    dbg("[TX-NOCONN]");
                }
            }
        } else {
            static unsigned char tx_at = 0;
            if (!tx_at) {
                tx_at = 1;
                dbg("[TX-AT]");
            }
        }
        ret_ax = fossil_status(port_idx);
        break;
    }

    /* ------------------------------------------------------------------
     * AH=02h  Receive character with wait
     * FOSSIL: Wait until data available, return AH=00h, AL=byte.
     * We can't truly block in a TSR, so if no data, return with
     * timeout indication instead of spinning.
     * ------------------------------------------------------------------ */
    case 0x02:
    {
        int b;
        b = ring_get(&p->rx);
        if (b < 0) {
            /* No data — drive mTCP so we can receive packets and
             * accept connections.  INT 14h is a software interrupt
             * from user code, so this is safe (not hardware IRQ). */
            if (!g_state.busy) {
                g_state.busy = 1;
                g_int14_safe = 1;
                _enable();
                poll_on_priv_stack();
                _disable();
                g_int14_safe = 0;
                g_state.busy = 0;
                b = ring_get(&p->rx);
            }
            if (b < 0) {
                ret_ax = 0x8000;  /* timeout — no data */
            } else {
                ret_ax = (unsigned short)b;
            }
        } else {
            ret_ax = (unsigned short)b;  /* AH=00h, AL=byte */
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=03h  Request status
     * FOSSIL: Return AH=LSR, AL=MSR (bit 3 always 1, bit 7=DCD)
     *
     * Drive mTCP here — apps loop on AH=03h waiting for data or DCD.
     * Without polling here, INT 28h may never fire if the app doesn't
     * call DOS idle functions.
     * ------------------------------------------------------------------ */
    case 0x03:
        if (!g_state.busy) {
            g_state.busy = 1;
            g_int14_safe = 1;
            _enable();
            poll_on_priv_stack();
            _disable();
            g_int14_safe = 0;
            g_state.busy = 0;
        }
        at_check_ring(port_idx);

        /* Detect BBS waiting for DCD drop (e.g. RA "Terminating Call").
         * After AH=09h (purge) while connected, count AH=03h status polls.
         * Once we've seen enough, just drop DCD — fossil_status() checks
         * g_purge_seen and returns DCD=0.  The actual TCP close is handled
         * by the idle timeout in the normal poll cycle (INT 28h). */
        if (g_purge_seen[port_idx] && p->mode == PORT_CONN && p->sock != NULL) {
            g_purge_seen[port_idx]++;
            if (g_purge_seen[port_idx] >= 3) {
                dbg("[DCD-DROP]");
                /* DCD is now dropped via fossil_status() check.
                 * Don't close socket here — let idle timeout handle it
                 * from the INT 28h poll context where it's safe. */
            }
        }

        ret_ax = fossil_status(port_idx);
        break;

    /* ------------------------------------------------------------------
     * AH=04h  Initialize FOSSIL driver
     * Return AX=1954h, BL=max func, BH=revision
     * Raises DTR, resets buffers and flow control.
     * ------------------------------------------------------------------ */
    case 0x04:
    {
        /* Reset buffers */
        ring_init(&p->rx);
        txring_init(&g_tx[port_idx]);

        /* Reset state */
        g_fossil_init[port_idx] = 1;
        g_flow_ctrl[port_idx] = 0;
        g_overrun[port_idx] = 0;
        g_dtr[port_idx] = 1;  /* DTR raised */
        g_purge_seen[port_idx] = 0;
        {
            unsigned long now = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
            p->last_tx_tick = now;
            p->last_rx_tick = now;
            p->idle_timeout = 30;  /* default 30 second idle timeout */
        }
        at_init(port_idx);

        /* Raise DTR on the real UART so direct-I/O MCR polling has
         * a known baseline (apps like Telix drop DTR via port I/O). */
        {
            unsigned short uart_base =
                *(volatile unsigned short __far *)MK_FP(0x0040, port_idx * 2);
            if (uart_base != 0) {
                unsigned char mcr = inp(uart_base + 4);
                outp(uart_base + 4, mcr | 0x01);  /* set DTR bit */
            }
        }

        ret_ax = 0x1954;

        /* Set BX: BH=revision(5), BL=max function(1Bh) */
        __asm {
            mov  ax, 051Bh
            mov  [bp+16], ax
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=05h  Deinitialize FOSSIL driver
     * DTR is NOT affected. Flush and close buffers.
     * ------------------------------------------------------------------ */
    case 0x05:
        dbg("[DEINIT]");
        fossil_flush_tx(port_idx);
        g_fossil_init[port_idx] = 0;

        /* If DTR is still raised and we have an active connection,
         * the BBS is terminating without explicitly dropping DTR.
         * Close the TCP connection so the telnet client sees the hangup. */
        if (g_dtr[port_idx] && p->mode == PORT_CONN && p->sock != NULL) {
            dbg("[DEINIT-DISC]");
            p->sock->close();
            TcpSocketMgr::freeSocket(p->sock);
            p->sock = NULL;
            ring_init(&p->rx);
            at_send_no_carrier(port_idx);
            if (p->listenSock)
                p->mode = PORT_LISTEN;
            else
                p->mode = PORT_DISC;
        }
        break;

    /* ------------------------------------------------------------------
     * AH=06h  Raise/lower DTR
     * AL=01h raise, AL=00h lower.
     * Lowering DTR = disconnect the TCP session.
     * ------------------------------------------------------------------ */
    case 0x06:
    {
        unsigned char al = (unsigned char)(orig_ax & 0xFF);
        g_dtr[port_idx] = al ? 1 : 0;
        {
            static const char dhx[] = "0123456789ABCDEF";
            static char dtrbuf[7] = { 'D', 'T', 'R', ':', '0', '\0', '\0' };
            dtrbuf[4] = dhx[(al >> 4) & 0x0F];
            dtrbuf[5] = dhx[al & 0x0F];
            dbg(dtrbuf);
        }

        if (al == 0) {
            /* DTR dropped — disconnect */
            if (p->mode == PORT_CONN && p->sock != NULL) {
                fossil_flush_tx(port_idx);
                p->sock->close();
                TcpSocketMgr::freeSocket(p->sock);
                p->sock = NULL;
                ring_init(&p->rx);
                at_send_no_carrier(port_idx);
                if (p->listenSock)
                    p->mode = PORT_LISTEN;
                else
                    p->mode = PORT_DISC;
            }
        } else {
            /* DTR raised — if ringing, answer the call */
            if (at_is_ringing(port_idx) && p->mode == PORT_CONN) {
                at_send_connect(port_idx);
            }
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=07h  Return timer tick parameters
     * AL=timer interrupt, AH=ticks/sec, DX=ms/tick
     * IBM PC: INT 1Ch, 18.2 Hz, ~55ms
     * ------------------------------------------------------------------ */
    case 0x07:
        ret_ax = (18 << 8) | 0x1C;  /* AH=18 ticks/sec, AL=INT 1Ch */
        /* Set DX = 55 (ms per tick) */
        __asm {
            mov  word ptr [bp+18], 55
        }
        break;

    /* ------------------------------------------------------------------
     * AH=08h  Flush output buffer (blocking)
     * Wait until all pending output has been sent.
     * ------------------------------------------------------------------ */
    case 0x08:
        fossil_flush_tx(port_idx);
        break;

    /* ------------------------------------------------------------------
     * AH=09h  Purge output buffer
     * Discard any pending output.
     * ------------------------------------------------------------------ */
    case 0x09:
        txring_init(&g_tx[port_idx]);
        /* Only set purge_seen if not already in DCD-dropped state (>=3).
         * BBS calls purge multiple times during "Terminating Call" —
         * resetting would re-assert DCD and freeze the BBS. */
        if (p->mode == PORT_CONN && p->sock != NULL
            && g_purge_seen[port_idx] < 3)
            g_purge_seen[port_idx] = 1;
        break;

    /* ------------------------------------------------------------------
     * AH=0Ah  Purge input buffer
     * Discard any pending input.
     * ------------------------------------------------------------------ */
    case 0x0A:
        ring_init(&p->rx);
        break;

    /* ------------------------------------------------------------------
     * AH=0Bh  Transmit no wait
     * Like AH=01h but returns immediately if buffer full.
     * AX=0001h if accepted, AX=0000h if not.
     * ------------------------------------------------------------------ */
    case 0x0B:
    {
        unsigned char byte_to_send = (unsigned char)(orig_ax & 0xFF);

        if (at_input(port_idx, byte_to_send)) {
            ret_ax = 0x0001;  /* consumed by AT parser */
        } else if (p->mode == PORT_CONN && p->sock != NULL) {
            if (txring_put(&g_tx[port_idx], byte_to_send) == 0) {
                ret_ax = 0x0001;  /* accepted */
            } else {
                ret_ax = 0x0000;  /* buffer full */
            }
        } else {
            ret_ax = 0x0000;  /* not connected */
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=0Ch  Non-destructive read-ahead (peek)
     * AH=00h, AL=next char if available; AX=FFFFh if not.
     * ------------------------------------------------------------------ */
    case 0x0C:
    {
        if (ring_count(&p->rx) > 0) {
            /* Peek at head without consuming */
            ret_ax = (unsigned short)p->rx.data[p->rx.head];
        } else {
            ret_ax = 0xFFFF;
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=0Dh  Keyboard read without wait
     * Return AX = IBM scan code, or FFFFh if nothing available.
     * Passthrough to BIOS INT 16h AH=01h.
     * ------------------------------------------------------------------ */
    case 0x0D:
    {
        unsigned short key;
        __asm {
            mov  ah, 01h
            int  16h
            jz   L_nokey_0d
            mov  ah, 00h
            int  16h
            mov  key, ax
            jmp  L_done_0d
        L_nokey_0d:
            mov  key, 0FFFFh
        L_done_0d:
        }
        ret_ax = key;
        break;
    }

    /* ------------------------------------------------------------------
     * AH=0Eh  Keyboard read with wait
     * Return AX = IBM scan code. Wait for keypress.
     * Passthrough to BIOS INT 16h AH=00h.
     * ------------------------------------------------------------------ */
    case 0x0E:
    {
        unsigned short key;
        __asm {
            mov  ah, 00h
            int  16h
            mov  key, ax
        }
        ret_ax = key;
        break;
    }

    /* ------------------------------------------------------------------
     * AH=0Fh  Enable or disable flow control
     * AL = bit mask. We accept the call but flow control is largely
     * meaningless over TCP. Store it for info queries.
     * ------------------------------------------------------------------ */
    case 0x0F:
        g_flow_ctrl[port_idx] = (unsigned char)(orig_ax & 0xFF);
        break;

    /* ------------------------------------------------------------------
     * AH=10h  Ctrl-C/K checking and transmit on/off
     * We don't implement Ctrl-C checking. Return 0 (not received).
     * ------------------------------------------------------------------ */
    case 0x10:
        ret_ax = 0x0000;
        break;

    /* ------------------------------------------------------------------
     * AH=11h  Set cursor position
     * DH=row, DL=col. Passthrough to BIOS INT 10h AH=02h.
     * ------------------------------------------------------------------ */
    case 0x11:
    {
        unsigned short pos = orig_dx;
        __asm {
            mov  ah, 02h
            mov  bh, 0
            mov  dx, pos
            int  10h
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=12h  Read cursor position
     * Return DH=row, DL=col via BIOS INT 10h AH=03h.
     * ------------------------------------------------------------------ */
    case 0x12:
    {
        unsigned short pos;
        __asm {
            mov  ah, 03h
            mov  bh, 0
            int  10h
            mov  pos, dx
        }
        /* Write cursor position back to DX in interrupt frame */
        __asm {
            mov  ax, pos
            mov  [bp+18], ax
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=13h  Single character ANSI write to screen
     * AL = character. Use DOS INT 21h AH=02h for ANSI processing.
     * ------------------------------------------------------------------ */
    case 0x13:
    {
        unsigned char ch = (unsigned char)(orig_ax & 0xFF);
        __asm {
            mov  ah, 02h
            mov  dl, ch
            int  21h
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=14h  Watchdog on/off
     * AL=01h enable, AL=00h disable.
     * We don't implement watchdog (no reboot on carrier loss).
     * ------------------------------------------------------------------ */
    case 0x14:
        break;

    /* ------------------------------------------------------------------
     * AH=15h  Write character to screen using BIOS
     * AL = character. Use BIOS INT 10h AH=0Eh (teletype).
     * ------------------------------------------------------------------ */
    case 0x15:
    {
        unsigned char ch = (unsigned char)(orig_ax & 0xFF);
        __asm {
            mov  ah, 0Eh
            mov  al, ch
            mov  bh, 0
            int  10h
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=16h  Timer tick chain add/remove
     * We don't implement the timer tick chain.
     * Return AX=FFFFh (unsuccessful).
     * ------------------------------------------------------------------ */
    case 0x16:
        ret_ax = 0xFFFF;
        break;

    /* ------------------------------------------------------------------
     * AH=17h  Reboot system
     * AL=00h cold, AL=01h warm.
     * ------------------------------------------------------------------ */
    case 0x17:
    {
        unsigned char boot_type = (unsigned char)(orig_ax & 0xFF);
        if (boot_type == 0x01) {
            /* Warm boot: set reset flag, jump to FFFF:0000 */
            *(unsigned short __far *)MK_FP(0x0040, 0x0072) = 0x1234;
        } else {
            /* Cold boot */
            *(unsigned short __far *)MK_FP(0x0040, 0x0072) = 0x0000;
        }
        __asm {
            db 0EAh        ; far JMP opcode
            dw 0000h       ; offset 0000h
            dw 0FFFFh      ; segment FFFFh
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=18h  Block read (FOSSIL to user buffer)
     * CX = max chars, DX = port, ES:DI = buffer
     * Return AX = actual chars transferred.
     * ------------------------------------------------------------------ */
    case 0x18:
    {
        unsigned short max_chars = orig_cx;
        unsigned char __far *ubuf = (unsigned char __far *)MK_FP(orig_es, orig_di);
        unsigned short count = 0;
        int b;

        while (count < max_chars) {
            b = ring_get(&p->rx);
            if (b < 0)
                break;
            ubuf[count++] = (unsigned char)b;
        }
        ret_ax = count;
        break;
    }

    /* ------------------------------------------------------------------
     * AH=19h  Block write (user buffer to FOSSIL)
     * CX = max chars, DX = port, ES:DI = buffer
     * Return AX = actual chars transferred.
     * ------------------------------------------------------------------ */
    case 0x19:
    {
        unsigned short max_chars = orig_cx;
        unsigned char __far *ubuf = (unsigned char __far *)MK_FP(orig_es, orig_di);
        unsigned short count = 0;

        while (count < max_chars) {
            if (at_input(port_idx, ubuf[count])) {
                count++;  /* consumed by AT parser */
            } else if (p->mode == PORT_CONN && p->sock != NULL) {
                if (txring_put(&g_tx[port_idx], ubuf[count]) < 0)
                    break;  /* TX buffer full */
                count++;
            } else {
                break;
            }
        }
        ret_ax = count;
        break;
    }

    /* ------------------------------------------------------------------
     * AH=1Ah  Break begin/end
     * AL=01h start, AL=00h stop. No-op for TCP.
     * ------------------------------------------------------------------ */
    case 0x1A:
        break;

    /* ------------------------------------------------------------------
     * AH=1Bh  Return driver information
     * CX = size of user buffer, DX = port, ES:DI = buffer
     * Return AX = bytes transferred.
     * ------------------------------------------------------------------ */
    case 0x1B:
    {
        unsigned short buf_sz = orig_cx;
        unsigned char __far *ubuf = (unsigned char __far *)MK_FP(orig_es, orig_di);
        FossilInfo info;
        unsigned short copy_sz;

        info.strsiz  = sizeof(FossilInfo);
        info.majver  = FOSSIL_REV;
        info.minver  = 1;  /* our driver revision */
        {
            char __far *id_far = (char __far *)fossil_id_str;
            info.ident = ((unsigned long)FP_SEG(id_far) << 16) | FP_OFF(id_far);
        }
        info.ibufr   = RING_SIZE;
        info.ifree   = (unsigned short)(RING_SIZE - ring_count(&p->rx));
        info.obufr   = TX_RING_SIZE;
        info.ofree   = (unsigned short)(TX_RING_SIZE - g_tx[port_idx].count);
        info.swidth  = 80;
        info.sheight = 25;
        info.baud    = 0xE3;  /* 115200-8N1: bits 7-5=111(115200), 4-3=00(none), 2=0(1stop), 1-0=11(8bit) */

        copy_sz = (buf_sz < sizeof(FossilInfo)) ? buf_sz : sizeof(FossilInfo);
        _fmemcpy(ubuf, (unsigned char __far *)&info, copy_sz);
        ret_ax = copy_sz;
        break;
    }

    /* ------------------------------------------------------------------
     * Unknown function — return status (safe default)
     * ------------------------------------------------------------------ */
    default:
        ret_ax = fossil_status(port_idx);
        break;
    }

    /* Write return AX to interrupt stack frame */
    __asm {
        mov  ax, ret_ax
        mov  [bp+22], ax
    }
}
