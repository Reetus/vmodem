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
 * Provides a control interface for VMODEMCTL and for a second VMODEM
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

void __interrupt __far int1c_handler(void)
{
    _chain_intr(old_int1c);
}

/* -----------------------------------------------------------------------
 * int28_handler  (INT 28h — DOS Idle)
 *
 * Switches to the private stack, drives mTCP, then restores the original
 * stack and chains to the previous INT 28h handler.
 * --------------------------------------------------------------------- */

void __interrupt __far int28_handler(void)
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
 *   [bp+10] = SI (hostname offset for MUX_CONNECT)
 *   [bp+4]  = ES (segment for MUX_CONNECT host / MUX_STATUS buffer)
 * --------------------------------------------------------------------- */

void __interrupt __far int2f_handler(void)
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

    case MUX_CONNECT:
        /*
         * CX = COM port index, DX = TCP remote port,
         * ES:SI → null-terminated hostname string
         */
        cmd_connect((int)orig_cx,
                    (unsigned short)orig_dx,
                    (char __far *)MK_FP(orig_es, orig_si));
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
