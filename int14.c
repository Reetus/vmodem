/*
 * int14.c - INT 14h (BIOS Serial I/O) hook for VMODEM
 *
 * Standard BIOS INT 14h calling convention:
 *   AH = function (00h-03h)
 *   DX = COM port index (0=COM1, 1=COM2, 2=COM3, 3=COM4)
 *
 * For ports managed by VMODEM we emulate the BIOS interface over TCP.
 * Unmanaged ports (not in our port table) are passed through to the
 * original BIOS handler via _chain_intr().
 *
 * Open Watcom __interrupt __far behavior (small model):
 *   - Saves all registers on the stack via this push sequence:
 *       push ax, cx, dx, bx, sp, bp, si, di, ds, es, ax, ax  (12 words)
 *       mov  bp, sp
 *     Offsets from BP to saved registers:
 *       [bp+22] = original AX  (AH = function code, AL = byte to send)
 *       [bp+20] = original CX
 *       [bp+18] = original DX  (DL = COM port index 0-3)
 *       [bp+16] = original BX
 *       [bp+12] = original BP
 *       [bp+10] = original SI
 *       [bp+8]  = original DI
 *       [bp+6]  = original DS
 *       [bp+4]  = original ES
 *   - Loads DS = DGROUP (the constant is embedded at link time)
 *   - OW 2.0 beta does not expose _AX/_DX/etc. pseudo-vars in C++ mode.
 *     We access the saved register values directly via inline assembly
 *     using the BP-relative offsets listed above.
 *   - To set return registers, write to the corresponding [bp+N] slot.
 *     The epilogue pops them back into the CPU registers before IRET.
 *   - _chain_intr(fn) jumps to fn as if it were the original interrupt
 *     handler (no IRET from us; fn issues the IRET).
 *
 * LSR (Line Status Register) bit meanings (returned in AH for AH=01h/02h,
 * and the high byte of AX for AH=03h):
 *   bit 0 = Data Ready (RX data available)
 *   bit 5 = TX Holding Register Empty (ready to send)
 *   bit 6 = TX Shift Register Empty
 *   bit 7 = Timeout error
 *
 * MSR (Modem Status Register) bit meanings (returned in AL for AH=03h):
 *   bit 4 = CTS  — Clear To Send
 *   bit 5 = DSR  — Data Set Ready
 *   bit 7 = DCD  — Data Carrier Detect (BBS software checks this!)
 */

#include CFG_H
#include <dos.h>
#include <i86.h>
#include "vmodem.h"

/* Saved original INT 14h vector — set during TSR install in vmodem.c */
void (__interrupt __far *old_int14)(void) = NULL;

/* -----------------------------------------------------------------------
 * int14_handler
 *
 * The actual ISR.  Watcom's prologue handles all register saving and the
 * DS reload, so we can access g_state directly.
 *
 * We read the caller's AX and DX from the interrupt stack frame via
 * BP-relative inline assembly, and write the return AX the same way.
 * --------------------------------------------------------------------- */

void __interrupt __far int14_handler(void)
{
    unsigned short orig_ax;     /* caller's AX: AH=func, AL=byte-to-send */
    unsigned short orig_dx;     /* caller's DX: DL=COM port index         */
    unsigned char  port_idx;
    unsigned char  func;
    PortState     *p;
    unsigned short ret_ax;      /* value to place in AX on return         */

    /*
     * Read original AX and DX from the interrupt stack frame.
     * The Watcom __interrupt prologue already ran; BP is now our frame ptr.
     * [bp+22] = original AX (first pushed register, deepest on stack)
     * [bp+18] = original DX (third pushed register)
     */
    __asm {
        mov  ax, [bp+22]
        mov  orig_ax, ax
        mov  ax, [bp+18]
        mov  orig_dx, ax
    }

    port_idx = (unsigned char)(orig_dx  & 0x03);
    func     = (unsigned char)(orig_ax >> 8);       /* AH */

    /* If this port is not managed by us, chain to the original handler */
    if (port_idx >= MAX_PORTS || !g_state.ports[port_idx].initialized) {
        _chain_intr(old_int14);
        return;
    }

    p = &g_state.ports[port_idx];
    ret_ax = 0;

    switch (func) {

    /* ------------------------------------------------------------------
     * AH=00h  Initialize Serial Port
     *
     * The caller passes a baud rate / parity / data bits config in AL.
     * We ignore all of that — the TCP connection runs at "wire speed".
     * Return a status word indicating TX ready.
     * ------------------------------------------------------------------ */
    case 0x00:
        ret_ax = 0x6000;    /* AH=0x60: TX holding & shift reg empty, AL=0 */
        break;

    /* ------------------------------------------------------------------
     * AH=01h  Write Character to Serial Port
     *
     * AL = byte to transmit.
     * If connected, send via Telnet path (escapes 0xFF).
     * Return AH = LSR: 0x60 (TX ready) on success, 0x80 (timeout) if not
     * connected.
     * ------------------------------------------------------------------ */
    case 0x01:
    {
        unsigned char byte_to_send = (unsigned char)(orig_ax & 0xFF); /* AL */

        if (p->mode == PORT_CONN && p->sock != NULL) {
            telnet_send_byte(p, byte_to_send);
            ret_ax = 0x6000;    /* AH=0x60: TX empty — success */
        } else {
            ret_ax = 0x8000;    /* AH=0x80: timeout bit — not connected */
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=02h  Read Character from Serial Port
     *
     * Returns: AH = LSR status, AL = received byte (if any).
     * If no data available sets the timeout bit (AH bit 7).
     * ------------------------------------------------------------------ */
    case 0x02:
    {
        int b = ring_get(&p->rx);

        if (b < 0) {
            ret_ax = 0x8000;    /* AH=0x80: timeout — no data in ring buffer */
        } else {
            ret_ax = (unsigned short)b; /* AH=0x00, AL=byte */
        }
        break;
    }

    /* ------------------------------------------------------------------
     * AH=03h  Get Serial Port Status
     *
     * Returns: AH = LSR, AL = MSR.
     *
     * BBS software (and terminal programs) read this before doing I/O.
     * Most importantly they check MSR for DCD (Data Carrier Detect) to
     * decide whether a modem is connected.  We must report DCD=1 when
     * a TCP connection is ESTABLISHED so the software does not hang up.
     * ------------------------------------------------------------------ */
    case 0x03:
    {
        unsigned char lsr, msr;

        if (p->mode == PORT_CONN && p->sock != NULL) {
            lsr = 0x60;     /* LSR: TX shift+holding reg empty (ready to send) */
            msr = 0xB0;     /* MSR: bits 4(CTS) + 5(DSR) + 7(DCD) set        */
        } else {
            lsr = 0x20;     /* LSR: TX shift reg empty only */
            msr = 0x00;     /* MSR: no modem — no carrier   */
        }

        /* Set RX data ready bit if bytes are waiting */
        if (ring_count(&p->rx) > 0)
            lsr |= 0x01;    /* LSR bit 0: Data Ready */

        ret_ax = ((unsigned short)lsr << 8) | (unsigned short)msr;
        break;
    }

    /* ------------------------------------------------------------------
     * Unknown function on a managed port (e.g. AH=04h extended init,
     * AH=05h modem control, AH=06h AMI extension used by Telix).
     *
     * Do NOT chain to the old BIOS handler — DOSBox-X logs "Unhandled"
     * for these and may return garbage that confuses the caller.
     * Return the current port status (same as AH=03h) so the caller
     * sees a consistent, sane response.
     * ------------------------------------------------------------------ */
    default:
    {
        unsigned char lsr, msr;
        lsr = (p->mode == PORT_CONN && p->sock != NULL) ? 0x60 : 0x20;
        msr = (p->mode == PORT_CONN && p->sock != NULL) ? 0xB0 : 0x00;
        if (ring_count(&p->rx) > 0) lsr |= 0x01;
        ret_ax = ((unsigned short)lsr << 8) | (unsigned short)msr;
        break;
    }
    }

    /*
     * Write the return AX value back into the interrupt stack frame so
     * that the epilogue's register restore puts it in AX on IRET.
     */
    __asm {
        mov  ax, ret_ax
        mov  [bp+22], ax
    }
}
