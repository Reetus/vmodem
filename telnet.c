/*
 * telnet.c - Minimal Telnet IAC negotiation for VMODEM
 *
 * Implements just enough of RFC 854 (Telnet) and related option RFCs to
 * interoperate with BBS hosts and Telnet clients:
 *
 *   - On connect: advertise WILL ECHO, WILL SGA, DO SGA (the "server" side
 *     options that most BBS hosts and Telnet clients expect).
 *   - Strip incoming IAC sequences from the data stream.
 *   - Respond correctly to received WILL/WONT/DO/DONT option commands.
 *   - Escape outgoing 0xFF bytes as IAC IAC (0xFF 0xFF).
 *
 * The parser is a simple 3-state FSM stored per PortState so it survives
 * across multiple calls from the INT 28h drain loop.
 *
 * Note: send() is called directly here.  If the outgoing TCP buffer is
 * full the bytes are silently dropped — acceptable for a TSR where we
 * cannot block.
 */

#include CFG_H
#include <string.h>
#include "vmodem.h"

/* -----------------------------------------------------------------------
 * Internal helper — send raw bytes to the TCP socket (no IAC escaping)
 * --------------------------------------------------------------------- */

void telnet_send_raw(PortState *p, unsigned char *buf, int len)
{
    if (p->sock == NULL || !p->sock->isEstablished())
        return;
    p->sock->send(buf, (uint16_t)len);
}

/* -----------------------------------------------------------------------
 * telnet_on_connect
 *
 * Call immediately after a TCP connection is established (in either
 * client or server mode).  Sends the initial option negotiations:
 *
 *   IAC WILL ECHO     (we will echo — BBS host style)
 *   IAC WILL SGA      (suppress go-ahead)
 *   IAC DO   SGA      (ask remote to suppress go-ahead)
 *
 * Resets the IAC parser state.
 * --------------------------------------------------------------------- */

void telnet_on_connect(int port_idx)
{
    PortState *p = &g_state.ports[port_idx];
    unsigned char neg[9];

    /* Reset parser */
    p->iac_state = IAC_NORMAL;
    p->iac_cmd   = 0;
    p->neg_echo  = 0;
    p->neg_sga   = 0;

    /* Build negotiation sequence */
    neg[0] = TEL_IAC;  neg[1] = TEL_WILL; neg[2] = TELOPT_ECHO;
    neg[3] = TEL_IAC;  neg[4] = TEL_WILL; neg[5] = TELOPT_SGA;
    neg[6] = TEL_IAC;  neg[7] = TEL_DO;   neg[8] = TELOPT_SGA;

    telnet_send_raw(p, neg, 9);
}

/* -----------------------------------------------------------------------
 * telnet_send_response
 *
 * Send a 3-byte IAC option response without escaping (they are control
 * bytes, not user data).
 * --------------------------------------------------------------------- */

static void telnet_send_response(PortState *p,
                                  unsigned char cmd,
                                  unsigned char opt)
{
    unsigned char resp[3];
    resp[0] = TEL_IAC;
    resp[1] = cmd;
    resp[2] = opt;
    telnet_send_raw(p, resp, 3);
}

/* -----------------------------------------------------------------------
 * telnet_handle_option
 *
 * Process a completed WILL/WONT/DO/DONT + option code sequence.
 * Policy:
 *   DO   ECHO → WILL ECHO  (we'll handle echo)
 *   DO   SGA  → WILL SGA   (suppress go-ahead — always agree)
 *   WILL SGA  → DO   SGA   (ack remote SGA)
 *   DO   <x>  → WONT <x>   (refuse unknown options)
 *   WILL <x>  → DONT <x>   (refuse unknown options)
 *   WONT <x>  → (ignore)
 *   DONT <x>  → (ignore)
 * --------------------------------------------------------------------- */

static void telnet_handle_option(PortState *p,
                                  unsigned char cmd,
                                  unsigned char opt)
{
    switch (cmd) {

    case TEL_DO:
        if (opt == TELOPT_ECHO && !p->neg_echo) {
            p->neg_echo = 1;
            telnet_send_response(p, TEL_WILL, opt);
        } else if (opt == TELOPT_SGA && !p->neg_sga) {
            p->neg_sga = 1;
            telnet_send_response(p, TEL_WILL, opt);
        } else if (opt != TELOPT_ECHO && opt != TELOPT_SGA) {
            telnet_send_response(p, TEL_WONT, opt);
        }
        break;

    case TEL_WILL:
        if (opt == TELOPT_SGA && !p->neg_sga) {
            p->neg_sga = 1;
            telnet_send_response(p, TEL_DO, opt);
        } else if (opt != TELOPT_SGA) {
            telnet_send_response(p, TEL_DONT, opt);
        }
        break;

    case TEL_WONT:
    case TEL_DONT:
        /* Nothing to do — remote refusing an option we offered */
        break;

    default:
        break;
    }
}

/* -----------------------------------------------------------------------
 * telnet_filter
 *
 * Feed one received byte through the IAC FSM.
 *
 * Returns: the byte to place in the ring buffer (0-255),
 *       or -1 if the byte is part of an IAC sequence and should be
 *          discarded from the user data stream.
 *
 * Must be called for every byte arriving from the TCP socket before it
 * is placed in the ring buffer.
 * --------------------------------------------------------------------- */

int telnet_filter(PortState *p, unsigned char b)
{
    switch (p->iac_state) {

    case IAC_NORMAL:
        if (b == TEL_IAC) {
            p->iac_state = IAC_SAW_FF;
            return -1;              /* consumed — wait for command byte */
        }
        return (int)b;             /* plain data byte */

    case IAC_SAW_FF:
        if (b == TEL_IAC) {
            /* IAC IAC → literal 0xFF in data stream */
            p->iac_state = IAC_NORMAL;
            return 0xFF;
        }
        if (b == TEL_WILL || b == TEL_WONT ||
            b == TEL_DO   || b == TEL_DONT) {
            p->iac_cmd   = b;
            p->iac_state = IAC_SAW_CMD;
            return -1;
        }
        /* Any other command (IP, AO, SB, SE, NOP, …) — ignore */
        p->iac_state = IAC_NORMAL;
        return -1;

    case IAC_SAW_CMD:
        /* b is the option code */
        telnet_handle_option(p, p->iac_cmd, b);
        p->iac_state = IAC_NORMAL;
        return -1;

    default:
        p->iac_state = IAC_NORMAL;
        return -1;
    }
}

/* -----------------------------------------------------------------------
 * telnet_send_byte
 *
 * Send one user data byte to the TCP socket, escaping 0xFF as IAC IAC.
 * Called from the INT 14h AH=01h send path — must not block.
 * If the TCP transmit buffer is full we drop the byte silently.
 * --------------------------------------------------------------------- */

void telnet_send_byte(PortState *p, unsigned char b)
{
    /*
     * IMPORTANT: buf must be static, not stack-local.
     * When called from the INT 14h handler, DS = VMODEM's DGROUP but
     * SS = the caller's stack segment.  sock->send() dereferences the
     * buffer pointer via DS, so the buffer must live in DGROUP.
     * A stack-local buffer lives in SS, causing send() to read garbage.
     * Static is safe here because INT 14h calls are serialized.
     */
    static unsigned char buf[2];

    if (p->sock == NULL || !p->sock->isEstablished())
        return;

    if (b == 0xFF) {
        /* Escape: send IAC IAC */
        buf[0] = 0xFF;
        buf[1] = 0xFF;
        p->sock->send(buf, 2);
    } else {
        buf[0] = b;
        p->sock->send(buf, 1);
    }
}
