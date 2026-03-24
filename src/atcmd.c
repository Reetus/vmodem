/*
 * atcmd.c - Hayes AT command interpreter for virtual modem emulation
 *
 * When no TCP connection is active, the BBS sends AT commands to
 * "initialize the modem."  We intercept TX bytes here, parse AT
 * commands, and inject appropriate responses (OK, CONNECT, RING,
 * NO CARRIER, ERROR) into the RX ring buffer.
 *
 * When connected (PORT_CONN), TX bytes pass through to TCP normally.
 *
 * Minimum command set to satisfy BBS software (RemoteAccess, etc.):
 *   AT        - attention, respond OK
 *   ATZ       - reset, respond OK
 *   ATE0/ATE1 - echo off/on
 *   ATH/ATH0  - hangup (disconnect if connected)
 *   ATO       - return to online state
 *   ATA       - answer incoming call
 *   ATQ0/ATQ1 - result codes on/off
 *   ATV0/ATV1 - verbose/numeric result codes
 *   ATS0=n    - set auto-answer ring count
 *   ATS0?     - query S0 register
 *   ATD            - dial (accepted, returns OK — no outbound support)
 *   ATX, ATL, ATM, AT&, etc. - accepted silently
 */

#include CFG_H
#include <dos.h>
#include <i86.h>
#include <string.h>
#include <conio.h>
#include "vmodem.h"
#include "tcp.h"
#include "tcpsockm.h"

#define AT_BUF_SIZE 128

typedef struct {
    char           buf[AT_BUF_SIZE];
    unsigned char  pos;
    unsigned char  echo;      /* 1 = echo typed chars to RX */
    unsigned char  quiet;     /* 1 = suppress result codes  */
    unsigned char  verbose;   /* 1 = verbose (OK), 0 = numeric (0) */
    unsigned char  s0;        /* S0: auto-answer ring count (0=off) */
    unsigned char  ringing;   /* 1 = incoming call pending answer */
    unsigned char  rings_sent;/* number of RINGs sent so far */
    unsigned char  cmd_mode;  /* 1 = +++ escape entered command mode */
    unsigned char  connect_pending; /* 1 = CONNECT response waiting for delivery */
    unsigned char  _pad2;          /* explicit pad for -zp2 alignment */
    unsigned long  ring_tick; /* BIOS tick when last RING was sent */
    unsigned long  connect_tick;   /* BIOS tick when CONNECT was initiated */

    /* +++ escape sequence tracking */
    unsigned char  plus_count;   /* consecutive '+' chars seen (0-3) */
    unsigned char  _pad1;
    unsigned long  last_tx_tick; /* BIOS tick of last non-'+' TX byte */
    unsigned long  plus_tick;    /* BIOS tick when 3rd '+' was received */
} AtState;

static AtState g_at[MAX_PORTS];

/* -----------------------------------------------------------------------
 * Response helpers — inject strings into the port's RX ring
 * --------------------------------------------------------------------- */

static void at_send_str(int port_idx, const char *str)
{
    PortState *p = &g_state.ports[port_idx];
    while (*str) {
        ring_put(&p->rx, (unsigned char)*str);
        str++;
    }
}

static void at_respond(int port_idx, const char *str)
{
    AtState *at = &g_at[port_idx];

    if (at->quiet)
        return;

    if (at->verbose) {
        at_send_str(port_idx, "\r\n");
        at_send_str(port_idx, str);
        at_send_str(port_idx, "\r\n");
    } else {
        at_send_str(port_idx, str);
        at_send_str(port_idx, "\r");
    }
}

static void at_ok(int port_idx)
{
    at_respond(port_idx, g_at[port_idx].verbose ? "OK" : "0");
}

static void at_error(int port_idx)
{
    at_respond(port_idx, g_at[port_idx].verbose ? "ERROR" : "4");
}

static void at_no_carrier(int port_idx)
{
    at_respond(port_idx, g_at[port_idx].verbose ? "NO CARRIER" : "3");
}

/* -----------------------------------------------------------------------
 * Public result-code functions (called from poll.c on connection events)
 * --------------------------------------------------------------------- */

void at_send_connect(int port_idx)
{
    g_at[port_idx].ringing = 0;
    g_at[port_idx].rings_sent = 0;
    g_at[port_idx].cmd_mode = 0;

    /* Don't send CONNECT immediately — the BBS will purge the input buffer
     * right after answering (AH=0Ah).  A real modem takes 5-20 seconds for
     * the handshake before sending CONNECT.  We defer it ~2 seconds so the
     * BBS's post-answer buffer purge doesn't destroy the CONNECT response. */
    g_at[port_idx].connect_pending = 1;
    g_at[port_idx].connect_tick =
        *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
    dbg("[CONN-PEND]");
}

void at_send_ring(int port_idx)
{
    dbg("[RING]");
    at_respond(port_idx, g_at[port_idx].verbose ? "RING" : "2");
    g_at[port_idx].ringing = 1;
    g_at[port_idx].rings_sent = 1;
    g_at[port_idx].ring_tick =
        *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
}

void at_send_no_carrier(int port_idx)
{
    dbg("[NO CARRIER]");
    g_at[port_idx].cmd_mode = 1;        /* back to command mode */
    g_at[port_idx].ringing = 0;
    g_at[port_idx].rings_sent = 0;
    g_at[port_idx].connect_pending = 0;
    g_at[port_idx].pos = 0;             /* reset partial command buffer */
    at_no_carrier(port_idx);
}

unsigned char at_get_s0(int port_idx)
{
    return g_at[port_idx].s0;
}

unsigned char at_is_ringing(int port_idx)
{
    return g_at[port_idx].ringing;
}

unsigned char at_is_connect_pending(int port_idx)
{
    return g_at[port_idx].connect_pending;
}

void at_set_ringing_silent(int port_idx)
{
    g_at[port_idx].ringing = 1;
    g_at[port_idx].rings_sent = 0;
    g_at[port_idx].ring_tick =
        *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
}

void at_set_cmd_mode(int port_idx)
{
    g_at[port_idx].cmd_mode = 1;
}

/* -----------------------------------------------------------------------
 * at_check_ring — called from status/poll path to drive ring/auto-answer
 *
 * Real modems send RING every ~6 seconds.  After S0 rings, they
 * auto-answer (send CONNECT).  We use BIOS ticks (~18.2/sec) for timing.
 * ~110 ticks ≈ 6 seconds between rings.
 * --------------------------------------------------------------------- */

#define RING_INTERVAL_TICKS  110   /* ~6 seconds between RINGs */

void at_check_ring(int port_idx)
{
    AtState *at = &g_at[port_idx];
    PortState *p = &g_state.ports[port_idx];
    unsigned long now;

    /* Deliver deferred CONNECT response after ~2 second simulated handshake.
     * This delay gives the BBS time to purge buffers (AH=0Ah) after ATA
     * before we inject the CONNECT text into the RX ring. */
    if (at->connect_pending) {
        now = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);
        if (now - at->connect_tick >= 36UL) {  /* ~2 seconds */
            at->connect_pending = 0;
            dbg("[CONNECT]");
            telnet_send_text(port_idx, "Connected!\r\n");

            /* Set MCR flags on the real UART */
            {
                unsigned short uart_base =
                    *(volatile unsigned short __far *)MK_FP(0x0040, port_idx * 2);
                if (uart_base != 0) {
                    outp(uart_base + 4, 0x0B);  /* DTR + RTS + OUT2 */
                }
            }

            at_respond(port_idx, at->verbose ? "CONNECT 57600" : "1");
        }
        return;
    }

    if (!at->ringing)
        return;

    now = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);

    /* Time for another RING or auto-answer? */
    if (now - at->ring_tick < RING_INTERVAL_TICKS)
        return;

    /* Auto-answer: if S0 > 0 and we've sent enough rings.
     * Only auto-answer if FOSSIL is initialized (a BBS is actually
     * listening on this port).  Without FOSSIL init, the call will
     * ring until timeout — the telnet client sees "host didn't answer". */
    if (at->s0 > 0 && at->rings_sent >= at->s0 && fossil_is_init(port_idx)) {
        at->ringing = 0;
        at->rings_sent = 0;
        at_send_connect(port_idx);
        return;
    }

    /* Give up after 10 rings — host didn't answer */
    if (at->rings_sent >= 10) {
        dbg("[RING-TIMEOUT]");
        at->ringing = 0;
        at->rings_sent = 0;
        telnet_send_text(port_idx, "\r\nThe host didn't answer :(\r\n");
        Tcp::drivePackets();
        if (p->sock) {
            p->sock->close();
            Tcp::drivePackets();
            TcpSocketMgr::freeSocket(p->sock);
            p->sock = NULL;
        }
        ring_init(&p->rx);
        at_no_carrier(port_idx);
        if (p->listenSock)
            p->mode = PORT_LISTEN;
        else if (p->huntGroupIdx >= 0)
            p->mode = PORT_LISTEN;
        else
            p->mode = PORT_DISC;
        return;
    }

    /* Send another RING */
    at_respond(port_idx, at->verbose ? "RING" : "2");
    at->rings_sent++;
    at->ring_tick = now;
    /* Notify the telnet client */
    telnet_send_text(port_idx, "RING...\r\n");
}

/* -----------------------------------------------------------------------
 * at_init — reset AT state for a port (called at FOSSIL init / TSR load)
 * --------------------------------------------------------------------- */

void at_init(int port_idx)
{
    AtState *at = &g_at[port_idx];
    memset(at, 0, sizeof(AtState));
    at->echo    = 1;
    at->verbose = 1;
    at->s0      = 0;   /* auto-answer off until BBS explicitly sets ATS0=n */
}

/* -----------------------------------------------------------------------
 * at_execute — process a completed AT command line
 * --------------------------------------------------------------------- */

static void at_execute(int port_idx)
{
    AtState *at = &g_at[port_idx];
    PortState *p = &g_state.ports[port_idx];
    char *cmd = at->buf;
    int len = (int)at->pos;
    int i = 0;
    char c;

    /* Log the command */
    dbg("[AT:");
    dbg(cmd);
    dbg("]");

    /* Skip leading whitespace */
    while (i < len && (cmd[i] == ' ' || cmd[i] == '\t'))
        i++;

    /* Must start with AT (case insensitive) */
    if (i + 1 >= len)
        goto do_error;
    if (cmd[i] != 'A' && cmd[i] != 'a')
        goto do_error;
    if (cmd[i+1] != 'T' && cmd[i+1] != 't')
        goto do_error;
    i += 2;

    /* "AT" alone = OK */
    if (i >= len) {
        at_ok(port_idx);
        return;
    }

    /* Process command characters sequentially */
    while (i < len) {
        c = cmd[i];
        if (c == ' ') { i++; continue; }

        /* Handle non-alpha prefix chars before the switch.
         * '&' (0x26), '\' (0x5C), '%' (0x25) are mangled by & 0xDF
         * so they can't be matched in the switch. */
        if (c == '&') {
            /* AT& commands */
            i++;
            if (i < len) {
                char subcmd = cmd[i];
                int val = 0;
                i++;
                while (i < len && cmd[i] >= '0' && cmd[i] <= '9') {
                    val = val * 10 + (cmd[i] - '0');
                    i++;
                }
                if (subcmd == 'D' || subcmd == 'd') {
                    /* &D0 = ignore DTR, &D2/&D3 = DTR drop disconnects */
                    {
                        int pi;
                        for (pi = 0; pi < MAX_PORTS; pi++) {
                            g_state.ports[pi].dtr_ignore =
                                (val == 0) ? 1 : 0;
                        }
                    }
                }
                /* Other &commands silently accepted */
            }
            continue;
        }
        if (c == '\\' || c == '%') {
            /* AT\ and AT% commands — skip subcmd + optional digits */
            i++;
            if (i < len) {
                i++;
                while (i < len && cmd[i] >= '0' && cmd[i] <= '9')
                    i++;
            }
            continue;
        }

        switch (c & 0xDF) {  /* force uppercase (letters only) */

        case 'Z':  /* ATZ — reset to factory defaults + disconnect */
            i++;
            if (i < len && cmd[i] >= '0' && cmd[i] <= '9')
                i++;  /* skip optional digit */
            at->echo    = 1;
            at->quiet   = 0;
            at->verbose = 1;
            at->s0      = 0;  /* auto-answer off (factory default) */
            at->cmd_mode = 1;  /* stay in command mode */
            at->plus_count = 0;
            p->dtr_ignore = 0;  /* reset &D0 */
            if (p->mode == PORT_CONN && p->sock != NULL)
                cmd_disconnect(port_idx);
            at_ok(port_idx);
            return;

        case 'E':  /* ATE0/ATE1 — echo */
            i++;
            if (i < len && cmd[i] == '0') {
                at->echo = 0; i++;
            } else if (i < len && cmd[i] == '1') {
                at->echo = 1; i++;
            } else {
                at->echo = 0;  /* ATE alone = ATE0 */
            }
            break;

        case 'Q':  /* ATQ0/ATQ1 — quiet mode */
            i++;
            if (i < len && cmd[i] == '1') {
                at->quiet = 1; i++;
            } else {
                if (i < len && cmd[i] == '0') i++;
                at->quiet = 0;
            }
            break;

        case 'V':  /* ATV0/ATV1 — verbose mode */
            i++;
            if (i < len && cmd[i] == '0') {
                at->verbose = 0; i++;
            } else {
                if (i < len && cmd[i] == '1') i++;
                at->verbose = 1;
            }
            break;

        case 'H':  /* ATH — hangup (go on-hook) */
            i++;
            if (i < len && cmd[i] >= '0' && cmd[i] <= '9')
                i++;
            at->cmd_mode = 0;
            at->plus_count = 0;
            if (at->ringing) {
                /* Ringing but not answered — we're already on-hook.
                 * ATH0 is a no-op here (real modem behavior).
                 * Continue parsing the rest of the command line so
                 * BBS init strings like ATH0S0=0M0 still process. */
                break;
            }
            if (p->mode == PORT_CONN && p->sock != NULL) {
                /* Answered call — disconnect */
                fossil_flush_tx(port_idx);
                p->sock->close();
                TcpSocketMgr::freeSocket(p->sock);
                p->sock = NULL;
                ring_init(&p->rx);
                if (p->listenSock)
                    p->mode = PORT_LISTEN;
                else if (p->huntGroupIdx >= 0)
                    p->mode = PORT_LISTEN;
                else
                    p->mode = PORT_DISC;
                at_no_carrier(port_idx);
                return;  /* disconnection terminates command line */
            }
            at->ringing = 0;
            break;  /* no connection — continue parsing rest of command */

        case 'O':  /* ATO — return to online */
            i++;
            if (i < len && cmd[i] >= '0' && cmd[i] <= '9')
                i++;
            at->cmd_mode = 0;
            at->plus_count = 0;
            if (p->mode == PORT_CONN)
                at_send_connect(port_idx);
            else
                at_no_carrier(port_idx);
            return;

        case 'A':  /* ATA — answer call */
            i++;
            if (p->mode == PORT_CONN) {
                at->ringing = 0;
                at_send_connect(port_idx);
            } else {
                at_no_carrier(port_idx);
            }
            return;

        case 'S':  /* ATSn=v or ATSn? — S-register access */
        {
            int reg = 0;
            int val;
            i++;
            while (i < len && cmd[i] >= '0' && cmd[i] <= '9') {
                reg = reg * 10 + (cmd[i] - '0');
                i++;
            }
            if (i < len && cmd[i] == '=') {
                /* Set register */
                i++;
                val = 0;
                while (i < len && cmd[i] >= '0' && cmd[i] <= '9') {
                    val = val * 10 + (cmd[i] - '0');
                    i++;
                }
                if (reg == 0)
                    at->s0 = (unsigned char)val;
                /* All other registers accepted silently */
            } else if (i < len && cmd[i] == '?') {
                /* Query register */
                char regbuf[8];
                i++;
                val = 0;
                if (reg == 0) val = at->s0;
                regbuf[0] = (char)('0' + (val / 100) % 10);
                regbuf[1] = (char)('0' + (val / 10) % 10);
                regbuf[2] = (char)('0' + val % 10);
                regbuf[3] = '\0';
                at_respond(port_idx, regbuf);
                return;
            }
            break;
        }

        case 'D':  /* ATD — dial */
        {
            char dial_type;
            i++;
            dial_type = 0;
            if (i < len && ((cmd[i] & 0xDF) == 'T' || (cmd[i] & 0xDF) == 'P')) {
                dial_type = cmd[i];
                i++;
            }
            /* Outbound dialing not supported — just acknowledge. */
            (void)dial_type;
            at_ok(port_idx);
            return;
        }

        case 'I':  /* ATI — identification */
            i++;
            if (i < len && cmd[i] >= '0' && cmd[i] <= '9')
                i++;
            at_respond(port_idx, "VMODEM " VMODEM_VER_STR);
            return;

        case 'X':  /* ATX — extended result codes */
        case 'L':  /* ATL — speaker volume */
        case 'M':  /* ATM — speaker control */
        case 'N':  /* ATN — connect negotiation */
        case 'W':  /* ATW — error correction reporting */
        case 'Y':  /* ATY — long space disconnect */
        case 'C':  /* ATC — carrier control */
        case 'F':  /* ATF — online echo */
        case 'P':  /* ATP — pulse dial default */
        case 'T':  /* ATT — tone dial default */
            i++;
            while (i < len && cmd[i] >= '0' && cmd[i] <= '9')
                i++;
            break;

        default:
            i++;
            break;
        }
    }

    at_ok(port_idx);
    return;

do_error:
    at_error(port_idx);
}

/* -----------------------------------------------------------------------
 * at_input — feed one byte from the application (AH=01h TX path)
 *
 * Returns 1 if the byte was consumed by the AT parser (don't send to TCP).
 * Returns 0 if the byte should go to TCP (we're connected, data mode).
 * --------------------------------------------------------------------- */

int at_input(int port_idx, unsigned char b)
{
    PortState *p = &g_state.ports[port_idx];
    AtState *at = &g_at[port_idx];


    /* +++ escape sequence detection.
     * Real Hayes: 1s silence, +++, 1s silence.
     * Virtual modem: we only require the leading guard time (~0.5s).
     * Once +++ is seen, enter command mode immediately — most terminal
     * software sends +++ATH as a rapid burst without trailing guard. */
    if (p->mode == PORT_CONN && p->sock != NULL && !at->ringing && !at->cmd_mode) {
        unsigned long now = *(volatile unsigned long __far *)MK_FP(0x0040, 0x006C);

        if (b == '+') {
            if (at->plus_count == 0) {
                /* First '+': check guard time since last data */
                if (now - at->last_tx_tick >= 9UL) {  /* ~0.5s */
                    at->plus_count = 1;
                } else {
                    at->last_tx_tick = now;
                    return 0;  /* no guard time — send as data */
                }
            } else {
                at->plus_count++;
            }

            if (at->plus_count >= 3) {
                /* +++ received — enter command mode immediately */
                at->cmd_mode = 1;
                at->plus_count = 0;
                at_respond(port_idx, at->verbose ? "OK" : "0");
            }
            return 1;  /* consume '+' — don't send to TCP */
        }

        /* Non-'+' character */
        if (at->plus_count > 0) {
            /* Incomplete +++ — reset */
            at->plus_count = 0;
        }
        at->last_tx_tick = now;
        return 0;  /* pass through to TCP */
    }

    /* If in command mode (after +++), or ringing, process as AT command */

    /* Echo the byte back if echo is enabled */
    if (at->echo)
        ring_put(&p->rx, b);

    /* CR = execute the command */
    if (b == '\r') {
        at->buf[at->pos] = '\0';
        if (at->pos > 0)
            at_execute(port_idx);
        at->pos = 0;
        return 1;
    }

    /* Backspace */
    if (b == '\b' || b == 0x7F) {
        if (at->pos > 0)
            at->pos--;
        return 1;
    }

    /* Ignore LF */
    if (b == '\n')
        return 1;

    /* Accumulate into command buffer */
    if (at->pos < AT_BUF_SIZE - 1)
        at->buf[at->pos++] = (char)b;

    return 1;
}
