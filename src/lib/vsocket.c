/*
 * vsocket.c - BSD-compatible socket API for DOS via VMODEM's mTCP stack
 *
 * Wraps VMODEM's INT 2Fh MUX socket API (subcommands 0x10-0x16) in
 * standard BSD socket functions.  Requires VMODEM TSR to be loaded.
 */

#include <string.h>
#include <dos.h>
#include <i86.h>

#include "vsocket.h"
#include "../vmodem_mux.h"

/* ---- Internal constants ---- */
#define VSOCK_FD_BASE   128
#define MAX_VSOCK       MAX_EXT_SOCKETS     /* 4 */

/* ---- Global state ---- */
int vsock_errno = 0;
int h_errno = 0;
int vsock_connect_timeout = 30;

/* ---- Per-socket tracking ---- */
static unsigned char vsock_allocated[MAX_VSOCK];

/* ---- DGROUP staging buffer for MUX send/recv ----
 * The MUX handler reads/writes via ES:BX where ES=DS (DGROUP).
 * In large model, caller buffers may be in other segments, so we
 * copy through this near buffer. */
static unsigned char mux_staging[1024];

/* ---- Static storage for gethostbyname ---- */
static struct hostent  s_hostent;
static char           *s_aliases[1];
static char           *s_addr_list[2];
static struct in_addr  s_addr;
static char            s_hostname[64];

/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

static unsigned long get_tick(void)
{
    return *(unsigned long __far *)MK_FP(0x0040, 0x006C);
}

static void dos_idle(void)
{
    __asm { int 28h }
}

static unsigned short mux_get_result(void)
{
    union REGS r;
    memset(&r, 0, sizeof(r));
    r.h.ah = MUX_ID;
    r.h.al = MUX_SOCK_RESULT;
    int86(0x2F, &r, &r);
    return r.x.ax;
}

static int mux_sock_alloc(void)
{
    union REGS r;
    unsigned short res;
    memset(&r, 0, sizeof(r));
    r.h.ah = MUX_ID;
    r.h.al = MUX_SOCK_ALLOC;
    int86(0x2F, &r, &r);
    res = mux_get_result();
    return (res == 0xFF) ? -1 : (int)(res & 0xFF);
}

static int mux_sock_connect(int handle, unsigned char *ip,
                             unsigned short port)
{
    /* Copy IP to staging buffer (ip may be a stack local or far ptr) */
    unsigned char h = (unsigned char)handle;
    unsigned short res;
    mux_staging[0] = ip[0]; mux_staging[1] = ip[1];
    mux_staging[2] = ip[2]; mux_staging[3] = ip[3];
    __asm {
        push es
        push ss
        pop  es          /* ES = SS = DGROUP */
        mov  ah, MUX_ID
        mov  al, MUX_SOCK_CONNECT
        mov  cl, h
        mov  dx, port
        lea  bx, mux_staging
        int  2Fh
        pop  es
    }
    res = mux_get_result();
    return (res == 0) ? 0 : -1;
}

static int mux_sock_status(int handle)
{
    union REGS r;
    memset(&r, 0, sizeof(r));
    r.h.ah = MUX_ID;
    r.h.al = MUX_SOCK_STATUS;
    r.h.cl = (unsigned char)handle;
    int86(0x2F, &r, &r);
    return (int)(mux_get_result() & 0xFF);
}

static int mux_sock_send(int handle, unsigned char *data,
                          unsigned short len)
{
    unsigned char h = (unsigned char)handle;
    unsigned short result;
    (void)data;  /* caller must pre-fill mux_staging[] */
    __asm {
        push es
        push ss
        pop  es          /* ES = SS = DGROUP (mux_staging is in DGROUP) */
        mov  ah, MUX_ID
        mov  al, MUX_SOCK_SEND
        mov  cl, h
        mov  dx, len
        lea  bx, mux_staging
        int  2Fh
        pop  es
    }
    result = mux_get_result();
    return (int)result;
}

static int mux_sock_recv(int handle, unsigned char *buf,
                          unsigned short bufsz)
{
    unsigned char h = (unsigned char)handle;
    unsigned short result;
    (void)buf;  /* caller must read mux_staging[] after call */
    __asm {
        push es
        push ss
        pop  es          /* ES = SS = DGROUP */
        mov  ah, MUX_ID
        mov  al, MUX_SOCK_RECV
        mov  cl, h
        mov  dx, bufsz
        lea  bx, mux_staging
        int  2Fh
        pop  es
    }
    result = mux_get_result();
    return (int)result;
}

static void mux_sock_close_internal(int handle)
{
    union REGS r;
    memset(&r, 0, sizeof(r));
    r.h.ah = MUX_ID;
    r.h.al = MUX_SOCK_CLOSE;
    r.h.cl = (unsigned char)handle;
    int86(0x2F, &r, &r);
}

static void mux_poll_internal(void)
{
    union REGS r;
    memset(&r, 0, sizeof(r));
    r.h.ah = MUX_ID;
    r.h.al = MUX_POLL;
    int86(0x2F, &r, &r);
}

/* Convert sockfd to MUX handle, validate */
static int fd_to_handle(int sockfd)
{
    int h = sockfd - VSOCK_FD_BASE;
    if (h < 0 || h >= MAX_VSOCK || !vsock_allocated[h]) {
        vsock_errno = VSOCK_EBADF;
        return -1;
    }
    return h;
}

/* -----------------------------------------------------------------------
 * Byte order conversion
 * ----------------------------------------------------------------------- */

unsigned short htons(unsigned short x)
{
    return (unsigned short)((x >> 8) | (x << 8));
}

unsigned short ntohs(unsigned short x)
{
    return (unsigned short)((x >> 8) | (x << 8));
}

unsigned long htonl(unsigned long x)
{
    return ((x & 0xFF) << 24) |
           ((x & 0xFF00) << 8) |
           ((x & 0xFF0000UL) >> 8) |
           ((x & 0xFF000000UL) >> 24);
}

unsigned long ntohl(unsigned long x)
{
    return htonl(x);
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

int vsock_init(void)
{
    union REGS r;
    memset(&r, 0, sizeof(r));
    r.h.ah = MUX_ID;
    r.h.al = MUX_INSTALL_CHK;
    int86(0x2F, &r, &r);
    return (r.h.al == 0xFF) ? 0 : -1;
}

void vsock_poll(void)
{
    mux_poll_internal();
}

int socket(int domain, int type, int protocol)
{
    int handle;
    (void)protocol;

    if (domain != AF_INET) {
        vsock_errno = VSOCK_EAFNOSUPPORT;
        return -1;
    }
    if (type != SOCK_STREAM) {
        vsock_errno = VSOCK_EAFNOSUPPORT;
        return -1;
    }

    handle = mux_sock_alloc();
    if (handle < 0) {
        vsock_errno = VSOCK_ENOBUFS;
        return -1;
    }

    vsock_allocated[handle] = 1;
    return handle + VSOCK_FD_BASE;
}

int connect(int sockfd, const struct sockaddr *addr, int addrlen)
{
    int h;
    const struct sockaddr_in *sin;
    unsigned char ip[4];
    unsigned short port;
    unsigned long deadline;
    int st;

    (void)addrlen;

    h = fd_to_handle(sockfd);
    if (h < 0) return -1;

    sin = (const struct sockaddr_in *)addr;
    if (sin->sin_family != AF_INET) {
        vsock_errno = VSOCK_EAFNOSUPPORT;
        return -1;
    }

    /* Extract IP bytes (already in network/wire order in s_addr) */
    {
        const unsigned char *p = (const unsigned char *)&sin->sin_addr.s_addr;
        ip[0] = p[0]; ip[1] = p[1]; ip[2] = p[2]; ip[3] = p[3];
    }

    /* MUX takes port in host byte order */
    port = ntohs(sin->sin_port);

    if (mux_sock_connect(h, ip, port) != 0) {
        vsock_errno = VSOCK_ECONNREFUSED;
        return -1;
    }

    /* Blocking poll until ESTABLISHED or timeout */
    deadline = get_tick() + (unsigned long)vsock_connect_timeout * 18UL;
    for (;;) {
        dos_idle();
        mux_poll_internal();
        st = mux_sock_status(h);

        if (st == EXT_SOCK_ESTABLISHED) return 0;
        if (st == EXT_SOCK_ERROR) {
            vsock_errno = VSOCK_ECONNREFUSED;
            return -1;
        }
        if (get_tick() >= deadline) {
            vsock_errno = VSOCK_ETIMEDOUT;
            mux_sock_close_internal(h);
            vsock_allocated[h] = 0;
            return -1;
        }
    }
}

int send(int sockfd, const void *buf, int len, int flags)
{
    int h;
    const unsigned char *p;
    int total = 0;
    int retries = 0;

    (void)flags;

    h = fd_to_handle(sockfd);
    if (h < 0) return -1;

    p = (const unsigned char *)buf;
    while (total < len) {
        unsigned short chunk;
        int n, i;

        chunk = (unsigned short)(len - total);
        if (chunk > 1024) chunk = 1024;

        /* Copy caller's buffer to DGROUP staging (required for large model
         * where caller data may be in a different segment) */
        for (i = 0; i < (int)chunk; i++)
            mux_staging[i] = p[i];

        n = mux_sock_send(h, mux_staging, chunk);
        if (n > 0) {
            total += n;
            p += n;
            retries = 0;
        } else {
            int st = mux_sock_status(h);
            if (st == EXT_SOCK_ERROR || st == EXT_SOCK_REMOTE_CLOSED) {
                vsock_errno = VSOCK_ECONNRESET;
                return total > 0 ? total : -1;
            }
            dos_idle();
            mux_poll_internal();
            retries++;
            if (retries > 2000) {
                vsock_errno = VSOCK_ETIMEDOUT;
                return total > 0 ? total : -1;
            }
        }
    }
    mux_poll_internal();
    return total;
}

int recv(int sockfd, void *buf, int len, int flags)
{
    int h;
    unsigned short chunk;
    int n;

    (void)flags;

    h = fd_to_handle(sockfd);
    if (h < 0) return -1;

    dos_idle();
    mux_poll_internal();

    chunk = (unsigned short)len;
    if (chunk > 256) chunk = 256;

    /* Receive into DGROUP staging, then copy to caller's buffer
     * (required for large model where buf may be in another segment) */
    n = mux_sock_recv(h, mux_staging, chunk);
    if (n > 0) {
        int i;
        unsigned char *dst = (unsigned char *)buf;
        for (i = 0; i < n; i++)
            dst[i] = mux_staging[i];
        return n;
    }

    /* Check for EOF / remote close */
    {
        int st = mux_sock_status(h);
        if (st == EXT_SOCK_REMOTE_CLOSED || st == EXT_SOCK_ERROR) {
            vsock_errno = 1;
            return -1;     /* remote closed */
        }
    }

    return 0;   /* no data available */
}

int closesocket(int sockfd)
{
    int h;

    h = fd_to_handle(sockfd);
    if (h < 0) return -1;

    mux_sock_close_internal(h);
    vsock_allocated[h] = 0;
    return 0;
}

int vsock_data_ready(int sockfd)
{
    int h;
    unsigned short result;

    h = fd_to_handle(sockfd);
    if (h < 0) return 0;

    mux_poll_internal();

    {
        unsigned char hb = (unsigned char)h;
        __asm {
            mov  ah, MUX_ID
            mov  al, MUX_SOCK_RECV_READY
            mov  cl, hb
            int  2Fh
        }
    }
    result = mux_get_result();
    return (int)result;
}

/* -----------------------------------------------------------------------
 * Name resolution
 * ----------------------------------------------------------------------- */

in_addr_t inet_addr(const char *cp)
{
    unsigned long octets[4];
    int i;
    const char *p = cp;

    for (i = 0; i < 4; i++) {
        unsigned long val = 0;
        int digits = 0;

        while (*p >= '0' && *p <= '9') {
            val = val * 10 + (*p - '0');
            p++;
            digits++;
        }
        if (digits == 0 || val > 255) return INADDR_NONE;
        octets[i] = val;
        if (i < 3) {
            if (*p != '.') return INADDR_NONE;
            p++;
        }
    }

    /* Reject trailing characters */
    if (*p != '\0') return INADDR_NONE;

    /* Network byte order: octet[0] at lowest address.
     * On little-endian 8086, that means octet[0] in the LSB. */
    return (in_addr_t)(octets[0] |
                       (octets[1] << 8) |
                       (octets[2] << 16) |
                       (octets[3] << 24));
}

/* -----------------------------------------------------------------------
 * DNS resolution via MUX_SOCK_RESOLVE
 * ----------------------------------------------------------------------- */

static int mux_resolve_start(const char *hostname)
{
    /* Caller must pre-copy hostname to s_hostname[].
     * ES:BX -> s_hostname in DGROUP */
    (void)hostname;
    __asm {
        push es
        push ss
        pop  es          /* ES = SS = DGROUP */
        mov  ah, MUX_ID
        mov  al, MUX_SOCK_RESOLVE
        lea  bx, s_hostname
        int  2Fh
        pop  es
    }
    return (int)(mux_get_result() & 0xFF);
}

static int mux_resolve_result(unsigned char *ip_buf)
{
    /* Receive into mux_staging[], then copy to caller's buffer */
    int state;
    (void)ip_buf;
    __asm {
        push es
        push ss
        pop  es          /* ES = SS = DGROUP */
        mov  ah, MUX_ID
        mov  al, MUX_SOCK_RESOLVE_RESULT
        lea  bx, mux_staging
        int  2Fh
        pop  es
    }
    state = (int)(mux_get_result() & 0xFF);
    if (state == DNS_RESOLVE_OK) {
        ip_buf[0] = mux_staging[0];
        ip_buf[1] = mux_staging[1];
        ip_buf[2] = mux_staging[2];
        ip_buf[3] = mux_staging[3];
    }
    return state;
}

void vsock_dns_flush(const char *hostname)
{
    /* Copy hostname to DGROUP, then call MUX to flush DNS cache entry */
    int i;
    for (i = 0; i < 63 && hostname[i]; i++)
        s_hostname[i] = hostname[i];
    s_hostname[i] = '\0';

    __asm {
        push es
        push ss
        pop  es
        mov  ah, MUX_ID
        mov  al, MUX_SOCK_DNS_FLUSH
        lea  bx, s_hostname
        int  2Fh
        pop  es
    }
}

static void fill_hostent(const char *name, in_addr_t addr)
{
    int i;
    for (i = 0; i < 63 && name[i]; i++)
        s_hostname[i] = name[i];
    s_hostname[i] = '\0';

    s_addr.s_addr = addr;
    s_aliases[0] = (char *)0;
    s_addr_list[0] = (char *)&s_addr;
    s_addr_list[1] = (char *)0;

    s_hostent.h_name = s_hostname;
    s_hostent.h_aliases = s_aliases;
    s_hostent.h_addrtype = AF_INET;
    s_hostent.h_length = 4;
    s_hostent.h_addr_list = s_addr_list;
}

struct hostent *gethostbyname(const char *name)
{
    in_addr_t addr;
    int state;
    unsigned long deadline;

    /* Try numeric IP first */
    addr = inet_addr(name);
    if (addr != INADDR_NONE) {
        fill_hostent(name, addr);
        h_errno = 0;
        return &s_hostent;
    }

    /* Copy hostname to DGROUP for MUX call (name may be far in large model) */
    {
        int i;
        for (i = 0; i < 63 && name[i]; i++)
            s_hostname[i] = name[i];
        s_hostname[i] = '\0';
    }

    /* Try DNS resolution via VMODEM's mTCP stack */
    state = mux_resolve_start(s_hostname);

    if (state == DNS_RESOLVE_OK) {
        /* Resolved immediately (cached) */
        unsigned char ip[4];
        mux_resolve_result(ip);
        addr = (in_addr_t)ip[0] |
               ((in_addr_t)ip[1] << 8) |
               ((in_addr_t)ip[2] << 16) |
               ((in_addr_t)ip[3] << 24);
        fill_hostent(name, addr);
        h_errno = 0;
        return &s_hostent;
    }

    if (state != DNS_RESOLVE_PENDING) {
        h_errno = HOST_NOT_FOUND;
        return (struct hostent *)0;
    }

    /* Poll until resolved or timeout (15 seconds) */
    deadline = get_tick() + 273UL;
    while (get_tick() < deadline) {
        unsigned char ip[4];

        dos_idle();
        mux_poll_internal();

        state = mux_resolve_result(ip);
        if (state == DNS_RESOLVE_OK) {
            addr = (in_addr_t)ip[0] |
                   ((in_addr_t)ip[1] << 8) |
                   ((in_addr_t)ip[2] << 16) |
                   ((in_addr_t)ip[3] << 24);
            fill_hostent(name, addr);
            h_errno = 0;
            return &s_hostent;
        }
        if (state == DNS_RESOLVE_ERROR) break;
    }

    h_errno = HOST_NOT_FOUND;
    return (struct hostent *)0;
}
