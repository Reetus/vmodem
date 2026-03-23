/*
 * vsocket.h - BSD-compatible socket API for DOS via VMODEM's mTCP stack
 *
 * Provides familiar socket(), connect(), send(), recv(), closesocket()
 * functions that communicate with the VMODEM TSR through INT 2Fh.
 *
 * Limitations:
 *   - AF_INET + SOCK_STREAM only (TCP); SOCK_DGRAM not supported
 *   - Max 4 simultaneous sockets
 *   - gethostbyname() parses dotted-decimal IPs only (no DNS yet)
 *   - VMODEM TSR must be loaded before calling any functions
 *
 * Compile: wpp vsocket -0 -ms -fo=.obj -zp2 -zpw -ei -s -we
 * Archive: wlib -n vsocket.lib +vsocket.obj
 */

#ifndef _VSOCKET_H
#define _VSOCKET_H

/* ---- Address families ---- */
#define AF_INET         2
#define AF_UNSPEC       0

/* ---- Socket types ---- */
#define SOCK_STREAM     1
#define SOCK_DGRAM      2

/* ---- Protocols ---- */
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

/* ---- Special addresses ---- */
#define INADDR_NONE     0xFFFFFFFFUL
#define INADDR_ANY      0x00000000UL

/* ---- Error codes (vsock_errno values) ---- */
#define VSOCK_EAFNOSUPPORT  97
#define VSOCK_ENOBUFS       105
#define VSOCK_ETIMEDOUT     110
#define VSOCK_ECONNREFUSED  111
#define VSOCK_EINVAL        22
#define VSOCK_ENOTCONN      107
#define VSOCK_ECONNRESET    104
#define VSOCK_EBADF         9

/* ---- h_errno values ---- */
#define HOST_NOT_FOUND  1
#define NO_DATA         4

/* ---- Types ---- */
typedef unsigned long   in_addr_t;
typedef unsigned short  in_port_t;

/* ---- Structures ---- */
struct in_addr {
    in_addr_t s_addr;
};

struct sockaddr {
    short   sa_family;
    char    sa_data[14];
};

struct sockaddr_in {
    short           sin_family;     /* AF_INET */
    in_port_t       sin_port;       /* port in network byte order */
    struct in_addr  sin_addr;
    char            sin_zero[8];
};

struct hostent {
    char           *h_name;
    char          **h_aliases;
    short           h_addrtype;
    short           h_length;
    char          **h_addr_list;
};
#define h_addr h_addr_list[0]

/* ---- Global error state ---- */
extern int vsock_errno;
extern int h_errno;

/* ---- Connect timeout (seconds, default 30) ---- */
extern int vsock_connect_timeout;

/* ---- Byte order conversion (8086 LE <-> network BE) ---- */
unsigned short htons(unsigned short hostshort);
unsigned short ntohs(unsigned short netshort);
unsigned long  htonl(unsigned long  hostlong);
unsigned long  ntohl(unsigned long  netlong);

/* ---- Socket API ---- */
int             socket(int domain, int type, int protocol);
int             connect(int sockfd, const struct sockaddr *addr, int addrlen);
int             send(int sockfd, const void *buf, int len, int flags);
int             recv(int sockfd, void *buf, int len, int flags);
int             closesocket(int sockfd);

/* ---- Name resolution ---- */
struct hostent *gethostbyname(const char *name);
in_addr_t       inet_addr(const char *cp);

/* ---- VMODEM extensions ---- */
int             vsock_init(void);   /* check TSR loaded; returns 0=ok, -1=absent */
void            vsock_poll(void);   /* drive one mTCP poll cycle */

#endif /* _VSOCKET_H */
