/*
 * vtls.h - Minimal TLS 1.2 client for DOS
 *
 * Supports TLS_RSA_WITH_AES_128_CBC_SHA (0x002F) only.
 * Uses crypto primitives from PuTTY/ssh2dos (AES, SHA-1, bignum)
 * plus a new SHA-256 for the TLS 1.2 PRF.
 *
 * Usage:
 *   int sock = socket(...);
 *   connect(sock, ...);
 *   if (vtls_handshake(sock) < 0) { error }
 *   vtls_send(sock, data, len);
 *   n = vtls_recv(sock, buf, bufsz);
 *   vtls_close(sock);
 */

#ifndef _VTLS_H
#define _VTLS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Perform TLS 1.2 handshake on an already-connected TCP socket.
 * Returns 0 on success, -1 on failure. */
int vtls_handshake(int sockfd);

/* Send data over TLS connection. Returns bytes sent or -1 on error. */
int vtls_send(int sockfd, const void *buf, int len);

/* Receive data over TLS connection. Returns bytes received,
 * 0 if no data available, -1 on error/close. */
int vtls_recv(int sockfd, void *buf, int len);

/* Get the peer certificate's Subject CN after a successful handshake.
 * Returns CN length or -1 if not available. */
int vtls_peer_cn(int sockfd, char *buf, int buflen);

/* Get the peer certificate's RSA key size in bits.
 * Returns key size (e.g. 2048, 4096) or -1 if not available. */
int vtls_peer_key_bits(int sockfd);

/* Close TLS session (does NOT close the underlying socket). */
void vtls_close(int sockfd);

/* Extract Subject CN from a DER-encoded X.509 certificate.
 * Copies CN into buf (NUL-terminated, up to buflen-1 chars).
 * Returns CN length or -1 if not found. */
int x509_extract_cn(const unsigned char *cert, int certlen,
                    char *buf, int buflen);

#ifdef __cplusplus
}
#endif

#endif /* _VTLS_H */
