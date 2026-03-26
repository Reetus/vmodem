/*
 * sha256.h - SHA-256 for vtls
 */
#ifndef _SHA256_H
#define _SHA256_H

typedef struct {
    unsigned long h[8];
    unsigned char block[64];
    int blkused;
    unsigned long totlen;
} SHA256_State;

void sha256_init(SHA256_State *s);
void sha256_update(SHA256_State *s, const void *p, int len);
void sha256_final(SHA256_State *s, unsigned char *digest);
void sha256_simple(const void *p, int len, unsigned char *digest);

#endif
