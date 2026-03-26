/*
 * sha256.c - SHA-256 implementation for vtls
 *
 * Standard FIPS 180-4 SHA-256.
 * Written for 16-bit DOS (Open Watcom, large model).
 */

#include <string.h>
#include "sha256.h"

static const unsigned long K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

#define ROR(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROR(x, 2) ^ ROR(x,13) ^ ROR(x,22))
#define EP1(x)  (ROR(x, 6) ^ ROR(x,11) ^ ROR(x,25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x,17) ^ ROR(x,19) ^ ((x) >> 10))

static void sha256_transform(SHA256_State *s, const unsigned char *data)
{
    unsigned long a, b, c, d, e, f, g, h, t1, t2, W[64];
    int i;

    for (i = 0; i < 16; i++)
        W[i] = ((unsigned long)data[i*4] << 24) |
               ((unsigned long)data[i*4+1] << 16) |
               ((unsigned long)data[i*4+2] << 8) |
               ((unsigned long)data[i*4+3]);

    for (i = 16; i < 64; i++)
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];

    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + W[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

void sha256_init(SHA256_State *s)
{
    s->h[0] = 0x6a09e667UL; s->h[1] = 0xbb67ae85UL;
    s->h[2] = 0x3c6ef372UL; s->h[3] = 0xa54ff53aUL;
    s->h[4] = 0x510e527fUL; s->h[5] = 0x9b05688cUL;
    s->h[6] = 0x1f83d9abUL; s->h[7] = 0x5be0cd19UL;
    s->totlen = 0;
    s->blkused = 0;
}

void sha256_update(SHA256_State *s, const void *p, int len)
{
    const unsigned char *d = (const unsigned char *)p;

    s->totlen += (unsigned long)len;

    if (s->blkused > 0 && s->blkused + len >= 64) {
        int fill = 64 - s->blkused;
        memcpy(s->block + s->blkused, d, fill);
        sha256_transform(s, s->block);
        d += fill;
        len -= fill;
        s->blkused = 0;
    }

    while (len >= 64) {
        sha256_transform(s, d);
        d += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(s->block + s->blkused, d, len);
        s->blkused += len;
    }
}

void sha256_final(SHA256_State *s, unsigned char *digest)
{
    unsigned long bits = s->totlen * 8;
    unsigned char pad = 0x80;
    unsigned char zero = 0;
    unsigned char lenbuf[8];
    int i;

    sha256_update(s, &pad, 1);
    while (s->blkused != 56) {
        sha256_update(s, &zero, 1);
    }

    /* Length in bits, big-endian 64-bit (high 32 always 0 for our sizes) */
    memset(lenbuf, 0, 4);
    lenbuf[4] = (unsigned char)(bits >> 24);
    lenbuf[5] = (unsigned char)(bits >> 16);
    lenbuf[6] = (unsigned char)(bits >> 8);
    lenbuf[7] = (unsigned char)(bits);
    sha256_update(s, lenbuf, 8);

    for (i = 0; i < 8; i++) {
        digest[i*4]   = (unsigned char)(s->h[i] >> 24);
        digest[i*4+1] = (unsigned char)(s->h[i] >> 16);
        digest[i*4+2] = (unsigned char)(s->h[i] >> 8);
        digest[i*4+3] = (unsigned char)(s->h[i]);
    }
}

void sha256_simple(const void *p, int len, unsigned char *digest)
{
    SHA256_State s;
    sha256_init(&s);
    sha256_update(&s, p, len);
    sha256_final(&s, digest);
}
