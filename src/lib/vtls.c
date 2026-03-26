/*
 * vtls.c - Minimal TLS 1.2 client for DOS
 *
 * Supports TLS_RSA_WITH_AES_128_CBC_SHA (0x002F) only.
 * Self-contained: all crypto is implemented inline.
 *
 * AES, SHA-1, and bignum algorithms adapted from PuTTY
 * (Simon Tatham et al), copyright (c) 1999-2005 Simon Tatham,
 * licensed under the MIT licence.
 *
 * TLS protocol, ASN.1 parser, HMAC, PRF are original work.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include <i86.h>

#include "vsocket.h"
#include "sha256.h"
#include "vtls.h"

/* Debug log — written to VTLS.LOG in current directory */
static FILE *vtls_dbg;
static void vtls_log(const char *fmt, ...)
{
    va_list ap;
    if (!vtls_dbg) vtls_dbg = fopen("VTLS.LOG", "w");
    if (!vtls_dbg) return;
    va_start(ap, fmt);
    vfprintf(vtls_dbg, fmt, ap);
    va_end(ap);
    fflush(vtls_dbg);
}

/* =====================================================================
 * Type definitions
 * ===================================================================== */
typedef unsigned long uint32;
typedef unsigned short uint16;

/* =====================================================================
 * Byte-order macros
 * ===================================================================== */
#define GET32_BE(cp) \
  (((unsigned long)(unsigned char)(cp)[0] << 24) | \
   ((unsigned long)(unsigned char)(cp)[1] << 16) | \
   ((unsigned long)(unsigned char)(cp)[2] << 8)  | \
   ((unsigned long)(unsigned char)(cp)[3]))

#define PUT32_BE(cp, v) do { \
  (cp)[0] = (unsigned char)((v) >> 24); \
  (cp)[1] = (unsigned char)((v) >> 16); \
  (cp)[2] = (unsigned char)((v) >> 8);  \
  (cp)[3] = (unsigned char)(v);         \
} while(0)

#define PUT16_BE(cp, v) do { \
  (cp)[0] = (unsigned char)((v) >> 8); \
  (cp)[1] = (unsigned char)(v);        \
} while(0)

#define GET16_BE(cp) \
  (((unsigned short)(unsigned char)(cp)[0] << 8) | \
   ((unsigned short)(unsigned char)(cp)[1]))

/* =====================================================================
 * SHA-1 (from PuTTY, MIT licence)
 * ===================================================================== */
typedef struct {
    uint32 h[5];
    unsigned char block[64];
    int blkused;
    uint32 lenhi, lenlo;
} SHA1_CTX;

#define sha1_rol(x,y) (((x) << (y)) | (((uint32)(x)) >> (32-(y))))

static void sha1_transform(uint32 *digest, const unsigned char *blk)
{
    uint32 w[80], a, b, c, d, e;
    int t;
    for (t = 0; t < 16; t++)
        w[t] = GET32_BE(blk + t*4);
    for (t = 16; t < 80; t++) {
        uint32 tmp = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16];
        w[t] = sha1_rol(tmp, 1);
    }
    a = digest[0]; b = digest[1]; c = digest[2];
    d = digest[3]; e = digest[4];
    for (t = 0; t < 20; t++) {
        uint32 tmp = sha1_rol(a,5) + ((b&c)|(d&~b)) + e + w[t] + 0x5a827999UL;
        e=d; d=c; c=sha1_rol(b,30); b=a; a=tmp;
    }
    for (t = 20; t < 40; t++) {
        uint32 tmp = sha1_rol(a,5) + (b^c^d) + e + w[t] + 0x6ed9eba1UL;
        e=d; d=c; c=sha1_rol(b,30); b=a; a=tmp;
    }
    for (t = 40; t < 60; t++) {
        uint32 tmp = sha1_rol(a,5) + ((b&c)|(b&d)|(c&d)) + e + w[t] + 0x8f1bbcdcUL;
        e=d; d=c; c=sha1_rol(b,30); b=a; a=tmp;
    }
    for (t = 60; t < 80; t++) {
        uint32 tmp = sha1_rol(a,5) + (b^c^d) + e + w[t] + 0xca62c1d6UL;
        e=d; d=c; c=sha1_rol(b,30); b=a; a=tmp;
    }
    digest[0]+=a; digest[1]+=b; digest[2]+=c; digest[3]+=d; digest[4]+=e;
}

static void sha1_init(SHA1_CTX *s)
{
    s->h[0]=0x67452301UL; s->h[1]=0xefcdab89UL; s->h[2]=0x98badcfeUL;
    s->h[3]=0x10325476UL; s->h[4]=0xc3d2e1f0UL;
    s->blkused = 0; s->lenhi = s->lenlo = 0;
}

static void sha1_update(SHA1_CTX *s, const void *p, int len)
{
    const unsigned char *q = (const unsigned char *)p;
    uint32 lenw = (uint32)len;
    s->lenlo += lenw;
    s->lenhi += (s->lenlo < lenw);
    if (s->blkused && s->blkused + len < 64) {
        memcpy(s->block + s->blkused, q, len);
        s->blkused += len;
    } else {
        while (s->blkused + len >= 64) {
            int fill = 64 - s->blkused;
            memcpy(s->block + s->blkused, q, fill);
            q += fill; len -= fill;
            sha1_transform(s->h, s->block);
            s->blkused = 0;
        }
        memcpy(s->block, q, len);
        s->blkused = len;
    }
}

static void sha1_final(SHA1_CTX *s, unsigned char *out)
{
    int pad, i;
    unsigned char c[64];
    uint32 lenhi, lenlo;
    pad = (s->blkused >= 56) ? 56 + 64 - s->blkused : 56 - s->blkused;
    lenhi = (s->lenhi << 3) | (s->lenlo >> 29);
    lenlo = (s->lenlo << 3);
    memset(c, 0, pad); c[0] = 0x80;
    sha1_update(s, c, pad);
    PUT32_BE(c, lenhi); PUT32_BE(c+4, lenlo);
    sha1_update(s, c, 8);
    for (i = 0; i < 5; i++) PUT32_BE(out + i*4, s->h[i]);
}

/* =====================================================================
 * HMAC-SHA1
 * ===================================================================== */
static void hmac_sha1(const unsigned char *key, int keylen,
                      const unsigned char *data, int datalen,
                      unsigned char *out)
{
    SHA1_CTX ctx;
    unsigned char ipad[64], opad[64], tmp[20];
    int i;
    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);
    for (i = 0; i < keylen && i < 64; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    sha1_init(&ctx); sha1_update(&ctx, ipad, 64);
    sha1_update(&ctx, data, datalen); sha1_final(&ctx, tmp);
    sha1_init(&ctx); sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, tmp, 20); sha1_final(&ctx, out);
}

/* =====================================================================
 * HMAC-SHA256 (for TLS 1.2 PRF)
 * ===================================================================== */
static void hmac_sha256(const unsigned char *key, int keylen,
                        const unsigned char *data, int datalen,
                        unsigned char *out)
{
    SHA256_State ctx;
    unsigned char ipad[64], opad[64], tmp[32];
    int i;
    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);
    for (i = 0; i < keylen && i < 64; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    sha256_init(&ctx); sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, datalen); sha256_final(&ctx, tmp);
    sha256_init(&ctx); sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, tmp, 32); sha256_final(&ctx, out);
}

/* =====================================================================
 * TLS 1.2 PRF (P_SHA256)
 * ===================================================================== */
static void tls_prf(const unsigned char *secret, int seclen,
                    const char *label,
                    const unsigned char *seed, int seedlen,
                    unsigned char *out, int outlen)
{
    /* PRF(secret, label, seed) = P_SHA256(secret, label + seed) */
    unsigned char A[32]; /* A(i) */
    unsigned char tmp[32];
    unsigned char *lseed;
    int labellen = (int)strlen(label);
    int lslen = labellen + seedlen;
    int pos = 0;

    lseed = (unsigned char *)malloc(lslen);
    memcpy(lseed, label, labellen);
    memcpy(lseed + labellen, seed, seedlen);

    /* A(1) = HMAC_SHA256(secret, label+seed) */
    hmac_sha256(secret, seclen, lseed, lslen, A);

    while (pos < outlen) {
        /* HMAC_SHA256(secret, A(i) + label+seed) */
        unsigned char *concat;
        int clen = 32 + lslen;
        int tocopy;
        concat = (unsigned char *)malloc(clen);
        memcpy(concat, A, 32);
        memcpy(concat + 32, lseed, lslen);
        hmac_sha256(secret, seclen, concat, clen, tmp);
        free(concat);

        tocopy = outlen - pos;
        if (tocopy > 32) tocopy = 32;
        memcpy(out + pos, tmp, tocopy);
        pos += tocopy;

        /* A(i+1) = HMAC_SHA256(secret, A(i)) */
        hmac_sha256(secret, seclen, A, 32, A);
    }
    free(lseed);
}

/* =====================================================================
 * AES-128 (from PuTTY, MIT licence)
 * Stripped to just what TLS needs: key setup, CBC encrypt/decrypt.
 * ===================================================================== */

#define AES_MAXROUNDS 14

typedef struct {
    uint32 keysched[(AES_MAXROUNDS+1)*4];
    uint32 invkeysched[(AES_MAXROUNDS+1)*4];
    uint32 iv[4];
    int Nr; /* number of rounds */
} AES_CTX;

#define mulby2(x) (((x&0x7F) << 1) ^ (x & 0x80 ? 0x1B : 0))

static const unsigned char Sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const unsigned char Sboxinv[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* Compute T-tables at init time to save code space */
static uint32 E0[256], E1[256], E2[256], E3[256];
static uint32 D0[256], D1[256], D2[256], D3[256];
static int aes_tables_init = 0;

static void aes_build_tables(void)
{
    int i;
    for (i = 0; i < 256; i++) {
        unsigned char s = Sbox[i];
        unsigned char s2 = mulby2(s);
        unsigned char s3 = s2 ^ s;
        E0[i] = ((uint32)s2 << 24) | ((uint32)s << 16) |
                ((uint32)s << 8) | s3;
        E1[i] = ((uint32)s3 << 24) | ((uint32)s2 << 16) |
                ((uint32)s << 8) | s;
        E2[i] = ((uint32)s << 24) | ((uint32)s3 << 16) |
                ((uint32)s2 << 8) | s;
        E3[i] = ((uint32)s << 24) | ((uint32)s << 16) |
                ((uint32)s3 << 8) | s2;
    }
    for (i = 0; i < 256; i++) {
        unsigned char s = Sboxinv[i];
        unsigned char s2 = mulby2(s);
        unsigned char s4 = mulby2(s2);
        unsigned char s8 = mulby2(s4);
        unsigned char s9 = s8 ^ s;
        unsigned char sb = s8 ^ s2 ^ s;
        unsigned char sd = s8 ^ s4 ^ s;
        unsigned char se = s8 ^ s4 ^ s2;
        D0[i] = ((uint32)se << 24) | ((uint32)s9 << 16) |
                ((uint32)sd << 8) | sb;
        D1[i] = ((uint32)sb << 24) | ((uint32)se << 16) |
                ((uint32)s9 << 8) | sd;
        D2[i] = ((uint32)sd << 24) | ((uint32)sb << 16) |
                ((uint32)se << 8) | s9;
        D3[i] = ((uint32)s9 << 24) | ((uint32)sd << 16) |
                ((uint32)sb << 8) | se;
    }
    aes_tables_init = 1;
}

static const uint32 Rcon[] = {
    0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL,
    0x10000000UL, 0x20000000UL, 0x40000000UL, 0x80000000UL,
    0x1b000000UL, 0x36000000UL
};

static void aes_setup(AES_CTX *ctx, const unsigned char *key, int keylen)
{
    int Nk = keylen / 4;
    int Nr, i, j;
    uint32 *sched, *invsched, temp;

    if (!aes_tables_init) aes_build_tables();

    Nr = Nk + 6;
    ctx->Nr = Nr;
    sched = ctx->keysched;
    invsched = ctx->invkeysched;

    for (i = 0; i < Nk; i++)
        sched[i] = GET32_BE(key + 4*i);

    for (i = Nk; i < (Nr+1)*4; i++) {
        temp = sched[i-1];
        if (i % Nk == 0) {
            temp = ((uint32)Sbox[(temp>>16)&0xFF] << 24) |
                   ((uint32)Sbox[(temp>>8)&0xFF] << 16) |
                   ((uint32)Sbox[temp&0xFF] << 8) |
                   Sbox[(temp>>24)&0xFF];
            temp ^= Rcon[i/Nk - 1];
        }
        sched[i] = sched[i-Nk] ^ temp;
    }

    /* Compute inverse key schedule */
    for (i = 0; i <= Nr; i++)
        for (j = 0; j < 4; j++)
            invsched[i*4+j] = sched[i*4+j];
    for (i = 1; i < Nr; i++) {
        for (j = 0; j < 4; j++) {
            unsigned char b0, b1, b2, b3;
            uint32 w = invsched[i*4+j];
            b0 = Sbox[(w>>24)&0xFF]; b1 = Sbox[(w>>16)&0xFF];
            b2 = Sbox[(w>>8)&0xFF]; b3 = Sbox[w&0xFF];
            invsched[i*4+j] = D0[b0] ^ D1[b1] ^ D2[b2] ^ D3[b3];
        }
    }
}

static void aes_encrypt_block(AES_CTX *ctx, uint32 *block)
{
    uint32 *sched = ctx->keysched;
    uint32 s0, s1, s2, s3, t0, t1, t2, t3;
    int r;

    s0 = block[0] ^ sched[0]; s1 = block[1] ^ sched[1];
    s2 = block[2] ^ sched[2]; s3 = block[3] ^ sched[3];
    sched += 4;

    for (r = 1; r < ctx->Nr; r++) {
        t0 = E0[(s0>>24)&0xFF] ^ E1[(s1>>16)&0xFF] ^
             E2[(s2>>8)&0xFF] ^ E3[s3&0xFF] ^ sched[0];
        t1 = E0[(s1>>24)&0xFF] ^ E1[(s2>>16)&0xFF] ^
             E2[(s3>>8)&0xFF] ^ E3[s0&0xFF] ^ sched[1];
        t2 = E0[(s2>>24)&0xFF] ^ E1[(s3>>16)&0xFF] ^
             E2[(s0>>8)&0xFF] ^ E3[s1&0xFF] ^ sched[2];
        t3 = E0[(s3>>24)&0xFF] ^ E1[(s0>>16)&0xFF] ^
             E2[(s1>>8)&0xFF] ^ E3[s2&0xFF] ^ sched[3];
        s0=t0; s1=t1; s2=t2; s3=t3;
        sched += 4;
    }
    /* Last round: no MixColumns */
    block[0] = ((uint32)Sbox[(s0>>24)&0xFF] << 24) |
               ((uint32)Sbox[(s1>>16)&0xFF] << 16) |
               ((uint32)Sbox[(s2>>8)&0xFF] << 8) |
               Sbox[s3&0xFF];
    block[0] ^= sched[0];
    block[1] = ((uint32)Sbox[(s1>>24)&0xFF] << 24) |
               ((uint32)Sbox[(s2>>16)&0xFF] << 16) |
               ((uint32)Sbox[(s3>>8)&0xFF] << 8) |
               Sbox[s0&0xFF];
    block[1] ^= sched[1];
    block[2] = ((uint32)Sbox[(s2>>24)&0xFF] << 24) |
               ((uint32)Sbox[(s3>>16)&0xFF] << 16) |
               ((uint32)Sbox[(s0>>8)&0xFF] << 8) |
               Sbox[s1&0xFF];
    block[2] ^= sched[2];
    block[3] = ((uint32)Sbox[(s3>>24)&0xFF] << 24) |
               ((uint32)Sbox[(s0>>16)&0xFF] << 16) |
               ((uint32)Sbox[(s1>>8)&0xFF] << 8) |
               Sbox[s2&0xFF];
    block[3] ^= sched[3];
}

static void aes_decrypt_block(AES_CTX *ctx, uint32 *block)
{
    uint32 *sched = ctx->invkeysched + ctx->Nr * 4;
    uint32 s0, s1, s2, s3, t0, t1, t2, t3;
    int r;

    s0 = block[0] ^ sched[0]; s1 = block[1] ^ sched[1];
    s2 = block[2] ^ sched[2]; s3 = block[3] ^ sched[3];
    sched -= 4;

    for (r = ctx->Nr - 1; r > 0; r--) {
        t0 = D0[(s0>>24)&0xFF] ^ D1[(s3>>16)&0xFF] ^
             D2[(s2>>8)&0xFF] ^ D3[s1&0xFF] ^ sched[0];
        t1 = D0[(s1>>24)&0xFF] ^ D1[(s0>>16)&0xFF] ^
             D2[(s3>>8)&0xFF] ^ D3[s2&0xFF] ^ sched[1];
        t2 = D0[(s2>>24)&0xFF] ^ D1[(s1>>16)&0xFF] ^
             D2[(s0>>8)&0xFF] ^ D3[s3&0xFF] ^ sched[2];
        t3 = D0[(s3>>24)&0xFF] ^ D1[(s2>>16)&0xFF] ^
             D2[(s1>>8)&0xFF] ^ D3[s0&0xFF] ^ sched[3];
        s0=t0; s1=t1; s2=t2; s3=t3;
        sched -= 4;
    }
    /* Last round */
    block[0] = ((uint32)Sboxinv[(s0>>24)&0xFF] << 24) |
               ((uint32)Sboxinv[(s3>>16)&0xFF] << 16) |
               ((uint32)Sboxinv[(s2>>8)&0xFF] << 8) |
               Sboxinv[s1&0xFF];
    block[0] ^= sched[0];
    block[1] = ((uint32)Sboxinv[(s1>>24)&0xFF] << 24) |
               ((uint32)Sboxinv[(s0>>16)&0xFF] << 16) |
               ((uint32)Sboxinv[(s3>>8)&0xFF] << 8) |
               Sboxinv[s2&0xFF];
    block[1] ^= sched[1];
    block[2] = ((uint32)Sboxinv[(s2>>24)&0xFF] << 24) |
               ((uint32)Sboxinv[(s1>>16)&0xFF] << 16) |
               ((uint32)Sboxinv[(s0>>8)&0xFF] << 8) |
               Sboxinv[s3&0xFF];
    block[2] ^= sched[2];
    block[3] = ((uint32)Sboxinv[(s3>>24)&0xFF] << 24) |
               ((uint32)Sboxinv[(s2>>16)&0xFF] << 16) |
               ((uint32)Sboxinv[(s1>>8)&0xFF] << 8) |
               Sboxinv[s0&0xFF];
    block[3] ^= sched[3];
}

static void aes_cbc_encrypt(AES_CTX *ctx, unsigned char *blk, int len)
{
    uint32 iv[4];
    int i;
    memcpy(iv, ctx->iv, 16);
    while (len >= 16) {
        for (i = 0; i < 4; i++)
            iv[i] ^= GET32_BE(blk + 4*i);
        aes_encrypt_block(ctx, iv);
        for (i = 0; i < 4; i++)
            PUT32_BE(blk + 4*i, iv[i]);
        blk += 16; len -= 16;
    }
    memcpy(ctx->iv, iv, 16);
}

static void aes_cbc_decrypt(AES_CTX *ctx, unsigned char *blk, int len)
{
    uint32 iv[4], x[4], ct[4];
    int i;
    memcpy(iv, ctx->iv, 16);
    while (len >= 16) {
        for (i = 0; i < 4; i++)
            x[i] = ct[i] = GET32_BE(blk + 4*i);
        aes_decrypt_block(ctx, x);
        for (i = 0; i < 4; i++) {
            PUT32_BE(blk + 4*i, iv[i] ^ x[i]);
            iv[i] = ct[i];
        }
        blk += 16; len -= 16;
    }
    memcpy(ctx->iv, iv, 16);
}

static void aes_set_iv(AES_CTX *ctx, const unsigned char *iv)
{
    int i;
    for (i = 0; i < 4; i++)
        ctx->iv[i] = GET32_BE(iv + 4*i);
}

/* =====================================================================
 * Minimal Bignum (from PuTTY, MIT licence)
 * Just enough for RSA modpow: from_bytes, modpow, free
 *
 * Bignum = pointer to unsigned short array.
 * [0] = number of 16-bit words, [1..n] = words, LSW first.
 * ===================================================================== */
typedef unsigned short *Bignum;

static Bignum bn_alloc(int words)
{
    Bignum b = (Bignum)calloc(words + 1, sizeof(unsigned short));
    if (b) b[0] = (unsigned short)words;
    return b;
}

static void bn_free(Bignum b) { if (b) free(b); }

static Bignum bn_from_bytes(const unsigned char *data, int nbytes)
{
    int nw = (nbytes + 1) / 2;
    Bignum b = bn_alloc(nw);
    int i;
    if (!b) return NULL;
    for (i = 0; i < nbytes; i++) {
        int wi = i / 2;
        int shift = (i & 1) ? 8 : 0;
        b[1 + wi] |= (unsigned short)data[nbytes - 1 - i] << shift;
    }
    return b;
}

static int bn_bits(Bignum b)
{
    int nw = b[0], bits;
    unsigned short top;
    while (nw > 0 && b[nw] == 0) nw--;
    if (nw == 0) return 0;
    bits = (nw - 1) * 16;
    top = b[nw];
    while (top) { bits++; top >>= 1; }
    return bits;
}

static int bn_bit(Bignum b, int n)
{
    int wi = n / 16 + 1;
    if (wi > b[0]) return 0;
    return (b[wi] >> (n % 16)) & 1;
}

/* c = a * b */
static Bignum bn_mul(Bignum a, Bignum b)
{
    int aw = a[0], bw = b[0], rw = aw + bw;
    Bignum r = bn_alloc(rw);
    int i, j;
    if (!r) return NULL;
    for (i = 1; i <= aw; i++) {
        unsigned long carry = 0;
        for (j = 1; j <= bw; j++) {
            unsigned long prod = (unsigned long)a[i] * b[j] +
                                 r[i+j-1] + carry;
            r[i+j-1] = (unsigned short)(prod & 0xFFFF);
            carry = prod >> 16;
        }
        r[i+bw] += (unsigned short)carry;
    }
    return r;
}

/* Compare: returns -1, 0, or 1 */
static int bn_cmp(Bignum a, Bignum b)
{
    int aw = a[0], bw = b[0], i, max;
    max = aw > bw ? aw : bw;
    for (i = max; i >= 1; i--) {
        unsigned short av = (i <= aw) ? a[i] : 0;
        unsigned short bv = (i <= bw) ? b[i] : 0;
        if (av < bv) return -1;
        if (av > bv) return 1;
    }
    return 0;
}

/* Shift bignum left by n bits */
static Bignum bn_shift_left(Bignum a, int n)
{
    int words = n / 16;
    int bits = n % 16;
    int aw = a[0];
    int rw = aw + words + 1;
    Bignum r = bn_alloc(rw);
    int i;
    if (!r) return NULL;
    r[0] = rw;
    /* Copy with word shift */
    for (i = 1; i <= aw; i++)
        r[i + words] = a[i];
    /* Bit shift within words */
    if (bits > 0) {
        unsigned short carry = 0;
        for (i = words + 1; i <= rw; i++) {
            unsigned long v = ((unsigned long)r[i] << bits) | carry;
            r[i] = (unsigned short)(v & 0xFFFF);
            carry = (unsigned short)(v >> 16);
        }
    }
    return r;
}

/* r = a mod m  (bit-at-a-time trial subtraction) */
static Bignum bn_mod(Bignum a, Bignum m)
{
    int aw, mw, i;
    Bignum r;

    mw = m[0];
    while (mw > 1 && m[mw] == 0) mw--;

    aw = a[0];
    r = bn_alloc(aw);
    if (!r) return NULL;
    r[0] = aw;
    memcpy(r + 1, a + 1, aw * sizeof(unsigned short));

    /* Bit-at-a-time trial subtraction */
    while (bn_cmp(r, m) >= 0) {
        /* Find how far to shift m so MSBs align */
        int rb = bn_bits(r);
        int mb = bn_bits(m);
        int shift = rb - mb;
        Bignum ms;

        if (shift < 0) break;

        ms = bn_shift_left(m, shift);
        if (!ms) break;
        if (bn_cmp(ms, r) > 0) {
            bn_free(ms);
            if (shift == 0) break;
            ms = bn_shift_left(m, shift - 1);
            if (!ms) break;
        }

        /* r -= ms */
        {
            unsigned long borrow = 0;
            int maxw = (r[0] > ms[0]) ? r[0] : ms[0];
            for (i = 1; i <= maxw; i++) {
                unsigned long rv = (i <= r[0]) ? r[i] : 0;
                unsigned long sv = (i <= ms[0]) ? ms[i] : 0;
                unsigned long sub = rv - sv - borrow;
                if (i <= r[0]) r[i] = (unsigned short)(sub & 0xFFFF);
                borrow = (sub >> 16) & 1;
            }
        }
        bn_free(ms);
    }

    /* Trim to modulus size */
    if (r[0] > mw) {
        Bignum trimmed = bn_alloc(mw);
        if (trimmed) {
            memcpy(trimmed + 1, r + 1, mw * sizeof(unsigned short));
            bn_free(r);
            r = trimmed;
        }
    }

    return r;
}

/* modpow: result = base^exp mod mod */
static Bignum bn_modpow(Bignum base, Bignum exp, Bignum mod)
{
    Bignum result, tmp, reduced;
    int i, nbits;

    result = bn_alloc(1);
    if (!result) return NULL;
    result[0] = 1; result[1] = 1; /* result = 1 */

    nbits = bn_bits(exp);
    for (i = nbits - 1; i >= 0; i--) {
        /* Keep network alive during long computation */
        vsock_poll();

        /* result = result * result mod mod */
        tmp = bn_mul(result, result);
        bn_free(result);
        result = bn_mod(tmp, mod);
        bn_free(tmp);

        if (bn_bit(exp, i)) {
            /* result = result * base mod mod */
            tmp = bn_mul(result, base);
            bn_free(result);
            result = bn_mod(tmp, mod);
            bn_free(tmp);
        }
    }
    return result;
}

/* Convert bignum to big-endian bytes, padded to 'len' */
static void bn_to_bytes(Bignum b, unsigned char *out, int len)
{
    int i;
    memset(out, 0, len);
    for (i = 0; i < len; i++) {
        int wi = i / 2 + 1;
        int shift = (i & 1) ? 8 : 0;
        if (wi <= b[0])
            out[len - 1 - i] = (unsigned char)(b[wi] >> shift);
    }
}

/* =====================================================================
 * RSA PKCS#1 v1.5 Type 2 encryption
 * ===================================================================== */
static int rsa_encrypt(const unsigned char *n_bytes, int n_len,
                       const unsigned char *e_bytes, int e_len,
                       const unsigned char *msg, int msg_len,
                       unsigned char *out, int out_len)
{
    /* PKCS#1 v1.5 Type 2: 0x00 0x02 <random nonzero padding> 0x00 <msg> */
    unsigned char *padded;
    int pad_len, i;
    Bignum bn_n, bn_e, bn_m, bn_c;

    if (msg_len > n_len - 11) return -1; /* too long */

    padded = (unsigned char *)malloc(n_len);
    if (!padded) return -1;

    padded[0] = 0x00;
    padded[1] = 0x02;
    pad_len = n_len - msg_len - 3;
    for (i = 0; i < pad_len; i++) {
        /* Random nonzero bytes */
        do { padded[2 + i] = (unsigned char)(rand() & 0xFF); }
        while (padded[2 + i] == 0);
    }
    padded[2 + pad_len] = 0x00;
    memcpy(padded + 3 + pad_len, msg, msg_len);

    bn_n = bn_from_bytes(n_bytes, n_len);
    bn_e = bn_from_bytes(e_bytes, e_len);
    bn_m = bn_from_bytes(padded, n_len);
    free(padded);

    bn_c = bn_modpow(bn_m, bn_e, bn_n);
    {
        int cmp = bn_cmp(bn_c, bn_n);
        vtls_log("modpow done: c_bits=%d n_bits=%d cmp(c,n)=%d c[%d]=%04X c[1]=%04X\n",
                 bn_bits(bn_c), bn_bits(bn_n), cmp,
                 bn_c[0], bn_c[0] > 0 ? bn_c[bn_c[0]] : 0,
                 bn_c[0] > 0 ? bn_c[1] : 0);
    }
    bn_to_bytes(bn_c, out, out_len);

    bn_free(bn_n); bn_free(bn_e); bn_free(bn_m); bn_free(bn_c);
    return 0;
}

/* =====================================================================
 * ASN.1 DER parser — extract RSA public key from X.509 certificate
 * ===================================================================== */
static int asn1_tag_len(const unsigned char *p, int *tag, int *hdrlen, int avail)
{
    int len;
    if (avail < 2) return -1;
    *tag = p[0];

    if (p[1] < 0x80) {
        len = p[1];
        *hdrlen = 2;
    } else {
        int nbytes = p[1] & 0x7F;
        int i;
        if (nbytes > 3 || 2 + nbytes > avail) return -1;
        len = 0;
        for (i = 0; i < nbytes; i++)
            len = (len << 8) | p[2 + i];
        *hdrlen = 2 + nbytes;
    }
    return len;
}

/*
 * Extract Subject CN from X.509 cert DER.
 * Copies CN string into buf (up to buflen-1 chars), NUL-terminated.
 * Returns length of CN or -1 on failure.
 */
int x509_extract_cn(const unsigned char *cert, int certlen,
                    char *buf, int buflen)
{
    const unsigned char *p, *end;
    int tag, hlen, len, field;
    /* OID for commonName: 2.5.4.3 = 55 04 03 */
    static const unsigned char cn_oid[] = {0x55, 0x04, 0x03};

    /* Outer SEQUENCE */
    len = asn1_tag_len(cert, &tag, &hlen, certlen);
    if (len < 0 || tag != 0x30) return -1;
    p = cert + hlen;

    /* TBSCertificate SEQUENCE */
    len = asn1_tag_len(p, &tag, &hlen, certlen - (int)(p - cert));
    if (len < 0 || tag != 0x30) return -1;
    p = p + hlen;
    end = p + len;

    /* Check for explicit version tag [0] */
    field = 0;
    if (p < end && (p[0] & 0xE0) == 0xA0) {
        len = asn1_tag_len(p, &tag, &hlen, (int)(end - p));
        if (len < 0) return -1;
        p += hlen + len;
        field = 1;
    }

    /* Skip to field 5 (subject) */
    while (field < 5 && p < end) {
        len = asn1_tag_len(p, &tag, &hlen, (int)(end - p));
        if (len < 0) return -1;
        p += hlen + len;
        field++;
    }
    if (field != 5 || p >= end) return -1;

    /* Subject is a SEQUENCE of SETs of SEQUENCE { OID, value } */
    {
        const unsigned char *subj_end;
        len = asn1_tag_len(p, &tag, &hlen, (int)(end - p));
        if (len < 0 || tag != 0x30) return -1;
        p += hlen;
        subj_end = p + len;

        while (p < subj_end) {
            const unsigned char *set_end, *seq_p;
            int set_len, seq_len;

            /* SET */
            set_len = asn1_tag_len(p, &tag, &hlen, (int)(subj_end - p));
            if (set_len < 0 || tag != 0x31) return -1;
            set_end = p + hlen + set_len;
            p += hlen;

            /* SEQUENCE inside the SET */
            seq_len = asn1_tag_len(p, &tag, &hlen, (int)(set_end - p));
            if (seq_len < 0 || tag != 0x30) { p = set_end; continue; }
            seq_p = p + hlen;

            /* OID */
            len = asn1_tag_len(seq_p, &tag, &hlen, (int)(set_end - seq_p));
            if (len < 0 || tag != 0x06) { p = set_end; continue; }

            if (len == 3 && memcmp(seq_p + hlen, cn_oid, 3) == 0) {
                /* Found CN — value follows */
                seq_p += hlen + len;
                len = asn1_tag_len(seq_p, &tag, &hlen, (int)(set_end - seq_p));
                if (len < 0) return -1;
                if (len >= buflen) len = buflen - 1;
                memcpy(buf, seq_p + hlen, len);
                buf[len] = '\0';
                return len;
            }

            p = set_end;
        }
    }
    return -1; /* CN not found */
}

/*
 * Walk through X.509 cert DER to find SubjectPublicKeyInfo.
 * Returns pointers to RSA n and e.
 */
static int x509_extract_rsa(const unsigned char *cert, int certlen,
                            const unsigned char **n_out, int *n_len,
                            const unsigned char **e_out, int *e_len)
{
    const unsigned char *p, *end, *tbs, *spki, *bitstr, *seq;
    int tag, hlen, len;
    int field;

    /* Outer SEQUENCE */
    len = asn1_tag_len(cert, &tag, &hlen, certlen);
    if (len < 0 || tag != 0x30) return -1;
    p = cert + hlen;

    /* TBSCertificate SEQUENCE */
    len = asn1_tag_len(p, &tag, &hlen, certlen - (int)(p - cert));
    if (len < 0 || tag != 0x30) return -1;
    tbs = p + hlen;
    end = tbs + len;

    /* Walk TBSCertificate fields:
     * 0: version (explicit tag [0], optional)
     * 1: serialNumber
     * 2: signature algorithm
     * 3: issuer
     * 4: validity
     * 5: subject
     * 6: subjectPublicKeyInfo  <-- we want this
     */
    p = tbs;
    field = 0;

    /* Check for explicit version tag [0] */
    if (p < end && (p[0] & 0xE0) == 0xA0) {
        len = asn1_tag_len(p, &tag, &hlen, (int)(end - p));
        if (len < 0) return -1;
        p += hlen + len; /* skip version */
        field = 1;
    }

    /* Skip fields until we reach field 6 (subjectPublicKeyInfo) */
    while (field < 6 && p < end) {
        len = asn1_tag_len(p, &tag, &hlen, (int)(end - p));
        if (len < 0) return -1;
        p += hlen + len;
        field++;
    }

    if (field != 6 || p >= end) return -1;

    /* SubjectPublicKeyInfo SEQUENCE */
    spki = p;
    len = asn1_tag_len(spki, &tag, &hlen, (int)(end - spki));
    if (len < 0 || tag != 0x30) return -1;
    p = spki + hlen;

    /* AlgorithmIdentifier SEQUENCE — skip it */
    len = asn1_tag_len(p, &tag, &hlen, (int)(end - p));
    if (len < 0 || tag != 0x30) return -1;
    p += hlen + len;

    /* BIT STRING containing RSA public key */
    len = asn1_tag_len(p, &tag, &hlen, (int)(end - p));
    if (len < 0 || tag != 0x03) return -1;
    bitstr = p + hlen;
    if (bitstr[0] != 0x00) return -1; /* unused bits must be 0 */
    seq = bitstr + 1;

    /* SEQUENCE { INTEGER n, INTEGER e } */
    len = asn1_tag_len(seq, &tag, &hlen, (int)(end - seq));
    if (len < 0 || tag != 0x30) return -1;
    p = seq + hlen;

    /* INTEGER n */
    len = asn1_tag_len(p, &tag, &hlen, (int)(end - p));
    if (len < 0 || tag != 0x02) return -1;
    *n_out = p + hlen;
    *n_len = len;
    /* Skip leading zero if present */
    if (*n_len > 0 && (*n_out)[0] == 0) { (*n_out)++; (*n_len)--; }
    p += hlen + len;

    /* INTEGER e */
    len = asn1_tag_len(p, &tag, &hlen, (int)(end - p));
    if (len < 0 || tag != 0x02) return -1;
    *e_out = p + hlen;
    *e_len = len;
    if (*e_len > 0 && (*e_out)[0] == 0) { (*e_out)++; (*e_len)--; }

    return 0;
}

/* =====================================================================
 * TLS record layer and connection state
 * ===================================================================== */

#define TLS_RT_CHANGE_CIPHER   20
#define TLS_RT_ALERT           21
#define TLS_RT_HANDSHAKE       22
#define TLS_RT_APPLICATION     23

#define TLS_HT_CLIENT_HELLO     1
#define TLS_HT_SERVER_HELLO     2
#define TLS_HT_CERTIFICATE     11
#define TLS_HT_CERT_REQUEST    13
#define TLS_HT_SERVER_DONE     14
#define TLS_HT_CLIENT_KEY_EX   16
#define TLS_HT_FINISHED        20

#define TLS_VERSION_12  0x0303

#define MAX_TLS_CONNS   4
#define MAX_RECORD     16384

typedef struct {
    int active;
    int sockfd;
    AES_CTX enc_ctx;
    AES_CTX dec_ctx;
    unsigned char mac_enc_key[20]; /* HMAC-SHA1 key for sending */
    unsigned char mac_dec_key[20]; /* HMAC-SHA1 key for receiving */
    unsigned long seq_send;
    unsigned long seq_recv;
    int cipher_active;   /* 1 after ChangeCipherSpec */

    /* Receive buffer for decrypted application data */
    unsigned char *app_buf;
    int app_len;
    int app_pos;

    /* Peer certificate (DER) — kept for CN extraction */
    unsigned char *peer_cert;
    int peer_cert_len;
    int peer_key_bits;  /* RSA modulus size in bits */
} VTlsConn;

static VTlsConn conns[MAX_TLS_CONNS];

static VTlsConn *find_conn(int sockfd)
{
    int i;
    for (i = 0; i < MAX_TLS_CONNS; i++)
        if (conns[i].active && conns[i].sockfd == sockfd)
            return &conns[i];
    return NULL;
}

static VTlsConn *alloc_conn(int sockfd)
{
    int i;
    for (i = 0; i < MAX_TLS_CONNS; i++)
        if (!conns[i].active) {
            memset(&conns[i], 0, sizeof(VTlsConn));
            conns[i].active = 1;
            conns[i].sockfd = sockfd;
            return &conns[i];
        }
    return NULL;
}

/* Blocking recv helper — vsocket recv() is non-blocking */
static int tls_recv_all(int s, unsigned char *buf, int len)
{
    int got = 0, n, loops = 0;
    while (got < len) {
        vsock_poll();
        n = recv(s, (char *)buf + got, len - got, 0);
        if (n < 0) {
            vtls_log("tls_recv_all: recv returned -1 at %d/%d loops=%d\n", got, len, loops);
            return -1;
        }
        got += n;
        loops++;
        if (loops > 50000 && got == 0) {
            vtls_log("tls_recv_all: timeout %d/%d\n", got, len);
            return -1;
        }
    }
    return got;
}

/* Send all bytes */
static int tls_send_all(int s, const unsigned char *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int n;
        vsock_poll();
        n = send(s, buf + sent, len - sent, 0);
        if (n < 0) { vtls_log("send failed at %d/%d\n", sent, len); return -1; }
        sent += n;
    }
    return sent;
}

/* =====================================================================
 * TLS record I/O
 * ===================================================================== */

/* Read one TLS record. Caller must free *out if *outlen > 0.
 * Returns content type, or -1 on error. */
static int tls_read_record(int sockfd, VTlsConn *c,
                           unsigned char **out, int *outlen)
{
    unsigned char hdr[5];
    unsigned char *body;
    int len, ct;

    {
        int rr = tls_recv_all(sockfd, hdr, 5);
        if (rr != 5) {
            vtls_log("tls_read_record: hdr recv got %d (want 5)\n", rr);
            return -1;
        }
    }
    vtls_log("tls_read_record: ct=%d ver=%02X%02X len=%d\n",
             hdr[0], hdr[1], hdr[2], (hdr[3]<<8)|hdr[4]);
    ct = hdr[0];
    len = GET16_BE(hdr + 3);
    if (len > MAX_RECORD + 2048) return -1;

    body = (unsigned char *)malloc(len);
    if (!body) return -1;
    if (tls_recv_all(sockfd, body, len) != len) { free(body); return -1; }

    if (c->cipher_active && (ct == TLS_RT_HANDSHAKE || ct == TLS_RT_APPLICATION)) {
        /* Decrypt: first 16 bytes are IV (TLS 1.2 explicit IV) */
        unsigned char record_mac[20], computed_mac[20];
        unsigned char seq_buf[8];
        unsigned char *mac_input;
        int mac_input_len;
        int content_len;

        if (len < 32) { free(body); return -1; } /* IV + at least 1 block */

        /* Set IV from first 16 bytes of record */
        aes_set_iv(&c->dec_ctx, body);
        /* Decrypt remaining */
        aes_cbc_decrypt(&c->dec_ctx, body + 16, len - 16);

        /* Remove padding (last byte = pad length) */
        {
            int padlen = body[len - 1];
            content_len = len - 16 - 20 - padlen - 1;
            if (content_len < 0) { vtls_log("tls_read: bad padding padlen=%d len=%d\n", padlen, len); free(body); return -1; }
        }

        /* Verify MAC */
        memset(seq_buf, 0, 4);
        PUT32_BE(seq_buf + 4, c->seq_recv);
        mac_input_len = 8 + 5 + content_len;
        mac_input = (unsigned char *)malloc(mac_input_len);
        if (!mac_input) { free(body); return -1; }
        memcpy(mac_input, seq_buf, 8);
        mac_input[8] = (unsigned char)ct;
        mac_input[9] = 0x03; mac_input[10] = 0x03; /* TLS 1.2 */
        PUT16_BE(mac_input + 11, content_len);
        memcpy(mac_input + 13, body + 16, content_len);
        hmac_sha1(c->mac_dec_key, 20, mac_input, mac_input_len, computed_mac);
        free(mac_input);

        memcpy(record_mac, body + 16 + content_len, 20);
        if (memcmp(record_mac, computed_mac, 20) != 0) {
            vtls_log("tls_read: MAC mismatch ct=%d seq=%lu\n", ct, c->seq_recv);
            free(body);
            return -1; /* MAC verify failed */
        }
        c->seq_recv++;

        /* Return just the plaintext */
        memmove(body, body + 16, content_len);
        *out = body;
        *outlen = content_len;
    } else {
        *out = body;
        *outlen = len;
    }
    return ct;
}

/* Write a TLS record. If cipher is active, encrypts it. */
static int tls_write_record(int sockfd, VTlsConn *c,
                            int content_type,
                            const unsigned char *data, int datalen)
{
    unsigned char hdr[5];

    if (c->cipher_active) {
        /* Build: IV(16) + encrypt(data + MAC(20) + padding) */
        unsigned char iv[16], seq_buf[8], mac[20];
        unsigned char *mac_input, *payload;
        int mac_input_len, padlen, payload_len, i;

        /* Generate random IV */
        for (i = 0; i < 16; i++) iv[i] = (unsigned char)(rand() & 0xFF);

        /* Compute MAC over: seq_num(8) + type(1) + version(2) + length(2) + data */
        memset(seq_buf, 0, 4);
        PUT32_BE(seq_buf + 4, c->seq_send);
        mac_input_len = 8 + 5 + datalen;
        mac_input = (unsigned char *)malloc(mac_input_len);
        if (!mac_input) return -1;
        memcpy(mac_input, seq_buf, 8);
        mac_input[8] = (unsigned char)content_type;
        mac_input[9] = 0x03; mac_input[10] = 0x03;
        PUT16_BE(mac_input + 11, datalen);
        memcpy(mac_input + 13, data, datalen);
        hmac_sha1(c->mac_enc_key, 20, mac_input, mac_input_len, mac);
        free(mac_input);

        /* Padding: pad to multiple of 16 */
        padlen = 16 - ((datalen + 20 + 1) % 16);
        if (padlen == 16) padlen = 0;
        payload_len = 16 + datalen + 20 + padlen + 1; /* IV + data + MAC + pad + padlen_byte */

        payload = (unsigned char *)malloc(payload_len);
        if (!payload) return -1;
        memcpy(payload, iv, 16);
        memcpy(payload + 16, data, datalen);
        memcpy(payload + 16 + datalen, mac, 20);
        for (i = 0; i < padlen + 1; i++)
            payload[16 + datalen + 20 + i] = (unsigned char)padlen;

        aes_set_iv(&c->enc_ctx, iv);
        aes_cbc_encrypt(&c->enc_ctx, payload + 16, payload_len - 16);

        hdr[0] = (unsigned char)content_type;
        PUT16_BE(hdr + 1, TLS_VERSION_12);
        PUT16_BE(hdr + 3, payload_len);

        c->seq_send++;

        if (tls_send_all(sockfd, hdr, 5) < 0 ||
            tls_send_all(sockfd, payload, payload_len) < 0) {
            free(payload);
            return -1;
        }
        free(payload);
    } else {
        hdr[0] = (unsigned char)content_type;
        PUT16_BE(hdr + 1, TLS_VERSION_12);
        PUT16_BE(hdr + 3, datalen);
        if (tls_send_all(sockfd, hdr, 5) < 0 ||
            tls_send_all(sockfd, data, datalen) < 0)
            return -1;
    }
    return 0;
}

/* =====================================================================
 * Random bytes (DOS timer tick seeded)
 * ===================================================================== */
static int rand_seeded = 0;

static void seed_rand(void)
{
    if (!rand_seeded) {
        unsigned long tick = *(unsigned long far *)MK_FP(0x0040, 0x006C);
        srand((unsigned int)(tick & 0xFFFF));
        rand_seeded = 1;
    }
}

static void rand_bytes(unsigned char *buf, int len)
{
    int i;
    seed_rand();
    for (i = 0; i < len; i++)
        buf[i] = (unsigned char)(rand() & 0xFF);
}

/* =====================================================================
 * TLS 1.2 Handshake
 * ===================================================================== */

/* Build a handshake message (type + 3-byte length + body).
 * Returns malloc'd buffer, sets *total_len. */
static unsigned char *hs_build(int type, const unsigned char *body,
                               int bodylen, int *total_len)
{
    unsigned char *msg = (unsigned char *)malloc(4 + bodylen);
    if (!msg) return NULL;
    msg[0] = (unsigned char)type;
    msg[1] = (unsigned char)(((long)bodylen >> 16) & 0xFF);
    msg[2] = (unsigned char)((bodylen >> 8) & 0xFF);
    msg[3] = (unsigned char)(bodylen & 0xFF);
    if (bodylen > 0) memcpy(msg + 4, body, bodylen);
    *total_len = 4 + bodylen;
    return msg;
}

int vtls_handshake(int sockfd)
{
    VTlsConn *c;
    unsigned char client_random[32], server_random[32];
    unsigned char pre_master[48], master_secret[48];
    unsigned char key_block[104]; /* 2*20 MAC + 2*16 key + 2*16 IV = 104 */
    SHA256_State hs_hash; /* running hash of all handshake messages */
    unsigned char *hs_msg;
    int hs_len;
    unsigned char verify_data[12];
    unsigned char hash_out[32];

    /* RSA key from certificate */
    const unsigned char *rsa_n, *rsa_e;
    int rsa_n_len, rsa_e_len;
    int cert_requested = 0;

    c = alloc_conn(sockfd);
    if (!c) { vtls_log("alloc_conn failed\n"); return -1; }

    sha256_init(&hs_hash);

    /* ---- ClientHello ---- */
    {
        unsigned char body[128]; /* room for hello + extensions */
        int pos = 0;
        int ext_start, ext_len_pos, ext_len;

        /* Version */
        PUT16_BE(body + pos, TLS_VERSION_12); pos += 2;

        /* Random */
        rand_bytes(client_random, 32);
        memcpy(body + pos, client_random, 32); pos += 32;

        /* Session ID length = 0 */
        body[pos++] = 0;

        /* Cipher suites: length=2, TLS_RSA_WITH_AES_128_CBC_SHA */
        PUT16_BE(body + pos, 2); pos += 2;
        PUT16_BE(body + pos, 0x002F); pos += 2;

        /* Compression: length=1, null */
        body[pos++] = 1;
        body[pos++] = 0;

        /* Extensions */
        ext_len_pos = pos; pos += 2; /* total extensions length (fill later) */
        ext_start = pos;

        /* signature_algorithms extension (0x000d) — required by most TLS 1.2 servers */
        PUT16_BE(body + pos, 0x000D); pos += 2; /* extension type */
        PUT16_BE(body + pos, 8); pos += 2;      /* extension data length */
        PUT16_BE(body + pos, 6); pos += 2;      /* sig alg list length */
        PUT16_BE(body + pos, 0x0401); pos += 2; /* rsa_pkcs1_sha256 */
        PUT16_BE(body + pos, 0x0501); pos += 2; /* rsa_pkcs1_sha384 */
        PUT16_BE(body + pos, 0x0201); pos += 2; /* rsa_pkcs1_sha1 */

        /* Fill in total extensions length */
        ext_len = pos - ext_start;
        PUT16_BE(body + ext_len_pos, ext_len);

        hs_msg = hs_build(TLS_HT_CLIENT_HELLO, body, pos, &hs_len);
        if (!hs_msg) goto fail;
        sha256_update(&hs_hash, hs_msg, hs_len);
        if (tls_write_record(sockfd, c, TLS_RT_HANDSHAKE, hs_msg, hs_len) < 0) {
            vtls_log("ClientHello write failed\n");
            free(hs_msg); goto fail;
        }
        free(hs_msg);
    }
    vtls_log("ClientHello sent\n");

    /* ---- Read ServerHello, Certificate, ServerHelloDone ---- */
    {
        int got_hello = 0, got_cert = 0, got_done = 0;
        unsigned char *cert_data = NULL;
        int cert_len = 0;

        while (!got_done) {
            unsigned char *rec;
            int rec_len, ct;
            ct = tls_read_record(sockfd, c, &rec, &rec_len);
            if (ct < 0) { vtls_log("read_record failed\n"); goto fail; }

            if (ct == TLS_RT_ALERT) {
                vtls_log("got alert: %d %d\n", rec[0], rec_len > 1 ? rec[1] : -1);
                free(rec);
                goto fail;
            }

            if (ct == TLS_RT_HANDSHAKE) {
                /* May contain multiple handshake messages */
                int off = 0;
                while (off < rec_len) {
                    int ht, hlen;
                    if (off + 4 > rec_len) { free(rec); goto fail; }
                    ht = rec[off];
                    hlen = ((long)rec[off+1] << 16) | ((int)rec[off+2] << 8) | rec[off+3];
                    if (off + 4 + hlen > rec_len) { free(rec); goto fail; }

                    /* Hash this handshake message */
                    sha256_update(&hs_hash, rec + off, 4 + hlen);

                    vtls_log("hs msg type=%d len=%d\n", ht, hlen);
                    switch (ht) {
                    case TLS_HT_SERVER_HELLO:
                        /* Parse server random */
                        if (hlen < 38) { free(rec); goto fail; }
                        memcpy(server_random, rec + off + 4 + 2, 32);
                        /* Check cipher suite */
                        {
                            int sid_len = rec[off + 4 + 34];
                            int cs_off = off + 4 + 35 + sid_len;
                            uint16 cs = GET16_BE(rec + cs_off);
                            if (cs != 0x002F) { vtls_log("bad cipher 0x%04X\n", cs); free(rec); goto fail; }
                        }
                        got_hello = 1;
                        break;

                    case TLS_HT_CERTIFICATE:
                    {
                        /* certificates_length (3 bytes) */
                        int certs_len, first_cert_len;
                        const unsigned char *cp = rec + off + 4;
                        certs_len = ((long)cp[0] << 16) | ((int)cp[1] << 8) | cp[2];
                        cp += 3;
                        /* First certificate length (3 bytes) */
                        first_cert_len = ((long)cp[0] << 16) | ((int)cp[1] << 8) | cp[2];
                        cp += 3;
                        cert_data = (unsigned char *)malloc(first_cert_len);
                        if (!cert_data) { free(rec); goto fail; }
                        memcpy(cert_data, cp, first_cert_len);
                        cert_len = first_cert_len;
                        got_cert = 1;
                        break;
                    }

                    case TLS_HT_CERT_REQUEST:
                        cert_requested = 1;
                        vtls_log("server requests client cert\n");
                        break;

                    case TLS_HT_SERVER_DONE:
                        got_done = 1;
                        break;
                    }
                    off += 4 + hlen;
                }
            }
            free(rec);
        }

        if (!got_hello || !got_cert) { vtls_log("missing hello=%d cert=%d\n", got_hello, got_cert); goto fail; }
        vtls_log("got ServerHello+Cert+Done, cert_len=%d\n", cert_len);

        /* Extract RSA public key from certificate */
        if (x509_extract_rsa(cert_data, cert_len,
                             &rsa_n, &rsa_n_len, &rsa_e, &rsa_e_len) < 0) {
            vtls_log("x509_extract_rsa failed\n");
            free(cert_data); goto fail;
        }
        vtls_log("RSA n_len=%d e_len=%d\n", rsa_n_len, rsa_e_len);
        c->peer_key_bits = rsa_n_len * 8;
        /* Copy n and e since cert_data will be freed */
        {
            unsigned char *n_copy = (unsigned char *)malloc(rsa_n_len);
            unsigned char *e_copy = (unsigned char *)malloc(rsa_e_len);
            if (!n_copy || !e_copy) { free(cert_data); goto fail; }
            memcpy(n_copy, rsa_n, rsa_n_len);
            memcpy(e_copy, rsa_e, rsa_e_len);
            rsa_n = n_copy;
            rsa_e = e_copy;
        }
        /* Keep cert for CN extraction later */
        c->peer_cert = cert_data;
        c->peer_cert_len = cert_len;
    }

    /* ---- Empty client Certificate (if server requested) ---- */
    if (cert_requested) {
        unsigned char empty_certs[3] = {0, 0, 0}; /* certificates_length = 0 */
        hs_msg = hs_build(TLS_HT_CERTIFICATE, empty_certs, 3, &hs_len);
        if (!hs_msg) goto fail;
        sha256_update(&hs_hash, hs_msg, hs_len);
        if (tls_write_record(sockfd, c, TLS_RT_HANDSHAKE, hs_msg, hs_len) < 0) {
            free(hs_msg); goto fail;
        }
        free(hs_msg);
        vtls_log("sent empty client cert\n");
    }

    /* ---- ClientKeyExchange ---- */
    {
        unsigned char *encrypted;
        unsigned char body_buf[520]; /* max 4096-bit RSA key = 512 bytes + 2 length */
        int enc_len;

        /* Generate pre-master secret: version(2) + random(46) */
        pre_master[0] = 0x03; pre_master[1] = 0x03;
        rand_bytes(pre_master + 2, 46);

        /* RSA-encrypt it */
        encrypted = (unsigned char *)malloc(rsa_n_len);
        if (!encrypted) goto fail;

        vtls_log("RSA encrypting... pms[0..3]=%02X%02X%02X%02X n[0..3]=%02X%02X%02X%02X e[0..2]=%02X%02X%02X\n",
                 pre_master[0], pre_master[1], pre_master[2], pre_master[3],
                 rsa_n[0], rsa_n[1], rsa_n[2], rsa_n[3],
                 rsa_e[0], rsa_e_len > 1 ? rsa_e[1] : 0, rsa_e_len > 2 ? rsa_e[2] : 0);
        if (rsa_encrypt(rsa_n, rsa_n_len, rsa_e, rsa_e_len,
                        pre_master, 48, encrypted, rsa_n_len) < 0) {
            vtls_log("rsa_encrypt failed\n");
            free(encrypted); goto fail;
        }
        vtls_log("RSA encrypt done, first 8: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                 encrypted[0], encrypted[1], encrypted[2], encrypted[3],
                 encrypted[4], encrypted[5], encrypted[6], encrypted[7]);

        /* TLS RSA key exchange: 2-byte length + encrypted data */
        PUT16_BE(body_buf, rsa_n_len);
        memcpy(body_buf + 2, encrypted, rsa_n_len);
        free(encrypted);

        hs_msg = hs_build(TLS_HT_CLIENT_KEY_EX, body_buf, 2 + rsa_n_len, &hs_len);
        if (!hs_msg) goto fail;
        sha256_update(&hs_hash, hs_msg, hs_len);
        vtls_log("sending CKE (%d bytes)\n", hs_len);
        if (tls_write_record(sockfd, c, TLS_RT_HANDSHAKE, hs_msg, hs_len) < 0) {
            vtls_log("CKE write failed\n");
            free(hs_msg); goto fail;
        }
        free(hs_msg);
        vtls_log("CKE sent\n");

        /* Free RSA key copies */
        free((void *)rsa_n);
        free((void *)rsa_e);
    }

    /* ---- Derive keys ---- */
    {
        unsigned char seed[64];
        memcpy(seed, client_random, 32);
        memcpy(seed + 32, server_random, 32);

        /* master_secret = PRF(pre_master_secret, "master secret", client_random + server_random) */
        tls_prf(pre_master, 48, "master secret", seed, 64, master_secret, 48);
        memset(pre_master, 0, 48);

        /* key_block = PRF(master_secret, "key expansion", server_random + client_random) */
        memcpy(seed, server_random, 32);
        memcpy(seed + 32, client_random, 32);
        tls_prf(master_secret, 48, "key expansion", seed, 64, key_block, 104);

        /* key_block layout:
         * [0..19]   client_write_MAC_key (20 bytes)
         * [20..39]  server_write_MAC_key (20 bytes)
         * [40..55]  client_write_key (16 bytes)
         * [56..71]  server_write_key (16 bytes)
         * [72..87]  client_write_IV (16 bytes) — not used for TLS 1.2 explicit IV
         * [88..103] server_write_IV (16 bytes)
         */
        memcpy(c->mac_enc_key, key_block, 20);
        memcpy(c->mac_dec_key, key_block + 20, 20);
        aes_setup(&c->enc_ctx, key_block + 40, 16);
        aes_setup(&c->dec_ctx, key_block + 56, 16);
        memset(key_block, 0, 104);
    }
    vtls_log("keys derived\n");

    /* ---- Send ChangeCipherSpec ---- */
    {
        unsigned char ccs = 1;
        if (tls_write_record(sockfd, c, TLS_RT_CHANGE_CIPHER, &ccs, 1) < 0) {
            vtls_log("CCS write failed\n"); goto fail;
        }
        vtls_log("CCS sent\n");
        c->cipher_active = 1;
        c->seq_send = 0;
    }

    /* ---- Send Finished ---- */
    {
        SHA256_State hs_copy;
        unsigned char seed_buf[47]; /* "client finished"(15) + hash(32) */

        /* Hash all handshake messages so far */
        hs_copy = hs_hash;
        sha256_final(&hs_copy, hash_out);

        memcpy(seed_buf, hash_out, 32);
        tls_prf(master_secret, 48, "client finished", seed_buf, 32,
                verify_data, 12);

        hs_msg = hs_build(TLS_HT_FINISHED, verify_data, 12, &hs_len);
        if (!hs_msg) goto fail;
        sha256_update(&hs_hash, hs_msg, hs_len);
        if (tls_write_record(sockfd, c, TLS_RT_HANDSHAKE, hs_msg, hs_len) < 0) {
            vtls_log("Finished write failed\n");
            free(hs_msg); goto fail;
        }
        free(hs_msg);
    }
    vtls_log("client Finished sent\n");

    /* ---- Read server ChangeCipherSpec + Finished ---- */
    {
        int got_ccs = 0, got_finished = 0;

        while (!got_finished) {
            unsigned char *rec;
            int rec_len, ct;

            ct = tls_read_record(sockfd, c, &rec, &rec_len);
            if (ct < 0) { vtls_log("server CCS/Fin read failed\n"); goto fail; }
            vtls_log("server record ct=%d len=%d\n", ct, rec_len);

            if (ct == TLS_RT_CHANGE_CIPHER) {
                c->seq_recv = 0;
                got_ccs = 1;
            } else if (ct == TLS_RT_HANDSHAKE) {
                if (!got_ccs) { free(rec); goto fail; }
                /* Verify server's Finished */
                if (rec_len >= 4 && rec[0] == TLS_HT_FINISHED) {
                    SHA256_State hs_copy;
                    unsigned char srv_verify[12];

                    hs_copy = hs_hash;
                    sha256_final(&hs_copy, hash_out);
                    tls_prf(master_secret, 48, "server finished",
                            hash_out, 32, srv_verify, 12);
                    /* Compare (skip 4-byte handshake header) */
                    if (memcmp(rec + 4, srv_verify, 12) != 0) {
                        vtls_log("server Finished verify mismatch\n");
                        free(rec); goto fail;
                    }
                    got_finished = 1;
                    vtls_log("handshake complete!\n");
                }
            } else if (ct == TLS_RT_ALERT) {
                free(rec); goto fail;
            }
            free(rec);
        }
    }

    memset(master_secret, 0, 48);
    return 0;

fail:
    c->active = 0;
    return -1;
}

/* =====================================================================
 * vtls_send / vtls_recv / vtls_close
 * ===================================================================== */

int vtls_send(int sockfd, const void *buf, int len)
{
    VTlsConn *c = find_conn(sockfd);
    if (!c) return -1;
    if (tls_write_record(sockfd, c, TLS_RT_APPLICATION,
                         (const unsigned char *)buf, len) < 0)
        return -1;
    return len;
}

int vtls_recv(int sockfd, void *buf, int len)
{
    VTlsConn *c = find_conn(sockfd);
    if (!c) return -1;

    /* Return buffered data first */
    if (c->app_buf && c->app_pos < c->app_len) {
        int avail = c->app_len - c->app_pos;
        int tocopy = (len < avail) ? len : avail;
        memcpy(buf, c->app_buf + c->app_pos, tocopy);
        c->app_pos += tocopy;
        if (c->app_pos >= c->app_len) {
            free(c->app_buf);
            c->app_buf = NULL;
            c->app_len = c->app_pos = 0;
        }
        return tocopy;
    }

    /* Check if data is waiting */
    if (!vsock_data_ready(sockfd)) return 0;

    /* Read a record */
    {
        unsigned char *rec;
        int rec_len, ct;
        ct = tls_read_record(sockfd, c, &rec, &rec_len);
        if (ct < 0) return -1;

        if (ct == TLS_RT_APPLICATION) {
            int tocopy = (len < rec_len) ? len : rec_len;
            memcpy(buf, rec, tocopy);
            if (tocopy < rec_len) {
                /* Buffer the rest */
                c->app_buf = rec;
                c->app_len = rec_len;
                c->app_pos = tocopy;
            } else {
                free(rec);
            }
            return tocopy;
        } else if (ct == TLS_RT_ALERT) {
            free(rec);
            return -1;
        } else {
            free(rec);
            return 0; /* ignore other record types */
        }
    }
}

int vtls_peer_cn(int sockfd, char *buf, int buflen)
{
    VTlsConn *c = find_conn(sockfd);
    if (!c || !c->peer_cert) return -1;
    return x509_extract_cn(c->peer_cert, c->peer_cert_len, buf, buflen);
}

int vtls_peer_key_bits(int sockfd)
{
    VTlsConn *c = find_conn(sockfd);
    if (!c) return -1;
    return c->peer_key_bits;
}

void vtls_close(int sockfd)
{
    VTlsConn *c = find_conn(sockfd);
    if (!c) return;

    /* Send close_notify alert */
    if (c->cipher_active) {
        unsigned char alert[2] = { 1, 0 }; /* warning, close_notify */
        tls_write_record(sockfd, c, TLS_RT_ALERT, alert, 2);
    }

    if (c->app_buf) free(c->app_buf);
    if (c->peer_cert) free(c->peer_cert);
    memset(c, 0, sizeof(VTlsConn));
}
