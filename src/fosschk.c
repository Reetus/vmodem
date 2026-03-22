/*
 * fosschk.c - FOSSIL driver detection and info check
 */

#include <stdio.h>
#include <string.h>
#include <dos.h>
#include <i86.h>

#pragma pack(push, 1)
typedef struct {
    unsigned short strsiz;      /* size of this structure */
    unsigned char  majver;      /* FOSSIL spec version */
    unsigned char  minver;      /* driver revision */
    unsigned long  ident;       /* FAR pointer to ID string */
    unsigned short ibufr;       /* input buffer size */
    unsigned short ifree;       /* input buffer free bytes */
    unsigned short obufr;       /* output buffer size */
    unsigned short ofree;       /* output buffer free bytes */
    unsigned char  swidth;      /* screen width */
    unsigned char  sheight;     /* screen height */
    unsigned char  baud;        /* baud rate bits */
} FossilInfo;
#pragma pack(pop)

int main(void)
{
    unsigned short vec_off, vec_seg;
    unsigned char __far *bp;
    unsigned short sig;

    printf("FOSSCHK - FOSSIL Driver Checker\n\n");

    /* Read INT 14h vector from IVT */
    vec_off = *(unsigned short __far *)MK_FP(0x0000, 0x0050);
    vec_seg = *(unsigned short __far *)MK_FP(0x0000, 0x0052);
    printf("INT 14h vector: %04X:%04X\n", vec_seg, vec_off);

    bp = (unsigned char __far *)MK_FP(vec_seg, vec_off);
    printf("Bytes at handler: %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
           bp[0], bp[1], bp[2], bp[3], bp[4], bp[5], bp[6], bp[7], bp[8]);

    sig = *(unsigned short __far *)MK_FP(vec_seg, vec_off + 6);
    printf("Signature at +6: 0x%04X -> %s\n\n",
           sig, (sig == 0x1954) ? "FOSSIL FOUND" : "NO FOSSIL");

    /* Try AH=04h FOSSIL init on COM1 */
    {
        union REGS r;
        r.h.ah = 0x04;
        r.w.dx = 0;
        r.w.bx = 0;
        int86(0x14, &r, &r);
        printf("AH=04h Init: AX=0x%04X BX=0x%04X -> %s\n",
               r.w.ax, r.w.bx,
               (r.w.ax == 0x1954) ? "OK" : "FAIL");
        if (r.w.ax == 0x1954)
            printf("  Spec rev=%d  Max func=0x%02X\n", r.h.bh, r.h.bl);
    }

    /* Try AH=1Bh driver info on COM1 */
    if (sig == 0x1954) {
        FossilInfo info;
        union REGS r;
        struct SREGS sr;
        char __far *idstr;

        memset(&info, 0, sizeof(info));
        segread(&sr);
        sr.es = FP_SEG(&info);

        r.h.ah = 0x1B;
        r.w.cx = sizeof(info);
        r.w.dx = 0;             /* COM1 */
        r.w.di = FP_OFF(&info);
        int86x(0x14, &r, &r, &sr);

        printf("\nAH=1Bh Driver Info (AX=%u bytes transferred):\n", r.w.ax);
        if (r.w.ax > 0) {
            printf("  Struct size: %u\n", info.strsiz);
            printf("  Spec ver: %u  Driver rev: %u\n", info.majver, info.minver);
            printf("  RX buf: %u (%u free)  TX buf: %u (%u free)\n",
                   info.ibufr, info.ifree, info.obufr, info.ofree);
            printf("  Screen: %ux%u  Baud: 0x%02X\n",
                   info.swidth, info.sheight, info.baud);

            /* Decode the FAR pointer to ID string */
            idstr = (char __far *)MK_FP(
                (unsigned short)(info.ident >> 16),
                (unsigned short)(info.ident & 0xFFFF));
            {
                char idbuf[65];
                int k;
                for (k = 0; k < 64 && idstr[k] != '\0'; k++)
                    idbuf[k] = idstr[k];
                idbuf[k] = '\0';
                printf("  ID string: \"%s\"\n", idbuf);
            }
        }

        /* Deinit (AH=05h) */
        r.h.ah = 0x05;
        r.w.dx = 0;
        int86(0x14, &r, &r);
    }

    return 0;
}
