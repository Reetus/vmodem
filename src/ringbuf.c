/*
 * ringbuf.c - Simple power-of-2 circular byte buffer for VMODEM
 *
 * The ring buffer is used to decouple the INT 28h background polling loop
 * (producer — writes incoming TCP data) from the INT 14h AH=02h receive
 * path (consumer — BBS software reading bytes).
 *
 * Because RING_SIZE is a power of 2 and head/tail are unsigned 16-bit
 * values that wrap naturally, head and tail updates are atomic on 16-bit
 * x86 (single MOV/INC instruction).  No explicit interrupt disable is
 * needed provided only one producer and one consumer exist per buffer.
 */

#include CFG_H
#include "vmodem.h"

void ring_init(RingBuf *r)
{
    r->head  = 0;
    r->tail  = 0;
    r->count = 0;
}

/* Add one byte to the ring.  Returns 0 on success, -1 if full. */
int ring_put(RingBuf *r, unsigned char b)
{
    if (r->count >= RING_SIZE)
        return -1;

    r->data[r->tail] = b;
    r->tail = (r->tail + 1) & (RING_SIZE - 1);
    r->count++;
    return 0;
}

/* Remove and return one byte.  Returns the byte (0-255) or -1 if empty. */
int ring_get(RingBuf *r)
{
    unsigned char b;

    if (r->count == 0)
        return -1;

    b = r->data[r->head];
    r->head = (r->head + 1) & (RING_SIZE - 1);
    r->count--;
    return (int)b;
}

/* Return number of bytes currently available. */
int ring_count(RingBuf *r)
{
    return (int)r->count;
}
