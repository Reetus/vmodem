; fossil.asm - FOSSIL INT 14h entry point with signature
;
; FOSSIL detection requires the word 1954h at offset +6 in the ISR,
; followed by a byte with the maximum supported function number.
;
; This naked entry shim contains the signature and jumps to the
; real __interrupt handler in int14.c.

        .MODEL SMALL
        .CODE

        EXTRN int14_real_handler_:FAR

        PUBLIC int14_handler_

int14_handler_ PROC FAR
        jmp     short past_sig      ; 2 bytes (EB xx)
        nop                         ; offset +2
        nop                         ; offset +3
        nop                         ; offset +4
        nop                         ; offset +5
        dw      1954h               ; offset +6: FOSSIL signature
        db      1Bh                 ; offset +8: max function number
past_sig:
        jmp     int14_real_handler_ ; far jump to real handler
int14_handler_ ENDP

        END
