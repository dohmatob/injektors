	;; quine.asm by h4lf-jiffie (dohmatob elvis dopgima) a tiny ALPHA decoder
	;; 4CKNOWLEDGEMENTS:
	;; 	0]-- the shellcoder's handbook

[SECTION .text]

BITS 32

global _start

_start:
	jmp		B
	
A:
	jmp		C
	
B:
	call	A
	
C:	
	pop		edi
	add		edi,0x1B
	push		edi
	pop		esi
	
here:
	mov		al,	[edi]
	sub		al,0x41
	shl		al,4
	inc		edi
	add		al,[edi]
	sub		al,0x41
	mov		[esi],al
	inc		esi
	inc		edi
	cmp		byte [edi],0x51
	jb		here
	
