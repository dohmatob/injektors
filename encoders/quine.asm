	;; quine.asm by h4lf-jiffie (dohmatob elvis dopgima) a tiny ALPHA decoder
	;; 4CKNOWLEDGEMENTS:
	;; 	0]-- the shellcoder's handbook

[SECTION .text]

BITS 32

global _start

_start:
	jmp		B
	
A:
	jmp		get_PC
	
B:
	call		A
	
get_PC:	
	pop		edi
	add		edi,0x1B	; edi now points to encrypted size of the input buffer
	push		edi
	pop		esi
	
decoder:	
	mov		al,[edi]
	sub		al,0x41
	shl		al,4
	inc		edi
	add		al,[edi]
	sub		al,0x41
	mov		[esi],al
	inc		esi
	inc		edi
	cmp		byte [esi],0x51
	jb		decoder

	
	
	
	
