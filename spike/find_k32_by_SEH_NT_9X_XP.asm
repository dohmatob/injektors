;  --[ find_k32_by_SEH_NT_9X_XP.asm: finds the base address of kernel32.dll in windows NT/9X/XP (weighs 30 bytes) ]--
; HOWTO:	
;    0]-- Compile with 'nasm -f bin -o find_k32_by_SEH_NT_9X_XP.bin find_k32_by_SEH_NT_9X_XP.asm'
;    1]-- Use some opcode wizard to extract the generated shellcode. I use PYHTON
;         Viz, 'shellcode = open("find_k32_by_SEH_NT_9X_XP.bin", "rb").read()'. You have the fire!

; 4CKNOWLEDGEMENT5:
; 0]-- http://www.deimos.fr/blocnotesinfo/images/b/ba/Trouver_kernel32.pdf

[SECTION .text]

BITS 32

global _start

_start:
	
find_kernel32dll:
	
get_SEH_record:
	xor	ecx,ecx		; set ecx to 0
	mov	esi,[fs:ecx]	; let esi point to SEH record
	not	ecx		; set ecx to -1 = FFFFFFFF	

find_unhandled_x_handler:
	lodsd
	mov 	esi,eax		; esi now points to next SEH record
	cmp	[eax],ecx	; check whether 'pointer to next SEH record' is -1, indicating end of SEH chain
	jne	find_unhandled_x_handler

unhandle_x_handler_found:
	mov	eax,[esi+0x4]	; esi points to last endtry in SEH chain; set eax to the 'unhandled exception handler'

find_kernel32:
	dec	eax		; correction for ..
	xor 	ax,ax		; .. 64K alignment
	cmp word [eax],0x5A4D	; compare 1st 2 bytes of [eax] with the string 'MZ'
	jne	find_kernel32

kernel32_found:
	ret			; now, eax --hopefully!-- contains base address of kernel32.dll
	
	