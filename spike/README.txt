++++++++++
+ README +
++++++++++

A tiny python command-line script/module for dll-injection-related business.

(c) h4lf-jiffie (dohmatob elvis dopgima)

-1. DISCLAIMER
++++++++++++++
Use for educational purposes only.
Do not use on production site or other valuable asset.
Use at your Own risk.
No warranty --whatsover-- implied.

0. TODO
+++++++
Re-write this README from from scratch!

1. Sample usage
+++++++++++++++
Below, we inject ghp_inject.dll into process with PID = 7748.

PS C:\users\rude-boi> python .\gadgets.py 7748 '.\Downloads\ghpython_src\src\ghp_inject.dll' unload
+++++++++++++ gadgets.py by h4lf-j1ff13 (dohmatob elvis dopgima) +++++++++++++
[+] Obtaining handle to target process ..
[+] OK.
[+] Allocating 400-byte codecave in target process ..
[+] OK.
[+] Building gadget ..
                GADGET (entry-point at 0x036C008B):
                036C0000:                   DB "gadgets.py: Error",0
                036C0012:                   DB "couldn't inject ghp_inject.dll",0
                036C0031:                   DB "couldn't eject ghp_inject.dll",0
                036C004F:                   DB "C:\users\rude-boi\Downloads\ghpython_src\src\ghp_inject.dll",0
                ->| BEGIN "grab ghp_inject.dll handle"
                036C008B:    68 4F 00 6C 03 PUSH 0x36C004F
                036C0090:    B8 77 28 C1 76 MOV EAX, 0x76C12877
                036C0095:             FF D0 CALL EAX
                |<- END   "grab ghp_inject.dll handle"
                036C0097:    3D 00 00 00 00 CMP EAX, 0x0
                036C009C: 0F 85 1E 00 00 00 JNZ 0x36C00C0
                ->| BEGIN "ejection failure popup"
                036C00A2:             6A 10 PUSH 0x10
                036C00A4:    68 00 00 6C 03 PUSH 0x36C0000
                036C00A9:    68 31 00 6C 03 PUSH 0x36C0031
                036C00AE:             6A 00 PUSH 0x0
                036C00B0:    B8 71 EA E4 76 MOV EAX, 0x76E4EA71
                036C00B5:             FF D0 CALL EAX
                |<- END   "ejection failure popup"
                ->| BEGIN "kernel32.dll!ExitThread"
                036C00B7:             6A 00 PUSH 0x0
                036C00B9:    B8 71 05 09 77 MOV EAX, 0x77090571
                036C00BE:             FF D0 CALL EAX
                |<- END   "kernel32.dll!ExitThread"
                036C00C0:    A3 4F 00 6C 03 MOV DWORD PTR DS:[036C004F], EAX
                ->| BEGIN "ghp_inject.dll unloader"
                036C00C5:             6A 00 PUSH 0x0
                036C00C7: FF 35 4F 00 6C 03 PUSH DWORD PTR DS:[0x36C004F]
                036C00CD:    B8 90 34 C0 76 MOV EAX, 0x76C03490
                036C00D2:             FF D0 CALL EAX
                |<- END   "ghp_inject.dll unloader"
                ->| BEGIN "kernel32.dll!ExitThread"
                036C00D4:             6A 00 PUSH 0x0
                036C00D6:    B8 71 05 09 77 MOV EAX, 0x77090571
                036C00DB:             FF D0 CALL EAX
                |<- END   "kernel32.dll!ExitThread"

                PAYLOAD (221 bytes):
                        \x67\x61\x64\x67\x65\x74\x73\x2E\x70\x79\x3A\x20
                        \x45\x72\x72\x6F\x72\x00\x63\x6F\x75\x6C\x64\x6E
                        \x27\x74\x20\x69\x6E\x6A\x65\x63\x74\x20\x67\x68
                        \x70\x5F\x69\x6E\x6A\x65\x63\x74\x2E\x64\x6C\x6C
                        \x00\x63\x6F\x75\x6C\x64\x6E\x27\x74\x20\x65\x6A
                        \x65\x63\x74\x20\x67\x68\x70\x5F\x69\x6E\x6A\x65
                        \x63\x74\x2E\x64\x6C\x6C\x00\x43\x3A\x5C\x75\x73
                        \x65\x72\x73\x5C\x72\x75\x64\x65\x2D\x62\x6F\x69
                        \x5C\x44\x6F\x77\x6E\x6C\x6F\x61\x64\x73\x5C\x67
                        \x68\x70\x79\x74\x68\x6F\x6E\x5F\x73\x72\x63\x5C
                        \x73\x72\x63\x5C\x67\x68\x70\x5F\x69\x6E\x6A\x65
                        \x63\x74\x2E\x64\x6C\x6C\x00\x68\x4F\x00\x6C\x03
                        \xB8\x77\x28\xC1\x76\xFF\xD0\x3D\x00\x00\x00\x00
                        \x0F\x85\x1E\x00\x00\x00\x6A\x10\x68\x00\x00\x6C
                        \x03\x68\x31\x00\x6C\x03\x6A\x00\xB8\x71\xEA\xE4
                        \x76\xFF\xD0\x6A\x00\xB8\x71\x05\x09\x77\xFF\xD0
                        \xA3\x4F\x00\x6C\x03\x6A\x00\xFF\x35\x4F\x00\x6C
                        \x03\xB8\x90\x34\xC0\x76\xFF\xD0\x6A\x00\xB8\x71
                        \x05\x09\x77\xFF\xD0

[+] Coping gadget to codecave in remote process ..
[+] OK.
[+] Deploying remote carrier-thread to trigger gadget in target process ..
[+] OK (remote carrier TID = 5656)
[+] Freeing codecave in target process ..
[+] OK.

That's all for now.

(c) h4lf-jiffie (dohmatob elvis dopgima)
