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
Below, we inject ghp_inject.dll int o process with PID = 7748.

PS C:\users\rude-boi> python .\gadgets.py 7748 '.\Downloads\ghpython_src\src\ghp_inject.dll' load
[+] +++++++++++++ gadgets.py by h4lf-j1ff13 (dohmatob elvis dopgima) +++++++++++++
[+] [+] Obtaining handle to target process ..
[+] OK.
[+] Allocating 400-byte codecave in target process ..
[+] OK.
[+] Building gadget ..
                GADGET (entry-point at 0x008F008B):
                008F0000:                   DB "gadgets.py: Error",0
                008F0012:                   DB "couldn't inject ghp_inject.dll",0
                008F0031:                   DB "couldn't eject ghp_inject.dll",0
                008F004F:                   DB "C:\users\rude-boi\Downloads\ghpython_src\src\ghp_inject.dll",0
                008F008B:    68 4F 00 8F 00 PUSH 0x8F004F
                008F0090:    B8 77 28 C1 76 MOV EAX, 0x76C12877
                008F0095:             FF D0 CALL EAX
                008F0097:    3D 00 00 00 00 CMP EAX, 0x0
                008F009C: 0F 85 0C 00 00 00 JNZ 0x8F00AE
                008F00A2:    68 4F 00 8F 00 PUSH 0x8F004F
                008F00A7:    B8 04 28 C1 76 MOV EAX, 0x76C12804
                008F00AC:             FF D0 CALL EAX
                008F00AE:    3D 00 00 00 00 CMP EAX, 0x0
                008F00B3: 0F 85 1E 00 00 00 JNZ 0x8F00D7
                008F00B9:             6A 10 PUSH 0x10
                008F00BB:    68 00 00 8F 00 PUSH 0x8F0000
                008F00C0:    68 12 00 8F 00 PUSH 0x8F0012
                008F00C5:             6A 00 PUSH 0x0
                008F00C7:    B8 71 EA E4 76 MOV EAX, 0x76E4EA71
                008F00CC:             FF D0 CALL EAX
                008F00CE:             6A 00 PUSH 0x0
                008F00D0:    B8 71 05 09 77 MOV EAX, 0x77090571
                008F00D5:             FF D0 CALL EAX
                008F00D7:    A3 4F 00 8F 00 MOV DWORD PTR DS:[008F004F], EAX
                008F00DC:             6A 00 PUSH 0x0
                008F00DE:    B8 71 05 09 77 MOV EAX, 0x77090571
                008F00E3:             FF D0 CALL EAX

                PAYLOAD (229 bytes):
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
                        \x63\x74\x2E\x64\x6C\x6C\x00\x68\x4F\x00\x8F\x00
                        \xB8\x77\x28\xC1\x76\xFF\xD0\x3D\x00\x00\x00\x00
                        \x0F\x85\x0C\x00\x00\x00\x68\x4F\x00\x8F\x00\xB8
                        \x04\x28\xC1\x76\xFF\xD0\x3D\x00\x00\x00\x00\x0F
                        \x85\x1E\x00\x00\x00\x6A\x10\x68\x00\x00\x8F\x00
                        \x68\x12\x00\x8F\x00\x6A\x00\xB8\x71\xEA\xE4\x76
                        \xFF\xD0\x6A\x00\xB8\x71\x05\x09\x77\xFF\xD0\xA3
                        \x4F\x00\x8F\x00\x6A\x00\xB8\x71\x05\x09\x77\xFF
                        \xD0

[+] Coping gadget to codecave in remote process ..
[+] OK.
[+] Deploying remote carrier-thread to trigger gadget in target process ..
[+] OK (remote carrier TID = 7936)
[+] Freeing codecave in target process ..
[+] OK.

That's all for now.

(c) h4lf-jiffie (dohmatob elvis dopgima)
