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
<<<<<<< HEAD
Below, we inject pinballspy.dll into pinball process (PID = 7748), and once the DLL is loaded, we
import and invoke pinballspy.dll!TrapScore API. Viz,
=======
Below, we eject ghp_inject.dll from process with PID 7748.
>>>>>>> a8a978e6cc2d5b0adbbf4ce1f1097dbb6ec360b5

PS C:\users\rude-boi> python code\injektors\spike\gadgets.py 8156 '.\Documents\Visual Studio 2010\
Projects\pinballspy\Debug\pinballspy.dll' --invoke-api TrapScore
+++++++++++++ gadgets.py by h4lf-j1ff13 (dohmatob elvis dopgima) +++++++++++++
[+] [+] Obtaining handle to target process ..
[+] OK.
[+] Allocating 500-byte codecave in target process ..
[+] OK.
[+] Building gadget ..
                GADGET (entry-point at 0x01F300DE):
                01F30000:                   DB "gadgets.py: Error",0
                01F30012:                   DB "couldn't inject pinballspy.dll",0
                01F30031:                   DB "couldn't eject pinballspy.dll",0
                01F3004F:                   DB "C:\users\rude-boi\Documents\Visual Studio 2010\Projects\pinballspy\Debug
\pinballspy.dll",0
                01F300A7:                   DB "TrapScore",0
                01F300B1:                   DB "couldn't import pinballspy.dll!TrapScore API",0
                ->| BEGIN "grab pinballspy.dll handle"
                01F300DE:    68 4F 00 F3 01 PUSH 0x1F3004F
                01F300E3:    B8 77 28 C1 76 MOV EAX, 0x76C12877
                01F300E8:             FF D0 CALL EAX
                [<- END   "grab pinballspy.dll handle"
                01F300EA:    3D 00 00 00 00 CMP EAX, 0x0
                01F300EF: 0F 85 0C 00 00 00 JNZ 0x1F30101
                ->| BEGIN "load pinballspy.dll"
                01F300F5:    68 4F 00 F3 01 PUSH 0x1F3004F
                01F300FA:    B8 04 28 C1 76 MOV EAX, 0x76C12804
                01F300FF:             FF D0 CALL EAX
                [<- END   "load pinballspy.dll"
                01F30101:    3D 00 00 00 00 CMP EAX, 0x0
                01F30106: 0F 85 1E 00 00 00 JNZ 0x1F3012A
                ->| BEGIN "popup pinballspy.dll injection failure notification"
                01F3010C:             6A 10 PUSH 0x10
                01F3010E:    68 00 00 F3 01 PUSH 0x1F30000
                01F30113:    68 12 00 F3 01 PUSH 0x1F30012
                01F30118:             6A 00 PUSH 0x0
                01F3011A:    B8 71 EA E4 76 MOV EAX, 0x76E4EA71
                01F3011F:             FF D0 CALL EAX
                [<- END   "popup pinballspy.dll injection failure notification"
                ->| BEGIN "invoke kernel32.dll!ExitThread"
                01F30121:             6A 00 PUSH 0x0
                01F30123:    B8 71 05 09 77 MOV EAX, 0x77090571
                01F30128:             FF D0 CALL EAX
                [<- END   "invoke kernel32.dll!ExitThread"
                01F3012A:    A3 4F 00 F3 01 MOV DWORD PTR DS:[01F3004F], EAX
                ->| BEGIN "import pinballspy.dll!TrapScore"
                01F3012F:    68 A7 00 F3 01 PUSH 0x1F300A7
                01F30134: FF 35 4F 00 F3 01 PUSH DWORD PTR DS:[0x1F3004F]
                01F3013A:    B8 D7 17 C1 76 MOV EAX, 0x76C117D7
                01F3013F:             FF D0 CALL EAX
                [<- END   "import pinballspy.dll!TrapScore"
                01F30141:    3D 00 00 00 00 CMP EAX, 0x0
                01F30146: 0F 85 1E 00 00 00 JNZ 0x1F3016A
                ->| BEGIN "pinballspy.dll!TrapScore import failure notification"
                01F3014C:             6A 10 PUSH 0x10
                01F3014E:    68 00 00 F3 01 PUSH 0x1F30000
                01F30153:    68 B1 00 F3 01 PUSH 0x1F300B1
                01F30158:             6A 00 PUSH 0x0
                01F3015A:    B8 71 EA E4 76 MOV EAX, 0x76E4EA71
                01F3015F:             FF D0 CALL EAX
                [<- END   "pinballspy.dll!TrapScore import failure notification"
                ->| BEGIN "invoke kernel32.dll!ExitThread"
                01F30161:             6A 00 PUSH 0x0
                01F30163:    B8 71 05 09 77 MOV EAX, 0x77090571
                01F30168:             FF D0 CALL EAX
                [<- END   "invoke kernel32.dll!ExitThread"
                01F3016A:    A3 A7 00 F3 01 MOV DWORD PTR DS:[01F300A7], EAX
                01F3016F:    A1 A7 00 F3 01 MOV EAX, DWORD PTR DS:[01F300A7]
                01F30174:             FF D0 CALL EAX
                ->| BEGIN "invoke kernel32.dll!ExitThread"
                01F30176:             6A 00 PUSH 0x0
                01F30178:    B8 71 05 09 77 MOV EAX, 0x77090571
                01F3017D:             FF D0 CALL EAX
                [<- END   "invoke kernel32.dll!ExitThread"


                PAYLOAD (383 bytes):
                        \x67\x61\x64\x67\x65\x74\x73\x2E\x70\x79\x3A\x20
                        \x45\x72\x72\x6F\x72\x00\x63\x6F\x75\x6C\x64\x6E
                        \x27\x74\x20\x69\x6E\x6A\x65\x63\x74\x20\x70\x69
                        \x6E\x62\x61\x6C\x6C\x73\x70\x79\x2E\x64\x6C\x6C
                        \x00\x63\x6F\x75\x6C\x64\x6E\x27\x74\x20\x65\x6A
                        \x65\x63\x74\x20\x70\x69\x6E\x62\x61\x6C\x6C\x73
                        \x70\x79\x2E\x64\x6C\x6C\x00\x43\x3A\x5C\x75\x73
                        \x65\x72\x73\x5C\x72\x75\x64\x65\x2D\x62\x6F\x69
                        \x5C\x44\x6F\x63\x75\x6D\x65\x6E\x74\x73\x5C\x56
                        \x69\x73\x75\x61\x6C\x20\x53\x74\x75\x64\x69\x6F
                        \x20\x32\x30\x31\x30\x5C\x50\x72\x6F\x6A\x65\x63
                        \x74\x73\x5C\x70\x69\x6E\x62\x61\x6C\x6C\x73\x70
                        \x79\x5C\x44\x65\x62\x75\x67\x5C\x70\x69\x6E\x62
                        \x61\x6C\x6C\x73\x70\x79\x2E\x64\x6C\x6C\x00\x54
                        \x72\x61\x70\x53\x63\x6F\x72\x65\x00\x63\x6F\x75
                        \x6C\x64\x6E\x27\x74\x20\x69\x6D\x70\x6F\x72\x74
                        \x20\x70\x69\x6E\x62\x61\x6C\x6C\x73\x70\x79\x2E
                        \x64\x6C\x6C\x21\x54\x72\x61\x70\x53\x63\x6F\x72
                        \x65\x20\x41\x50\x49\x00\x68\x4F\x00\xF3\x01\xB8
                        \x77\x28\xC1\x76\xFF\xD0\x3D\x00\x00\x00\x00\x0F
                        \x85\x0C\x00\x00\x00\x68\x4F\x00\xF3\x01\xB8\x04
                        \x28\xC1\x76\xFF\xD0\x3D\x00\x00\x00\x00\x0F\x85
                        \x1E\x00\x00\x00\x6A\x10\x68\x00\x00\xF3\x01\x68
                        \x12\x00\xF3\x01\x6A\x00\xB8\x71\xEA\xE4\x76\xFF
                        \xD0\x6A\x00\xB8\x71\x05\x09\x77\xFF\xD0\xA3\x4F
                        \x00\xF3\x01\x68\xA7\x00\xF3\x01\xFF\x35\x4F\x00
                        \xF3\x01\xB8\xD7\x17\xC1\x76\xFF\xD0\x3D\x00\x00
                        \x00\x00\x0F\x85\x1E\x00\x00\x00\x6A\x10\x68\x00
                        \x00\xF3\x01\x68\xB1\x00\xF3\x01\x6A\x00\xB8\x71
                        \xEA\xE4\x76\xFF\xD0\x6A\x00\xB8\x71\x05\x09\x77
                        \xFF\xD0\xA3\xA7\x00\xF3\x01\xA1\xA7\x00\xF3\x01
                        \xFF\xD0\x6A\x00\xB8\x71\x05\x09\x77\xFF\xD0

[+] Coping gadget to codecave in remote process ..
[+] OK.
[+] Deploying remote carrier-thread to trigger gadget in target process ..
[+] OK (remote carrier TID = 2456)
[+] Freeing codecave in target process ..
[+] OK.
PS C:\users\rude-boi>

That's all for now.

(c) h4lf-jiffie (dohmatob elvis dopgima)
