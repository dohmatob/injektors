+++++++++++++++++++++++++++++++++++++
+ HERE BE CODE FOR DLLI AND THE ILK +
+++++++++++++++++++++++++++++++++++++

(c) h4lf-jiffie (dohmatob elvis dopgima)

++++++++++++++++
+ INSTALLATION +
++++++++++++++++
step 1]- build and install the libdebug package by running the following 'python setup.py install' command:
PS C:\Users\rude-boi\CODE\injektors> cd .\dev-libs\libdebug
PS C:\Users\rude-boi\CODE\injektors\dev-libs\libdebug> python setup.p
running install
running build
running build_py
creating build
creating build\lib
creating build\lib\libdebug
copying libdebug\constants.py -> build\lib\libdebug
copying libdebug\debug.py -> build\lib\libdebug
copying libdebug\injector.py -> build\lib\libdebug
copying libdebug\__init__.py -> build\lib\libdebug
running install_lib
running install_egg_info
Removing C:\python27\Lib\site-packages\libdebug-0.1dev-py2.7.egg-info
Writing C:\python27\Lib\site-packages\libdebug-0.1dev-py2.7.egg-info
PS C:\Users\rude-boi\CODE\injektors\dev-libs\libdebug>

step 2]- build and install the libpayload package by running the following 'python setup.py install' command:
PS C:\Users\rude-boi\CODE\injektors\dev-libs\libdebug> cd ..\libpayload
PS C:\Users\rude-boi\CODE\injektors\dev-libs\libpayload> python setup.py install
running install
running build
running build_py
creating build
creating build\lib
creating build\lib\libpayload
copying libpayload\payload.py -> build\lib\libpayload
copying libpayload\__init__.py -> build\lib\libpayload
running install_lib
running install_egg_info
Removing C:\python27\Lib\site-packages\libpayload-0.1dev-py2.7.egg-info
Writing C:\python27\Lib\site-packages\libpayload-0.1dev-py2.7.egg-info
PS C:\Users\rude-boi\CODE\injektors\dev-libs\libpayload>
PS C:\Users\rude-boi\CODE\injektors\dev-libs\libpayload> cd ../..
   
+++++++++++
+ USAGE ? +
+++++++++++

N.B.:- This is just a stub --for now!

See a usage-scenario below ..

PS C:\Users\rude-boi\CODE\injektors> python .\injection\dll_injection pinball 'C:\Users\rude-boi\Documents\Visual Studio
2010\Projects\pinballspy\Debug\pinballspy.dll' --function TrapScore --hijack-primary-thread
C:\python27\python.exe: can't find '__main__' module in '.\\injection\\dll_injection'
PS C:\Users\rude-boi\CODE\security> python .\injection\dll_injection\generic_loader.py pinball 'C:\Users\rude-boi\Docume
nts\Visual Studio 2010\Projects\pinballspy\Debug\pinballspy.dll' --function TrapScore --hijack-primary-thread
generic_loader.py version 1.0dev: a tiny code-injector using thread-hijack and CreateRemoteThread techniques
(c) d0hm4t06 3. d0p91m4 (half-jiffie)
+++CONFIGURATION+++
        TARGET PID       : 6664
        DLL NAME         : pinballspy.dll
        DLL PATH         : C:\Users\rude-boi\Documents\Visual Studio 2010\Projects\pinballspy\Debug\pinballspy.dll
        ACTION           : INJECT
        METHOD           : HIJACK PRIMARY THREAD
        DLL FUNCTION     : TrapScore
Obtaining handle to target process ..
OK.
Allocating 600-byte code-cave in target process ..
OK (code-cave starts at 0x00690000).
Obtaing remote process primary thread ID ..
OK (target process primary thread ID = 6704).
Obtaining handle to target process primary thread ..
Obtaining target process primary thread context ..
OK (target process primary thread EIP = 0x77D76194)
OK.
Building payload ..
        00690000:                          DB "generic_loader.py: Error:",0
        0069001A:                          DB "Couldn't eject pinballspy.dll",0
        00690038:                          DB "Couldn't inject C:\Users\rude-boi\Documents\Visual Studio 2010\Projects\p
inballspy\Debug\pinballspy.dll",0
        006900A0:                          DB "TrapScore",0
        006900AA:                          DB "Couldn't import TrapScore API from pinballspy.dll",0
        006900DC:                          DB "C:\Users\rude-boi\Documents\Visual Studio 2010\Projects\pinballspy\Debug\
pinballspy.dll",0
        ->| START OF BLOCK (carrier thread prolog)
        00690134:           68 94 61 D7 77 PUSH 0x77D76194
        00690139:                       60 PUSHAD
        0069013A:                       9C PUSHFD
        |<- END OF BLOCK (carrier thread prolog)
        ->| START OF BLOCK (get pinballspy.dll handle)
        0069013B:           68 DC 00 69 00 PUSH 0x6900DC
        00690140:           B8 77 28 CA 77 MOV EAX, 0x77CA2877
        00690145:                    FF D0 CALL EAX
        |<- END OF BLOCK (get pinballspy.dll handle)
        00690147:           3D 00 00 00 00 CMP EAX, 0x0
        0069014C:        0F 85 0C 00 00 00 JNZ 0x69015E
        ->| START OF BLOCK (load pinballspy.dll)
        00690152:           68 DC 00 69 00 PUSH 0x6900DC
        00690157:           B8 04 28 CA 77 MOV EAX, 0x77CA2804
        0069015C:                    FF D0 CALL EAX
        |<- END OF BLOCK (load pinballspy.dll)
        0069015E:           3D 00 00 00 00 CMP EAX, 0x0
        00690163:        0F 84 C0 00 00 00 JZ 0x690229
        00690169:           A3 DC 00 69 00 MOV DWORD PTR DS:[006900DC], EAX
        ->| START OF BLOCK (import TrapScore API from pinballspy.dll)
        0069016E:           68 A0 00 69 00 PUSH 0x6900A0
        00690173:        FF 35 DC 00 69 00 PUSH DWORD PTR DS:[0x6900DC]
        00690179:           B8 D7 17 CA 77 MOV EAX, 0x77CA17D7
        0069017E:                    FF D0 CALL EAX
        |<- END OF BLOCK (import TrapScore API from pinballspy.dll)
        00690180:           3D 00 00 00 00 CMP EAX, 0x0
        00690185:        0F 84 6A 00 00 00 JZ 0x6901F5
        0069018B:           A3 A0 00 69 00 MOV DWORD PTR DS:[006900A0], EAX
        |<- END OF BLOCK (invoke TrapScore(..))
        00690190:           A1 A0 00 69 00 MOV EAX, DWORD PTR DS:[0x6900A0]
        00690195:                    FF D0 CALL EAX
        |<- END OF BLOCK (invoke TrapScore(..))
        00690197:           E9 B9 00 00 00 JMP 0x690255
        ->| START OF BLOCK (NOP-sled)
        0069019C:                       90 NOP
        0069019D:                       90 NOP
        0069019E:                       90 NOP
        0069019F:                       90 NOP
        006901A0:                       90 NOP
        006901A1:                       90 NOP
        006901A2:                       90 NOP
        006901A3:                       90 NOP
        006901A4:                       90 NOP
        006901A5:                       90 NOP
        006901A6:                       90 NOP
        006901A7:                       90 NOP
        006901A8:                       90 NOP
        006901A9:                       90 NOP
        006901AA:                       90 NOP
        006901AB:                       90 NOP
        006901AC:                       90 NOP
        006901AD:                       90 NOP
        006901AE:                       90 NOP
        006901AF:                       90 NOP
        006901B0:                       90 NOP
        006901B1:                       90 NOP
        006901B2:                       90 NOP
        006901B3:                       90 NOP
        006901B4:                       90 NOP
        006901B5:                       90 NOP
        006901B6:                       90 NOP
        006901B7:                       90 NOP
        006901B8:                       90 NOP
        006901B9:                       90 NOP
        006901BA:                       90 NOP
        006901BB:                       90 NOP
        006901BC:                       90 NOP
        006901BD:                       90 NOP
        006901BE:                       90 NOP
        006901BF:                       90 NOP
        006901C0:                       90 NOP
        006901C1:                       90 NOP
        006901C2:                       90 NOP
        006901C3:                       90 NOP
        006901C4:                       90 NOP
        006901C5:                       90 NOP
        006901C6:                       90 NOP
        006901C7:                       90 NOP
        006901C8:                       90 NOP
        006901C9:                       90 NOP
        006901CA:                       90 NOP
        006901CB:                       90 NOP
        006901CC:                       90 NOP
        006901CD:                       90 NOP
        006901CE:                       90 NOP
        006901CF:                       90 NOP
        006901D0:                       90 NOP
        006901D1:                       90 NOP
        006901D2:                       90 NOP
        006901D3:                       90 NOP
        006901D4:                       90 NOP
        006901D5:                       90 NOP
        006901D6:                       90 NOP
        006901D7:                       90 NOP
        006901D8:                       90 NOP
        006901D9:                       90 NOP
        006901DA:                       90 NOP
        006901DB:                       90 NOP
        006901DC:                       90 NOP
        006901DD:                       90 NOP
        006901DE:                       90 NOP
        006901DF:                       90 NOP
        006901E0:                       90 NOP
        006901E1:                       90 NOP
        006901E2:                       90 NOP
        006901E3:                       90 NOP
        006901E4:                       90 NOP
        006901E5:                       90 NOP
        006901E6:                       90 NOP
        006901E7:                       90 NOP
        006901E8:                       90 NOP
        006901E9:                       90 NOP
        006901EA:                       90 NOP
        006901EB:                       90 NOP
        006901EC:                       90 NOP
        006901ED:                       90 NOP
        006901EE:                       90 NOP
        006901EF:                       90 NOP
        006901F0:                       90 NOP
        006901F1:                       90 NOP
        006901F2:                       90 NOP
        006901F3:                       90 NOP
        006901F4:                       90 NOP
        |<- END OF BLOCK (NOP-sled)
        ->| START OF BLOCK (TrapScore API import failure notification)
        006901F5:                    6A 10 PUSH 0x10
        006901F7:           68 00 00 69 00 PUSH 0x690000
        006901FC:           68 AA 00 69 00 PUSH 0x6900AA
        00690201:                    6A 00 PUSH 0x0
        00690203:           B8 71 EA 1D 76 MOV EAX, 0x761DEA71
        00690208:                    FF D0 CALL EAX
        |<- END OF BLOCK (TrapScore API import failure notification)
        0069020A:           E9 46 00 00 00 JMP 0x690255
        ->| START OF BLOCK (pinballspy.dll ejection failure notification)
        0069020F:                    6A 10 PUSH 0x10
        00690211:           68 00 00 69 00 PUSH 0x690000
        00690216:           68 1A 00 69 00 PUSH 0x69001A
        0069021B:                    6A 00 PUSH 0x0
        0069021D:           B8 71 EA 1D 76 MOV EAX, 0x761DEA71
        00690222:                    FF D0 CALL EAX
        |<- END OF BLOCK (pinballspy.dll ejection failure notification)
        00690224:           E9 2C 00 00 00 JMP 0x690255
        ->| START OF BLOCK (pinballspy.dll injection failure notification)
        00690229:                    6A 10 PUSH 0x10
        0069022B:           68 00 00 69 00 PUSH 0x690000
        00690230:           68 38 00 69 00 PUSH 0x690038
        00690235:                    6A 00 PUSH 0x0
        00690237:           B8 71 EA 1D 76 MOV EAX, 0x761DEA71
        0069023C:                    FF D0 CALL EAX
        |<- END OF BLOCK (pinballspy.dll injection failure notification)
        0069023E:           E9 12 00 00 00 JMP 0x690255
        ->| START OF BLOCK (unload pinballspy.dll)
        00690243:        FF 35 DC 00 69 00 PUSH DWORD PTR DS:[0x6900DC]
        00690249:           B8 89 19 CA 77 MOV EAX, 0x77CA1989
        0069024E:                    FF D0 CALL EAX
        |<- END OF BLOCK (unload pinballspy.dll)
        00690250:           E9 00 00 00 00 JMP 0x690255
        ->| START OF BLOCK (carrier thread epilog)
        00690255:                       9D POPFD
        00690256:                       61 POPAD
        00690257:                       C3 RET
        |<- END OF BLOCK (carrier thread epilog)
OK (payload EP = 0x00690134).
Writing payload to code-cave in remote process ..
OK.
Hijacking target process primary thread to execute payload ..
OK.
Freeing code-cave in target process ..
OK.