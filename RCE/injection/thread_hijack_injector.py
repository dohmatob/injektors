from libshellcode.shellcode import *
from libutils.debug import EnumThreads
from ctypes import *
import sys
import os
from optparse import OptionParser

kernel32 = windll.kernel32

MAX_DLL_PATHLEN = 200
CODECAVE_SIZE = 0x400
MAX_DLL_FUNCTION_LEN = 25

__AUTHOR__ = 'd0hm4t06 3. d0p91m4 (half-jiffie)'
__VERSION__ = '1.0'
__FULL_VERSION__ = '%s version %s: a tiny code-injector using thread-hijack technique\r\n(c) %s' %(os.path.basename(sys.argv[0]),__VERSION__,__AUTHOR__)

def hijack(remote_pid,
           dll_path,
           eject=False,
           dll_function=None,
           dll_function_args=None):
    dll_name = os.path.basename(dll_path)
    print "++CONFIGURATION++"
    print "\tREMOTE PID                    : %s" %remote_pid
    print "\tDLL NAME                      : %s" %dll_name
    if eject:
        print"\tACTION:                       : EJECT"
    else:
        print"\tDLL PATH                      : %s" %dll_path
        print"\tACTION:                       : INJECT"
    remote_process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, 
                                                 0, 
                                                 remote_pid,
                                                 )
    print "Obtaining handle to remote process .."
    if not remote_process_handle:
        print "Error: couldn't obtain handle to remote process."
        sys.exit(1)
    print "OK."
    print "Allocating %d-byte space for shellcode in remote process memory .." %CODECAVE_SIZE
    codecave_addr = kernel32.VirtualAllocEx(remote_process_handle,
                                            0,
                                            CODECAVE_SIZE,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE,
                                            )
    print "OK (code-cave starts at 0x%08X)." %codecave_addr
    if not codecave_addr:
        print "Error: couldn't allocate remote code-cave."
        sys.exit(1)
    print "Obtaining remote process primary thread ID .."
    te32_generator = EnumThreads(remote_pid)
    for te32 in te32_generator:
        # XXX filter
        primary_tid = te32.th32ThreadID
        break
    print "OK (primary thread ID = %d)." %primary_tid
    print "Obtainging handle to remote process primary thread handle .."
    primary_thread_handle = kernel32.OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                                0,
                                                primary_tid,
                                                )
    if not primary_thread_handle:
        print "Error: couldn't obtain remote process primary thread."
        sys.exit(1)  
    print "OK."
    print "Building shellcode .."
    """
    The following code stub will generate shellcode similar to (strings stripped):
    ..
     ->| START OF BLOCK (carrier thread's prolog)
     00260151:           68 44 63 C0 77 PUSH 0x77C06344
     00260156:                       60 PUSHAD
     00260157:                       9C PUSHFD
     ->| START OF BLOCK (load user32.Dll)
     00260158:           68 32 00 26 00 PUSH 0x260032
     0026015D:           B8 04 28 0F 76 MOV EAX, 0x760F2804
     00260162:                    FF D0 CALL EAX
     |<- END OF BLOCK (load user32.Dll)
     00260164:           A3 32 00 26 00 MOV DWORD PTR DS:[00260032], EAX
     ->| START OF BLOCK (import MessageBoxA)
     00260169:           68 3D 00 26 00 PUSH 0x26003D
     0026016E:        FF 35 32 00 26 00 PUSH DWORD PTR DS:[0x260032]
     00260174:           B8 D7 17 0F 76 MOV EAX, 0x760F17D7
     00260179:                    FF D0 CALL EAX
     |<- END OF BLOCK (import MessageBoxA)
     0026017B:           A3 3D 00 26 00 MOV DWORD PTR DS:[0026003D], EAX
     ->| START OF BLOCK (get inlinedetoursclientdll.dll handle)
     00260180:           68 E1 00 26 00 PUSH 0x2600E1
     00260185:           B8 77 28 0F 76 MOV EAX, 0x760F2877
     0026018A:                    FF D0 CALL EAX
     |<- END OF BLOCK (get inlinedetoursclientdll.dll handle)
     0026018C:           3D 00 00 00 00 CMP EAX, 0x0
     00260191:        0F 84 0A 00 00 00 JZ 0x2601A1
     00260197:           A3 E1 00 26 00 MOV DWORD PTR DS:[002600E1], EAX
     0026019C:           E9 1C 00 00 00 JMP 0x2601BD
     ->| START OF BLOCK (load inlinedetoursclientdll.dll)
     002601A1:           68 E1 00 26 00 PUSH 0x2600E1
     002601A6:           B8 04 28 0F 76 MOV EAX, 0x760F2804
     002601AB:                    FF D0 CALL EAX
     |<- END OF BLOCK (load inlinedetoursclientdll.dll)
     002601AD:           3D 00 00 00 00 CMP EAX, 0x0
     002601B2:        0F 84 30 02 00 00 JZ 0x2603E8
     002601B8:           A3 E1 00 26 00 MOV DWORD PTR DS:[002600E1], EAX
     ->| START OF BLOCK (import HookSleepEx)
     002601BD:           68 49 00 26 00 PUSH 0x260049
     002601C2:        FF 35 E1 00 26 00 PUSH DWORD PTR DS:[0x2600E1]
     002601C8:           B8 D7 17 0F 76 MOV EAX, 0x760F17D7
     002601CD:                    FF D0 CALL EAX
     |<- END OF BLOCK (import HookSleepEx)
     002601CF:           A3 49 00 26 00 MOV DWORD PTR DS:[00260049], EAX
     002601D4:           3D 00 00 00 00 CMP EAX, 0x0
     002601D9:        0F 84 C3 01 00 00 JZ 0x2603A2
     ->| START OF BLOCK (invoke HookSleepEx(..))
     002601DF:           A1 49 00 26 00 MOV EAX, DWORD PTR DS:[0x260049]
     002601E4:                    FF D0 CALL EAX
     |<- END OF BLOCK (invoke HookSleepEx(..))
     ->| START OF BLOCK (NOP-sled)
     002601E6:                       90 NOP
     002601E7:                       90 NOP
     ..
     0026039B:                       90 NOP
     0026039C:                       90 NOP
     |<- END OF BLOCK (NOP-sled)
     0026039D:           E9 5B 00 00 00 JMP 0x2603FD
     ->| START OF BLOCK (failed inlinedetoursclientdll.dll ejection notification)
     002603CE:                    6A 10 PUSH 0x10
     002603D0:           68 00 00 26 00 PUSH 0x260000
     002603D5:           68 BA 00 26 00 PUSH 0x2600BA
     002603DA:                    6A 00 PUSH 0x0
     002603DC:           A1 3D 00 26 00 MOV EAX, DWORD PTR DS:[0x26003D]
     002603E1:                    FF D0 CALL EAX
     |<- END OF BLOCK (failed HookSleepEx(..) from inlinedetoursclientdll.dll notification)
     002603B7:           E9 41 00 00 00 JMP 0x2603FD
     ->| START OF BLOCK (unload inlinedetoursclientdll.dll)
     002603BC:        FF 35 E1 00 26 00 PUSH DWORD PTR DS:[0x2600E1]
     002603C2:           B8 89 19 0F 76 MOV EAX, 0x760F1989
     002603C7:                    FF D0 CALL EAX
     |<- END OF BLOCK (unload inlinedetoursclientdll.dll)
     002603C9:           E9 2F 00 00 00 JMP 0x2603FD
     ->| START OF BLOCK (failed inlinedetoursclientdll.dll ejection notification)
     002603CE:                    6A 10 PUSH 0x10
     002603D0:           68 00 00 26 00 PUSH 0x260000
     002603D5:           68 BA 00 26 00 PUSH 0x2600BA
     002603DA:                    6A 00 PUSH 0x0
     002603DC:           A1 3D 00 26 00 MOV EAX, DWORD PTR DS:[0x26003D]
     002603E1:                    FF D0 CALL EAX
     |<- END OF BLOCK (failed inlinedetoursclientdll.dll ejection notification)
     002603E3:           E9 15 00 00 00 JMP 0x2603FD
     ->| START OF BLOCK (failed inlinedetoursclientdll.dll injection notification)
     002603E8:                    6A 10 PUSH 0x10
     002603EA:           68 00 00 26 00 PUSH 0x260000
     002603EF:           68 92 00 26 00 PUSH 0x260092
     002603F4:                    6A 00 PUSH 0x0
     002603F6:           A1 3D 00 26 00 MOV EAX, DWORD PTR DS:[0x26003D]
     002603FB:                    FF D0 CALL EAX
     |<- END OF BLOCK (failed inlinedetoursclientdll.dll injection notification)
     ->| START OF BLOCK (carrier thread's epilog)
     002603FD:                       9D POPFD
     002603FE:                       61 POPAD
     002603FF:                       C3 RET
     |<- END OF BLOCK (carrier thread's epilog)
    ..
    """
    shellcode = Shellcode(start_offset=codecave_addr)
    err_caption_addr = shellcode.addConstStr("%s: Error:" %sys.argv[0])
    user32dll_addr = shellcode.addConstStr("user32.dll")
    messagebox_addr = shellcode.addConstStr("MessageBoxA")
    if dll_function:
        dll_function_remote_addr = shellcode.addConstStr(dll_function)
        import_dll_function_failure_txt_addr = shellcode.addConstStr("Can't import %s(..) from %s" %(dll_function, dll_name))
    injection_failure_err_txt_addr = shellcode.addConstStr("Can't inject %s" %dll_name)
    ejection_failure_err_txt_addr = shellcode.addConstStr("Can't eject %s" %dll_name)
    dll_remote_addr = shellcode.addConstStr(dll_path)
    entry_point = shellcode.getCurrentOffset()
    prolog = codecave_addr + CODECAVE_SIZE - 1 - 1 - 1
    injection_failure_EP = prolog - MESSAGEBOXSHELLCODE_LEN 
    ejection_failure_EP = injection_failure_EP - MESSAGEBOXSHELLCODE_LEN - UNCONDITIONALJMPSHELLCODE_LEN
    unload_dll_EP = ejection_failure_EP - FREELIBRARYSHELLCODE_LEN -  UNCONDITIONALJMPSHELLCODE_LEN
    seh_EP = unload_dll_EP
    if dll_function:
        import_dll_function_failure_EP = seh_EP = unload_dll_EP - MESSAGEBOXSHELLCODE_LEN - UNCONDITIONALJMPSHELLCODE_LEN
    ctx = CONTEXT(0)
    ctx.ContextFlags = CONTEXT_CONTROL
    kernel32.GetThreadContext(primary_thread_handle, byref(ctx))
    shellcode.addBlockEntryTag("carrier thread's prolog")
    shellcode.push(ctx.Eip)
    shellcode.pushAd()
    shellcode.pushFd()
    shellcode.addBlockEntryTag("carrier thread's prolog")
    injection_failure_shellcode = MessageBoxShellcode(messagebox_addr,
                                                      injection_failure_err_txt_addr,
                                                      err_caption_addr,
                                                      kind=MB_ICONERROR,
                                                      pseudo="failed %s injection notification" %dll_name,
                                                      start_offset=injection_failure_EP,
                                                      )
    ejection_failure_shellcode = MessageBoxShellcode(messagebox_addr,
                                                     ejection_failure_err_txt_addr,
                                                     err_caption_addr,
                                                     kind=MB_ICONERROR,
                                                     pseudo="failed %s ejection notification" %dll_name,
                                                     start_offset=ejection_failure_EP,
                                                     )
    if dll_function:
        import_dll_function_failure_shellcode = MessageBoxShellcode(messagebox_addr,
                                                                    import_dll_function_failure_txt_addr,
                                                                    err_caption_addr,
                                                                    kind=MB_ICONERROR,
                                                                    pseudo="failed %s(..) from %s notification" %(dll_function,dll_name),
                                                                    start_offset=ejection_failure_EP,
                                                                    )
    unload_dll_shellcode = FreeLibraryShellcode(dll_remote_addr,
                                                pseudo="unload %s" %dll_name,
                                                start_offset=unload_dll_EP,
                                                )
    load_user32dll_shellcode = LoadLibraryShellcode(user32dll_addr,
                                                    start_offset=shellcode.getCurrentOffset(),
                                                    pseudo="load user32.Dll",
                                                    )
    shellcode.addShellcode(load_user32dll_shellcode)
    shellcode.saveEax(user32dll_addr)
    import_messagebox_shellcode = GetProcAddressShellcode(user32dll_addr,
                                                          messagebox_addr,
                                                          start_offset=shellcode.getCurrentOffset(),
                                                          pseudo="import MessageBoxA",
                                                          )
    shellcode.addShellcode(import_messagebox_shellcode)
    shellcode.saveEax(messagebox_addr)
    get_dll_handle_shellcode = GetModuleHandleShellcode(dll_remote_addr,
                                                        start_offset=shellcode.getCurrentOffset(),
                                                        pseudo="get %s handle" %dll_name,
                                                        )
    shellcode.addShellcode(get_dll_handle_shellcode)
    shellcode.cmpEax(0x0)
    if eject:
        shellcode.jz(ejection_failure_EP)
    else:
        shellcode.jz(shellcode.getCurrentOffset() + CONDITIONALJMPSHELLCODE_LEN + 5 + UNCONDITIONALJMPSHELLCODE_LEN) 
    shellcode.saveEax(dll_remote_addr)
    if eject:
        shellcode.jmp(unload_dll_EP)
    else:
        shellcode.jmp(shellcode.getCurrentOffset() + UNCONDITIONALJMPSHELLCODE_LEN + LOADLIBRARYSHELLCODE_LEN + 5 + CONDITIONALJMPSHELLCODE_LEN + 5)
    load_dll_shellcode = LoadLibraryShellcode(dll_remote_addr,
                                              start_offset=shellcode.getCurrentOffset(),
                                              pseudo="load %s" %dll_name,
                                              )
    shellcode.addShellcode(load_dll_shellcode)
    shellcode.cmpEax(0x0)
    shellcode.jz(injection_failure_EP)
    shellcode.saveEax(dll_remote_addr)
    if dll_function:
        import_dll_function_shellcode = GetProcAddressShellcode(dll_remote_addr,
                                                               dll_function_remote_addr,
                                                               start_offset=shellcode.getCurrentOffset(),
                                                               pseudo="import %s" %dll_function,
                                                               )
        shellcode.addShellcode(import_dll_function_shellcode)
        shellcode.saveEax(dll_function_remote_addr)
        shellcode.cmpEax(0x0)
        shellcode.jz(import_dll_function_failure_EP)
        shellcode.addBlockEntryTag("invoke %s(..)" %dll_function)
        if dll_function_args:
            l = len(dll_function_args)
            for j in xrange(l):
                shellcode.push(int(dll_function_args[l - j - 1]))
        shellcode.callByReference(dll_function_remote_addr)
        shellcode.addBlockExitTag("invoke %s(..)" %dll_function)
    shellcode.nopSled(seh_EP - shellcode.getCurrentOffset() - UNCONDITIONALJMPSHELLCODE_LEN)
    shellcode.jmp(prolog)
    if dll_function:
        shellcode.addShellcode(import_dll_function_failure_shellcode)
        shellcode.jmp(prolog)
    for seh in [unload_dll_shellcode,
                ejection_failure_shellcode,
                ]:
        shellcode.addShellcode(seh)
        shellcode.jmp(prolog)
    shellcode.addShellcode(injection_failure_shellcode)
    shellcode.addBlockEntryTag("carrier thread's epilog")
    shellcode.popFd()
    shellcode.popAd()
    shellcode.ret()
    shellcode.addBlockExitTag("carrier thread's epilog")
    shellcode.display()
    # sys.exit(0)
    print "OK (%d-byte shellcode built; Entry Point = 0x%08X)." %(shellcode.getSize(), entry_point)
    print "Copying shellcode to remote code-cave .."
    bytes_written = DWORD(0)
    copy_OK = kernel32.WriteProcessMemory(remote_process_handle,
                                          codecave_addr,
                                          shellcode.getEgg(),
                                          shellcode.getSize(),
                                          byref(bytes_written),
                                          )
    copy_OK = copy_OK and  (bytes_written.value == shellcode.getSize())
    if not copy_OK:
        print "Error: couldn't copy shellcode to remote code-cave."
    print "OK."
    print "Hijacking remote process primary thread to execute shellcod for us .."
    ctx.Eip = entry_point
    kernel32.SetThreadContext(primary_thread_handle, byref(ctx))
    kernel32.ResumeThread(primary_thread_handle)
    print "OK."

if __name__ == "__main__":
    usage = "Usage: python %s [--eject] <remote_pid> <dll_path> [--function <function_name> <function_arg1> <function_arg2> .. <function_argn>]\r\n" %sys.argv[0]
    usage += "\r\nExamples:"
    usage += "\r\n[1] python %s 6408  .\evildll\bin\Debug\evildll.dll --function Initialize" %sys.argv[0]
    usage += "\r\n[2] python %s 6408  .\evildll\bin\Debug\evildll.dll --eject" %sys.argv[0]
    parser = OptionParser(version=__FULL_VERSION__,
                          usage=usage,
                          )
    parser.add_option('--function',
                      dest='function',
                      default=None,
                      type=str,
                      help="""specify function to invoke once DLL is injected (by default, we expect all DLL's payload to be carried by its DLLMain)""",
                      )
    parser.add_option('--eject',
                      dest='eject',
                      action="store_true",
                      default=False,
                      help="""eject DLL from remote process""",
                      )
    options, args = parser.parse_args()
    print __FULL_VERSION__
    if len(args) < 2:
        print "Error: Insufficient arguments\nUse the --help option to get help"
        sys.exit(1)
    remote_pid = int(args[0])
    dll_path = os.path.abspath(args[1])
    if len(dll_path) > MAX_DLL_PATHLEN:
        print "DLL path too long (must be at most %d characters); please rename" %MAX_DLL_PATHLEN
        sys.exit(1)
    if options.function:
        if len(options.function) > MAX_DLL_FUNCTION_LEN:
            print "function name too long (must be at most %d characters)" %MAX_DLL_FUNCTION_LEN
            sys.exit(1)
    if options.eject:
        if options.function:
            parser.error("It doesn't make any sense to use the '--eject' and '--function' options together; use '--help' option for help")
    hijack(remote_pid,
           dll_path,
           eject=options.eject,
           dll_function=options.function,
           dll_function_args=args[2:],
           )

