from libshellcode.shellcode import *
from libutils.debug import *
from ctypes import *
import sys
import os
from optparse import OptionParser

kernel32 = windll.kernel32

MAX_DLL_PATHLEN = 200
CODECAVE_SIZE = 535
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
    primary_tid = GetPrimaryThreadId(remote_pid)
    if not primary_tid:
        print "Couln't obtain remote process primary thread"
        sys.exit(0)
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
    0072013A:           68 3A 01 71 00 PUSH 0x71013A
    0072013F:                       60 PUSHAD
    00720140:                       9C PUSHFD
    ->| START OF BLOCK (get inlinedetoursclientdll.dll handle)
    00720141:           68 CA 00 72 00 PUSH 0x7200CA
    00720146:           B8 77 28 0F 76 MOV EAX, 0x760F2877
    0072014B:                    FF D0 CALL EAX
    |<- END OF BLOCK (get inlinedetoursclientdll.dll handle)
    0072014D:           3D 00 00 00 00 CMP EAX, 0x0
    00720152:        0F 84 0A 00 00 00 JZ 0x720162
    00720158:           A3 CA 00 72 00 MOV DWORD PTR DS:[007200CA], EAX
    0072015D:           E9 1C 00 00 00 JMP 0x72017E
    ->| START OF BLOCK (load inlinedetoursclientdll.dll)
    00720162:           68 CA 00 72 00 PUSH 0x7200CA
    00720167:           B8 04 28 0F 76 MOV EAX, 0x760F2804
    0072016C:                    FF D0 CALL EAX
    |<- END OF BLOCK (load inlinedetoursclientdll.dll)
    0072016E:           3D 00 00 00 00 CMP EAX, 0x0
    00720173:        0F 84 86 00 00 00 JZ 0x7201FF
    00720179:           A3 CA 00 72 00 MOV DWORD PTR DS:[007200CA], EAX
    ->| START OF BLOCK (import HookSleepEx)
    0072017E:           68 32 00 72 00 PUSH 0x720032
    00720183:        FF 35 CA 00 72 00 PUSH DWORD PTR DS:[0x7200CA]
    00720189:           B8 D7 17 0F 76 MOV EAX, 0x760F17D7
    0072018E:                    FF D0 CALL EAX
    |<- END OF BLOCK (import HookSleepEx)
    00720190:           A3 32 00 72 00 MOV DWORD PTR DS:[00720032], EAX
    00720195:           3D 00 00 00 00 CMP EAX, 0x0
    0072019A:        0F 84 19 00 00 00 JZ 0x7201B9
    ->| START OF BLOCK (invoke HookSleepEx(..))
    007201A0:           A1 32 00 72 00 MOV EAX, DWORD PTR DS:[0x720032]
    007201A5:                    FF D0 CALL EAX
    |<- END OF BLOCK (invoke HookSleepEx(..))
    ->| START OF BLOCK (NOP-sled)
    007201A7:                       90 NOP
    007201A8:                       90 NOP
    007201A9:                       90 NOP
    007201AA:                       90 NOP
    007201AB:                       90 NOP
    007201AC:                       90 NOP
    007201AD:                       90 NOP
    007201AE:                       90 NOP
    007201AF:                       90 NOP
    007201B0:                       90 NOP
    007201B1:                       90 NOP
    007201B2:                       90 NOP
    007201B3:                       90 NOP
    |<- END OF BLOCK (NOP-sled)
    007201B4:           E9 5B 00 00 00 JMP 0x720214
    ->| START OF BLOCK (failed inlinedetoursclientdll.dll ejection notification)
    007201E5:                    6A 10 PUSH 0x10
    007201E7:           68 00 00 72 00 PUSH 0x720000
    007201EC:           68 A3 00 72 00 PUSH 0x7200A3
    007201F1:                    6A 00 PUSH 0x0
    007201F3:           B8 71 EA 61 76 MOV EAX, 0x7661EA71
    007201F8:                    FF D0 CALL EAX
    |<- END OF BLOCK (failed HookSleepEx(..) from inlinedetoursclientdll.dll notificati
    007201CE:           E9 41 00 00 00 JMP 0x720214
    ->| START OF BLOCK (unload inlinedetoursclientdll.dll)
    007201D3:        FF 35 CA 00 72 00 PUSH DWORD PTR DS:[0x7200CA]
    007201D9:           B8 89 19 0F 76 MOV EAX, 0x760F1989
    007201DE:                    FF D0 CALL EAX
    |<- END OF BLOCK (unload inlinedetoursclientdll.dll)
    007201E0:           E9 2F 00 00 00 JMP 0x720214
    ->| START OF BLOCK (failed inlinedetoursclientdll.dll ejection notification)
    007201E5:                    6A 10 PUSH 0x10
    007201E7:           68 00 00 72 00 PUSH 0x720000
    007201EC:           68 A3 00 72 00 PUSH 0x7200A3
    007201F1:                    6A 00 PUSH 0x0
    007201F3:           B8 71 EA 61 76 MOV EAX, 0x7661EA71
    007201F8:                    FF D0 CALL EAX
    |<- END OF BLOCK (failed inlinedetoursclientdll.dll ejection notification)
    007201FA:           E9 15 00 00 00 JMP 0x720214
    ->| START OF BLOCK (failed inlinedetoursclientdll.dll injection notification)
    007201FF:                    6A 10 PUSH 0x10
    00720201:           68 00 00 72 00 PUSH 0x720000
    00720206:           68 7B 00 72 00 PUSH 0x72007B
    0072020B:                    6A 00 PUSH 0x0
    0072020D:           B8 71 EA 61 76 MOV EAX, 0x7661EA71
    00720212:                    FF D0 CALL EAX
    |<- END OF BLOCK (failed inlinedetoursclientdll.dll injection notification)
    ->| START OF BLOCK (carrier thread's epilog)
    00720214:                       9D POPFD
    00720215:                       61 POPAD
    00720216:                       C3 RET
    |<- END OF BLOCK (carrier thread's epilog)
    ..
    """
    shellcode = Shellcode(start_offset=codecave_addr)
    err_caption_remote_addr = shellcode.addConstStr("%s: Error:" %sys.argv[0]) 
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
    injection_failure_shellcode = MessageBoxShellcode(injection_failure_err_txt_addr,
                                                      err_caption_remote_addr,
                                                      kind=MB_ICONERROR,
                                                      pseudo="failed %s injection notification" %dll_name,
                                                      start_offset=injection_failure_EP,
                                                      )
    ejection_failure_shellcode = MessageBoxShellcode(ejection_failure_err_txt_addr,
                                                     err_caption_remote_addr,
                                                     kind=MB_ICONERROR,
                                                     pseudo="failed %s ejection notification" %dll_name,
                                                     start_offset=ejection_failure_EP,
                                                     )
    if dll_function:
        import_dll_function_failure_shellcode = MessageBoxShellcode(import_dll_function_failure_txt_addr,
                                                                    err_caption_remote_addr,
                                                                    kind=MB_ICONERROR,
                                                                    pseudo="failed %s(..) from %s notification" %(dll_function,dll_name),
                                                                    start_offset=ejection_failure_EP,
                                                                    )
    unload_dll_shellcode = FreeLibraryShellcode(dll_remote_addr,
                                                pseudo="unload %s" %dll_name,
                                                start_offset=unload_dll_EP,
                                                )
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

