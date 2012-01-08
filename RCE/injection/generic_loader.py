import os
import sys
from optparse import OptionParser
from libutils.injector import *
from libshellcode.shellcode import *

CODECAVE_SIZE = 675
MAX_DLL_PATHLEN = 100
MAX_DLL_FUNCTION_LEN = 25

__AUTHOR__ = 'd0hm4t06 3. d0p91m4 (RUDEBOI)'
__VERSION__ = '1.0'
__FULL_VERSION__ = '%s version %s: a tiny code-injector using runtime codecaving technique\r\n(c) %s December 13, 2011 -BORDEAUX' %(os.path.basename(sys.argv[0]),\
                                                                                                                                        __VERSION__,__AUTHOR__)

def hack(remote_pid,
         dll_path,
         eject = True,
         inject_eject = False,
         dll_function = None,
         dll_function_args = None,
         ):
    dll_path = os.path.abspath(dll_path)
    dll_name = os.path.basename(dll_path)
    debug("+- CONFIGURATION -+")
    debug("\tREMOTE PID                    : %s" %remote_pid)
    debug("\tDLL NAME                      : %s" %dll_name)
    if eject:
        debug("\tACTION:                       : EJECT")
    else:
        debug("\tDLL PATH                      : %s" %dll_path)
        debug("\tACTION:                       : INJECT")
        debug("\tINJECT PERMANENTLY            : %s" %(not inject_eject))
        debug("\tDLL PAYLOAD FUNCTION          : %s" %dll_function)
    debug("Obtaining remote process handle")
    remote_process_handle = getRemoteProcessHandle(remote_pid)
    if not remote_process_handle:
        debug("Couldn't obtain remote process handle")
        return
    debug("OK")
    debug("Allocating %s-byte codecave in remote process")
    codecave_addr = allocateCodecaveInRemoteProcess(remote_process_handle,
                                                    CODECAVE_SIZE,
                                                    )
    if not codecave_addr:
        debug("Couldn't allocate codecave in remote process")
        return
    debug("OK (codecave starts at 0x%08X)" %codecave_addr)
    debug("Building shellcode ..")
    """
    The following code will generate and ASM stub + payload similar to the following:
    ...
    00E00000:                          DB "Error",0
    00E00006:                          DB "Couldn't eject pinballcheatengine.dll from remote process",0
    00E00040:                          DB "TrapScore",0
    00E0004A:                          DB "Couldn't import function TrapScore(..) from pinballcheatengine.dll",0
    00E0008D:                          DB "Couldn't inject C:\Users\rude-boi\Documents\Visual Studio 2010\Projects\pinballcheatengine\Debug\pinballcheatengine.dll into remote process",0
    00E00119:                          DB "user32.dll",0
    00E00124:                          DB "MessageBoxA",0
    00E00130:                          DB "C:\Users\rude-boi\Documents\Visual Studio 2010\Projects\pinballcheatengine\Debug\pinballcheatengine.dll",0
    ->| START OF BLOCK (load user32.Dll)
    00E00198:           68 19 01 E0 00 PUSH 0xE00119
    00E0019D:           B8 7C 95 CA 75 MOV EAX, 0x75CA957C
    00E001A2:                    FF D0 CALL EAX
    |<- END OF BLOCK (load user32.Dll)
    00E001A4:           A3 19 01 E0 00 MOV DWORD PTR DS:[00E00119], EAX
    ->| START OF BLOCK (import MessageBoxA from user32.dll)
    00E001A9:           68 24 01 E0 00 PUSH 0xE00124
    00E001AE:        FF 35 19 01 E0 00 PUSH DWORD PTR DS:[0xE00119]
    00E001B4:           B8 5B 92 CC 75 MOV EAX, 0x75CC925B
    00E001B9:                    FF D0 CALL EAX
    |<- END OF BLOCK (import MessageBoxA from user32.dll)
    00E001BB:           A3 24 01 E0 00 MOV DWORD PTR DS:[00E00124], EAX
    ->| START OF BLOCK (get handle to pinballcheatengine.dll instance)
    00E001C0:           68 30 01 E0 00 PUSH 0xE00130
    00E001C5:           B8 C5 94 CC 75 MOV EAX, 0x75CC94C5
    00E001CA:                    FF D0 CALL EAX
    |<- END OF BLOCK (get handle to pinballcheatengine.dll instance)
    00E001CC:           3D 00 00 00 00 CMP EAX, 0x0
    00E001D1:        0F 85 17 00 00 00 JNZ 0xE001EE
    ->| START OF BLOCK (load pinballcheatengine.dll)
    00E001D7:           68 30 01 E0 00 PUSH 0xE00130
    00E001DC:           B8 7C 95 CA 75 MOV EAX, 0x75CA957C
    00E001E1:                    FF D0 CALL EAX
    |<- END OF BLOCK (load pinballcheatengine.dll)
    00E001E3:           3D 00 00 00 00 CMP EAX, 0x0
    00E001E8:        0F 84 69 00 00 00 JZ 0xE00257
    00E001EE:           A3 30 01 E0 00 MOV DWORD PTR DS:[00E00130], EAX
    ->| START OF BLOCK (import TrapScore(..) from pinballcheatengine.dll)
    00E001F3:           68 40 00 E0 00 PUSH 0xE00040
    00E001F8:        FF 35 30 01 E0 00 PUSH DWORD PTR DS:[0xE00130]
    00E001FE:           B8 5B 92 CC 75 MOV EAX, 0x75CC925B
    00E00203:                    FF D0 CALL EAX
    |<- END OF BLOCK (import TrapScore(..) from pinballcheatengine.dll)
    00E00205:           3D 00 00 00 00 CMP EAX, 0x0
    00E0020A:        0F 84 2D 00 00 00 JZ 0xE0023D
    00E00210:           A3 40 00 E0 00 MOV DWORD PTR DS:[00E00040], EAX
    ->| START OF BLOCK (invoke TrapScore(..))
    00E00215:           68 80 75 01 01 PUSH 0x1017580
    00E0021A:           A1 40 00 E0 00 MOV EAX, DWORD PTR DS:[0xE00040]
    00E0021F:                    FF D0 CALL EAX
    |<- END OF BLOCK (invoke TrapScore(..))
    00E00221:           E9 74 00 00 00 JMP 0xE0029A
    ->| START OF BLOCK (NOP-sled)
    00E00226:                       90 NOP
    00E00227:                       90 NOP
    00E00228:                       90 NOP
    00E00229:                       90 NOP
    00E0022A:                       90 NOP
    00E0022B:                       90 NOP
    00E0022C:                       90 NOP
    00E0022D:                       90 NOP
    00E0022E:                       90 NOP
    00E0022F:                       90 NOP
    00E00230:                       90 NOP
    00E00231:                       90 NOP
    00E00232:                       90 NOP
    00E00233:                       90 NOP
    00E00234:                       90 NOP
    00E00235:                       90 NOP
    00E00236:                       90 NOP
    00E00237:                       90 NOP
    00E00238:                       90 NOP
    00E00239:                       90 NOP
    00E0023A:                       90 NOP
    00E0023B:                       90 NOP
    00E0023C:                       90 NOP
    |<- END OF BLOCK (NOP-sled)
    ->| START OF BLOCK (import TrapScore(..) failure notification)
    00E0023D:                    6A 10 PUSH 0x10
    00E0023F:           68 00 00 E0 00 PUSH 0xE00000
    00E00244:           68 4A 00 E0 00 PUSH 0xE0004A
    00E00249:                    6A 00 PUSH 0x0
    00E0024B:           A1 24 01 E0 00 MOV EAX, DWORD PTR DS:[0xE00124]
    00E00250:                    FF D0 CALL EAX
    |<- END OF BLOCK (import TrapScore(..) failure notification)
    00E00252:           E9 43 00 00 00 JMP 0xE0029A
    ->| START OF BLOCK (injection failure notification)
    00E00257:                    6A 10 PUSH 0x10
    00E00259:           68 00 00 E0 00 PUSH 0xE00000
    00E0025E:           68 8D 00 E0 00 PUSH 0xE0008D
    00E00263:                    6A 00 PUSH 0x0
    00E00265:           A1 24 01 E0 00 MOV EAX, DWORD PTR DS:[0xE00124]
    00E0026A:                    FF D0 CALL EAX
    |<- END OF BLOCK (injection failure notification)
    00E0026C:           E9 29 00 00 00 JMP 0xE0029A
    ->| START OF BLOCK (ejection failure notification)
    00E00271:                    6A 10 PUSH 0x10
    00E00273:           68 00 00 E0 00 PUSH 0xE00000
    00E00278:           68 06 00 E0 00 PUSH 0xE00006
    00E0027D:                    6A 00 PUSH 0x0
    00E0027F:           A1 24 01 E0 00 MOV EAX, DWORD PTR DS:[0xE00124]
    00E00284:                    FF D0 CALL EAX
    |<- END OF BLOCK (ejection failure notification)
    00E00286:           E9 0F 00 00 00 JMP 0xE0029A
    ->| START OF BLOCK (unload pinballcheatengine.dll and exit remote thread)
    00E0028B:                    6A 00 PUSH 0x0
    00E0028D:        FF 35 30 01 E0 00 PUSH DWORD PTR DS:[0xE00130]
    00E00293:           B8 5E 48 CC 75 MOV EAX, 0x75CC485E
    00E00298:                    FF D0 CALL EAX
    |<- END OF BLOCK (unload pinballcheatengine.dll and exit remote thread)
    ->| START OF BLOCK (exit remote thread)
    00E0029A:                    6A 00 PUSH 0x0
    00E0029C:           B8 BB 1D 48 77 MOV EAX, 0x77481DBB
    00E002A1:                    FF D0 CALL EAX
    |<- END OF BLOCK (exit remote thread)
    ...
    """
    shellcode = Shellcode(start_offset=codecave_addr)
    err_caption_addr = shellcode.addConstStr("Error")
    eject_dll_failure_notification_txt_addr = shellcode.addConstStr("Couldn't eject %s from remote process" %dll_name)
    if dll_function:
        dll_function_addr = shellcode.addConstStr(dll_function)
        import_dll_function_failure_notification_txt_addr = shellcode.addConstStr("Couldn't import function %s(..) from %s" %(dll_function,dll_name))               
    inject_dll_failure_notification_txt_addr = shellcode.addConstStr("Couldn't inject %s into remote process" %dll_path)
    user32dll_addr = shellcode.addConstStr("user32.dll")
    messagebox_addr = shellcode.addConstStr("MessageBoxA")
    dll_addr = shellcode.addConstStr(dll_path)
    shellcode_EP = shellcode.getCurrentOffset()
    exitthread_EP = codecave_addr + CODECAVE_SIZE - EXITTHREADSHELLCODE_LEN
    freelibraryandexitthread_EP = exitthread_EP - FREELIBRARYANDEXITTHREADSHELLCODE_LEN
    eject_dll_failure_notification_EP = freelibraryandexitthread_EP - MESSAGEBOXSHELLCODE_LEN - UNCONDITIONALJMPSHELLCODE_LEN 
    inject_dll_failure_notification_EP = eject_dll_failure_notification_EP - MESSAGEBOXSHELLCODE_LEN - UNCONDITIONALJMPSHELLCODE_LEN 
    seh_EP = inject_dll_failure_notification_EP
    if dll_function:
        import_dll_function_failure_notification_EP = inject_dll_failure_notification_EP - MESSAGEBOXSHELLCODE_LEN - UNCONDITIONALJMPSHELLCODE_LEN                        
        seh_EP = import_dll_function_failure_notification_EP                                         
    load_user32dll_shellcode = LoadLibraryShellcode(user32dll_addr,
                                                    start_offset=shellcode.getCurrentOffset(),
                                                    pseudo="load user32.Dll",
                                                    )
    shellcode.addShellcode(load_user32dll_shellcode)
    shellcode.saveEax(user32dll_addr)
    import_messagebox_shellcode = GetProcAddressShellcode(user32dll_addr,
                                                          messagebox_addr,
                                                          start_offset=shellcode.getCurrentOffset(),
                                                          pseudo="import MessageBoxA from user32.dll",
                                                          )

    shellcode.addShellcode(import_messagebox_shellcode)
    shellcode.saveEax(messagebox_addr)
    get_dll_handle_shellcode = GetModuleHandleShellcode(dll_addr,
                                                        start_offset=shellcode.getCurrentOffset(),
                                                        pseudo="get handle to %s instance" %dll_name,
                                                        )
    shellcode.addShellcode(get_dll_handle_shellcode)
    shellcode.cmpEax(0x0)
    if eject:
        shellcode.saveEax(dll_addr)
        shellcode.jz(eject_dll_failure_notification_EP)
        shellcode.jmp(freelibraryandexitthread_EP)
    else:
        shellcode.jnz(shellcode.getCurrentOffset() + CONDITIONALJMPSHELLCODE_LEN + LOADLIBRARYSHELLCODE_LEN \
                          + CMPEAXSHELLCODE_LEN + CONDITIONALJMPSHELLCODE_LEN)
        load_dll_shellcode = LoadLibraryShellcode(dll_addr,
                                                  start_offset=shellcode.getCurrentOffset(),
                                                  pseudo="load %s" %dll_name,
                                                  )
        shellcode.addShellcode(load_dll_shellcode)
        shellcode.cmpEax(0x0)
        shellcode.jz(inject_dll_failure_notification_EP)
        shellcode.saveEax(dll_addr)
        if dll_function:
            dll_function_import_shellcode = GetProcAddressShellcode(dll_addr,
                                                                    dll_function_addr,
                                                                    start_offset=shellcode.getCurrentOffset(),
                                                                    pseudo='import %s(..) from %s' %(dll_function,dll_name),                                                                )        
            shellcode.addShellcode(dll_function_import_shellcode)
            shellcode.cmpEax(0x0)
            shellcode.jz(import_dll_function_failure_notification_EP)
            shellcode.saveEax(dll_function_addr)
            shellcode.addBlockEntryTag("invoke %s(..)" %dll_function)
            if dll_function_args:
                l = len(dll_function_args)
                for j in xrange(l):
                    shellcode.push(int(dll_function_args[l - j - 1]))
            shellcode.callByReference(dll_function_addr)
            shellcode.addBlockExitTag("invoke %s(..)" %dll_function)
        if inject_eject:
            shellcode.jmp(freelibraryandexitthread_EP)
        else:
            shellcode.jmp(exitthread_EP)
    nopsled = shellcode.nopSled(seh_EP - shellcode.getCurrentOffset())
    exitthread_shellcode = ExitThreadShellcode(start_offset=exitthread_EP,
                                               pseudo="exit remote thread")
    freelibraryandexitthread_shellcode = FreeLibraryAndExitThreadShellcode(dll_addr,
                                                                           start_offset=freelibraryandexitthread_EP,
                                                                           pseudo="unload %s and exit remote thread" %dll_name,
                                                                           )
    eject_dll_failure_notification_shellcode = MessageBoxShellcode(messagebox_addr,
                                                                   eject_dll_failure_notification_txt_addr,                
                                                                   err_caption_addr,
                                                                   kind=MB_ICONERROR,
                                                                   start_offset=eject_dll_failure_notification_EP,
                                                                   pseudo="ejection failure notification",
                                                                   )
    inject_dll_failure_notification_shellcode = MessageBoxShellcode(messagebox_addr,
                                                                    inject_dll_failure_notification_txt_addr,     
                                                                    err_caption_addr,
                                                                    kind=MB_ICONERROR,
                                                                    start_offset=inject_dll_failure_notification_EP,
                                                                    pseudo="injection failure notification",
                                                                    )
    if dll_function:
        import_dll_function_failure_notification_shellcode = MessageBoxShellcode(messagebox_addr,
                                                                                 import_dll_function_failure_notification_txt_addr,  
                                                                                 err_caption_addr,
                                                                                 kind=MB_ICONERROR,
                                                                                 start_offset=import_dll_function_failure_notification_EP,
                                                                                 pseudo="import %s(..) failure notification" %dll_function,
                                                                                 )
        shellcode.addShellcode(import_dll_function_failure_notification_shellcode)
        shellcode.jmp(exitthread_EP)
    for seh in [inject_dll_failure_notification_shellcode, 
                eject_dll_failure_notification_shellcode,
                ]:
        shellcode.addShellcode(seh)
        shellcode.jmp(exitthread_EP)
    shellcode.addShellcode(freelibraryandexitthread_shellcode)
    shellcode.addShellcode(exitthread_shellcode)
    shellcode.display()
    debug("OK (built %d-byte shellcode; EP = 0x%08X)" %(shellcode.getSize(),shellcode_EP))
    debug("Writing shellcode to remote process memory")
    if not writeRemoteProcessAddressSpace(remote_process_handle,
                                   codecave_addr,
                                   shellcode.getEgg(),
                                   ):
        debug("Couldn't write shellcode to remote process memory")
        return
    debug("OK")
    debug("Deploying remote thread to trigger shellcode in remote process")
    remote_thread_handle, remote_tid = fireupShellcodeInRemoteProcess(remote_process_handle,
                                   shellcode_EP,
                                               )
    if not remote_thread_handle:
        debug("Couldn't deploy remote thread")
        return
    debug("OK (remote tid = %d)" %remote_tid)
    debug("Freeing remote codecave")
    freeCodecaveInRemoteProcess(remote_process_handle,
                                codecave_addr,
                                CODECAVE_SIZE,
                                )
    debug("OK")


if __name__ == '__main__':
    usage = "Usage: python %s [options] <remote_pid> <dll_path>\r\n" %sys.argv[0]
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
    parser.add_option('--inject-eject',
                      dest='injecteject',
                      action="store_true",
                      default=False,
                      help="""inject DLL, and then eject it right away (by default the DLL will be injected permanently)""",
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
        debug("Error: Insufficient arguments")
        die("Use the --help option to get help")
    remote_pid = int(args[0])
    dll_path = args[1]
    if len(dll_path) > MAX_DLL_PATHLEN:
        die("DLL path too long (must be at most %d characters); please rename" %MAX_DLL_PATHLEN)
    if options.function:
        if len(options.function) > MAX_DLL_FUNCTION_LEN:
            die("function name too long (must be at most %d characters)" %MAX_DLL_FUNCTION_LEN)        
    if options.eject:
        if options.injecteject:
            parser.error("It doesn't make any sense to use the '--eject' and '--inject-eject' options together; use '--help' option for help")
        if options.function:
            parser.error("It doesn't make any sense to use the '--eject' and '--function' options together; use '--help' option for help")
    debug('Starting engines at %s (%s)' %pretty_time())
    hack(remote_pid,
         dll_path,
         eject=options.eject,
         inject_eject=options.injecteject,
         dll_function=options.function,
         dll_function_args=args[2:],
           )
    debug('Done: %s (%s).' %pretty_time())
