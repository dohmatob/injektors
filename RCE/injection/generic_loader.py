import os
import sys
from optparse import OptionParser
from libutils.injector import *
from libshellcode.shellcode import *

CODECAVE_SIZE = 1024
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
        # XXX code to invoke dll payload function goes right here <------
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
