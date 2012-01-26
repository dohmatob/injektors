"""
(c) d0hm4t06 3. d0p91m4 (h4lf-jiffie)
"""
from libpayload.payload import *
from libdebug.constants import *
from libdebug.debug import *
from ctypes import *
import sys
import os
from optparse import OptionParser

CODECAVE_SIZE = 600
MAX_DLL_PATHLEN = 200
MAX_DLL_FUNCTION_LEN = 25

__AUTHOR__ = 'd0hm4t06 3. d0p91m4 (half-jiffie)'
__VERSION__ = '1.0dev'
__FULL_VERSION__ = '%s version %s: a tiny code-injector using thread-hijack and CreateRemoteThread techniques\r\n(c) %s' \
    %(os.path.basename(sys.argv[0]),__VERSION__,__AUTHOR__)


def printDebug(msg):
    print msg

def hack(target_pid,
         dll_path,
         eject=False,
         createremotethread=True,
         dll_function=None,
         dll_function_args=None,
         ):
    dll_name = os.path.basename(dll_path)
    printDebug("+++CONFIGURATION+++")
    printDebug("\tTARGET PID       : %s" %target_pid)
    printDebug("\tDLL NAME         : %s" %dll_name)
    printDebug("\tDLL PATH         : %s" %dll_path)
    if eject:
        printDebug("\tACTION           : EJECT")
    else:
        printDebug("\tACTION           : INJECT")
    if createremotethread:
        printDebug("\tMETHOD           : CreateRemoteThread")
    else:
        printDebug("\tMETHOD           : HIJACK PRIMARY THREAD")
    if dll_function:
        printDebug("\tDLL FUNCTION     : %s" %dll_function)
        if dll_function_args:
            printDebug("\tDLL FUNCTION ARGS: %s" %' '.join(dll_function_args))
    # obtain handle to target process
    printDebug("Obtaining handle to target process ..")
    target_process_handle = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS,
                                                        0,
                                                        target_pid,
                                                        )
    if not target_process_handle: # error-check
        printDebug("Error: windll.kernel32.OpenProcess: couldn't obtain handle to target process (GetLastError()\
 = 0x%08X)." %windll.kernel32.GetLastError())
        sys.exit(1)
    printDebug("OK.")
    # make space for payload
    printDebug("Allocating %d-byte code-cave in target process .." %CODECAVE_SIZE)
    codecave_addr = windll.kernel32.VirtualAllocEx(target_process_handle,
                                                   0,
                                                   CODECAVE_SIZE,
                                                   MEM_COMMIT,
                                                   PAGE_EXECUTE_READWRITE,
                                                   )
    if not codecave_addr: # error-check
        printDebug("Error: windll.kernel32.VirtualAllocEx: couldn't allocate code-cave in target process (GetLastError()\
 = 0x%08X)." %windll.kernel32.GetLastError())
        sys.exit(1)
    printDebug("OK (code-cave starts at 0x%08X)." %codecave_addr)
    if not createremotethread:
        # we will hijack the primary thread of the target process and let it trigger our payload for us
        printDebug("Obtaing remote process primary thread ID ..")
        primary_tid = GetPrimaryThreadId(target_pid)
        if not primary_tid:
            printDebug("Error: GetPrimaryThreadId: couldn't get target process primary thread ID \
(windll.kernel32.GetLastError() = 0x%08X)." %windll.kernel32.GetLastError())
            sys.Exit(1)
        printDebug("OK (target process primary thread ID = %d)." %primary_tid)
        printDebug("Obtaining handle to target process primary thread ..")
        primary_thread_handle = windll.kernel32.OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | \
                                                               THREAD_SET_CONTEXT,
                                                           0,
                                                           primary_tid,
                                                           )
        windll.kernel32.SuspendThread(primary_thread_handle)
        printDebug("Obtaining target process primary thread context ..")
        primary_thread_ctx = CONTEXT(0)
        primary_thread_ctx.ContextFlags = CONTEXT_CONTROL
        windll.kernel32.GetThreadContext(primary_thread_handle,
                                          byref(primary_thread_ctx),
                                          )
        primary_thread_saved_EIP = primary_thread_ctx.Eip # so we may de-hijack the thread in case of trouble
        printDebug("OK (target process primary thread EIP = 0x%0X)" %primary_thread_ctx.Eip)
        if not primary_thread_handle:
            printDebug("Error: windll.kernel32.OpenThread: couldn't obtain handle to target process primary thread \
(windll.kernel32.GetLastError() = 0x%08X)." %windll.kernel32.GetLastError())
            sys.exit(1)
        printDebug("OK.")
    printDebug("Building payload ..")
    payload = Payload(start_offset=codecave_addr)
    # start: build data-section of payload
    err_caption_addr = payload.addConstStr("%s: Error:" %os.path.basename(sys.argv[0]))
    ejection_failure_err_txt_addr = payload.addConstStr("Couldn't eject %s" %dll_name)
    injection_failure_err_txt_addr = payload.addConstStr("Couldn't inject %s" %dll_path)
    if dll_function:
        dll_function_addr = payload.addConstStr(dll_function)
        import_dll_function_failure_err_txt_addr = payload.addConstStr("Couldn't import %s API from %s" \
                                                                             %(dll_function,dll_name))
    # end: build data-section of payload
    dll_addr = payload.addConstStr(dll_path)
    EP  = payload.getCurrentOffset() # Entry Point
    if createremotethread:
        exitthread_EP = codecave_addr + CODECAVE_SIZE - EXITTHREADPAYLOAD_LEN
        prolog = exitthread_EP
        exitthread_payload = ExitThreadPayload(start_offset=exitthread_EP,
                                                  pseudo="exit thread",
                                                  )
        freelibraryandexitthread_EP = exitthread_EP - FREELIBRARYANDEXITTHREADPAYLOAD_LEN - \
            UNCONDITIONALJMPPAYLOAD_LEN
        freelibraryandexitthread_payload = FreeLibraryAndExitThreadPayload(dll_addr,
                                                                               start_offset=freelibraryandexitthread_EP,
                                                                               pseudo="unload %s and exit thread" \
                                                                                   %dll_name,
                                                                               )
        end_of_seh = freelibraryandexitthread_EP
    else: 
        prolog = codecave_addr + CODECAVE_SIZE - 1 - 1 - 1 
        freelibrary_EP = prolog - FREELIBRARYPAYLOAD_LEN - UNCONDITIONALJMPPAYLOAD_LEN 
        freelibrary_payload = FreeLibraryPayload(dll_addr,
                                                    start_offset=freelibrary_EP,
                                                    pseudo="unload %s" %dll_name,
                                                    )
        end_of_seh = freelibrary_EP
    unload_dll_EP = end_of_seh
    injection_failure_EP = end_of_seh - MESSAGEBOXPAYLOAD_LEN - UNCONDITIONALJMPPAYLOAD_LEN
    injection_failure_payload = MessageBoxPayload(injection_failure_err_txt_addr,
                                                     err_caption_addr,
                                                     kind=MB_ICONERROR,
                                                     start_offset=injection_failure_EP,
                                                     pseudo="%s injection failure notification" %dll_name,
                                                      )
    ejection_failure_EP = injection_failure_EP - MESSAGEBOXPAYLOAD_LEN - UNCONDITIONALJMPPAYLOAD_LEN
    ejection_failure_payload = MessageBoxPayload(ejection_failure_err_txt_addr,
                                                     err_caption_addr,
                                                     kind=MB_ICONERROR,
                                                     start_offset=ejection_failure_EP,
                                                     pseudo="%s ejection failure notification" %dll_name,
                                                     )
    start_of_seh = ejection_failure_EP # SEH = Structured-Exception-Handling
    if dll_function:
        import_dll_function_failure_EP = start_of_seh - MESSAGEBOXPAYLOAD_LEN - UNCONDITIONALJMPPAYLOAD_LEN
        import_dll_function_failure_payload = MessageBoxPayload(import_dll_function_failure_err_txt_addr,
                                                                    err_caption_addr,
                                                                    kind=MB_ICONERROR,
                                                                    start_offset=import_dll_function_failure_EP,
                                                                    pseudo="%s API import failure notification" \
                                                                        %dll_function,
                                                                    )
        start_of_seh = import_dll_function_failure_EP
    # start: build tail of payload
    payload_tail = Payload(start_offset=start_of_seh)
    if dll_function:
        payload_tail.addPayload(import_dll_function_failure_payload)
        payload_tail.jmp(prolog)
    payload_tail.addPayload(ejection_failure_payload)
    payload_tail.jmp(prolog)
    payload_tail.addPayload(injection_failure_payload)
    payload_tail.jmp(prolog)
    if createremotethread:
        payload_tail.addPayload(freelibraryandexitthread_payload)
        payload_tail.jmp(prolog)
        payload_tail.addPayload(exitthread_payload)
    else:
        payload_tail.addPayload(freelibrary_payload)
        payload_tail.jmp(prolog)
        payload_tail.addBlockEntryTag("carrier thread epilog")
        payload_tail.popFd() # restore flags
        payload_tail.popAd() # restore all general-purpose registers
        payload_tail.ret()
        payload_tail.addBlockExitTag("carrier thread epilog")
    # end: build tail of payload
    # start: build body of payload
    if not createremotethread:
        payload.addBlockEntryTag("carrier thread prolog")
        payload.push(primary_thread_ctx.Eip) # save EIP
        payload.pushAd() # save all general-purpose registers
        payload.pushFd() # save flags (EFLAGS)
        payload.addBlockExitTag("carrier thread prolog")
    get_dll_handle_payload = GetModuleHandlePayload(dll_addr,
                                                        start_offset=payload.getCurrentOffset(),
                                                        pseudo="get %s handle" %dll_name,
                                                        )
    payload.addPayload(get_dll_handle_payload)
    payload.cmpEax(0x0)
    if eject:
        payload.jz(ejection_failure_EP)
        payload.saveEax(dll_addr)
        payload.jmp(unload_dll_EP)
    else:
        payload.jnz(payload.getCurrentOffset() + CONDITIONALJMPPAYLOAD_LEN + LOADLIBRARYPAYLOAD_LEN)
    load_dll_payload = LoadLibraryPayload(dll_addr,
                                              start_offset=payload.getCurrentOffset(),
                                              pseudo="load %s" %dll_name,
                                              )
    payload.addPayload(load_dll_payload)
    payload.cmpEax(0x0)
    payload.jz(injection_failure_EP)
    payload.saveEax(dll_addr)
    if dll_function: 
        import_dll_function_payload = GetProcAddressPayload(dll_addr,
                                                                dll_function_addr,
                                                                start_offset=payload.getCurrentOffset(),
                                                                pseudo="import %s API from %s" %(dll_function,dll_name),
                                                                )
        payload.addPayload(import_dll_function_payload)
        payload.cmpEax(0x0)
        payload.jz(import_dll_function_failure_EP)
        payload.saveEax(dll_function_addr)
        payload.addBlockExitTag("invoke %s(..)" %dll_function)
        if dll_function_args:
            l = len(dll_function_args)
            for j in xrange(l):
                payload.push(int(dll_function_args[l - j - 1]))
        payload.callByReference(dll_function_addr)
        payload.addBlockExitTag("invoke %s(..)" %dll_function)
    payload.jmp(prolog)
    payload.nopSled(start_of_seh - payload.getCurrentOffset())
    # end: build body of payload
    payload.addPayload(payload_tail)
    payload.display()
    printDebug("OK (payload EP = 0x%08X)." %EP)
    # sys.exit(0)
    # copy payload to remote code-cave dug earlier
    printDebug("Writing payload to code-cave in remote process ..")
    nb_bytes_written = DWORD(0)
    copy_OK = windll.kernel32.WriteProcessMemory(target_process_handle,
                                                 codecave_addr,
                                                 payload.getEgg(),
                                                 payload.getSize(),
                                                 byref(nb_bytes_written), 
                                                 )
    copy_OK = copy_OK and (nb_bytes_written.value == payload.getSize())
    if not copy_OK: # error-check
        printDebug("Error: windll.kernel32.WirteProcessMeMemory: couldn't copy payload to code-cave in remote process \
(windll.kernel32.GetLastError() = 0x%08X)." %windll.kernel32.GetLastError())
        sys.exit(1)
    printDebug("OK.")
    # start: deploy carrier thread
    if createremotethread:
        printDebug("Creating remote payload carrier thread in target process ..")
        carrier_tid = DWORD(0)
        carrier_thread_handle = windll.kernel32.CreateRemoteThread(target_process_handle,
                                                                   0,
                                                                   0,
                                                                   EP,
                                                                   0,
                                                                   0,
                                                                   byref(carrier_tid),
                                                                   )
        if not carrier_thread_handle: # error-check
            printDebug("Error: windll.kernel32.CreateRemoteThread: couldn't create remote thread \
(windll.kernel32.GetLastError() = 0x%08X)." %windll.kernel32.GetLastError())
            sys.exit(1)
        printDebug("OK (carrier thread ID = %d)." %carrier_tid.value)
        windll.kernel32.WaitForSingleObject(carrier_thread_handle, INFINITE)
    else:
        printDebug("Hijacking target process primary thread to execute payload ..")
        primary_thread_ctx.Eip = EP
        windll.kernel32.SetThreadContext(primary_thread_handle,
                                         byref(primary_thread_ctx),
                                         )
        windll.kernel32.ResumeThread(primary_thread_handle)
        windll.kernel32.WaitForSingleObject(primary_thread_handle, INFINITE)
        printDebug("OK.")
    # free code-cave
    printDebug("Freeing code-cave in target process ..")
    codecave_addr = windll.kernel32.VirtualFreeEx(target_process_handle,
                                                  codecave_addr,
                                                  CODECAVE_SIZE,
                                                  MEM_RELEASE
                                                  )
    printDebug("OK.")

if __name__ == "__main__":
    usage = "Usage: python %s [--eject] <target_proc_name_or_id> <dll_path> [--function <function_name> <function_arg1> \
<function_arg2> .. <function_argn>]\r\n" %sys.argv[0]
    usage += "\r\n+++Examples+++"
    usage += "\r\n[1] Eject evildll.dll from process with ID = 6408:\r\n\tpython %s 6408  evildll.dll --eject" \
        %sys.argv[0]
    usage += "\r\n[2] Inject pinballspy\Debug\pinballspy.dll into pinball process and then invoke TrapScore API on \
argument 0x010196BE:\r\n\tpython %s pinball pinballspy\Debug\pinballspy.dll --hijack-primary-thread --function \
TrapScore $(python -c \"print 0x010196BE\")" %sys.argv[0]
    parser = OptionParser(version=__FULL_VERSION__,
                          usage=usage,
                          )
    parser.add_option('--hijack-primary-thread',
                      dest='hijackprimarythread',
                      action='store_true',
                      default=False,
                      help="""hijack target process primary thread and use it as payload-carrier (by default, we'll \
create a brand-new payload-carrier thread)""",
                      )
    parser.add_option('--function',
                      dest='function',
                      default=None,
                      type=str,
                      help="""specify function to invoke once DLL is injected (by default, we expect all DLL's payload \
to be carried by its DLLMain)""",
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
    try:
        remote_pid = int(args[0])
    except ValueError:
        remote_pid = GetProcessIdFromName(args[0])
        if not remote_pid:
            print "Error: '%s' doesn't match any process name or ID." %args[0]
            sys.exit(1)
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
            parser.error("It doesn't make any sense to use the '--eject' and '--function' options together; use '--help' \
option for help")
    hack(remote_pid,
         dll_path,
         eject=options.eject,
         dll_function=options.function,
         dll_function_args=args[2:],
         createremotethread=not options.hijackprimarythread,
         )
