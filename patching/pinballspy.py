"""
pinballspy.py: a tiny python script to spy on pinball game scores
technology: pydbg, libdebug, ctypes

By h4lf-jiffie (dohmatob elvis dopgima)
"""
from pydbg import *
from pydbg.defines import *
from libdebug.debug import *
import sys
from ctypes import * 
from libdebug.constants import *

pinball_signature = "\x01\x30\x8B\x10\x81\xFA\x00\xCA\x9A\x3B"
thread_ctx = CONTEXT()
thread_ctx.ContextFlags = CONTEXT_FULL # we own this thing!
previous_score = 0

def log(msg):
    print '[+] %s' %msg

def die(reason):
    log(reason)
    sys.exit(1)

def handler_breakpoint(pydbg):
    global previous_score
    # ignore the first windows driven breakpoint. # <-- if uncle PEDRAM thinks so, it must be so!
    if pydbg.first_breakpoint:
        return DBG_CONTINUE
    # log("bp hit from thread %d /@%08x" % (pydbg.dbg.dwThreadId, pydbg.exception_address))
    h = windll.kernel32.OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 
                                   0, 
                                   pydbg.dbg.dwThreadId,
                                   )
    windll.kernel32.SuspendThread(h)
    windll.kernel32.GetThreadContext(h, byref(thread_ctx))
    # by manipulating thread_ctx and committing, we could do really evil things here! No ?
    if (thread_ctx.Edx < previous_score):
        log("Game restarting ? New player ?")
    log('Current pinball score is %d' %thread_ctx.Edx)
    previous_score = thread_ctx.Edx
    windll.kernel32.ResumeThread(h)
    windll.kernel32.CloseHandle(h)
    return DBG_CONTINUE
    
if __name__ == '__main__':
    debugger = pydbg()
    # register a breakpoint handler function.
    debugger.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)
    log("Obtaining pinball PID ..")
    pinball_pid = GetProcessIdFromName('pinball')
    if not pinball_pid:
        die("Error: couldn't get pinball PID (is pinball even running ?).")
    log("OK.")
    log("Searching for characteristic '%s' signature in pinball process memory .."%pinball_signature)
    pinball_handle = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, 
                                                 0, 
                                                 pinball_pid,
                                                 )
    if not pinball_handle:
        die("Error: couldn't obtain handle to pinball process.")
    results = FindSignatureInProcessMemory(pinball_handle,
                                           pinball_signature,
                                           )
    try:
        grail = results.next() + 4  # address of \x08\x1F\xA0\x0CA\x9A\x3B (i.e cmp edx, 3B91CA00)
        try:
            results.next()
            die("Error: oops! found characteristic signature at multiple address in pinball process memory; aborting ..")
        except StopIteration:
            pass
    except StopIteration:
        die("Error: oops! couldn't find characteristic signature in pinball process (this is strange!); aborting ..\n")
    log("OK (Found signature at 0x%08X)." %grail)
    log("Attaching to pinball process ..")
    debugger.attach(pinball_pid)
    log("OK.")
    log("Setting bp at 0x%08X .."%grail)
    debugger.bp_set(grail)
    log("OK.")
    log("Starting DEBUG_EVENT loop ..")
    debugger.debug_event_loop()
