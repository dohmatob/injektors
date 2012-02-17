"""
pinballspy.py: a tiny python script to spy on pinball game scores
technology: pydbg, libdebug, ctypes

By h4lf-jiffie (dohmatob elvis dopgima)
"""
from ctypes import *
from libdebug.debug import GetProcessIdFromName, FindSignatureInProcessMemory
from pydbg import *
from pydbg.defines import *
import sys

pinball_signature = "\x01\x30\x8B\x10\x81\xFA\x00\xCA\x9A\x3B"
previous_score = 0

def log_debug(msg):
    print '[+] %s' %msg

def die(reason):
    log_debug(reason)
    sys.exit(1)

def handler_breakpoint(pydebugger):
    global previous_score
    # ignore the first windows driven breakpoint. # <-- if uncle PEDRAM thinks so, it must be so!
    if pydebugger.first_breakpoint:
        return DBG_CONTINUE

    # at this point, the EDX register of the debuggee's current thread's context contains the current pinball score! 
    if (pydebugger.context.Edx < previous_score):
        log_debug("Game restarting ? New player ?")
    log_debug('Current pinball score is %d' %pydebugger.context.Edx)
    previous_score = pydebugger.context.Edx
    return DBG_CONTINUE
    
if __name__ == '__main__':
    # instantiate debugger
    debugger = pydbg()

    # register a breakpoint handler function
    debugger.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

    # obtain pid to pinball process
    log_debug("Obtaining pinball PID ..")
    pinball_pid = None
    for pid, name in debugger.enumerate_processes():
        if name.lower() == 'pinball.exe':
            pinball_pid = pid
            break
    if pinball_pid is None:
        log_debug("Error: couldn't get pinball PID (is pinball even running? If so, tell me its PID).")
        pinball_pid = int(raw_input("[+] Enter pinball PID: "))
    log_debug("OK (pinball PID = %d)."%pinball_pid)

    # search signature in process image
    log_debug("Searching for characteristic '%s' signature in pinball process memory .."%pinball_signature)
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
    log_debug("OK (Found signature at 0x%08X)." %(grail - 4))

    # hack
    log_debug("Attaching to pinball process ..")
    debugger.attach(pinball_pid)
    log_debug("OK.")
    log_debug("Setting bp at 0x%08X .."%grail)
    debugger.bp_set(grail)
    log_debug("OK.")
    log_debug("Starting DEBUG_EVENT loop ..")
    debugger.debug_event_loop()
