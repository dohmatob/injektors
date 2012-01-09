# This module implements handly FFIs for stuff like thread enumeration, etc.
# (c) half-jiffie (dohmatob elvis dopgima)
from ctypes import *
from libshellcode.constants import * 
import sys

kernel32 = windll.kernel32

def EnumThreads(dwOwnerId=None):
    """
    Yields a generator of THREADENTRY32 objects for threads of the given process
    """
    if dwOwnerId is None:
        dwOwnerId = kernel32.GetCurrentProcessId()
    te32 = THREADENTRY32(0)
    te32.dwSize = sizeof(te32) # this is vital, please!
    # take a snapshot of all running threads
    hThreadSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if hThreadSnap == INVALID_HANDLE_VALUE:
        return
    # retrieve first thread entry; if gabbage then no return NIL
    if not kernel32.Thread32First(hThreadSnap, byref(te32)):
        return
    if te32.th32OwnerProcessID == dwOwnerId: # we are only interested in threads in dwOwernerId 
        yield te32 # yield, don't <<return>> !
    # walk the rest of the thread entries
    while kernel32.Thread32Next(hThreadSnap, byref(te32)):
        if te32.th32OwnerProcessID == dwOwnerId: # filter out only those that belong to dwOwnerId
            yield te32
    CloseHandle(hThreadSnap) # sanity
    

if __name__ == '__main__':
    print "[EnumThreads DEMO] Enumerating threads in process .."
    if len(sys.argv) > 1:
        te32_generator = EnumThreads(int(sys.argv[1]))
    else:
        te32_generator = EnumThreads()
    dwNbThreads = 0
    if not te32_generator is None:
        for te32 in te32_generator:
            dwNbThreads += 1
            print "\tTHREAD ID     = %d" %te32.th32ThreadID
            print "\tBASE PRIORITY = %d" %te32.tpBasePri
    
    print "[EnumThreads DEMO] Total thread count = %d" %dwNbThreads


