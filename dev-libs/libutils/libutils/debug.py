# This module implements handly FFIs for stuff like thread enumeration, etc.
# (c) half-jiffie (dohmatob elvis dopgima)
from ctypes import *
from libutils.constants import * 
import sys
import os

kernel32 = windll.kernel32

def GetPrimaryThreadId(dwOwnerId):
    """
    Returns ID main/primary thread in given process
    """
    dwMainThreadId = None
    for te32 in EnumThreads(dwOwnerId):
        # XXX search of appropriate thread using creationg time, etc., heuristics
        dwMainThreadId = te32.th32ThreadID
        break
    return dwMainThreadId
        
def GetProcessIdFromName(szProcName):
    pe32 = PROCESSENTRY32(0)
    pe32.dwSize = sizeof(PROCESSENTRY32)
    # take a snapshot of all running processes
    hProcSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hProcSnap == INVALID_HANDLE_VALUE:
        return
    # loop over all process structures
    if kernel32.Process32First(hProcSnap, byref(pe32)):
        while True:
            if os.path.basename(szProcName).lower() == pe32.szExeFile.rstrip(".exe").lower(): # filter
                kernel32.CloseHandle(hProcSnap)
                return pe32.th32ProcessID
            if not kernel32.Process32Next(hProcSnap, byref(pe32)):
                break
    kernel32.CloseHandle(hProcSnap)

def EnumThreads(dwOwnerId=None):
    """
    Yields a THREADENTRY32 objects generator for threads of the given process
    """
    if dwOwnerId is None:
        dwOwnerId = kernel32.GetCurrentProcessId()
    te32 = THREADENTRY32(0)
    te32.dwSize = sizeof(te32) # this is vital, please!
    # take a snapshot of all running threads
    hThreadSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if hThreadSnap == INVALID_HANDLE_VALUE:
        return
    # loop over all thread structures
    if kernel32.Thread32First(hThreadSnap, byref(te32)):
        while True:
            if te32.th32OwnerProcessID == dwOwnerId: # filter out only those that belong to dwOwnerId
                yield te32
            if not kernel32.Thread32Next(hThreadSnap, byref(te32)):
                break
    kernel32.CloseHandle(hThreadSnap) # sanity

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


