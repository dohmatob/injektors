# This module implements handly FFIs for stuff like thread enumeration, etc.
# (c) half-jiffie (dohmatob elvis dopgima)
from ctypes import *
from libutils.constants import * 
import sys
import os

__AUTHOR__ = 'd0hm4t06 3. d0p91m4 (half-jiffie)'
__VERSION__ = '1.0dev'
__FULL_VERSION__ = '%s version %s: a module for doing exporting routine facilities like thread/process enumeration, primary-thread obtention\r\n(c) %s' %(os.path.basename(sys.argv[0]),__VERSION__,__AUTHOR__)

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
        
def EnumProcesses():
    """
    Yields a PROCESSENTRY32 objects generator for all running processes
    """
    pe32 = PROCESSENTRY32(0)
    pe32.dwSize = sizeof(PROCESSENTRY32)
    # take a snapshot of all running processes
    hProcSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hProcSnap == INVALID_HANDLE_VALUE:
        return
    # loop over all process structures
    if kernel32.Process32First(hProcSnap, byref(pe32)):
        while True:
            yield pe32
            if not kernel32.Process32Next(hProcSnap, byref(pe32)):
                break
    kernel32.CloseHandle(hProcSnap) # sanity
    
def GetProcessIdFromName(szProcName):
    for pe32 in EnumProcesses():
        if os.path.basename(szProcName).lower() == pe32.szExeFile.rstrip(".exe").lower(): # filter
            return pe32.th32ProcessID
        
def EnumThreads(dwOwnerId):
    """
    Yields a THREADENTRY32 objects generator for threads of the given process
    """
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
    from optparse import OptionParser
    parser = OptionParser(version=__FULL_VERSION__)
    parser.add_option('--enumerate-process-threads',
                      dest='enumerateprocessthreads',
                      action='store_true',
                      default=False,
                      help="""enumerate all threads of a given process""",
                      )
    parser.add_option('--get-primary-thread-id',
                      dest='getprimarythreadid',
                      action='store_true',
                      default=False,
                      help="""get primary thread ID for given process""",
                      )
    parser.add_option('--enumerate-all-processes',
                      dest='enumerateallprocesses',
                      action='store_true',
                      default=True,
                      help="""enumerate all running processes""",
                      )
    options, args = parser.parse_args()
    if options.enumerateallprocesses:
        print "Enumerating all running processes ..3"
        dwProcesses = 0
        for pe32 in EnumProcesses():
            print "\tPROCESS ID  : %d" %pe32.th32ProcessID
            print "\tPROCESS NAME: %s" %pe32.szExeFile
            dwProcesses = dwProcesses + 1
        print "OK (%d processes)." %dwProcesses
    if options.enumerateprocessthreads:
        if not args:
            print "Error: --enumerate-proess-threads needs the process ID/name as argument"
            sys.exit(1)
        try:
            dwOwnerId = int(args[0])
        except ValueError:
            dwOwnerId = GetProcessIdFromName(args[0])
            if not dwOwnerId:
                print "Error: no process associated with ID/name: %s" %args[0]
                sys.exit(1)
        print "Enumerating threads in process (process ID = %d) .." %dwOwnerId
        dwNbThreads = 0
        for te32 in EnumThreads(dwOwnerId):
            dwNbThreads += 1
            print "\tTHREAD ID    : %d" %te32.th32ThreadID
            print "\tBase Priority: %d" %te32.tpBasePri
            print "OK (Total thread count = %d)." %dwNbThreads
        if dwNbThreads and options.getprimarythreadid:
            print "PRIMARY THREAD ID: %d" %GetPrimaryThreadId(dwOwnerId)
            


