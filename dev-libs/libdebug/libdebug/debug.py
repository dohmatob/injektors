"""
This module implements handy win32 FFIs (Foreign-Function Interfaces) for stuff like thread enumeration,
memory walking, etc.

(c) half-jiffie (dohmatob elvis dopgima)
"""
from ctypes import *
from constants import * 
import sys
import os
import re
import struct

__AUTHOR__ = 'd0hm4t06 3. d0p91m4 (half-jiffie)'
__VERSION__ = '1.0dev'
__FULL_VERSION__ = '%s version %s: a module exporting routine facilities like thread/process enumeration, primary-thread \
obtention\r\n(c) %s' %(os.path.basename(sys.argv[0]),__VERSION__,__AUTHOR__)

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

def FindSignatureInProcessMemory(hProcess, 
                                 pSignature, # sought-for signature, a character-string/buffer
                                 isBadMbi=None, # filter for MBIs to avoid
                                 isBadAddress=None, # fiter for hit addresses to avoid
                                 lower=None,        # don't search before this point
                                 upper=None,        # don't search behond this point
                                 ):
    """
    Passively scrapes a given process's memory, looking for specified signature (string of bytes)
    """
    
    # grab process handle
    if not hProcess:
        return # XXX This is not enough; raise exception or something similar
    
    # initialize variables
    mbi = MEMORY_BASIC_INFORMATION()
    si = SYSTEM_INFO(SYSTEM_INFO_UNION(0))  # we'll need to know the system page size, etc.
    dwOldProtection = DWORD()  # we'll be tweaking page protections
    windll.kernel32.GetSystemInfo(byref(si))
    dwSignature = len(pSignature)
    pattern = re.compile(pSignature) # RE engine for sought-for pSignature
    pBytesRead = create_string_buffer(si.dwPageSize) # create a character-buffer as large as a system page
    dwBytesRead = DWORD()
    lower_bound = si.lpMinimumApplicationAddress
    upper_bound = si.lpMaximumApplicationAddress
    if not lower is None:
        lower_bound = max(lower_bound, lower)
    if not upper is None:
        upper_bound = min(upper_bound, upper)
    
    # scrape
    dwRegionOffset = lower_bound # start searching here
    while dwRegionOffset < upper_bound:
        windll.kernel32.VirtualQueryEx(hProcess,
                                       dwRegionOffset,
                                       byref(mbi),
                                       sizeof(MEMORY_BASIC_INFORMATION),
                                       )
        if not isBadMbi is None:
            if isBadMbi(mbi):
                dwRegionOffset = dwRegionOffset + mbi.RegionSize
            continue # barren; move-on to next region
        
        # scrape current memory region in si.dwPageSize-byte blocks.
        # XXX BTW, my assumption is that regions are always multiples of the system page size --No?
        for dwBlockOffset in xrange(dwRegionOffset, dwRegionOffset + mbi.RegionSize, si.dwPageSize):
            if not windll.kernel32.VirtualProtectEx(hProcess,
                                                    dwBlockOffset,
                                                    si.dwPageSize,
                                                    PAGE_READWRITE,
                                                    byref(dwOldProtection),
                                                    ):
                continue # barren; move-on to next block
            read_OK = windll.kernel32.ReadProcessMemory(hProcess,
                                                        dwBlockOffset,
                                                        pBytesRead,
                                                        si.dwPageSize,
                                                        byref(dwBytesRead),
                                                        )
            windll.kernel32.VirtualProtectEx(hProcess,
                                             dwBlockOffset,
                                             si.dwPageSize,
                                             dwOldProtection,
                                             byref(dwOldProtection),
                                             ) # restore protections
            read_OK = read_OK and (dwBytesRead.value == si.dwPageSize)
            if not read_OK:
                continue # barren; move-on to next block
            
            # finally (sighs!), we've managed to scrape something: search for'll occurences of sought-for signature
            for item in pattern.finditer(pBytesRead):
                hit = item.start() + dwBlockOffset
                if not isBadAddress is None:
                    if isBadAddress(hit):
                        continue
                yield hit
                
        # continue
        dwRegionOffset = dwRegionOffset + mbi.RegionSize # move-on to next block
        
    # sanity
    windll.kernel32.CloseHandle(hProcess) 

def FindDwordInProcessMemory(hProcess, 
                             dwValue,
                             ):
    """
    Finds a DWORD value (e.g. a game score, etc.) in a process's memory
    """
    def DonnotSearchHere(mbi):
        return mbi.Protect in [PAGE_GUARD, # certainly barren
                               PAGE_EXECUTE_READ, # the value must be written by somebody, somehow
                               PAGE_NOACCESS, # certainly barren
                               PAGE_READONLY, # the value muorst be written by somebody, somehow
                               ]
    pSignature = struct.pack('<i', # XXX windows uses little-endian (No?)
                             dwValue,
                             )
    return FindSignatureInProcessMemory(hProcess,
                                        pSignature,
                                        BadMbiFilter=DonnotSearchHere,
                                        )

def FindSignatureInBinaryFile(filename,
                              byte_seq,
                              isBadAddress=None,
                              ):
    """
    Passively scrapes a specified program (PE binary file), looking for a specified signature (string of bytes)
    """
    try:
        import pefile
    except ImportError:
        print "[+] Error: FindSignatureInBinaryFile: you don't have pefile installed on your python path; \
this feature won't work"
        sys.exit(1)
    pe_obj = pefile.PE(filename) 
    for item in re.finditer(byte_seq,
                            pe_obj.get_memory_mapped_image(), 
                            ):
        hit = item.start() + pe_obj.OPTIONAL_HEADER.ImageBase
        if not isBadAddress is None:
            if isBadAddress(hit):
                continue
        yield 
                    
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
            print "\tPARENT ID   : %d" %pe32.th32ParentProcessID
            print "\tPROCESS NAME: %s" %pe32.szExeFile
            print "\tTHREAD COUNT: %d" %pe32.cntThreads
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


