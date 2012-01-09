"""
(c) d0hm4t06 3. d0p91m4 (RUDEBOI) December 13, 2011 -BORDEAUX
"""

from ctypes import *
 
# Some pretty win32 constant macros
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PROCESS_ALL_ACCESS = 0x1F0FFF
INFINITE = 0xFFFFFFFF
INVALID_HANDLE_VALUE = 0xFFFFFFFF
TH32CS_SNAPTHREAD = 0x00000004
MB_OK = 0x00
MB_ICONINFORMATION = 0x40
MB_ICONERROR = 0x10

# Microsoft types
HANDLE   = c_void_p
LPVOID = c_void_p
DWORD = c_void_p
LPDWORD = c_ulong

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",             DWORD),
        ("cntUsage",           DWORD),
        ("th32ThreadID",       DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri",          DWORD),
        ("tpDeltaPri",         DWORD),
        ("dwFlags",            DWORD),
    ]
