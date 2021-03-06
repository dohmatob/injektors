# win32api constants and data types
# (c) half-jiffie (dohmatob elvis dopgima)

from ctypes import *

# Fundamental win32api data types
BYTE = c_ubyte
PVOID = c_void_p
HANDLE   = c_void_p
LPVOID = c_void_p
WORD = c_ushort
DWORD = c_ulong # c_void_p
SIZE_T = c_ulong
LPDWORD = c_ulong

# Memory-related structures
class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture",    WORD),
        ("wReserved",                 WORD),
]

class SYSTEM_INFO_UNION(Union):
    _fields_ = [("dwOemId",    DWORD),
                ("sProcStruc", PROC_STRUCT),
]

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [("BaseAddress", PVOID),
                ("AllocationBase", PVOID),
                ("AllocationProtect", DWORD),
                ("RegionSize", SIZE_T),
                ("State", DWORD),
                ("Protect", DWORD),
                ("Type", DWORD),
                ]
    
class SYSTEM_INFO(Structure):
    _fields_ = [("uSysInfo", SYSTEM_INFO_UNION),
                ("dwPageSize", DWORD),
                ("lpMinimumApplicationAddress", LPVOID),
                ("lpMaximumApplicationAddress", LPVOID),
                ("dwActiveProcessorMask", DWORD),
                ("dwNumberOfProcessors", DWORD),
                ("dwProcessorType", DWORD),
                ("dwAllocationGranularity", DWORD),
                ("wProcessorLevel", WORD),
                ("wProcessorRevision", WORD),
]
    
# Memory-permission-related structures
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_READONLY = 0x02
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000

# Process/thread access
PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x001FFFFF
THREAD_GET_CONTEXT = 0x00000008
THREAD_SUSPEND_RESUME = 0x00000002
THREAD_SET_CONTEXT = 0x00000010
THREAD_QUERY_INFORMATION = 0x00000040

# Messagebox stuff
MB_OK = 0x00
MB_ICONINFORMATION = 0x40
MB_ICONERROR = 0x10

# Debugging
INFINITE = 0xFFFFFFFF
INVALID_HANDLE_VALUE = 0xFFFFFFFF
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPTHREAD = 0x00000004
CONTEXT_FULL = 0x00010007
CONTEXT_CONTROL = 0x00010001 

class THREADENTRY32(Structure):
    _fields_ = [("dwSize",             DWORD),
                ("cntUsage",           DWORD),
                ("th32ThreadID",       DWORD),
                ("th32OwnerProcessID", DWORD),
                ("tpBasePri",          DWORD),
                ("tpDeltaPri",         DWORD),
                ("dwFlags",            DWORD),
                ]

class PROCESSENTRY32(Structure):
    _fields_ = [( 'dwSize' , c_uint ) , 
                ( 'cntUsage' , c_uint) ,
                ( 'th32ProcessID' , c_uint) ,
                ( 'th32DefaultHeapID' , c_uint) ,
                ( 'th32ModuleID' , c_uint) ,
                ( 'cntThreads' , c_uint) ,
                ( 'th32ParentProcessID' , c_uint) ,
                ( 'pcPriClassBase' , c_long) ,
                ( 'dwFlags' , c_uint) ,
                ( 'szExeFile' , c_char * 260 ) , 
                ( 'th32MemoryBase' , c_long) ,
                ( 'th32AccessKey' , c_long ) ]

class FLOATING_SAVE_AREA(Structure):
   _fields_ = [
   
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
]

class CONTEXT(Structure):
    _fields_ = [    
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
]
