"""
(c) d0hm4t06 3. d0p91m4 (RUDEBOI) December 13, 2011 -BORDEAUX
"""

import time
import sys
from ctypes import windll, byref
from constants import *

kernel32 = windll.kernel32

def pretty_time():
    t = time.ctime()
    t = t.split(' ')
    if '' in t:
        t.remove('')
    return t[3], '-'.join([t[0],t[2],t[1],t[4]])

def debug(msg):
    print "[*] %s" %msg

def die(reason):
    debug(reason)
    sys.exit(0)

def getRemoteProcessHandle(remote_pid):
    return kernel32.OpenProcess(PROCESS_ALL_ACCESS,
                                0,
                                int(remote_pid),
                                )

def allocateCodecaveInRemoteProcess(remote_process_handle,
                                       size,
                                       ):
    return kernel32.VirtualAllocEx(remote_process_handle,
                                   0,
                                   size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE,
                                   )

def freeCodecaveInRemoteProcess(remote_process_handle,
                                            start_addr,
                                            size,
                                            ):
    return kernel32.VirtualFreeEx(remote_process_handle,
                                  start_addr,
                                  size,
                                  MEM_RELEASE,
                                  )

def writeRemoteProcessAddressSpace(remote_process_handle,
                                       start_addr,
                                       data,
                                       ):
    """
    Will write data to remote process address space starting from start_address
    """
    nb_bytes_to_write = len(data)
    nb_bytes_written = DWORD(0)
    success = kernel32.WriteProcessMemory(remote_process_handle,
                                       start_addr,
                                       data,
                                       nb_bytes_to_write,
                                       byref(nb_bytes_written),
                                       )
    if nb_bytes_written.value < nb_bytes_to_write:
        return False # no everything written !
    kernel32.FlushInstructionCache(remote_process_handle,
                                   start_addr,
                                   nb_bytes_to_write,
                                   )
    return success

def fireupShellcodeInRemoteProcess(remote_process_handle,
                                   shellcode_entry_point,
                                   ):
    remote_tid = DWORD(0)
    remote_thread_handle = kernel32.CreateRemoteThread(remote_process_handle,
                                                       0,
                                                       0,
                                                       shellcode_entry_point,
                                                       0,
                                                       0,
                                                       byref(remote_tid),
                                                       )
    if remote_thread_handle:
        """
        join remote thread
        """
        kernel32.WaitForSingleObject(remote_thread_handle,
                                     INFINITE,
                                     )
    return remote_thread_handle, remote_tid.value
                                       
