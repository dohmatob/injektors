"""
A tiny python command-line script/module for dll-injection-related business

(c) h4lf-jiffie (dohmatob elvis dopgima)
"""

import unittest
import struct
from ctypes import *
import sys
import os
from optparse import OptionParser
from libdebug.constants import *

__AUTHOR__ = "by h4lf-j1ff13 (dohmatob elvis dopgima)"
__VERSION__ = "%s %s %s %s"%("+"*13,os.path.basename(sys.argv[0]),__AUTHOR__,"+"*13)

# exported constants
CMPEAXPAYLOAD_LEN = 5
MESSAGEBOXPAYLOAD_LEN = 21
EXITTHREADPAYLOAD_LEN = 9
LOADLIBRARYPAYLOAD_LEN = 12
FREELIBRARYPAYLOAD_LEN = 13
FREELIBRARYANDEXITTHREADPAYLOAD_LEN = 15
GETPROCADDRESSPAYLOAD_LEN = 18
UNCONDITIONALJMPPAYLOAD_LEN = 5
CONDITIONALJMPPAYLOAD_LEN = 6

# position-independent (unrebased) APIs
kernel32dll_handle = windll.kernel32.GetModuleHandleA("kernel32.dll")
user32dll_handle = windll.kernel32.GetModuleHandleA("user32.dll")
WINAPI = dict()
for api_name in ["ExitThread",
                 "FreeLibraryAndExitThread",
                 "FreeLibrary",
                 "LoadLibraryA",
                 "GetModuleHandleA",
                 "GetProcAddress",
                 "Sleep",
                 "SleepEx",
                 "WinExec"
                 ]:
    WINAPI[api_name] = windll.kernel32.GetProcAddress(kernel32dll_handle,
                                                      api_name,
                                                      )
for api_name in ["MessageBoxA",
                 ]:
    WINAPI[api_name] = windll.kernel32.GetProcAddress(user32dll_handle,
                                                      api_name,
                                                      )

class AsmInstruction:
    def __init__(self):
        self._offset = 0
        self._mnemonic = "NOP"
        self._payload = "\x90"
    
    def get_offset(self):
        return self._offset
    
    def get_size(self):
        return len(self._payload)
        
    def get_payload(self):
        return self._payload
    
    def set_offset(self, offset):
        self._offset = offset
        
    def set_payload(self, payload):
        self._payload = payload
        
    def set_mnemonic(self, mnemonic):
        self._mnemonic = mnemonic
        
    def get_mnemonic(self):
        return self._mnemonic
    
    def __str__(self):
        if self.get_size() > 6:
            return "%08X: "%self._offset + " "*18 + self._mnemonic
        else:
            return "%08X: %18s%s"%(self._offset, ''.join(['%02X '%ord(byte) for byte in self._payload]),self._mnemonic)
        
        
class AnInstanceOfAsmInstructionShould(unittest.TestCase):
    def setUp(self):
        self._ai = AsmInstruction()
        
    def testBeNopIfNotPrecised(self):
        self.assertEqual(self._ai.get_payload(), "\x90")
        
    def testShouldAllowItsGadgetToBeSet(self):
        self._ai.set_payload("\xFF\xD0")
        self.assertEqual(self._ai.get_payload(), "\xFF\xD0")
        
    def testHaveAMnemonic(self):
        self.assertEqual(self._ai.get_mnemonic(), "NOP")
        self._ai.set_mnemonic("x86 NOP")
        self.assertEqual(self._ai.get_mnemonic(), "x86 NOP")
        
    def testHaveANiceStringRepresentationIfNop(self):
        self.assertEqual(str(self._ai), "00000000:                90 NOP")
        
    def testHaveNiceStringRepesentionIF5ByteGadget(self):
        self._ai.set_payload("\xE9\xEA\xBE\xAD\xDE")
        self._ai.set_mnemonic("JMP 0xDEADBEEF")
        self.assertEqual(str(self._ai), "00000000:    E9 EA BE AD DE JMP 0xDEADBEEF")
        
        
class Gadget:
    def __init__(self,
                 start_offset=0,
                 max_size=None,
                 mnemonic=None,
                 ):
        self._start_offset = start_offset
        self._max_size = max_size
        self._mnemonic = mnemonic
        self._offset = start_offset
        self._ep = start_offset
        self._payload = ""
        self._ais = dict()
        self._offsets = list()
        self._pretty_string = ""
        
    def get_offset(self):
        """
        @returns:  current offset of payload
        """
        return self._offset
    
    def get_ep(self):
        """
        @returns: the entry-point
        """
        return self._ep
    
    def set_ep(self, offset=None):
        """
        @description: sets the entry-point to given value
        @returns: True if successful, False otherwise
        """
        if offset is None:
            self._ep = self._offset
        else:
            if offset in self._offsets:
                self._ep = offset
            else: # such an ep would land us right in the middle of an instruction; w'd crash the target for sure!
                return False
        return True
    
    def get_offsets(self):
        """
        @returns:  the (ordered) offsets of (the instructions in) this gadget
        """
        return self._offsets
    
    def get_mnemonic(self):
        """
        @returns: the mnemonic of this gadget
        """
        return self._mnemonic
    
    def get_size(self):
        """
        @returns:  size of payload buffer
        """
        return len(self._payload)
    
    def get_max_size(self):
        """
        @returns: the max-size gadget may attain
        """
        return self._max_size
    
    def get_start_offset(self):
        """
        @returns:  start offset of payload
        """
        return self._start_offset
    
    def get_payload(self):
        """
        @returns:  payload buffer
        """
        return self._payload
        
    def packed_dword(self, dword):
        return struct.pack('<I', dword)
        
    def packed_byte(self, byte):
        return struct.pack('B', byte)
    
    def commit_ai(self, ai, append_mnemonic=True,):
        """
        @description: commits a new assembly instruction at current offset of payload
        @returns:  returns the offset where the instruction starts
        """
        offset = self.get_offset()
        self._offsets.append(offset)
        ai.set_offset(offset)
        self._ais[offset] = ai
        self._payload += ai.get_payload()
        self._offset += ai.get_size()
        if append_mnemonic:
            self._pretty_string += "\t\t%s\n"%str(ai)
        if not self.get_max_size() is None:
            if self.get_size() > self.get_max_size():
                self.display()
                assert False, "Oops! gadget has overflowed by %d bytes; max size was set to %d."%(
                    self.get_size() - self.get_max_size(), self.get_max_size())
        return offset
        
    def db(self, string_token):
        """
        @description: appends a string token to payload 
        """
        ai = AsmInstruction()
        ai.set_mnemonic('DB "%s",0'%string_token)
        ai.set_payload(string_token + '\x00')
        return self.commit_ai(ai)
    
    def call_eax(self):
        """
        @description: commits a 'call eax' instruction 
        """
        ai = AsmInstruction()
        ai.set_mnemonic("CALL EAX")
        ai.set_payload("\xFF\xD0")
        return self.commit_ai(ai)
        
    def nop(self):
        """
        @description: commits a 'NOP' instruction 
        """
        ai = AsmInstruction()
        return self.commit_ai(ai)
        
    def ret(self):
        """
        @description: commits a 'RET' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("RET")
        ai.set_payload("\xC3")
        return self.commit_ai(ai)
        
    def int3(self):
        """
        @description: commits an 'INT3' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("INT3")
        ai.set_payload("\xCC")
        return self.commit_ai(ai)
        
    def nop_sled(self, n):
        """
        @description: commits an n-byte NOP-sled at current payload offset
        """
        for z in xrange(n):
            self.nop()
            
    def cmp_eax(self, val):
        """
        @description: commits a 'cmp eax, val' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic('CMP EAX, 0x%0X'%val)
        ai.set_payload("\x3D" + self.packed_dword(val))
        return self.commit_ai(ai)
        
    def push(self, val):
        """
        @description: commits a 'push val' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("PUSH 0x%0X"%val)
        if 0 <= val <= 0xFF:
            payload = '\x6A' + self.packed_byte(val)
        else:
            payload = '\x68' + self.packed_dword(val)
        ai.set_payload(payload)
        return self.commit_ai(ai)
        
    def push_content(self, addr):
        """
        push the content of and address: @description: commits a 'push [addr]' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("PUSH DWORD PTR DS:[0x%0X]"%addr)
        ai.set_payload('\xFF\x35' + self.packed_dword(addr))
        return self.commit_ai(ai)
        
    def mov_to_eax(self, val):
        """
        @description: commits a 'mov eax, val' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic('MOV EAX, 0x%0X'%val)
        ai.set_payload("\xB8" + self.packed_dword(val))
        return self.commit_ai(ai)
        
    def mov_to_ebx(self, val):
        """
        @description: commits a 'mov ebx, val' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic('MOV EBX, 0x%0X'%val)
        ai.set_payload("\xBB" + self.packed_dword(val))
        return self.commit_ai(ai)
        
    def mov_content_to_eax(self, addr):
        """
        @description: commits "MOV EAX, [addr]" instruction, which derefences addr into eax register
        """
        ai = AsmInstruction()
        ai.set_mnemonic('MOV EAX, DWORD PTR DS:[%08X]'%addr)
        ai.set_payload("\xA1" + self.packed_dword(addr))
        return self.commit_ai(ai)
        
    def mov_eax_to_addr(self, addr):
        """
        @description: commits a 'mov [addr], eax' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic('MOV DWORD PTR DS:[%08X], EAX'%addr)
        ai.set_payload("\xA3" + self.packed_dword(addr))
        return self.commit_ai(ai)
        
    def jne(self, offset):
        """
        @description: commits a 'jne offset' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic('JNE 0x%0X'%offset)
        delta = offset - self.get_offset() - CONDITIONALJMPPAYLOAD_LEN
        if delta < 0:
             delta = delta + 1
        ai.set_payload('\x0F\x85' + self.packed_dword(delta % 0xFFFFFFFF))
        return self.commit_ai(ai)
        
    def je(self, offset):
       """
       @description: commits a 'je offset' instruction
       """
       ai = AsmInstruction()
       ai.set_mnemonic('JE 0x%0X'%offset)
       delta = offset - self.get_offset() - CONDITIONALJMPPAYLOAD_LEN
       if delta < 0:
            delta = delta + 1
       ai.set_payload('\x0F\x84' + self.packed_dword(delta % 0xFFFFFFFF))
       return self.commit_ai(ai)
       
    def jmp(self, offset):
       """
       @description: commits a 'jmp offset' instruction
       """
       ai = AsmInstruction()
       ai.set_mnemonic('JMP 0x%0X'%offset)
       delta = offset - self.get_offset() - UNCONDITIONALJMPPAYLOAD_LEN
       if delta < 0:
             delta = delta + 1
       ai.set_payload('\xE9' + self.packed_dword(delta % 0xFFFFFFFF))
       return self.commit_ai(ai)
     
    def push_ebx(self):
        """
        @description: commits an 'PUSH EBX' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("PUSH EBX")
        ai.set_payload("\x53")
        return self.commit_ai(ai)
        
    def pushad(self):
        """
        @description: commits an 'PUSHAD' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("PUSHAD")
        ai.set_payload("\x60")
        return self.commit_ai(ai)
        
    def pushfd(self):
        """
        @description: commits an 'PUSHFD' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("PUSHFD")
        ai.set_payload("\x9C")
        return self.commit_ai(ai)
        
    def push_eax(self):
        """
        @description: commits an 'PUSH EAX' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("PUSH EAX")
        ai.set_payload("\x50")
        return self.commit_ai(ai)
      
    def pop_eax(self):
        """
        @description: commits an 'POP EAX' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("POP EAX")
        ai.set_payload("\x58")
        return self.commit_ai(ai)
        
    def popfd(self):
        """
        @description: commits an 'POPFD' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("POPFD")
        ai.set_payload("\x9D")
        return self.commit_ai(ai)
        
    def popad(self):
        """
        @description: commits an 'POPAD' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic("POPAD")
        ai.set_payload("\x61")
        return self.commit_ai(ai)
        
    def call(self, offset):
        """
        @description: commits a 'call offset' instruction
        """
        self.mov_to_eax(offset)
        self.call_eax()

    def call_by_value(self, offset):
        """
        an alias for self.call method
        """
        self.call(offset)

    def call_by_reference(self, offset_ptr):
        """
        calls an offset pointer (jump tables ?): @description: commits a 'mov eax, [offset_prt], call eax' instruction sequence
        """
        self.mov_content_to_eax(offset_ptr)
        self.call_eax()
        
    def get_ai(self, offset):
        """
        @returns:  the asm instruction at a specified offset
        """
        return self._ais[offset]

    def commit_gadget(self, gadget):
        """
        @description: commits another gadget to this instance
        @returns: the offset where the gadget starts and its size too
        """
        if gadget.get_start_offset() != self._offset:
            return
        self._pretty_string += str(gadget) + '\n'
        for offset in gadget.get_offsets():
            self.commit_ai(gadget.get_ai(offset), append_mnemonic=False,)
        if not self.get_max_size() is None:
            if self.get_size() > self.get_max_size():
                self.display()
                assert False, "Oops! gadget has overflowed by %d bytes; max size was set to %d."%(
                    self.get_size() - self.get_max_size(), self.get_max_size())
        return gadget.get_start_offset(), gadget.get_size()
        
    def get_eip(self):
       """
       @description: uses fnstenv-technique (http://www.phrack.org/issues.html?id=7&issue=62)
                     to obtain self._offset (eip); ecx then contains the stuff
       """
       ai = AsmInstruction()
       ai.set_mnemonic("FLDZ")
       ai.set_payload("\xD9\xEE")
       self.commit_ai(ai)
       
       ai.set_mnemonic("fnstenv [esp-C]")
       ai.set_payload("\xD9\x74\x24\xF4")
       self.commit_ai(ai)
       
       ai.set_mnemonic("POP ECX")
       ai.set_payload("\x59")
       self.commit_ai(ai)
       
       ai.set_mnemonic("ADD CL, 0A")
       ai.set_payload("\x80\xC1\x0A")
       self.commit_ai(ai)
       
       self.nop()
       
       self.set_ep()
       
    def push_offset(self, offset):
        ai = AsmInstruction()
        ai.set_mnemonic("MOV EAX, ECX")
        ai.set_payload("\x8B\xC1")
        self.commit_ai(ai)
        
        delta = self.get_ep() - offset
        ai.set_payload("\x83\xEB" + self.packed_dword(delta))
        ai.set_mnemonic("SUB EAX, 0%X"%delta)
        self.commit_ai(ai)
        
        self.push_eax()
        
    def jne_skip_stub(self, stub):
        """
        @description: commits stub, and then jumps to offset just after stub if ZF is not set
        """
        offset_just_after_stub = self.get_offset() # we're here
        offset_just_after_stub += stub.get_size() # correction due to stub code
        offset_just_after_stub += CONDITIONALJMPPAYLOAD_LEN # correction due to 'jne' instruction itself
        gadget.jne(offset_just_after_stub) # skip stub code is ZF is 0
        gadget.commit_gadget(stub) # hey! this is the stub code
        
    def je_skip_stub(self, stub):
        """
        @description: commits stub, and then jumps to offset just after stub if ZF is set
        """
        offset_just_after_stub = self.get_offset() # we're here
        offset_just_after_stub += stub.get_size() # correction due stub code
        offset_just_after_stub += CONDITIONALJMPPAYLOAD_LEN # correction due to 'je' instruction itself
        gadget.je(offset_just_after_stub) # skip sub code if ZF is 1
        gadget.commit_gadget(stub) # hey! this is the stub code :)
        
    def jmp_skip_stub(self, stub):
        """
        @description: commits stub, and then jumps to offset just after stub
        """
        offset_just_after_stub = self.get_offset() # we're here
        offset_just_after_stub += stub.get_size() # correction due to stub code
        offset_just_after_stub += UNCONDITIONALJMPPAYLOAD_LEN # correction due to 'jmp' instruction itself
        gadget.jmp(offset_just_after_stub) # skip sub code
        gadget.commit_gadget(stub) # hey! this is the stub code :)
      
    def __str__(self):
        """
        @returns:  instance as a mnemonic string
        """
        if not self._mnemonic is None:
            self._pretty_string = '\t\t->| BEGIN "%s"\n%s\t\t|<- END   "%s"'%(self._mnemonic,
                                                                             self._pretty_string,self._mnemonic)
        return self._pretty_string
        
    def display(self):
        """
        displays instance as a pretty-string
        """
        print '\t\tGADGET (entry-point at 0x%08X):\n%s'%(self._ep,str(self))
        opcodes = ""
        for j in xrange(self.get_size()):
            byte = self._payload[j]
            if j % 12 == 0:
                opcodes += "\n\t\t\t"
            opcodes += r"\x%02X"%ord(byte)
        print "\n\t\tPAYLOAD (%d bytes):%s\n"%(self.get_size(),opcodes,)
        
 
class SleepExGadget(Gadget):
    """
    gadget for invoking kenel32!SleepEx API
    """
    def __init__(self,
                 dwMilliseconds,
                 bAlertable=1,
                 start_offset=0,
                 mnemonic="invoke kernel32.dll!SleepEx",
                 ):
        Gadget.__init__(self, start_offset=start_offset, mnemonic=mnemonic)
        self.push(bAlertable)
        self.push(dwMilliseconds)
        self.call(WINAPI["SleepEx"])
        
        
class ExitThreadGadget(Gadget):
    """
    gadget for invoking kernel32.dll!ExitThread API
    """
    def __init__(self,
                dwExitCode=0,
                start_offset=0,
                mnemonic="invoke kernel32.dll!ExitThread"
                ):
        Gadget.__init__(self, start_offset=start_offset, mnemonic=mnemonic)
        self.push(dwExitCode)
        self.call(WINAPI["ExitThread"])
        
        
class FreeLibraryAndExitThreadGadget(Gadget):
    """
    gadget for invoking kernel32.dll!FreeLibraryAndExitThread API
    """
    def __init__(self,
                 dll_handle, # dll handle in target process
                 start_offset=0,
                 mnemonic='invoke kernel32.dll!FreeLibraryAndExitThread',
                 ):
        Gadget.__init__(self, start_offset=start_offset, mnemonic=mnemonic)
        self.push(0x0)
        self.push_content(dll_handle) # push deferenced handle
        self.call(WINAPI["FreeLibraryAndExitThread"])
                
                
class FreeLibraryGadget(Gadget):
    """
    Gadget for invoking kernel32.dll!Freelibrary API
    [snip]
    006C017A:         FF 35 1D 00 6C 00 PUSH DWORD PTR DS:[006C001D] ; 006C001D = dll handle
    006C0180:            B8 89 19 15 76 MOV EAX, 76151989 ;  76151989 = FreeLibrary
    006C0185:                     FF D0 CALL EAX
    [snip]
    """
    def __init__(self,
                 dll_handle,
                 start_offset=0,
                 mnemonic='invoke kernel32.dll!FreeLibrary',
                 ):
        Gadget.__init__(self, start_offset=start_offset, mnemonic=mnemonic,)
        self.push_content(dll_handle)
        self.call(WINAPI['FreeLibrary'])
        
        
class LoadLibraryGadget(Gadget):
    """
    gadget for invoking kernel32.dll!LoadLibraryA API
    """
    def __init__(self,
                 dll_addr, # address of dll path in target process memory
                 start_offset=0,
                 mnemonic='invoke kernel32.dll!LoadLibraryA',
                 ):
        Gadget.__init__(self, start_offset=start_offset, mnemonic=mnemonic,)
        self.push_offset(dll_addr)
        self.pushad()
        self.pushfd()
        self.call(WINAPI['LoadLibraryA'])
        self.popfd()
        self.popad()
        
        
class GetModuleHandleGadget(Gadget):
    """
    gadget for invoking kernel32.dll!GetModuleHandleA API
    """
    def __init__(self,
                 dll_addr, # address of dll in target process memory or its offset relative to ecx value
                 start_offset=0,
                 mnemonic='invoke kernel32.dll!GetModuleHandleA',
                 ):
        Gadget.__init__(self, start_offset=start_offset, mnemonic=mnemonic,)
        self.push(dll_addr)
        self.pushad()
        self.pushfd()
        self.call(WINAPI['GetModuleHandleA'])
        self.popfd()
        self.popad()

    
class GetProcAddressGadget(Gadget):
    """
    gadget for invoking kernel32.dll!GetProcAddress API
    [snip]
    006C0107:            68 B8 00 6C 00 PUSH 006C00B8 ; 006C00B8 = address of to-be-imported function's name
    006C010C:         FF 35 1D 00 6C 00 PUSH DWORD PTR DS:[006C001D] ; 006C001D = dll handle
    006C0112:            B8 D7 17 15 76 MOV EAX, 761517D7 ; 761517D7 = GetProcAddress
    006C0117:                     FF D0 CALL EAX
    [snip]
    """
    def __init__(self,
                 dll_handle, 
                 api_addr, # address of api in target process memory
                 start_offset=0,
                 mnemonic='invoke GetProcAddress',
                 ):
        Gadget.__init__(self, start_offset=start_offset, mnemonic=mnemonic,)
        self.push(api_addr)
        self.push_content(dll_handle)
        self.call(WINAPI['GetProcAddress'])
        
        
class MessageBoxGadget(Gadget):
    """
    gadget for invoking user32.dll!MessageBoxA API
    [snip]
    006C014B:                     6A 10 PUSH BYTE 10 ; 0x10 = MB_ICONERROR
    006C014D:            68 00 00 6C 00 PUSH 006C0000 ; 006C0000 = address of caption
    006C0152:            68 82 00 6C 00 PUSH 006C0082 ; 006C0082 = address of text
    006C0157:                     6A 00 PUSH BYTE 00
    006C0159:            A1 11 00 6C 00 MOV EAX, DWORD PTR DS:[006C0011] ; 006C0011 = MessageBoxA double-word pointer
    006C015E:                     FF D0 CALL EAX
    [snip]
    """
    def __init__(self,
                 txt_addr,
                 caption_addr,
                 category=MB_OK | MB_ICONINFORMATION,
                 start_offset=0,
                 mnemonic='invoke user32.dll!MessageBoxA',
                 ):
        Gadget.__init__(self,
                           start_offset=start_offset,
                           mnemonic=mnemonic,
                           )
        self.push(category)
        self.push(caption_addr)
        self.push(txt_addr)
        self.push(0x0)
        self.call(WINAPI["MessageBoxA"])
        
        
class ErrorPopupGadget(Gadget):
    """
    @description: gadget for poping-up failure notfications with customized messages;
                  ebx should contain the address of the text
    """
    def __init__(self,
                 caption_addr,
                 start_offset=0,
                 mnemonic='invoke user32.dll!MessageBoxA and then kernel32.dll:ExitThread API',
                 ):
        Gadget.__init__(self,
                        start_offset=start_offset,
                        mnemonic=mnemonic,
                        )
        self.push(MB_ICONERROR)
        self.push(caption_addr)
        self.push_ebx() # text customization: we espect ebx to contain the address of the text to display
        self.push(0x0)
        self.call(WINAPI["MessageBoxA"])
    
        
class WinExecGadget(Gadget):
    def __init__(self,
                 lpCmdLine,
                 uCmdShow=0,
                 start_offset=0,
                 mnemonic = "invoke kernel32.WinExec API",
                ):
        Gadget.__init__(self,
                        start_offset=start_offset,
                        mnemonic=mnemonic,
                        )
        self.push(uCmdShow)
        self.push(lpCmdLine)
        self.call(WINAPI["WinExec"])
        
        
class AnInstanceOfGadgetShould(unittest.TestCase):
    def testHaveZerostartOffsetIfJustCreated(self):
        gadget = Gadget()
        self.assertEqual(gadget.get_start_offset(), 0)
        
    def testHaveItsStartOffsetOptionallyPassedInConstructor(self):
        gadget = Gadget(start_offset=0xDEADBEEF)
        self.assertEqual(gadget.get_start_offset(), 0xDEADBEEF)
        
    def testHaveCallEaxMethod(self):
        gadget = Gadget()
        gadget.call_eax()
        self.assertEqual(gadget.get_offset(), 2)
        self.assertEqual(gadget.get_size(), 2)
        self.assertEqual("\xFF\xD0", gadget.get_payload()[-2:]) # last two bytes should be \xff\xd0
        
    def testHaveDbethod(self):
        gadget = Gadget(start_offset=1234)
        gadget.db("infamous.dll")
        self.assertEqual(gadget.get_offset(), 1247)
        self.assertEqual(gadget.get_size(), 13)
        self.assertEqual("infamous.dll\x00", gadget.get_payload()[-13:]) # last 13 bytes should be infamous.dll
        
    def testHaveNopMethod(self):
        gadget = Gadget()
        gadget.nop()
        self.assertEqual(gadget.get_offset(), 1)
        self.assertEqual(gadget.get_size(), 1)
        self.assertEqual("\x90", gadget.get_payload()[-1:])
        
    def testHaveRetMethod(self):
        gadget = Gadget()
        gadget.ret()
        self.assertEqual(gadget.get_offset(), 1)
        self.assertEqual(gadget.get_size(), 1)
        self.assertEqual("\xC3", gadget.get_payload()[-1:])
        
    def testHaveInt3Method(self):
        gadget = Gadget()
        gadget.int3()
        self.assertEqual(gadget.get_offset(), 1)
        self.assertEqual(gadget.get_size(), 1)
        self.assertEqual("\xCC", gadget.get_payload()[-1:])
        
    def testHaveNopSledMethod(self):
        gadget = Gadget(start_offset=4321)
        gadget.nop_sled(11)
        self.assertEqual(gadget.get_offset(), 4332)
        self.assertEqual(gadget.get_size(), 11)
        self.assertEqual("\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90", gadget.get_payload())
        
    def testHaveCmpEaxMethod(self):
        gadget = Gadget()
        gadget.cmp_eax(0x41424344)
        self.assertEqual(gadget.get_offset(), 5)
        self.assertEqual(gadget.get_size(), 5)
        self.assertEqual("\x3D\x44\x43\x42\x41", gadget.get_payload())
        
    def testShouldHavePushMethod(self):
        # push double-word
        gadget = Gadget()
        gadget.push(0x41424344)
        self.assertEqual(gadget.get_offset(), 5)
        self.assertEqual(gadget.get_size(), 5)
        self.assertEqual("\x68\x44\x43\x42\x41", gadget.get_payload())
        
        # push byte
        gadget = Gadget()
        gadget.push(0x1)
        self.assertEqual(gadget.get_offset(), 2)
        self.assertEqual(gadget.get_size(), 2)
        self.assertEqual("\x6A\x01", gadget.get_payload())
        
    def testHaveMovToEaxMethod(self):
        gadget = Gadget()
        gadget.mov_to_eax(0xDEADBEEF)
        self.assertEqual(gadget.get_offset(), 5)
        self.assertEqual(gadget.get_size(), 5)
        self.assertEqual(gadget.get_payload(), "\xB8\xEF\xBE\xAD\xDE")
        
    def testHaveMovEaxToAddrMethod(self):
        gadget = Gadget()
        gadget.mov_eax_to_addr(0x45444342)
        self.assertEqual(gadget.get_offset(), 5)
        self.assertEqual(gadget.get_size(), 5)
        self.assertEqual(gadget.get_payload(), "\xA3BCDE")
        
    def testHaveJnzMethod(self):
        gadget = Gadget(0x000C440D)
        gadget.jne(0x000C5000)
        self.assertEqual(gadget.get_offset(), 0x000C4413)
        self.assertEqual(gadget.get_size(), 6)
        self.assertEqual(gadget.get_payload(), "\x0F\x85\xED\x0B\x00\x00")
        
    def testHaveJzMethod(self):
        gadget = Gadget(0x000B1000)
        gadget.je(0x000BF000)
        self.assertEqual(gadget.get_offset(), 0x000B1006)
        self.assertEqual(gadget.get_size(), 6)
        self.assertEqual(gadget.get_payload(), "\x0f\x84\xfa\xdf\x00\x00")
        
    def testHaveJmpMethod(self):
        gadget = Gadget(0x000BE010)
        gadget.jmp(0x000C0000)
        self.assertEqual(gadget.get_offset(), 0x000BE015)
        self.assertEqual(gadget.get_size(), 5)
        self.assertEqual(gadget.get_payload(), "\xe9\xeb\x1f\x00\x00")
        
    def testHavePushadMethod(self):
        gadget = Gadget()
        gadget.pushad()
        self.assertEqual(gadget.get_offset(), 1)
        self.assertEqual(gadget.get_size(), 1)
        self.assertEqual(gadget.get_payload(), "\x60")
        
    def testHavePushfdMethod(self):
        gadget = Gadget()
        gadget.pushfd()
        self.assertEqual(gadget.get_offset(), 1)
        self.assertEqual(gadget.get_size(), 1)
        self.assertEqual(gadget.get_payload(), "\x9C")
        
    def testHavePopfdMethod(self):
        gadget = Gadget()
        gadget.popfd()
        self.assertEqual(gadget.get_offset(), 1)
        self.assertEqual(gadget.get_size(), 1)
        self.assertEqual(gadget.get_payload(), "\x9D")
        
    def testHavePopadMethod(self):
        gadget = Gadget()
        gadget.popad()
        self.assertEqual(gadget.get_offset(), 1)
        self.assertEqual(gadget.get_size(), 1)
        self.assertEqual(gadget.get_payload(), "\x61")
        
    def testHaveAppendGadgetMethod(self):
        g1 = Gadget()
        g1.push(1234)
        g2 = Gadget(g1.get_offset())
        g2.push(4321)
        o1 = g1.get_offset()
        p1 = g1.get_payload()
        self.assertEqual(g1.get_payload(), p1 + g2.get_payload())
        self.assertEqual(g1.get_offset(), o1 + g2.get_size() )
        
    def testOnlyCommitGadgetWhoseStartOFfseFitsIn(self):
        """
        can't concat gadgets whose offsets are out-of-phase!
        """
        g1 = Gadget()
        g1.mov_to_eax(0xDEADBEEF)
        g1.call_eax()
        o1 = g1.get_offset()
        p1 = g1.get_payload()
        s1 = g1.get_size()
        g2 = Gadget()
        g2.pushad()
        self.assertEqual(g1.commit_gadget(g2), None)
        self.assertEqual(g1.get_size(), s1)
        self.assertEqual(g1.get_offset(), o1)
        self.assertEqual(g1.get_payload(), p1)
        
    def testBeRepresentableInAmnemonicStringDisplay(self):
        gadget = Gadget()
        gadget.push(0)
        gadget.mov_to_eax(0x71727374)
        gadget.call_eax()
        mnemonic_string = """
00000000:             6A 00 PUSH 0x0
00000002:    B8 74 73 72 71 MOV EAX, 0x71727374
00000007:             FF D0 CALL EAX""".rstrip('\n')
        self.assertEqual(mnemonic_string[1:], str(gadget))
        
        
class weShouldHaveASleepExGadget(unittest.TestCase):
    def testOkWeDo(self):
        gadget = SleepExGadget(2500)
        gadget.display()
        
class weShouldHaveAnExitThreadGadget(unittest.TestCase):
    def testOkWeDo(self):
        gadget = ExitThreadGadget()
        gadget.display()
        
        
class weShouldHaveAFreeLibraryAndExitThreadGadget(unittest.TestCase):
    def testOkWeDo(self):
        gadget = FreeLibraryAndExitThreadGadget(0xDEADBEEF)
        gadget.display()
        
        
class weShouldHaveAFreeLibraryGadget(unittest.TestCase):
    def testOkWeDo(self):
        gadget = FreeLibraryGadget(0xDEADBEEF)
        gadget.display()
        
        
class weShouldHaveAGetModuleHandleGadget(unittest.TestCase):
    def testOkWeDo(self):
        gadget = GetModuleHandleGadget(0xDEADBEEF)
        gadget.display()
        
        
class weShouldHaveALoadLibraryGadget(unittest.TestCase):
    def testOkWeDo(self):
        gadget = LoadLibraryGadget(0xDEADBEEF)
        gadget.display()
        
        
class weShouldHaveAGetProcAddressGadget(unittest.TestCase):
    def testOkWeDo(self):
        gadget = GetProcAddressGadget(0xDEADBEEF, 0x44434241)
        gadget.display() 
        
        
# main
if __name__ == '__main__':
    
    # sanitize command-line
    parser = OptionParser(version=__VERSION__,
                          usage="python %s [OPTIONS] <target_PID> </path/to/dll/to/inject>"%sys.argv[0],
                          )
    parser.add_option("--eject",
                      dest="eject",
                      action='store_true',
                      default=False,
                      help="eject DLL from target process",
                      )
    parser.add_option("--invoke-api",
                      dest="apiname",
                      action='store',
                      type=str,
                      default=None,
                      help="once DLL is loaded into target process, import named API from it, and then invoke the API",
                      )
    options, args = parser.parse_args()
    if len(args) < 2:
        parser.print_help()
        sys.exit(1)
    pid = int(args[0])
    dll_path = os.path.abspath(args[1])
    dll_name = os.path.basename(dll_path)
    codecave_size = 500 # XXX should not be hard-coded!!!
    action = 0x1 # 0x0 unload, 0x1 load, 0x2 load and invoke some api
    if options.eject:
        action = 0x0
    if not options.apiname is None:
        if options.eject:
            parser.error("It's senseless to specify '--eject' and '--invoke' options together")
        action = 0x2
        dll_api_name = options.apiname
    print __VERSION__
    
    # grab a handle to the target process
    print "[+] Obtaining handle to target process .."
    h = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, 0, pid)
    assert h, "can't obtain handle target process"
    print "[+] OK."
    
    # allocate codecave in target process
    print "[+] Allocating %d-byte codecave in target process .."%codecave_size
    codecave = windll.kernel32.VirtualAllocEx(h, 0, codecave_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    assert codecave, "can't allocate codecave in target process"
    print "[+] OK."
    
    # instantiate our gadget; its code starts at codecode address
    gadget = Gadget(start_offset=codecave, max_size=codecave_size)
    
    # commit string tokens into gadget
    err_caption_addr = gadget.db("%s: Error"%os.path.basename(sys.argv[0]))
    injection_failure_notification_txt_addr = gadget.db("couldn't inject %s"%dll_name)
    ejection_failure_notification_txt_addr = gadget.db("couldn't eject %s"%dll_name)
    dll_addr = gadget.db(dll_path)
    #devil_addr = gadget.db("c:\windows\system32\cmd.exe /c ipconfig")
    if action == 0x2:
        dll_api_addr = gadget.db(dll_api_name)
        dll_api_import_failure_notification_txt_addr = gadget.db("couldn't import %s!%s API"%
                                                                 (dll_name,dll_api_name,))
    
    # build functional part of gadget
    print "[+] Building gadget .."
    """
    First, we enter dll_handle_grabber code, which tries to grab a handle to the dll.
    When this code returns, eax contiains a handle to the dll (success) or 0 (failure).
    We thus enter the following switch. Viz,
    [snip]
    if action eq "load"
    then
        if success
        then
            skip dll_loader code
        else
            load_dll 
            if ok # loaded
            then
                enter following error_handler (<- popup + quit)
            endif
            error_handler (= popup + quit)
        end if
    elif action eq "unload":
    then
        if success
        then
            skip following error_handler (= popup + quit)
        end if
        unload_dll
        if ok # unloaded
        then
            skip following error_handler (<- popup + quit)
        end if
    end if
    quit
    [snip]
    """
    #gadget.int3()
    #gadget.get_eip()
    #gadget.int3()
    error_handler = ErrorPopupGadget(err_caption_addr,
                                     start_offset=gadget.get_offset(),
                                     mnemonic="error_handler",)
    thread_killer = ExitThreadGadget(start_offset=error_handler.get_offset(),
                                     mnemonic='game over')
    gadget.commit_gadget(error_handler) 
    gadget.commit_gadget(thread_killer)
    gadget.set_ep() # set gadget entry-point
    gadget.int3()
    dll_handle_grabber = GetModuleHandleGadget(dll_addr, start_offset=gadget.get_offset(),
                                               mnemonic='grab %s handle'%dll_name)
    gadget.commit_gadget(dll_handle_grabber)
    gadget.int3()
    gadget.cmp_eax(0x0)
    if action != 0x0:
        dll_loader = LoadLibraryGadget(dll_addr, start_offset=gadget.get_offset() + CONDITIONALJMPPAYLOAD_LEN,
                                       mnemonic='load %s'%dll_name)
        gadget.jne_skip_stub(dll_loader)
        gadget.int3()
        gadget.cmp_eax(0x0)
        gadget.mov_to_ebx(injection_failure_notification_txt_addr) 
        gadget.je(error_handler.get_ep())
        gadget.mov_eax_to_addr(dll_addr)
    else:
        gadget.mov_to_ebx(ejection_failure_notification_txt_addr)
        gadget.je(error_handler.get_ep())
        gadget.mov_eax_to_addr(dll_addr)
        dll_unloader = FreeLibraryAndExitThreadGadget(dll_addr, start_offset=gadget.get_offset())
        gadget.commit_gadget(dll_unloader)
        gadget.cmp_eax(0x0)
        gadget.mov_to_ebx(ejection_failure_notification_txt_addr)
        gadget.je(error_handler.get_ep())
    if action == 0x2:
        dll_api_grabber = GetProcAddressGadget(dll_addr, dll_api_addr, start_offset=gadget.get_offset(),
                                               mnemonic="import %s!%s"%(dll_name,dll_api_name))
        gadget.commit_gadget(dll_api_grabber)
        gadget.cmp_eax(0x0)
        gadget.mov_to_ebx(dll_api_import_failure_notification_txt_addr)
        gadget.je(error_handler.get_ep())
        gadget.mov_eax_to_addr(dll_api_addr)
        gadget.call_by_reference(dll_api_addr)
    #devil = WinExecGadget(devil_addr,
    #                      start_offset=gadget.get_offset(),
    #                      mnemonic="invoke ipconfig",
    #                      )
    #gadget.commit_gadget(devil)
    #eip_grabber = "\xD9\xEE\xD9\x74\x24\xF4\x59\x80\xC1\x0A\x90"
    #gadget._payload += eip_grabber
    #gadget._offset += len(eip_grabber)
    #gadget.int3()
    gadget.jmp(thread_killer.get_ep())
    gadget.display()
        
    # copy gadget to codecave dug earlier in target process
    print "[+] Copying gadget to codecave in remote process .."
    assert windll.kernel32.WriteProcessMemory(h, codecave, gadget.get_payload(), gadget.get_size(), 0)
    print "[+] OK."
    
    # flush instruction cache
    windll.kernel32.FlushInstructionCache(h, codecave, gadget.get_size())
    
    # deploy carrier thread to execute our gadget in target process
    print "[+] Deploying remote carrier-thread to trigger gadget in target process .."
    dwTid = DWORD()
    hThread = windll.kernel32.CreateRemoteThread(h, 0, 0, gadget.get_ep(), 0, 0, byref(dwTid),)
    assert hThread
    print "[+] OK (remote carrier TID = %d)"%dwTid.value
    
    # render
    windll.kernel32.WaitForSingleObject(hThread, INFINITE)
    
    # liberate codecave in target process
    print "[+] Freeing codecave in target process .."
    windll.kernel32.VirtualFreeEx(h, codecave, codecave_size, MEM_RELEASE,)
    print "[+] OK."
    # unittest.main()