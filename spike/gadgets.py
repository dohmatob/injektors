"""
A tiny python command-line script/module for dll-injection-related business

(c) h4lf-jiffie (dohmatob elvis dopgima)
"""

import unittest
import struct
from ctypes import *
import sys
import os
from libdebug.constants import *

__AUTHOR__ = "by h4lf-j1ff13 (dohmatob elvis dopgima)"

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
                 mnemonic=None,
                 ):
        self._start_offset = start_offset
        self._mnemonic = mnemonic
        self._offset = start_offset
        self._ep = start_offset
        self._payload = ""
        self._ais = dict()
        self._offsets = list()
        
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
    
    def get_size(self):
        """
        @returns:  size of payload buffer
        """
        return len(self._payload)
    
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
    
    def commit_ai(self, ai):
        """
        @description: commits a new assembly instruction at current offset of payload
        @returns:  returns the offset where the instruction starts
        """
        offset = self._offset
        self._offsets.append(offset)
        ai.set_offset(offset)
        self._ais[offset] = ai
        self._payload += ai.get_payload()
        self._offset += ai.get_size()
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
        
    def mov_eax_to_addr(self, addr):
        """
        @description: commits a 'mov [addr], eax' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic('MOV DWORD PTR DS:[%08X], EAX'%addr)
        ai.set_payload("\xA3" + self.packed_dword(addr))
        return self.commit_ai(ai)
        
    def jnz(self, offset):
        """
        @description: commits a 'jnz offset' instruction
        """
        ai = AsmInstruction()
        ai.set_mnemonic('JNZ 0x%0X'%offset)
        ai.set_payload('\x0F\x85' + self.packed_dword(offset - self._offset - CONDITIONALJMPPAYLOAD_LEN))
        return self.commit_ai(ai)
        
    def jz(self, offset):
       """
       @description: commits a 'jz offset' instruction
       """
       ai = AsmInstruction()
       ai.set_mnemonic('JZ 0x%0X'%offset)
       ai.set_payload('\x0F\x84' + self.packed_dword(offset - self._offset - CONDITIONALJMPPAYLOAD_LEN))
       return self.commit_ai(ai)
       
    def jmp(self, offset):
       """
       @description: commits a 'jmp offset' instruction
       """
       ai = AsmInstruction()
       ai.set_mnemonic('JMP 0x%0X'%offset)
       ai.set_payload('\xE9' + self.packed_dword(offset - self._offset - UNCONDITIONALJMPPAYLOAD_LEN))
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
        for offset in gadget.get_offsets():
            self.commit_ai(gadget.get_ai(offset))
        return gadget.get_start_offset(), gadget.get_size()
      
    def __str__(self):
        """
        @returns:  instance as a mnemonic string
        """
        return "\n".join(['\t\t' + str(self._ais[offset]) for offset in self._offsets])
        
    def display(self):
        """
        displays instance ias a mnemonic-string
        """
        mnemonic_string = str(self)
        if self._mnemonic:
            mnemonic_string = '->| BEGIN "%s"\n%s\n|<- END "%s"'%(self._mnemonic,mnemonic_string,self._mnemonic)
        print '\t\tGADGET (entry-point at 0x%08X):\n%s'%(self._ep,mnemonic_string)
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
                 dll_addr, # address of dll in target process memory
                 start_offset=0,
                 mnemonic='invoke kernel32.dll!LoadLibraryA',
                 ):
        Gadget.__init__(self, start_offset=start_offset, mnemonic=mnemonic,)
        self.push(dll_addr)
        self.call(WINAPI['LoadLibraryA'])
        
        
class GetModuleHandleGadget(Gadget):
    """
    gadget for invoking kernel32.dll!GetModuleHandleA API
    """
    def __init__(self,
                 dll_addr, # address of dll in target process memory
                 start_offset=0,
                 mnemonic='invoke kernel32.dll!GetModuleHandleA',
                 ):
        Gadget.__init__(self, start_offset=start_offset, mnemonic=mnemonic,)
        self.push(dll_addr)
        self.call(WINAPI['GetModuleHandleA'])

    
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
        gadget.jnz(0x000C5000)
        self.assertEqual(gadget.get_offset(), 0x000C4413)
        self.assertEqual(gadget.get_size(), 6)
        self.assertEqual(gadget.get_payload(), "\x0F\x85\xED\x0B\x00\x00")
        
    def testHaveJzMethod(self):
        gadget = Gadget(0x000B1000)
        gadget.jz(0x000BF000)
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
    print "[+] %s %s %s %s"%("+"*13,os.path.basename(sys.argv[0]),__AUTHOR__,"+"*13)
    
    # sanitize command-line
    if len(sys.argv) < 3:
        print "[+] [+]Usage: python %s [OPTIONS] <target_PID> </path/to/dll/to/inject>"%sys.argv[0]
        sys.exit(1)
    pid = int(sys.argv[1])
    dll_path = os.path.abspath(sys.argv[2])
    dll_name = os.path.basename(dll_path)
    codecave_size = 400 # XXX should not be hard-coded!!!
    action = "load"
    if len(sys.argv) > 3:
        action = sys.argv[3]
    
    # grab a handle to the target process
    print "[+] [+] Obtaining handle to target process .."
    h = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, 0, pid)
    assert h, "can't obtain handle target process"
    print "[+] OK."
    
    # allocate codecave in target process
    print "[+] Allocating %d-byte codecave in target process .."%codecave_size
    codecave = windll.kernel32.VirtualAllocEx(h, 0, codecave_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    assert codecave, "can't allocate codecave in target process"
    print "[+] OK."
    
    # instantiate our gadget; its code starts at codecode address
    gadget = Gadget(start_offset=codecave)
    
    # commit string tokens into gadget
    err_caption_addr = gadget.db("%s: Error"%os.path.basename(sys.argv[0]))
    injection_failure_notification_txt_addr = gadget.db("couldn't inject %s"%dll_name)
    ejection_failure_notification_txt_addr = gadget.db("couldn't eject %s"%dll_name)
    dll_addr = gadget.db(dll_path)
    
    # set gadget entry-point
    gadget.set_ep() 
    
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
                enter following seh (<- popup + quit)
            endif
            seh (= popup + quit)
        end if
    elif action eq "unload":
    then
        if success
        then
            skip following seh (= popup + quit)
        end if
        unload_dll
        if ok # unloaded
        then
            skip following seh (<- popup + quit)
        end if
    end if
    quit
    [snip]
    """
    dll_handle_grabber = GetModuleHandleGadget(dll_addr, start_offset=gadget.get_ep())
    gadget.commit_gadget(dll_handle_grabber)
    gadget.cmp_eax(0x0)
    if action == "load":
        gadget.jnz(gadget.get_offset() + CONDITIONALJMPPAYLOAD_LEN + LOADLIBRARYPAYLOAD_LEN)
        dll_loader = LoadLibraryGadget(dll_addr, start_offset=gadget.get_offset())
        gadget.commit_gadget(dll_loader)
        gadget.cmp_eax(0x0)
        msgb_ep = gadget.get_offset() + CONDITIONALJMPPAYLOAD_LEN
        msgb = MessageBoxGadget(injection_failure_notification_txt_addr, err_caption_addr, category=MB_ICONERROR,
                               start_offset=msgb_ep,)
        thread_killer_ep = msgb_ep + msgb.get_size()
        thread_killer = ExitThreadGadget(start_offset=thread_killer_ep,)
        offset_just_after_error_stuff = gadget.get_offset() # we are here
        offset_just_after_error_stuff += CONDITIONALJMPPAYLOAD_LEN # offset correction
        offset_just_after_error_stuff += msgb.get_size() # skip msgb code
        offset_just_after_error_stuff += thread_killer.get_size() # skip thread_killer code
        gadget.jnz(offset_just_after_error_stuff)
        gadget.commit_gadget(msgb)
        gadget.commit_gadget(thread_killer)
        gadget.mov_eax_to_addr(dll_addr)
    else:
        msgb_ep = gadget.get_offset() + CONDITIONALJMPPAYLOAD_LEN
        msgb = MessageBoxGadget(ejection_failure_notification_txt_addr, err_caption_addr, category=MB_ICONERROR,
                               start_offset=msgb_ep,)
        thread_killer_ep = msgb_ep + msgb.get_size()
        thread_killer = ExitThreadGadget(start_offset=thread_killer_ep,)
        offset_just_after_error_stuff = gadget.get_offset() # we are here
        offset_just_after_error_stuff += CONDITIONALJMPPAYLOAD_LEN # offset correction
        offset_just_after_error_stuff += msgb.get_size() # skip msgb code
        offset_just_after_error_stuff += thread_killer.get_size() # skip thread_killer code
        gadget.jnz(offset_just_after_error_stuff)
        gadget.commit_gadget(msgb)
        gadget.commit_gadget(thread_killer)
        gadget.mov_eax_to_addr(dll_addr)
        dll_unloader = FreeLibraryAndExitThreadGadget(dll_addr, start_offset=gadget.get_offset())
        gadget.commit_gadget(dll_unloader)
    thread_killer = ExitThreadGadget(start_offset=gadget.get_offset())
    gadget.commit_gadget(thread_killer)
    gadget.display()
        
    # copy gadget to codecave dug earlier in target process
    print "[+] Coping gadget to codecave in remote process .."
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