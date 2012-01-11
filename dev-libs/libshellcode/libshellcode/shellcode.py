"""
(c) d0hm4t06 3. d0p91m4
"""
import struct
import unittest
from ctypes import windll, byref
from libutils.constants import *

# exported constants
CMPEAXSHELLCODE_LEN = 5
MESSAGEBOXSHELLCODE_LEN = 21
EXITTHREADSHELLCODE_LEN = 9
LOADLIBRARYSHELLCODE_LEN = 12
FREELIBRARYSHELLCODE_LEN = 13
FREELIBRARYANDEXITTHREADSHELLCODE_LEN = 15
GETPROCADDRESSSHELLCODE_LEN = 18
UNCONDITIONALJMPSHELLCODE_LEN = 5
CONDITIONALJMPSHELLCODE_LEN = 6

# position-independent (unrebased) APIs
kernel32 = windll.kernel32
kernel32dll_handle = kernel32.GetModuleHandleA("kernel32.dll")
user32dll_handle = kernel32.GetModuleHandleA("user32.dll")
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
    WINAPI[api_name] = kernel32.GetProcAddress(kernel32dll_handle,
                                               api_name,
                                               )
for api_name in ["MessageBoxA",
                 ]:
    WINAPI[api_name] = kernel32.GetProcAddress(user32dll_handle,
                                               api_name,
                                               )


class AsmInstruction:
    """
    Model for assembly (machine) instructions
    """
    def __init__(self,
                 opcodes, # for example, '\xFF\xD0'
                 mnemonic, # thus, CALL EAX
                 offset=0,
                 donot_format_mnemonic=False,
                 processor='Intel', # reserved for future use
                 mode=32, # reserved for future use
                 ):
        self._opcodes = opcodes;
        self._mnemonic = mnemonic 
        self._offset = offset
        self._processor = processor
        self._mode = mode
        self._donot_format_mnemonic = donot_format_mnemonic
        self._size = len(opcodes)

    def getOpcodes(self):
        return self._opcodes

    def getMnemonic(self):
        return self._mnemonic

    def getOffset(self):
        return self._offset

    def display(self):
        if not self._donot_format_mnemonic:
            print '\t%s:%25s %s' %('%08X' %self._offset,' '.join(map(lambda byte: '%02X' %ord(byte), self._opcodes)),self._mnemonic) 
        else:
            print '\t%s:%25s %s' %('%08X' %self._offset,' ',self._mnemonic) 

    def getSize(self):
        return self._size


class Shellcode:
    """
    Model for shellcode: encapsulates payload + other control attributes + methods for manipulation.
    Fundamental assembly instructions like CALL EAX, POP EDX, MOVSB, etc., are implemented, thus 
    providing a powerway of building arbitrarily complex payloads incrementally; all you need to 
    remember are the mnemonics; we take care of the opcodes --back end.
    """
    def __init__(self,
                 start_offset=0, # an 'artificial' offset where the shellcode starts
                 pseudo=None, # a pseudo for the shellcode (could be a string like <unload dll and exit remote thread>
                 ):
        self._start_offset = start_offset
        self._current_offset = start_offset
        self._pseudo = pseudo
        self._egg = "" # payload (opcodes) contained by shellcode
        self._asm_instructions = dict() # a dictionary of assembly instructions that make up the shellcode
        self._offsets = list()
        self._block_entry_tags = dict()
        self._block_exit_tags = dict()

    def getSize(self):
        return len(self._egg)

    def getEgg(self):
        return self._egg

    def getPseudo(self):
        return self._pseudo

    def getCurrentOffset(self):
        return self._current_offset
    
    def getAsmInstructions(self):
        return self._asm_instructions

    def display(self):
        for offset in self._offsets:
            if offset in self._block_exit_tags:
                print '\t|<- END OF BLOCK (%s)' %self._block_exit_tags[offset]
            if offset in self._block_entry_tags:
                print '\t->| START OF BLOCK (%s)' %self._block_entry_tags[offset]
            self._asm_instructions[offset].display()
        for offset in self._block_exit_tags:
            if not offset in self._offsets:
                print '\t|<- END OF BLOCK (%s)' %self._block_exit_tags[offset]
                break

    def getOffsets(self):
        return self._offsets

    def addAsmInstruction(self, asm):
        self._offsets.append(self._current_offset)
        self._asm_instructions[self._current_offset] = asm
        self._egg += asm.getOpcodes()
        self._current_offset += asm.getSize()
    
    def addConstStr(self, const_str):
        opcodes = const_str + '\x00'
        mnemonic = 'DB "%s",0' %const_str
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             self._current_offset,
                             True,
                             )
        self.addAsmInstruction(asm)
        return asm.getOffset()

    def addShellcode(self, shellcode):
        if shellcode.getPseudo():
            self._block_entry_tags[self._current_offset] = shellcode.getPseudo()
        self._egg += shellcode.getEgg()
        self._offsets += shellcode.getOffsets()
        for offset in shellcode.getOffsets():
            self._asm_instructions[offset] = shellcode.getAsmInstructions()[offset]
        self._current_offset += shellcode.getSize()
        if shellcode.getPseudo():
            self._block_exit_tags[self._current_offset] = shellcode.getPseudo()

    def addBlockEntryTag(self, tag):
        self._block_entry_tags[self._current_offset] = tag

    def addBlockExitTag(self, tag):
        self._block_exit_tags[self._current_offset] = tag

    def ret(self):
        opcodes = '\xC3'
        mnemonic = "RET"
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             self._current_offset
                             )
        self.addAsmInstruction(asm)
        
    def nop(self):
        opcodes = "\x90"
        mnemonic = 'NOP'
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             self._current_offset
                             )
        self.addAsmInstruction(asm)
        
    def nopSled(self,
                size):
        self._block_entry_tags[self._current_offset] = 'NOP-sled'
        for j in xrange(size):
            self.nop()
        self._block_exit_tags[self._current_offset] = 'NOP-sled'

    def int3(self):
        opcodes = "\xCC"
        mnemonic = 'INT3'
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             self._current_offset
                             )
        self.addAsmInstruction(asm)

    def int3Sled(self,
                size):
        self._block_entry_tags[self._curren_offset] = 'INT3-sled'
        for j in xrange(size):
            self.int3()
        self._block_exit_tags[self._current_offset] = 'INT3-sled'
                            
    def jnz(self, addr):
        opcodes = "\x0F\x85" + struct.pack("<I", addr - self._current_offset - CONDITIONALJMPSHELLCODE_LEN)
        mnemonic = 'JNZ 0x%0X' %addr
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def jz(self, addr):
        opcodes = "\x0F\x84" + struct.pack("<I", addr - self._current_offset - CONDITIONALJMPSHELLCODE_LEN)
        mnemonic = 'JZ 0x%0X' %addr
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             self._current_offset,
                             )
        self.addAsmInstruction(asm)


    def jmp(self, addr):
        opcodes = "\xE9" + struct.pack("<I", addr - self._current_offset - UNCONDITIONALJMPSHELLCODE_LEN)
        mnemonic = 'JMP 0x%0X' %addr
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def callEax(self):
        opcodes = '\xFF\xD0'
        mnemonic = 'CALL EAX'
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             offset=self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def call(self, func_addr):
        self.mov2Eax(func_addr)
        self.callEax()

    def callByValue(self, func_addr):
        self.call(func_addr)

    def callByReference(self, func_addr_ptr):
        self.movDwPtrDs2Eax(func_addr_ptr)
        self.callEax()

    def saveEax(self, addr):
        opcodes = "\xA3" + struct.pack('<I', addr)
        mnemonic = "MOV DWORD PTR DS:[%08X], EAX" %addr
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def cmpEax(self, val):
        opcodes = '\x3D' + struct.pack('<I', val)
        mnemonic = "CMP EAX, 0x%0X" %val
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def push(self, value):
        if 0 <= value < 0xFF:
            opcodes = '\x6A' + struct.pack('B', value)
        else:
            opcodes = '\x68' + struct.pack('<I', value)
        mnemonic = "PUSH 0x%0X" %value
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             offset=self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def pushAd(self):
        opcodes = '\x60'
        mnemonic = "PUSHAD"
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             offset=self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def pushFd(self):
        opcodes = '\x9C'
        mnemonic = "PUSHFD"
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             offset=self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def popAd(self):
        opcodes = '\x61'
        mnemonic = "POPAD"
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             offset=self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def popFd(self):
        opcodes = '\x9D'
        mnemonic = "POPFD"
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             offset=self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def pushDwPtrDs(self, ptr):
        opcodes = '\xFF\x35' + struct.pack('<I', ptr)
        mnemonic = "PUSH DWORD PTR DS:[0x%0X]" %ptr
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             offset=self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def mov2Eax(self, value):
        opcodes = '\xB8' + struct.pack('<I', value)
        mnemonic = "MOV EAX, 0x%0X" %value
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             offset=self._current_offset,
                             )
        self.addAsmInstruction(asm)

    def movDwPtrDs2Eax(self, ptr):
        opcodes = '\xA1' + struct.pack('<I', ptr)
        mnemonic = "MOV EAX, DWORD PTR DS:[0x%0X]" %ptr
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             offset=self._current_offset,
                             )
        self.addAsmInstruction(asm)


class SleepExShellcode(Shellcode):
    def __init__(self,
                 nb_milliseconds=INFINITE,
                 alertable=1,
                 start_offset=0,
                 pseudo='invoke SleepEx',
                 ):
        Shellcode.__init__(self, 
                           start_offset=start_offset,
                           pseudo=pseudo,
                           )
        self.push(alertable)
        self.push(nb_milliseconds)
        self.call(WINAPI["SleepEx"])

    
class ExitThreadShellcode(Shellcode):
    """
    instantiates an egg like:
    ...
    006C0187:                     6A 00 PUSH BYTE 00
    006C0189:            B8 89 06 81 77 MOV EAX, 77810689 ; 77810689 = ExitThread
    006C018E:                     FF D0 CALL EAX
    ...
    """
    def __init__(self,
                 start_offset=0,
                 pseudo='invoke ExitThread',
                 ):
        Shellcode.__init__(self, 
                           start_offset=start_offset,
                           pseudo=pseudo,
                           )
        self.push(0x0)
        self.call(WINAPI["ExitThread"])


class FreeLibraryAndExitThreadShellcode(Shellcode):
    def __init__(self,
                 dll_addr,
                 start_offset=0,
                 pseudo='invoke FreeLibraryAndExitThread',
                 ):
        Shellcode.__init__(self,
                           start_offset=start_offset,
                           pseudo=pseudo,
                           )
        self._dll_addr = dll_addr
        self.push(0x0)
        self.pushDwPtrDs(dll_addr)
        self.call(WINAPI["FreeLibraryAndExitThread"])


class LoadLibraryShellcode(Shellcode):
    def __init__(self,
                 dll_addr,
                 start_offset=0,
                 pseudo='invoke LoadLibraryA',
                 ):
        Shellcode.__init__(self,
                           start_offset=start_offset,
                           pseudo=pseudo,
                           )
        self._dll_addr = dll_addr
        self.push(dll_addr)
        self.call(WINAPI['LoadLibraryA'])


class FreeLibraryShellcode(Shellcode):
    """
    instantiates and egg like:
    ...
    006C017A:         FF 35 1D 00 6C 00 PUSH DWORD PTR DS:[006C001D] ; 006C001D = dll handle 
    006C0180:            B8 89 19 15 76 MOV EAX, 76151989 ;  76151989 = FreeLibrary
    006C0185:                     FF D0 CALL EAX
    ...
    """
    def __init__(self,
                 dll_addr,
                 start_offset=0,
                 pseudo='invoke FreeLibrary',
                 ):
        Shellcode.__init__(self,
                           start_offset=start_offset,
                           pseudo=pseudo,
                           )
        self._dll_addr = dll_addr
        self.pushDwPtrDs(dll_addr)
        self.call(WINAPI['FreeLibrary'])
                 

class GetModuleHandleShellcode(Shellcode):
    def __init__(self,
                 dll_name,
                 start_offset=0,
                 pseudo='invoke GetProcessHandle',
                 ):
        Shellcode.__init__(self,
                           start_offset=start_offset,
                           pseudo=pseudo,
                           )
        self.push(dll_name)
        self.call(WINAPI['GetModuleHandleA'])

                 
class GetProcAddressShellcode(Shellcode):
    """
    instantiates an egg like:
    ...
    006C0107:            68 B8 00 6C 00 PUSH 006C00B8 ; 006C00B8 = address of to-be-imported function's name
    006C010C:         FF 35 1D 00 6C 00 PUSH DWORD PTR DS:[006C001D] ; 006C001D = dll handle  
    006C0112:            B8 D7 17 15 76 MOV EAX, 761517D7 ; 761517D7 = GetProcAddress 
    006C0117:                     FF D0 CALL EAX
    ...
    """
    def __init__(self,
                 dll_handle,
                 func_name,
                 start_offset=0,
                 pseudo='invoke GetProcAddress',
                 ):
        Shellcode.__init__(self,
                           start_offset=start_offset,
                           pseudo=pseudo,
                           )
        self.push(func_name)
        self.pushDwPtrDs(dll_handle)
        self.call(WINAPI['GetProcAddress'])
        

class MessageBoxShellcode(Shellcode):
    """
    instantiates an egg like:
    ...
    006C014B:                     6A 10 PUSH BYTE 10 ; 0x10 = MB_ICONERROR
    006C014D:            68 00 00 6C 00 PUSH 006C0000 ; 006C0000 = address of caption
    006C0152:            68 82 00 6C 00 PUSH 006C0082 ; 006C0082 = address of text 
    006C0157:                     6A 00 PUSH BYTE 00
    006C0159:            A1 11 00 6C 00 MOV EAX, DWORD PTR DS:[006C0011] ; 006C0011 = MessageBoxA double-word pointer
    006C015E:                     FF D0 CALL EAX
    ...
    """
    def __init__(self,
                 txt_addr,
                 caption_addr,
                 kind=MB_OK | MB_ICONINFORMATION,
                 start_offset=0,
                 pseudo='invoke MessageBox',
                 ):
        Shellcode.__init__(self,
                           start_offset=start_offset,
                           pseudo=pseudo,
                           )
        self.push(kind)
        self.push(caption_addr)
        self.push(txt_addr)
        self.push(0x0)
        self.call(WINAPI["MessageBoxA"])


class TestAsmInstruction(unittest.TestCase):
    def test_init(self):
        asm = AsmInstruction('\xFF\xD0', 'CALL EAX')
        self.assertEqual(asm.getSize(), 2)
        self.assertEqual(asm.getOpcodes(), '\xFF\xD0')
        self.assertEqual(asm.getMnemonic(), 'CALL EAX')
        # asm.display()
        

class TestShellcode(unittest.TestCase):
    def test__init(self):
        sc = Shellcode()
        self.assertEqual(sc.getSize(), 0)
        
    def test_callEax(self):
        sc = Shellcode(start_offset=0xDEADBEEF)
        sc.pushDwPtrDs(0x404111)
        sc.movDwPtrDs2Eax(0x77550234)
        sc.callEax()
        # self.assertEqual(sc.getSize(), 2)
        sc.display()

    def test_jnz(self):
        sc = Shellcode(0xDEADBEEF)
        sc.jmp(0xDEADDEEF)
        self.assertEqual(sc.getSize(), UNCONDITIONALJMPSHELLCODE_LEN)
        sc.display()

if __name__ == '__main__':
    unittest.main()



                              
