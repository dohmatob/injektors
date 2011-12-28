import struct
import unittest
from ctypes import windll, byref

CMPEAXSHELLCODE_LEN = 5
MESSAGEBOXSHELLCODE_LEN = 21
EXITTHREADSHELLCODE_LEN = 9
LOADLIBRARYSHELLCODE_LEN = 12
FREELIBRARYSHELLCODE_LEN = 13
FREELIBRARYANDEXITTHREADSHELLCODE_LEN = 15
GETPROCADDRESSSHELLCODE_LEN = 18
UNCONDITIONALJMPSHELLCODE_LEN = 5
CONDITIONALJMPSHELLCODE_LEN = 6

kernel32 = windll.kernel32
kernel32_handle = kernel32.GetModuleHandleA("kernel32.dll")
WINAPI = dict()
for api_name in ["ExitThread", 
                 "FreeLibraryAndExitThread", 
                 "FreeLibrary",
                 "LoadLibraryA",
                 "GetModuleHandleA",
                 "GetProcAddress",
                 ]:
    WINAPI[api_name] = kernel32.GetProcAddress(kernel32_handle,
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
                 processor='Intel', # reserved for future use
                 mode=32, # reserved for future use
                 ):
        self._opcodes = opcodes;
        self._mnemonic = mnemonic 
        self._offset = offset
        self._processor = processor
        self._mode = mode
        self._size = len(opcodes)

    def getOpcodes(self):
        return self._opcodes

    def getMnemonic(self):
        return self._mnemonic

    def getOffset(self):
        return self._offset

    def display(self):
        print '%s:%25s %s' %('0x%08X' %self._offset,' '.join(map(lambda byte: '%02X' %ord(byte), self._opcodes)),self._mnemonic) 

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

    def getCurrentOffset(self):
        return self._current_offset
    
    def display(self):
        for offset in self._offsets:
            self._asm_instructions[offset].display()

    def addAsmInstruction(self, asm):
        self._offsets.append(self._current_offset)
        self._asm_instructions[self._current_offset] = asm
        self._egg += asm.getOpcodes()
        self._current_offset += asm.getSize()
        
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
        self._block_entry_tags[self.getCurrentIndex()] = 'NOP-sled'
        for j in xrange(size):
            self.nop()
        self._block_exit_tags[self.getCurrentIndex()] = 'NOP-sled'

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
        self._block_entry_tags[self.getCurrentIndex()] = 'INT3-sled'
        for j in xrange(size):
            self.int3()
        self._block_exit_tags[self.getCurrentIndex()] = 'INT3-sled'
                            
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
        print addr - self._current_offset - CONDITIONALJMPSHELLCODE_LEN
        opcodes = "\xE9" + struct.pack("<I", addr - self._current_offset - CONDITIONALJMPSHELLCODE_LEN)
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
        self.movDwPtr2Eax(func_addr_ptr)
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

    def pushDwPtr(self, ptr):
        opcodes = '\xFF\x35' + struct.pack('<I', ptr)
        mnemonic = "MOV DWORD PTR DS:[0x%0X]" %ptr
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

    def movDwPtr2Eax(self, ptr):
        opcodes = '\xA1' + struct.pack('<I', ptr)
        mnemonic = "MOV EAX, DWORD PTR DS:[0x%0X]" %ptr
        asm = AsmInstruction(opcodes,
                             mnemonic,
                             offset=self._current_offset,
                             )
        self.addAsmInstruction(asm)


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
        sc.pushDwPtr(0x404111)
        sc.movDwPtr2Eax(0x77550234)
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



                              
