import struct
import unittest

class AsmInstruction:
    def __init__(self,
                 opcodes,
                 mnemonic,
                 ):
        self._opcodes = opcodes;
        self._mnemonic = mnemonic
        self._size = len(opcodes)

    def getOpcodes(self):
        return self._opcodes

    def getMnemonic(self):
        return self._mnemonic

    def display(self):
        print '%25s %s' %(' '.join(map(lambda byte: '%02X' %ord(byte), self._opcodes)), self._mnemonic) 

    def getSize(self):
        return self._size


class Shellcode:
    def __init__(self,
                 start_index=0,
                 pseudo=None,
                 ):
        self._start_index = start_index
        self._current_index = start_index
        self._pseudo = pseudo

            
class TestAsmInstruction(unittest.TestCase):
    def test_init(self):
        asm = AsmInstruction('\xFF\xD0', 'CALL EAX')
        self.assertEqual(asm.getSize(), 2)
        self.assertEqual(asm.getOpcodes(), '\xFF\xD0')
        self.assertEqual(asm.getMnemonic(), 'CALL EAX')
        asm.display()
        

if __name__ == '__main__':
    unittest.main()



                              
