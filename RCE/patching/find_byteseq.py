from optparse import OptionParser
import sys
import os
import re
import pefile
from codecs import escape_decode
import traceback
from injectors.utils import pretty_time, debug, die

__AUTHOR__ = 'd0hm4t06 3. d0p91m4 (RUDEBOI)'
__VERSION__ = '1.0'
__FULL_VERSION__ = '%s version %s: a tiny command-line tool for finding locations of a specified byte-sequence in an PE binary\r\n(c) %s October 22, 2011 -BORDEAUX' %(os.path.basename(sys.argv[0]),__VERSION__,__AUTHOR__)

def findByteSeq(filename,
                byte_seq,
                ):
    byte_seq = escape_decode(byte_seq)[0]
    pe_obj = pefile.PE(filename) 
    results = []
    for item in re.finditer(byte_seq,
                              pe_obj.get_memory_mapped_image(), 
                              ): 
        addr = item.start() + pe_obj.OPTIONAL_HEADER.ImageBase
        debug("Found occurence at 0x%08X" %addr)
        results.append(addr)
    if not results:
        debug("Found no occurence")
    return results


if __name__ == '__main__':
    usage = "python %s [OPTIONS] <input_binary_file> <byte_sequence>" %sys.argv[0]
    usage += "\r\n\r\nExamples:\r\n"
    usage += r"[1] python %s C:\\Users\\rude-boi\\Desktop\\Pinball.exe \x01\x30\x8B\x10\x81\xFA\xA0\x86\x01\x00" %(sys.argv[0])
    usage += "\r\nwill attempt to find the stub"
    usage += "\r\n"
    usage += """
    ->|
    MOV DWORD PTR DS:[EAX], ESI
    MOV EDX, DWORD PTR DS:[EAX]
    CMP EDX, 186A0
    |<-
    """
    usage += "\r\nin the binary C:\\Users\\rude-boi\\Desktop\\Pinball.exe !\r\n\r\n"
    usage += r"[2] python %s C:\\Users\\rude-boi\\Desktop\\Pinball.exe $(python -c \"print '\\x00'*20\")" %sys.argv[0]
    usage += "\r\nwill attempt to find a codecave (a contiguous block of zero-bytes) of size 200 in C:\\Users\\rude-boi\\Desktop\\Pinball.exe"
    parser = OptionParser(usage=usage,
                          version=__FULL_VERSION__,
                          )
    options, args = parser.parse_args()
    findByteSeq(args[0], 
                args[1],
                )
    



