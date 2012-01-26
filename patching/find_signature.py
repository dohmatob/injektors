from optparse import OptionParser
import sys
import os
import re
from libutils.debug import *
from libutils.constants import *
from ctypes import *
from codecs import escape_decode
import binascii

__AUTHOR__ = 'dohmatob elvis dopgima (h4lf-jiffie)'
__VERSION__ = '1.0dev'
__FULL_VERSION__ = '%s version %s: a tiny command-line tool that finds locations of a specified byte-sequence (signature)\
 in PE binary or process memory\r\n\r\n(c) %s October 22, 2011 (BORDEAUX)' %(os.path.basename(sys.argv[0]),__VERSION__,\
__AUTHOR__)

"""
The function below attempts to eliminate fake addresses from a list of possible candidates 
for the address of a signature in a process's memory
"""
def EliminateFakeAddresses(pid,
                        infile,
                        outfile=None,
                        regexp='([0-9a-fA-F]{1,8}): ([0-9a-fA-F]+)', 
                        ):
    hProcess = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS,
                                           0,
                                           pid,
                                           )
    if outfile is None:
        outfile = infile
    ifh = open(infile, 'r')
    ofh = open(outfile, 'w')
    dump = ifh.read()
    regexp_pattern = re.compile(regexp)
    dwOldProtection = DWORD()
    dwBytesRead = DWORD()
    for item in regexp_pattern.finditer(dump):
        addr = int(item.group(1), 16)
        try:
            pSignature = binascii.a2b_hex(item.group(2)) # item.group(2) is in the form 41424344; convert to \x41\x42\x43\x44 
        except TypeError:
            print "WARNING: ignoring bad line '0x%08X: %s'" %(addr,item.group(2))
            continue
        dwSignature = len(pSignature)    
        pBytesRead = create_string_buffer(dwSignature)
        if not windll.kernel32.VirtualProtectEx(hProcess,
                                                addr,
                                                dwSignature,
                                                PAGE_READWRITE,
                                                byref(dwOldProtection),
                                                ):
            print "Can't tweak protection on 0x%08X - 0x%08X" %(addr,addr+dwSignature)
            continue
        read_OK = windll.kernel32.ReadProcessMemory(hProcess,
                                                    addr,
                                                    pBytesRead,
                                                    dwSignature,
                                                    byref(dwBytesRead),
                                                    )
        windll.kernel32.VirtualProtectEx(hProcess,
                                         addr,
                                         dwSignature,
                                         dwOldProtection,
                                         byref(dwOldProtection),
                                         )
        read_OK = read_OK and (dwBytesRead.value == dwSignature)
        if not read_OK:
            print "Can't read 0x%08X" %addr
            continue 
        if pBytesRead.raw == pSignature:
            print "address 0x%08X is FAKE! pBytesRead = %s; pSignature = %s" %(addr,binascii.b2a_hex(pBytesRead.raw),binascii.b2a_hex(pSignature))
            continue
        ofh.write("0x%08X: %s\r\n"%(addr,binascii.b2a_hex(escape_decode(pSignature)[0])))
        print "0x%08X: %s (%d bytes)" %(addr,pSignature,dwSignature)        
        
if __name__ == '__main__':
    usage = "python %s [OPTIONS] <input_binary_file_or_process_name_or_PID> <signature_to_find>" %sys.argv[0]
    usage += "\r\n\r\nExamples:\r\n"
    usage += r"[1] python %s C:\\Users\\rude-boi\\Desktop\\Pinball.exe 01308B1081FA00CA9A3B" \
        %(sys.argv[0])
    usage += "\r\nwill attempt to find the stub"
    usage += "\r\n"
    usage += """
    ->|
    MOV DWORD PTR DS:[EAX], ESI
    MOV EDX, DWORD PTR DS:[EAX]
    CMP EDX, 3B9ACA00
    |<-
    """
    usage += "\r\nin the binary C:\\Users\\rude-boi\\Desktop\\Pinball.exe !\r\n\r\n"
    usage += r"[2] python %s pinball 01308B1081FAA0860100" %(sys.argv[0])
    usage += "\r\n\r\nsame as above, but the search will be done in the pinball process's memory \
(a pinball session should be running, of course!)\r\n\r\n"
    usage += r"[3] python %s C:\\Users\\rude-boi\\Desktop\\Pinball.exe $(python -c \"print '00'*20\")" %sys.argv[0]
    usage += "\r\nwill attempt to find a codecave (a contiguous block of zero-bytes) of size 200 in \
C:\\Users\\rude-boi\\Desktop\\Pinball.exe"
    parser = OptionParser(usage=usage,
                          version=__FULL_VERSION__,
                          )
    parser.add_option('--outfile',
                      dest="outfile",
                      default=None,
                      help="""specify output file to which findings will be dumped""",
                      )
    parser.add_option('--eliminate-fake',
                      dest="eliminatefake",
                      action="store_true",
                      default=False,
                      help="""eliminate fake values from previous findings""",
                      )
    options, args = parser.parse_args()
    if len(args) < 2:
        print "Error: wrong command-line"
        parser.print_help()
        sys.exit(1)
    if not options.outfile is None:
        ofh = open(options.outfile, 'w')
    if os.path.isfile(args[0]):
        if not options.eliminatefake:
            pSignature = binascii.a2b_hex(args[1])
            print "Searching for signature %s in file %s .." %(args[1],args[0])
            for addr in FindSignatureInBinaryFile(args[0], 
                                                  pSignature,
                                                  ):
                print 'Found signature at 0x%08X' %addr
                if options.outfile:
                    ofh.write("0x%08X: %s\r\n" %(addr,binascii.b2a_hex(escape_decode(pSignature)[0])))
    else:
        try:
            pid = int(args[0])
        except ValueError:
            pid = GetProcessIdFromName(args[0])
            if not pid:
                print "Error: '%s' is neither a binary file, nor a process name, nor a PID" %args[0]
                sys.exit(1)
        hProcess = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS,
                                               0,
                                               pid,
                                               )
        if not hProcess:
            print "Error: couldn't obtain handle to process %d" %pid
            sys.exit(1)
        if not options.eliminatefake:
            pSignature = binascii.a2b_hex(args[1])
            print "Searching for signature %s in process %d .." %(args[1],pid) 
            for addr in FindSignatureInProcessMemory(hProcess ,
                                                     pSignature,
                                                     ):
                print 'Found signature at 0x%08X' %addr
                if options.outfile:
                    ofh.write("0x%08X: %s\r\n"%(addr,binascii.b2a_hex(escape_decode(pSignature)[0])))
    if options.eliminatefake:
        previous = args[1]
        outfile = previous
        if options.outfile:
            outfile = options.outfile
        print "eliminating fake findings from %s (output will be written to %s) .." %(previous, outfile)
        EliminateFakeAddresses(pid, previous, outfile)
                              
                            
    



