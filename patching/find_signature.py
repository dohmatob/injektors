from optparse import OptionParser
import sys
import os
import traceback
from libutils.debug import *

__AUTHOR__ = 'dohmatob elvis dopgima (h4lf-jiffie)'
__VERSION__ = '1.0dev'
__FULL_VERSION__ = '%s version %s: a tiny command-line tool that finds locations of a specified byte-sequence (signature)\
 in PE binary or process memory\r\n\r\n(c) %s October 22, 2011 (BORDEAUX)' %(os.path.basename(sys.argv[0]),__VERSION__,\
__AUTHOR__)

if __name__ == '__main__':
    usage = "python %s [OPTIONS] <input_binary_file_or_process_name_or_PID> <signature_to_find>" %sys.argv[0]
    usage += "\r\n\r\nExamples:\r\n"
    usage += r"[1] python %s C:\\Users\\rude-boi\\Desktop\\Pinball.exe \x01\x30\x8B\x10\x81\xFA\x00\xCA\x9A\x3B" \
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
    usage += r"[2] python %s pinball \x01\x30\x8B\x10\x81\xFA\xA0\x86\x01\x00" %(sys.argv[0])
    usage += "\r\n\r\nsame as above, but the search will be done in the pinball process's memory \
(a pinball session should be running, of course!)\r\n\r\n"
    usage += r"[3] python %s C:\\Users\\rude-boi\\Desktop\\Pinball.exe $(python -c \"print '\\x00'*20\")" %sys.argv[0]
    usage += "\r\nwill attempt to find a codecave (a contiguous block of zero-bytes) of size 200 in \
C:\\Users\\rude-boi\\Desktop\\Pinball.exe"
    parser = OptionParser(usage=usage,
                          version=__FULL_VERSION__,
                          )
    options, args = parser.parse_args()
    if os.path.isfile(args[0]):
        print "Searching for signature %s in file %s .." %(args[1],args[0])
        results = FindSignatureInBinaryFile(args[0], 
                                            args[1],
                                            )
        for result in  results:
            print 'Found signature at 0x%08X' %result
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
        print "Searching for signature %s in process %d .." %(args[1],pid)
        results = FindSignatureInProcessMemory(hProcess, 
                                               args[1],
                                               ) 
        for result in results:
            print 'Found signature at 0x%08X' %result
        

    



