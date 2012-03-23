from optparse import OptionParser
import sys
import os
import re
from libdebug.debug import *
from libdebug.constants import *
from ctypes import *
from codecs import escape_decode
import binascii
import struct

__AUTHOR__ = 'dohmatob elvis dopgima (h4lf-jiffie)'
__VERSION__ = '1.0dev'
__FULL_VERSION__ = '%s version %s: a tiny command-line tool that finds locations of a specified byte-sequence (signature)\
 in PE binary or process memory\r\n\r\n(c) %s October 22, 2011 (BORDEAUX)' %(os.path.basename(sys.argv[0]),__VERSION__,\
__AUTHOR__)

def is_nonalpha(addr):
    for byte in struct.pack('<I', addr):
	if not byte.isalpha():
	    return True
    return False

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
    parser.add_option('--alpha',
                      dest="alpha",
                      default=False,
		      action="store_true",
                      help="""indicates that only hit addresses with alphabetic bytes should be returned""",
                      )
    parser.add_option('--lower',
                      dest="lower",
                      default=None,
		      type=int,
		      action="store",
                      help="""indicates lower bound for memory region to scrape""",
                      )
    parser.add_option('--upper',
                      dest="upper",
                      default=None,
		      type=int,
		      action="store",
                      help="""indicates upper bound for memory region to scrape""",
                      )
    options, args = parser.parse_args()
    
    if len(args) < 2:
        print "Error: wrong command-line"
        parser.print_help()
        sys.exit(1)
	
    isBadAddress = None
    if options.alpha:
	isBadAddress = is_nonalpha
	
    if os.path.isfile(args[0]):
	pSignature = binascii.a2b_hex(args[1])
	print "Searching for signature %s in file %s .." %(args[1],args[0])
	for addr in FindSignatureInBinaryFile(args[0], 
					      pSignature,
					      isBadAddress=isBadAddress,
					      lower=options.lower,
					      upper=options.upper,
					      ):
	    print 'Found signature at 0x%08X' %addr
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
	pSignature = binascii.a2b_hex(args[1])
	print "Searching for signature '%s' in process %d .." %("".join(["\\x%s"%args[1][j:j+2] for j in xrange(0,len(args[1]),2)]),pid) 
	for addr in FindSignatureInProcessMemory(hProcess,
						 pSignature,
						 isBadAddress=isBadAddress,
						 lower=options.lower,
						 upper=options.upper,
						 ):
	    print 'Found signature at 0x%08X' %addr
                              
                            
    



