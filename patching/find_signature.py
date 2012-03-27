from optparse import OptionParser
import sys
import os
import re   
from libdebug.debug import *
from libdebug.constants import *
from libgadget.gadget import *
from ctypes import *
from codecs import escape_encode, escape_decode
import binascii 
import struct

__AUTHOR__ = 'h4lf-jiffie (dohmatob elvis dopgima)'
__VERSION__ = '%s-1.0dev'%os.path.basename(sys.argv[0])
__FULL_VERSION__ = '%s : a tiny command-line tool that finds locations of a specified byte-sequence (signature)\
 in PE binary or process memory\r\n\r\n(c) %s October 22, 2011 (BORDEAUX)' %(__VERSION__,__AUTHOR__)

def mapped_mem_MBI(mbi):
    return mbi.Type == MEM_MAPPED

if __name__ == '__main__':
    # command-line stuff
    usage = "python %s [OPTIONS] <input_binary_file_or_process_name_or_PID> <signature_to_find>" %sys.argv[0]
    usage += "\r\n\r\nExamples:\r\n"
    usage += r"[1] python %s C:\\Users\\rude-boi\\Desktop\\Pinball.exe 01308B1081FA00CA9A3B" \
        %(sys.argv[0])
    usage += "\r\n> will attempt to find the stub"
    usage += "\r\n"
    usage += """
    ->|		
    MOV DWORD PTR DS:[EAX], ESI
    MOV EDX, DWORD PTR DS:[EAX]
    CMP EDX, 3B9ACA00
    |<-
    """
    usage += "\r\nin the binary C:\\Users\\rude-boi\\Desktop\\Pinball.exe\r\n\r\n"
    usage += r"[2] python %s pinball 01308B1081FAA0860100" %(sys.argv[0])
    usage += "\r\n\r\n> same as above, but the search will be done in the pinball process's memory \
(a pinball session should be running, of course!)\r\n\r\n"
    usage += r"[3] python %s C:\\Users\\rude-boi\\Desktop\\Pinball.exe $(python -c \"print '00'*20\")" %sys.argv[0]
    usage += "\r\n> will attempt to find a codecave (a contiguous block of zero-bytes) of size 200 in \
C:\\Users\\rude-boi\\Desktop\\Pinball.exe"
    usage += r"[4] python %s C:\\Users\\rude-boi\\Desktop\\Pinball.exe $(python -c \"print '00'*20\")" %sys.argv[0]
    usage += "\r\n> will attempt to find a codecave (a contiguous block of zero-bytes) of size 200 in \
C:\\Users\\rude-boi\\Desktop\\Pinball.exe"
    parser = OptionParser(usage=usage,
                          version=__FULL_VERSION__,
                          )
    parser.add_option('--pcregexp',
                      dest="pcregexp",
                      default=False,
		      action="store_true",
                      help="""indicates that the sought-for signature is actually a PCRE""",
                      )
    parser.add_option('--alpha',
                      dest="alpha",
                      default=False,
		      action="store_true",
                      help="""indicates that hit addresses with non-alphabetic bytes should be ignored""",
                      )
    parser.add_option('--alphanum',
                      dest="alphanum",
                      default=False,
		      action="store_true",
                      help="""indicates that hit addresses with non-alpha-numeric bytes should be ignored""",
                      )
    parser.add_option('--zero-free',
                      dest="zerofree",
                      default=False,
		      action="store_true",
                      help="""indicates that hit addresses with zero bytes should be ignored""",
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
    parser.add_option('--max-hits',
                      dest="maxhits",
                      default=None,
		      type=int,
		      action="store",
                      help="""specifies tha maximum number of results to return""",
                      )
    parser.add_option('--gadget',
                      dest="gadget",
                      default=False,
		      action="store_true",
                      help="""search for gadget""",
                      )
    options, args = parser.parse_args()
    
    if len(args) < 2:
        print "Error: wrong command-line"
        parser.print_help()
        sys.exit(1)
	
    pSignature = args[1] # binascii.a2b_hex(args[1])
    isBadAddress = None
    
    # --gadget switch entered
    if options.gadget:
        options.pcregexp = True
        pSignature = ""
        for item in args[1].split(","):
            basic = generate_basic_gadget(item)
            if basic is None:
                parser.error("Unknown/unsupported gadget '%s'"%args[1])
            pSignature += basic

    # --alpha switch entered
    if options.alpha:
	isBadAddress = is_nonalpha
        l = 0x41414141 # 0x41 = 'A' is the least possible alphabetic byte
        if options.lower:
            options.lower = max(options.lower, l)
        else:
            options.lower = l
        u = 0x7A7A7A7A # 0x7A = 'z' is the largest possible alphabetic byte
        if options.upper:
            options.upper = min(options.upper, u)
        else:
            options.upper = u
            
    # --alphanum switch entered
    if options.alphanum:
	isBadAddress = is_nonalphanum
        l = 0x30303030 # 0x30 = '0' is the least possible alpha-numeric byte
        if options.lower:
            options.lower = max(options.lower, l)
        else:
            options.lower = l
        u = 0x7A7A7A7A  
        if options.upper:
            options.upper = min(options.upper, u)
        else:
            options.upper = u
            
    # --zero-free switch entered
    if options.zerofree:
	isBadAddress = is_notzerofree
        l = 0x01010101  # 0x01 is the least possible non-zero byte
        if options.lower:
            options.lower = max(options.lower, l)
        else:
            options.lower = l
	
    # --pcregexp switch
    if not options.pcregexp:
        pSignature = r'%s'%(pSignature)
        
    # do real business now
    print "\r\n   --[ %s by %s ]--\r\n"%(__VERSION__,__AUTHOR__)
    if os.path.isfile(args[0]):
	print "[*] Searching for signature %s in file %s ..\r\n" %(args[1],args[0])
	for addr in FindSignatureInBinaryFile(args[0], 
					      pSignature,
					      isBadAddress=isBadAddress,
					      lower=options.lower,
					      upper=options.upper,
					      ):
	    print '[*] Found signature at 0x%08X.' %addr
    else:
        try:
            pid = int(args[0])
        except ValueError:
            pid = GetProcessIdFromName(args[0])
            if not pid:
                print "[*] Error: '%s' is neither a binary file, nor a process name, nor a PID." %args[0]
                sys.exit(1)
        hProcess = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS,
                                               0,
                                               pid,
                                               )
        if not hProcess:
            print "[*] Error: Couldn't obtain handle to process %d." %pid
            sys.exit(1)
	print "[*] Searching for signature '%s' in process %d ..\r\n" %(pSignature,pid) 
	for addr, sig in FindSignatureInProcessMemory(hProcess,
						 pSignature,
						 isBadAddress=isBadAddress,
                                                 isBadMbi=mapped_mem_MBI,
						 lower=options.lower,
						 upper=options.upper,
                                                 max_hits=options.maxhits,
						 ):
            printable = ""
            for byte in sig:
                printable += "\\x%02X"%ord(byte)
	    print "[*]\tFound '%s' at 0x%08X."%(printable,addr)
                              
                            
    



