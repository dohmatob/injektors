# quine.py by h4lf-jiffie (dohmatob elvis dopgima) a tiny ALPHA encoder
# 4CKNOWLEDGEMENTS:
#    0]-- the shellcoder's handbook

import sys
import struct

quine_decoder = (
"\xEB\x02\xEB\x05\xE8\xF9\xFF\xFF\xFF\x5E\x83\xEE\x12\x56\xB9\x08\x00"
"\x00\x00\x56\x5F\xE8\x10\x00\x00\x00\x5E\x8B\x0E\x01\xCE\x56\x56\x5F"
"\xE8\x03\x00\x00\x00\x5E\xFF\xE6\xE3\x13\x49\x8A\x07\x2C\x41\xC0\xE0"
"\x04\x47\x02\x07\x2C\x41\x88\x06\x46\x47\xEB\xEB\xC3")

def encode(buf, junz_size=0):
	encoded_buf = "" 
	for byte in buf:
		byte = ord(byte)
		right = (byte&0xF)+0x41
		left = ((byte&0xF0)>>4)+0x41
		encoded_buf += chr(left)+chr(right)
		
	encoded_buf += struct.pack('<I', len(encoded_buf) + junk_size)

	return encoded_buf
	
if __name__ == '__main__':
	raw = ""
	for byte in open("quine.bin", 'rb').read():
		raw += "\\x%02X"%ord(byte)
	print raw

	# sanitize command-line
	if len(sys.argv) < 2:
		print "Usage: python [OPTIONS] <string_to_encode>"
		sys.exit(1)

	print encode(sys.argv[1])
	
	

		
	
