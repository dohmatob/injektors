import sys
import struct

def compute_hash(string_litteral):
    _hash = 0
    for byte in string_litteral:
        _hash += ord(byte) | 0x60
        _hash = ((_hash >> 0xD) | (_hash << (32 - 0xD)) & 0xFFFFFFFF)
        
    return _hash

def compute_rhash(_hash):
    rhash = 0
    rotor = 0xFF
    for j in xrange(0, 25, 8):
        rhash &= 0XFFFFFFFFF
        rhash |= ((_hash & rotor) >> j) << 24 - j;
        rotor <<= 8;
        
    return rhash
    
if __name__ == '__main__':
    # sanitize command-line
    if len(sys.argv) < 2:
        print "Usage: python %s <string>"%sys.argv[0]
        sys.exit(1)
        
    # compute hash
    _hash = compute_hash(sys.argv[1])
        
    # compute reverse hash
    rhash = compute_rhash(_hash)
        
    # render result
    for byte in struct.pack('<I', _hash):
        print 'db 0x%02X'%ord(byte)
    
    print hex(rhash)
        