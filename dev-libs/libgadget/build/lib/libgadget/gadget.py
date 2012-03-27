import struct

# API/stub signatures
ABUSABLE_XHANDLER_SIGNATURE = (
"\\x55\\x8B\\xEC\\x83\\xEC\\x08\\x53\\x56\\x57\\x55\\xFC\\x8B\\x5D\\x0C\\x8B"
"\\x45\\x08\\xF7\\x40\\x04\\x06\\x00\\x00\\x00")

#
# fundamental gadget generators
#

def generate_basic_gadget(kind, **kwargs):
    if kind == "popr32":
        return generate_popr32(**kwargs)
        
    elif kind == "ret":
        return generate_ret(**kwargs)
        
    elif kind == "nop":
        return generate_nop(**kwargs)
        
    elif kind == "shortjmp":
        return generate_shortjmp(**kwargs) 
    else:
        return None
    
def generate_popr32(**kwargs):
    return "[\\x58\\x59\\x5A\\x5B\\x5E\\x5F]"

def generate_ret(**kwargs):
    return "(?:\\xC3|\\xC2[%s])"%''.join(['\\x%02X'%j for j in xrange(0,0xF0)])

def generate_nop(**kwargs):
    return "(?:\\x90|[\\x40\\x41\\x42\\x43\\x46\\x47\\x48\\x49\\x4A\\x4B\\x4E\\x4F])"

def generate_shortjmp(**kwargs):
    size = "."
    if 'size' in kwargs:
        size = struct.pack('B', kwargs['size']&0xFF)
    return "\\xEB%s"%size

#
# 'bad ddress' filters
#
def is_nonalpha(addr):
    """
    @description: Non-alpha filter
    """
    for byte in struct.pack('<I', addr):
        if not byte.isalpha():
            return True
    return False

def is_nonalphanum(addr):
    """
    @description: Non-alphanum filter
    """
    for byte in struct.pack('<I', addr):
        if not (byte.isalpha() or (ord(byte) in xrange(0x30,0x3A))):
            return True
        
    return False
    
def has_zero(addr):
    """
    @description: Zero-byte filter
    """
    for byte in struct.pack('<I', addr):
        if ord(byte) == 0:
            return True
    return False

def is_notzerofree(addr):
    return has_zero(addr)