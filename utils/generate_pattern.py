"""
This tiny scripts generates handy patterns used for such stuff like stack fingerprinting (during BOF), etc.

(c) h4lf-jiffie (dohmatob elvis dopgima)
"""
import sys

def generate_pattern(size):
    """
    @description: Generates an alphanumeric irreducible pattern of given length. The output pattern is irreducible 
                  in the sense that each sub-pattern longer than 2 bytes appears exactly once!
    """

    pattern = ""

    if size > 26*26*9:
        print "Error: requested pattern too long (you certainly don't need that for an exploit)!"
        return pattern
    cnt = 0
    for x in xrange(ord('A'), ord('Z') + 1):
        for y in xrange(ord('a'), ord('z') + 1):
            for z in xrange(0x31,0x3a):
                pattern += "%s%s%s"%(chr(x),chr(y),chr(z))
                cnt += 3
                if cnt >= size:
                    break

    return pattern[:size]  

if __name__ == '__main__':
    # sanitize command-line
    if len(sys.argv) < 2:
        print "Usage: python %s [OPTIONS] <size_of_pattern_to_generate>"%sys.argv[0]
        sys.exit(1)

    print generate_pattern(int(sys.argv[1]))

