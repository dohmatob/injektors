import re
from generate_pattern import *

def get_pattern_offsets(pattern, superpattern_size):
    return [match.start() for match in re.finditer(pattern, generate_pattern(superpattern_size))]    

if __name__ == '__main__':
    # sanitize command-line
    if len(sys.argv) < 2:
        print "Usage: python %s [OPTIONS] <pattern_to_search> <length_of_superpattern_to_search_in>"%sys.argv[0]
        sys.exit(1)

    hits = get_pattern_offsets(sys.argv[1], int(sys.argv[2]))

    if not hits:
        print "[+] Insoluble."
        sys.exit(1)
        
    print "[+] Pattern found at following offsets:"
    print "\t" + ', '.join([str(j) for j in hits])
