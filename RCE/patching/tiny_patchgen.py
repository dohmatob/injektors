#!/usr/bin/env python
import re
from optparse import OptionParser
import sys
import os
import time

__author__ = 'd0hm4t06 3. d0p91m4 (RUDEBOI)'
__version__ = '1.0'
__full_version__ = '%s version %s: a tiny command-line binary patch generator of IDA-like difs\r\n(c) %s' %(os.path.basename(sys.argv[0]),__version__,__author__)

def pretty_time():
    t = time.ctime()
    t = t.split(' ')
    if '' in t:
        t.remove('')
    return t[3], '-'.join([t[0],t[2],t[1],t[4]])

def diff(infile_1, # first input file
         infile_2, # second input file
         outfile=None): # write output to file ?
    print 'Starting engines at %s (%s)' %pretty_time()
    print '+++CONFIGURATION+++'
    print '\tFIRST INPUT FILE : %s' %infile_1
    print '\tSECOND INPUT FILE: %s' %infile_2
    print '\tOUTPUT FILE      : %s' %outfile
    ifh_1 = open(infile_1, 'rb')
    dump_1 = ifh_1.read()
    ifh_1.close()
    ifh_2 = open(infile_2, 'rb')
    dump_2 = ifh_2.read()
    ifh_2.close()
    ofh = None
    if not outfile is None:
        ofh = open(outfile, 'w')
        metadata = 'Local time: %s\r\nThis patch was generated by %s\r\n' %(time.ctime(),__full_version__)
        data = ''
    l = min(len(dump_1), len(dump_2))
    print 'Comparing %s byte-wise against %s' %(infile_1,infile_2)
    nb_patch_bytes = 0
    for j in xrange(l):
        if dump_1[j] != dump_2[j]:
            nb_patch_bytes += 1
            offset = '%08X' %j # 8-byte address
            diff_token = '%s: %02X %02X' %(offset,ord(dump_1[j]),ord(dump_2[j]))
            if not ofh is None:
                data += diff_token + '\r\n'
            print diff_token
    if not ofh is None:
        metadata += 'Size: %s patch tokens\r\n\r\n' %nb_patch_bytes
        ofh.write(metadata + data + '\r\n')
        print 'Patch written to %s (%s patch tokens)' %(outfile,nb_patch_bytes)
        ofh.close()
    print 'Done: %s (%s).' %pretty_time()


if __name__ == '__main__':
    parser = OptionParser(version=__full_version__,
                          usage='%s [options] <input_binary_file_1> <input_binary_file_2>' %sys.argv[0])
    parser.add_option('--outputfile', '-o',
                      action='store',
                      dest='outputfile',
                      help="""specify file to which patch should be writen"""
                      )
    options, args = parser.parse_args()
    if len(args) != 2:
        parser.error('invalid command-line arguments')
    infile_1, infile_2 = args
    print __full_version__
    diff(infile_1, 
         infile_2, 
         outfile=options.outputfile
         )