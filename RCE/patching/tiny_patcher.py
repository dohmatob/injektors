#!/usr/bin/env python
from optparse import OptionParser
import sys
import os
import re
from utils import pretty_time
import traceback

__author__ = 'd0hm4t06 3. d0p91m4 (RUDEBOI)'
__version__ = '1.0'
__full_version__ = '%s version %s: a tiny command-line binary patcher (IDA-like difs) for RCE people\r\n(c) %s October 22, 2011 -BORDEAUX' %(os.path.basename(sys.argv[0]),__version__,__author__)

def pretty_time():
    t = time.ctime()
    t = t.split(' ')
    if '' in t:
        t.remove('')
    return t[3], '-'.join([t[0],t[2],t[1],t[4]])

def patch(infile, # target binary file
          patchfile, # (IDA) patch/dif file
          patch_RE='([0-9a-fA-F]+): ([0-9a-fA-F]+) ([0-9a-fA-F]+)', # IDA-like difs
          outfile=None, # by default, overwrite input file with patched image
          revert=False, # are we patching or unpatching ?
          strict=True, # don't give a **** ? 
          ):
    if outfile is None:
        outfile = infile
    revert_flag = strict_flag = 'NO'
    if revert:
        revert_flag = 'YES'
    if strict:
        strict_flag = 'YES'
    print '++CONFIGURATION++'
    print '\tINPUT BINARY      : %s' %infile
    print '\tPATCH FILE        : %s' %patchfile
    print '\tPATCH TOKEN REGEXP: %s' %patch_RE
    print '\tOUTPUT BINARY     : %s' %outfile
    print '\tREVERT PATCH ?    : %s' %revert_flag
    print '\tSTRICTNESS ?      : %s' %strict_flag
    if revert:
        print "We'll try to revert patch %s on %s" %(patchfile,infile)
    else:
        print "We'll try patching %s with %s" %(infile,patchfile)
    ifh = open(infile, 'rb')
    bindump = ifh.read()
    pfh = open(patchfile, 'r')
    patchdump = pfh.read()
    nb_patched_bytes = 0
    patch_RE_pattern = re.compile(patch_RE)
    print 'Moon-walking a binary (generating patched image of %s)..' %(infile)
    for match in patch_RE_pattern.finditer(patchdump):
        offset, original, new = match.group(1), match.group(2), match.group(3)
        o, original_byte, new_byte = int(offset, 16), original.decode('hex'), new.decode('hex')
        try:
            if revert:
                print '%s: %02X -> %02X (byte patch)' %(offset,ord(new_byte),ord(original_byte))
                if strict and bindump[o] != new_byte:
                    raise Exception, "At %s, to-be-patched byte is not %02X (it is %02X)" %(offset,ord(new_byte),ord(bindump[o]))
                bindump = bindump[:o] + original_byte + bindump[o+1:]
            else:
                print '%s: %02X -> %02X (byte patch)' %(offset,ord(original_byte),ord(new_byte))
                if strict and bindump[o] != original_byte:
                    raise Exception, "At %s, to-be-patched byte is not %02X (it is %02X)" %(offset,ord(original_byte),ord(bindump[o]))
                bindump = bindump[:o] + new_byte + bindump[o+1:]
            nb_patched_bytes += 1
        except IndexError:
            raise Exception, "Incompartible patch file and input binary file"
    ifh.close()
    pfh.close()
    plus = 'plus'
    if revert:
        plus = 'minus'
    print 'Writing %s %s %s patch to %s (%s bytes patched)' %(infile,plus,patchfile,outfile,nb_patched_bytes)
    ofh = open(outfile, 'wb')
    ofh.write(bindump)
    ofh.close()
    
if __name__ == '__main__':
    parser = OptionParser(version=__full_version__,
                          usage='%s [options] <input_binary_file> <patch_file_1> <patch_file_2> .. <patch_file_n>' %sys.argv[0])
    parser.add_option('--revert', '-r',
                     action='store_true',
                     default=False,
                     dest='revert',
                     help="""revert patch (option disabled by default)"""
                     )
    parser.add_option('--outputfile', '-o',
                      action='store',
                      dest='outputfile',
                      help="""specify file to which output binary will be writen (by default, we'll overwrite the input binary file)"""
                      )
    parser.add_option('--disable-strict',
                     action='store_true',
                     default=False,
                     dest='disablestrict',
                     help="""in case of minor binary/patch compatibility troubles -e.g some patch token are contradictory w.r.t target binary file, etc.-, ignore and move on  (option disabled by default)""" 
                     )
    options, args = parser.parse_args()
    if len(args) < 2:
        parser.error('invalid command-line arguments')
    infile, patchfiles = args[0], args[1:]
    print __full_version__
    print 
    print 'Starting engines at %s (%s)' %pretty_time()
    for patchfile in patchfiles:
        try:
            patch(infile, 
                  patchfile, 
                  outfile=options.outputfile, 
                  revert=options.revert,
                  strict=(not options.disablestrict)
                  )
        except:
            print 'caught excepiton while patching %s with %s (see traceback below); patch will be ignored\n%s' %(infile,patchfile,traceback.format_exc())
            pass
    print 'Done: %s (%s).' %pretty_time()
