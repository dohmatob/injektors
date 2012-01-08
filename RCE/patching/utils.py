"""
(c) d0hm4t06 3. d0p91m4 (RUDEBOI) December 13, 2011 -BORDEAUX
"""

import time
import sys

def pretty_time():
    t = time.ctime()
    t = t.split(' ')
    if '' in t:
        t.remove('')
    return t[3], '-'.join([t[0],t[2],t[1],t[4]])

def debug(msg):
    print "[*] %s" %msg

def die(reason):
    debug(reason)
    sys.exit(0)
