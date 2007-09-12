#!/usr/bin/python
#

import xmlrpclib
import sys

def list_keys():
    # keys = server.doListKeys(authstuff)
    # for kmail, keyid in keys:
    #   print "%s (%s)" % (kmail, keyid)
    print "Not implemented"
    
def sign_packages(key, pkglist):
    retval = server.doSignRPMsandVerify(key, ' '.join(pkglist))
    if not retval:
        print "Signing successful"
    else:
        print "Signing failed."
    return retval

def clear_sign(key, content):
    signed_content = server.doClearSign(key, content)
    return signed_content

server = xmlrpclib.ServerProxy("http://localhost:8000")

if server.auth('jkeating', 'foobar'):
    print "success!"

key = sys.argv[1]
pkglist = sys.argv[2:]

sign_packages(key, pkglist)

content = """Hi there, I am going to be clearsigned.
I hope I work...
"""

print clear_sign(key, content)

