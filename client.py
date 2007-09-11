#!/usr/bin/python
#

import xmlrpclib
import sys

server = xmlrpclib.ServerProxy("http://localhost:8000")

if server.auth('jkeating', 'foobar'):
    print "success!"

key = sys.argv[1]
pkglist = sys.argv[2:]

server.doSignRPMsandVerify(key, ' '.join(pkglist))

content = """Hi there, I am going to be clearsigned.
I hope I work...
"""

signed_content = server.doClearSign(key, content)

print signed_content
