#!/usr/bin/python
#

import SimpleXMLRPCServer
import signstuff

server = SimpleXMLRPCServer.SimpleXMLRPCServer(("localhost", 8000))
server.register_introspection_functions()

def auth(username, password):
    if username:
        if password:
            return True
    return False

server.register_function(auth)
server.register_instance(signstuff.SigningStuff())

server.serve_forever()

