#!/usr/bin/python
__requires__="TurboGears"
import pkg_resources

from turbogears import config, update_config, start_server
import cherrypy
cherrypy.lowercase_api = True
from os.path import *
import sys

# first look on the command line for a desired config file,
# if it's not on the command line, then
# look for setup.py in this directory. If it's not there, this script is
# probably installed
if len(sys.argv) > 1:
    update_config(configfile=sys.argv[1], modulename="sigul.config")
elif exists(join(dirname(__file__), "setup.py")):
    update_config(configfile="dev.cfg",modulename="sigul.config")
else:
    update_config(configfile="prod.cfg",modulename="sigul.config")
config.update(dict(package="sigul"))

# Check if gpg-agent is running, and bail out
import os
if not os.WEXITSTATUS(os.system("pidof gpg-agent >/dev/null")):
    print "Error: gpg-agent is running, which is known to cause issue with gpgme."
    sys.exit(-1)

from sigul.controllers import Root
start_server(Root())
