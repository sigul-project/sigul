#!/usr/bin/python -tt
# Copyright 2007  Red Hat, Inc.
# Luke Macken <lmacken@redhat.com>

import sys
import logging

from getpass import getpass, getuser
from optparse import OptionParser
from fedora.tg.client import BaseClient, AuthError, ServerError

__version__ = '$Revision: $'[11:-2]
__description__ = 'The signing client'

log = logging.getLogger(__name__)
URL = 'http://localhost:8088'

class SigningClient(BaseClient):

    def list_keys(self):
        # keys = server.doListKeys(authstuff)
        # for kmail, keyid in keys:
        #   print "%s (%s)" % (kmail, keyid)
        data = self.send_request('listkeys', auth=True)
        log.info(data)

    #def sign_packages(key, pkglist):
    #    retval = server.doSignRPMsandVerify(key, ' '.join(pkglist))
    #    if not retval:
    #        print "Signing successful"
    #    else:
    #        print "Signing failed."
    #    return retval

    #def clear_sign(key, content):
    #    signed_content = server.doClearSign(key, content)
    #    return signed_content

if __name__ == '__main__':
    usage = "usage: %prog [options]"
    parser = OptionParser(usage, description=__description__,
                          version=__version__)
    parser.add_option("-s", "--sign", action="store", type="string",
                      dest="sign", metavar="BUILDS",
                      help="Mark an update for push to stable")
    parser.add_option("-k", "--key", action="store", type="string",
                      dest="key", help="Specify a GPG key to sign with")
    parser.add_option("-c", "--clear", action="store_true",
                      dest="clear", help="Make a clear text signature")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      help="Show debugging messages")
    parser.add_option("-l", "--list", action="store_true", dest="list",
                      help="List available keys")
    parser.add_option("-u", "--username", action="store", type="string",
                      dest="username", default=getuser(),
                      help="Fedora username")
    (opts, args) = parser.parse_args()

    # Setup the logger
    sh = logging.StreamHandler()
    if opts.verbose:
        log.setLevel(logging.DEBUG)
        sh.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
        sh.setLevel(logging.INFO)
    format = logging.Formatter("%(message)s")
    sh.setFormatter(format)
    log.addHandler(sh)

    #client = SigningClient(URL, opts.username, None, debug=opts.verbose)
    client = SigningClient(URL, opts.username, None)

    while True:
        try:
            if opts.sign:
                client.sign(opts)
            elif opts.list:
                client.list_keys()
            else:
                parser.print_help()
            break
        except AuthError:
            client.password = getpass('Password for %s: ' % opts.username)
        except ServerError, e:
            log.error(e.message)
            sys.exit(-1)
