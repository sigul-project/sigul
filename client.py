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

URL = 'http://localhost:8088/'
log = logging.getLogger(__name__)


class SigningClient(BaseClient):

    def list_keys(self):
        data = self.send_request('list_keys', auth=True)
        for key in data['keys']:
            log.info(key)

    def sign_packages(self, key, pkglist):
        retval = server.doSignRPMsandVerify(key, ' '.join(pkglist))
        log.info(data['tg_flash'])

    def clear_sign(self, key, content):
        input = { 'key' : key, 'content' : content }
        data = self.send_request('clear_sign', input=input, auth=True)
        if data.has_key('tg_flash') and data['tg_flash']:
            log.error(data['tg_flash'])
        else:
            log.info(data['signature'])

if __name__ == '__main__':
    usage = "usage: %prog [options]"
    parser = OptionParser(usage, description=__description__,
                          version=__version__)
    parser.add_option("-s", "--sign", action="store", type="string",
                      dest="sign", metavar="BUILDS",
                      help="Sign builds")
    parser.add_option("-k", "--key", action="store", type="string",
                      dest="key", help="Specify a GPG key to sign with")
    parser.add_option("-c", "--clear", action="store", type="string",
                      dest="clear", help="Make a clear text signature")
    parser.add_option("-l", "--list", action="store_true", dest="list",
                      help="List available keys")
    parser.add_option("-u", "--username", action="store", type="string",
                      dest="username", default=getuser(),
                      help="Fedora username")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      help="Show debugging messages")
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

    client = SigningClient(URL, opts.username, None, opts.verbose)

    while True:
        try:
            if opts.sign:
                client.sign(opts)
            elif opts.list:
                client.list_keys()
            elif opts.clear:
                if not opts.key:
                    log.error("You need to specify a key to sign with")
                    sys.exit(-1)
                client.clear_sign(opts.key, opts.clear)
            else:
                parser.print_help()
            break
        except AuthError:
            client.password = getpass('Password for %s: ' % opts.username)
        except ServerError, e:
            log.error(e.message)
            sys.exit(-1)
