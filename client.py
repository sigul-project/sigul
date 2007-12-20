#!/usr/bin/python -tt
#
# This copyrighted material is made available to anyone wishing to use, modify,
# copy, or redistribute it subject to the terms and conditions of the GNU
# General Public License v.2.  This program is distributed in the hope that it
# will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
# implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.  You should have
# received a copy of the GNU General Public License along with this program;
# if not, write to the Free Software Foundation, Inc., 51 Franklin Street,
# Fifth Floor, Boston, MA 02110-1301, USA. Any Red Hat trademarks that are
# incorporated in the source code or documentation are not subject to the GNU
# General Public License and may only be used or replicated with the express
# permission of Red Hat, Inc.
#
# Copyright (C) 2007  Red Hat, Inc.
# Author: Luke Macken <lmacken@redhat.com>

import os
import sys
import logging

from getpass import getpass, getuser
from optparse import OptionParser
from fedora.tg.client import BaseClient, AuthError, ServerError

__version__ = '$Revision: $'[11:-2]
__description__ = 'The sigul client'

URL = 'http://localhost:8088/'
log = logging.getLogger(__name__)

class SigulClient(BaseClient):

    def list_keys(self):
        """
        Display a list of available keys on the server
        """
        data = self.send_request('list_keys', auth=True)
        for key in data['keys']:
            log.info(key)

    def sign(self, key, pkglist):
        """
        Sign a list of packages with the specified key
        """
        log.debug("pkglist = %s" % pkglist)
        input = { 'key' : key, 'files' : ' '.join(pkglist) }
        data = self.send_request('sign', input=input, auth=True)
        log.info(data)

    def clear_sign(self, key, content):
        """
        Clear sign the specified content, which could be a filename or text
        """
        input = { 'key' : key, 'content' : content }
        if os.path.isfile(content):
            fp = open(content, 'rb')
            input['content'] = fp.read()
            fp.close()
        data = self.send_request('clear_sign', input=input, auth=True)
        if data.has_key('tg_flash') and data['tg_flash']:
            log.error(data['tg_flash'])
        else:
            log.info(data['signature'])

if __name__ == '__main__':
    usage = "usage: %prog [options]"
    parser = OptionParser(usage, description=__description__,
                          version=__version__)
    parser.add_option("-s", "--sign", action="store_true", dest="sign",
                      help="Sign a list of RPMs")
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

    client = SigulClient(URL, opts.username, None, opts.verbose)

    # Our main loop.  Ideally, we should only have to make it through this once,
    # assuming our credentials are valid.
    while True:
        try:
            if opts.sign:
                if not opts.key:
                    log.error("You need to specify a key to sign with")
                    sys.exit(-1)
                client.sign(opts.key, args)
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
