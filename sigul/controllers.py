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
# Copyright (C) 2007  Red Hat, Inc. All rights reserved.
# Author: Luke Macken <lmacken@redhat.com>

import os
import rpm
import gpgme
import pexpect
import logging

from model import Key, KeyNotFound
from StringIO import StringIO
from cherrypy import request, response
from turbogears import controllers, expose, flash
from turbogears import identity, redirect

log = logging.getLogger("sigul.controllers")

class Root(controllers.RootController):

    @expose()
    def login(self, forward_url=None, previous_url=None, *args, **kw):
        if not identity.current.anonymous \
           and identity.was_login_attempted() \
           and not identity.get_identity_errors():
            return dict(user=identity.current.user)
        forward_url=None
        previous_url= request.path
        if identity.was_login_attempted():
            msg=_("The credentials you supplied were not correct or "
                   "did not grant access to this resource.")
        elif identity.get_identity_errors():
            msg=_("You must provide your credentials before accessing "
                   "this resource.")
        else:
            msg=_("Please log in.")
            forward_url= request.headers.get("Referer", "/")
        return dict(message=msg, previous_url=previous_url, logging_in=True,
                    original_parameters=request.params,
                    forward_url=forward_url)

    @expose()
    @identity.require(identity.in_group("releng"))
    def list_keys(self):
        """
        @return: A list of keys in our database
        """
        return dict(keys=[str(key) for key in Key.select()])

    @expose()
    @identity.require(identity.in_group("releng"))
    def clear_sign(self, key, content):
        """
        Clearsign the provided content with the requested key.

        @param key: The key id/name/email
        @param content: The string of content to sign
        @return: The provided content signed with the given key
        """
        log.debug("clear_sign(%s, %s)" % (key, content))
        try:
            key = Key.fetch(key)
        except KeyNotFound, e:
            flash(e)
            return dict()

        # Override gpgme's passphrase callback so that we can utilize
        # the passphrase in our database, rather than prompting us
        def passphrase_cb(uid_hint, passphrase_info, prev_was_bad, fd):
            os.write(fd, key.passphrase + '\n')

        ctx = gpgme.Context()
        ctx.armor = True
        sigkey = ctx.get_key(key.key_id)
        ctx.signers = [sigkey]
        ctx.passphrase_cb = passphrase_cb
        plaintext = StringIO(str(content))
        signature = StringIO()

        try:
            new_sigs = ctx.sign(plaintext, signature, gpgme.SIG_MODE_CLEAR)
            log.info("Successfully clear signed the following with %s\n%s" %
                    (key.name, content))
        except gpgme.GpgmeError, e:
            flash("Error: %s" % e)
            return dict()

        return dict(signature=signature.getvalue())

    @expose()
    @identity.require(identity.in_group("releng"))
    def sign(self, key, files):
        """
        Sign all packages in paths with the given key.  Verify signature.
        Returns return code from rpm call.

        @param key: The key id/name/email
        @param files: A list of RPMs to sign
        """
        try:
            key = Key.fetch(key)
        except KeyNotFound, e:
            flash(e)
            return dict()

        # Set up the rpm signing command as a list
        command = ['rpm', '--define', '_gpg_name %s' % key.key_id, '--resign']
        command.extend(files.split())

        # now for some expect fun (open to suggestions on how to do this better)
        p = pexpect.spawn(command[0], command[1:], timeout=200)

        # Being a bit adventurous - no need for timeouts
        p.delaybeforesend = 0
        p.delayafterclose = 0
        p.expect('Enter pass phrase:')
        p.sendline(key.passphrase + '\n')
        i = p.expect(['Pass phrase is good.', 'Pass phrase check failed',])
        log.debug("rpm returned with %s" % i)
        data = p.after
        p.expect(pexpect.EOF)
        p.close()
        retcode = p.exitstatus

        if i == 1:
            flash("Pass phrase check failed")
            return dict()

        # Check to see if rpm returned happy, and if so, verify signed paths
        if not retcode:
            resign = self._doReturnUnsignedRPMs(key, files)
            if resign:
                # We have some that didn't get signed, try again.
                self.doSignRPMsandVerify(key, ' '.join(resign))

        # Pass up return code to calling function.
        return retcode

    def _doReturnUnsignedRPMs(self, key, paths):
        """Verify that the rpms listed in paths are signed with the given key.
           Returns any paths that aren't signed with key."""

        unsigned = []
        ts = rpm.TransactionSet()
        ts.setVSFlags(~(rpm.RPMVSF_NOMD5|rpm.RPMVSF_NEEDPAYLOAD))
        string = '%|SIGGPG?{%{SIGGPG:pgpsig}}|' # not sure if this is right...
        stderr = os.dup(2)
        null = os.open("/dev/null", os.O_WRONLY | os.O_APPEND)
        os.dup2(null, 2)

        # Do some verification here
        for package in paths:
            fdno = os.open(package, os.O_RDONLY)
            try:
                hdr = ts.hdrFromFdno(fdno)
            except rpm.error, e:
                if str(e) == "error reading package header":
                    print "Package %s unreadable." % package # needs to be a raise. 

            sigtype, sigdate, sigkey = hdr.sprintf(string).split(',')
            gpgkey = sigkey[-8:]
            if not gpgkey == keydict[key]['keyid']:
                print "%s is not signed with %s." % (package, key)
                unsigned.append(package)
            os.close(fdno)

        os.dup2(stderr, 2)
        os.close(null)
        os.close(stderr)

        return unsigned


## Some useful methods for sending messages to our logger,
## as well as the client
def error(msg):
    log.error(msg)
    flash(msg)
    return msg

def info(msg):
    log.info(msg)
    flash(msg)
    return msg
