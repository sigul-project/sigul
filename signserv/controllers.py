import os
import gpgme
import logging
import StringIO

from model import Key
from cherrypy import request, response
from turbogears import controllers, expose, flash
from turbogears import identity, redirect

log = logging.getLogger("signserv.controllers")

class Root(controllers.RootController):

    @expose("json", as_format="json")
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

    @expose("json", as_format="json")
    @identity.require(identity.in_group("releng"))
    def list_keys(self):
        """ Return list of keys """
        return dict(keys=map(unicode, Key.select()))

    @expose("json", as_format="json")
    @identity.require(identity.in_group("releng"))
    def clear_sign(self, key, content):
        """
            Clearsign the provided content with the requested key.
        """

        # Override gpgme's passphrase callback so that we can utilize
        # the passphrase in our database, rather than prompting us
        def passphrase_cb(uid_hint, passphrase_info, prev_was_bad, fd):
            # This is ugly ugly ugly.  Please somebody fix it...
            keyid = uid_hint.split(' ')[-1].strip('<').rstrip('>')
            key = Key.select(Key.q.email == keyid)[0]
            os.write(fd, key.passphrase + '\n')

        ctx = gpgme.Context()
        ctx.armor = True
        sigkey = ctx.get_key(key)
        ctx.signers = [sigkey]
        ctx.passphrase_cb = passphrase_cb
        plaintext = StringIO.StringIO(str(content))
        signature = StringIO.StringIO()

        try:
            new_sigs = ctx.sign(plaintext, signature, gpgme.SIG_MODE_CLEAR)
        except gpgme.GpgmeError, e: # handle this better
            flash("Something went wrong: %s" % e)
            return dict()

        return dict(signature=signature.getvalue())

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

    def doSignRPMsandVerify(self, key, *paths):
        """Sign all packages in paths with the given key.  Verify signature.
           Returns return code from rpm call."""

        # Set up the rpm signing command as a list
        command = ['rpm', '--define', '_gpg_name %s' % key, '--resign']
        command.extend(paths)

        # now for some expect fun (open to suggestions on how to do this better)
        p = pexpect.spawn(command[0], command[1:], timeout=200)

        # Being a bit adventurous - no need for timeouts
        p.delaybeforesend = 0
        p.delayafterclose = 0
        p.expect('Enter pass phrase:')
        p.sendline(keydict[key]['passphrase'])
        i = p.expect(['Pass phrase is good.', 'Pass phrase check failed',])
        data = p.after
        p.expect(pexpect.EOF)
        p.close()
        retcode = p.exitstatus

        if i == 1:
            # Pass phrase check failed This should be a raise
            print "Pass phrase check failed"
            return retcode

        # Check to see if rpm returned happy, and if so, verify signed paths
        if not retcode:
            resign = self._doReturnUnsignedRPMs(key, paths)
            if resign:
                # We have some that didn't get signed, try again.
                self.doSignRPMsandVerify(key, ' '.join(resign))

        # Pass up return code to calling function.
        return retcode
