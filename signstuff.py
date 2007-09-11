#!/usr/bin/python
#

import pexpect
import rpm
import os
import gpgme
import StringIO

# Set up a dict from file.  This really needs to get better...
keydict = {}
keydefs = open('./keydefs', 'r').readlines()
for line in keydefs:
    if line.startswith('#'):
        continue
    email, keyid, passphrase = line.split(';')
    keydict[email] = {'keyid': keyid.lower(), 'passphrase': passphrase}
    
class SigningStuff:

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

        paths = list(paths)
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
        return str(retcode)

    def doClearSign(self, key, content):
        """Clearsign the provided content with the requested key.

        key is the email ID of the desired gpg key to sign with
        content is an absolute string (triple quotes)

        Returns an absolute string of the clearsigned content.
        """

        # Override gpgme's passphrase callback so that we can stuff the
        # passphrase in without prompting.
        def stuff_passphrase(uid_hint, passphrase_info, prev_was_bad, fd):
            # This is ugly ugly ugly.  Please somebody fix it...
            keyid = uid_hint.split(' ')[-1].strip('<').rstrip('>')
            os.write(fd, keydict[keyid]['passphrase'])

        ctx = gpgme.Context()
        ctx.passphrase_cb = stuff_passphrase
        sigkey = ctx.get_key(key)
        ctx.signers = [sigkey]
        plaintext = StringIO.StringIO(content)
        signature = StringIO.StringIO()

        try:
            new_sigs = ctx.sign(plaintext, signature, gpgme.SIG_MODE_CLEAR)
        except gpgme.GpgmeError, e: # handle this better
            print "Something went wrong: %s" % e
            return ''

        return signature.getvalue()

