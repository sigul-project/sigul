# Copyright (C) 2019 Red Hat, Inc.  All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use, modify,
# copy, or redistribute it subject to the terms and conditions of the GNU
# General Public License v.2.  This program is distributed in the hope that it
# will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
# implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.  You should have
# received a copy of the GNU General Public License along with this program; if
# not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.  Any Red Hat trademarks that are
# incorporated in the source code or documentation are not subject to the GNU
# General Public License and may only be used or replicated with the express
# permission of Red Hat, Inc.
#
# Red Hat Author: Patrick Uiterwijk <puiterwijk@redhat.com>


class GPGError(Exception):
    '''Error performing a GPG operation.'''
    pass


try:
    # Implement based on top of python-gpg
    import gpg.core
    import gpg.constants
    import gpg.errors

    def wrapsio(ioval):
        """ Return a gpg.core.Data from an ioval. """
        def readcb(amount, hook=None):
            raise NotImplementedError("readcb not implemented!")

        def writecb(data, hook=None):
            ioval.write(data.decode('utf-8'))
            return len(data)

        def seekcb(offset, whence, hook=None):
            raise NotImplementedError("seekcb is not implemented!")

        def releasecb(hook=None):
            pass

        cbs = (readcb, writecb, seekcb, releasecb)

        return gpg.core.Data(cbs=cbs)

    GPGMEError = gpg.errors.GPGMEError
    constants = gpg.constants

    class Context(gpg.core.Context):
        @property
        def is_gpgv2(self):
            return self.engine_info.version[0] == "2"

        def delete(self, key, delete_secret):
            return self.op_delete(key, delete_secret)

        def edit(self, key, func, sink):
            def wrapper(*args, **kwargs):
                res = func(*args)
                if isinstance(res, bytes):
                    res = res.decode('utf-8')
                return res

            def pass_cb(unused_uid_int, info, prev_was_bad, hook=None, *args):
                return func(
                    gpg.constants.STATUS_GET_HIDDEN,
                    "passphrase.enter"
                )

            self.set_passphrase_cb(pass_cb)
            self.interact(key, wrapper, wrapsio(sink))

        def export(self, fingerprint, data):
            res = self.op_export(fingerprint, 0, wrapsio(data))
            return res

        def sigul_import(self, key_file):
            self.op_import(key_file)
            r = self.op_import_result()
            if (r.imported == 0 and r.secret_imported == 0
                    and len(r.imports) == 1
                    and (r.imports[0].status & gpg.constants.IMPORT_NEW) == 0):
                raise GPGError('Key already exists')
            if (r.imported != 1 or r.secret_imported != 1
                or len(r.imports) != 2
                or set((r.imports[0].status, r.imports[1].status))
                != set((gpg.constants.IMPORT_NEW,
                        gpg.constants.IMPORT_NEW
                        | gpg.constants.IMPORT_SECRET))
                    or r.imports[0].fpr != r.imports[1].fpr):
                raise GPGError('Unexpected import file contents')
            gpg.errors.errorcheck(r.imports[0].result)
            gpg.errors.errorcheck(r.imports[1].result)
            return r.imports[0].fpr

        def sigul_encrypt_symmetric(self, cleartext, passphrase):
            cleartext = cleartext.encode('utf-8')
            enc, _, _ = self.encrypt(cleartext,
                                     passphrase=passphrase,
                                     sign=False)
            return enc

        def sigul_decrypt_symmetric(self, ciphertext, passphrase):
            dec, _, _ = self.decrypt(ciphertext,
                                     passphrase=passphrase)
            dec = dec.decode('utf-8')
            return dec

        def sigul_set_passphrase(self,
                                 passphrase,
                                 fingerprint=None,
                                 errlist=None):
            '''Let ctx use passphrase.'''
            def cb(unused_uid_int, info, prev_was_bad, hook=None, *args):
                if prev_was_bad:
                    if fingerprint:
                        correct_key = False
                        for kid in info.split()[:2]:
                            if fingerprint.endswith(kid):
                                correct_key = True
                                break
                        if not correct_key:
                            error = GPGError(
                                'Requested key %s not in unlocked keys %s'
                                % (fingerprint, info))
                            if errlist is not None:
                                errlist.append(error)
                            raise error
                    else:
                        raise GPGError('Key passphrase incorrect?')
                return passphrase
            self.set_passphrase_cb(cb)


except ImportError:
    # Implement based on top of python-gpgme
    import gpgme

    from six import StringIO
    import os

    GPGMEError = gpgme.GpgmeError
    constants = gpgme

    class Context(gpgme.Context):
        @property
        def is_gpgv2(self):
            return False

        def set_empty_passphrase_cb(self):
            pass

        def sigul_encrypt_symmetric(self, cleartext, passphrase):
            self.sigul_set_passphrase(passphrase)
            data = StringIO()
            self.encrypt(None, 0, StringIO(cleartext),
                         data)
            return data.getvalue()

        def sigul_decrypt_symmetric(self, ciphertext, passphrase):
            self.sigul_set_passphrase(passphrase)
            data = StringIO()
            self.decrypt(StringIO(ciphertext), data)
            return data.getvalue()

        def edit(self, key, func, sink):
            def cbwrapper(self, status, args, fd):
                os.write(fd, func(status, args))
            return super(Context, self).edit(key, cbwrapper, sink)

        def sigul_set_passphrase(self,
                                 passphrase,
                                 fingerprint=None,
                                 errlist=None):
            '''Let ctx use passphrase.'''
            def cb(unused_uid_int, info, prev_was_bad, fd):
                if prev_was_bad:
                    if fingerprint:
                        correct_key = False
                        for kid in info.split()[:2]:
                            if fingerprint.endswith(kid):
                                correct_key = True
                                break
                        if not correct_key:
                            error = GPGError(
                                'Requested key %s not in unlocked keys %s'
                                % (fingerprint, info))
                            if errlist is not None:
                                errlist.append(error)
                            raise error
                    else:
                        raise GPGError('Key passphrase incorrect?')
                data = passphrase + '\n'
                while len(data) > 0:
                    run = os.write(fd, data)
                    data = data[run:]
            self.passphrase_cb = cb

        def sigul_import(self, key_file):
            r = self.import_(key_file)
            if (r.imported == 0 and r.secret_imported == 0
                    and len(r.imports) == 1
                    and (r.imports[0][2] & gpgme.IMPORT_NEW) == 0):
                raise GPGError('Key already exists')
            if (r.imported != 1 or r.secret_imported != 1
                or len(r.imports) != 2
                or set((r.imports[0][2], r.imports[1][2]))
                != set((gpgme.IMPORT_NEW,
                        gpgme.IMPORT_NEW | gpgme.IMPORT_SECRET))
                    or r.imports[0][0] != r.imports[1][0]):
                raise GPGError('Unexpected import file contents')
            if r.imports[0][1] is not None:
                raise r.imports[0][1]
            if r.imports[1][1] is not None:
                raise r.imports[1][1]
            return r.imports[0][0]
