# Copyright (C) 2008-2021 Red Hat, Inc.  All rights reserved.
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
# Red Hat Author: Miloslav Trmac <mitr@redhat.com>
# Red Hat Author: Patrick Uiterwijk <puiterwijk@redhat.com>

import copy
import crypt
import enum
import logging
import os
from six import StringIO
import shutil
import subprocess
import tempfile

import cryptography.hazmat.primitives.asymmetric.ec

import nss.nss
import sqlalchemy
import sqlalchemy.orm

import server_gpg as ourgpg
from server_gpg import GPGError
import settings
import utils

# Configuration


class ServerBaseConfiguration(utils.DaemonIDConfiguration,
                              utils.BindingConfiguration,
                              utils.NSSConfiguration, utils.Configuration):
    '''General server configuration.'''

    default_config_file = 'server.conf'

    def __init__(self, config_file, allow_missing_database_path=False,
                 **kwargs):
        self.__allow_missing_database_path = allow_missing_database_path
        super(ServerBaseConfiguration, self).__init__(config_file, **kwargs)

    def _add_defaults(self, defaults):
        super(ServerBaseConfiguration, self)._add_defaults(defaults)
        defaults.update({'database-path': settings.default_database_path})
        # Override NSSConfiguration default
        defaults.update({'nss-dir': settings.default_server_nss_path})

    def _add_sections(self, sections):
        super(ServerBaseConfiguration, self)._add_sections(sections)
        sections.add('database')

    def _read_configuration(self, parser):
        super(ServerBaseConfiguration, self)._read_configuration(parser)
        self.database_path = parser.get('database', 'database-path')
        if (not self.__allow_missing_database_path
                and not os.path.isfile(self.database_path)):
            raise utils.ConfigurationError(
                '[database] database-path \'%s\' is '
                'not an existing file' %
                self.database_path)


# General utilities
def _handle_errlist(errlist):
    if len(errlist) == 1:
        raise errlist[0]
    elif len(errlist) == 0:
        logging.error('Raising original')
        raise
    elif len(errlist) > 1:
        raise Exception('Multiple errors occured: %s' % errlist)


# Database
class User(object):

    def __init__(self, name, clear_password=None, admin=False):
        self.name = name
        if clear_password is not None:
            self.clear_password = clear_password
        self.admin = admin

    __salt_length = 16
    __salt_characters = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
        'abcdefghijklmnopqrstuvwxyz'

    def __set_clear_password(self, clear_password):
        random = nss.nss.generate_random(self.__salt_length)
        salt = '$6$'
        for i in range(self.__salt_length):
            salt += self.__salt_characters[random[i] %
                                           len(self.__salt_characters)]
        self.sha512_password = crypt.crypt(
            clear_password, salt).encode('utf-8')
    clear_password = property(fset=__set_clear_password,
                              doc='Setting this attribute updates '
                              'sha512_password')


class Key(object):

    def __init__(self, name, keytype, fingerprint):
        self.name = name
        self.keytype = keytype
        self.fingerprint = fingerprint


class KeyAccess(object):

    def __init__(self, key, user, key_admin=False):
        self.key = key
        self.user = user
        self.key_admin = key_admin
        self.encrypted_passphrase = None

    def get_passphrase(self, config, user_passphrase):
        if self.encrypted_passphrase is None:
            # Perform a decryption attempt anyway to make timing attacks more
            # difficult.  gpg will probably choke on the attempt quickly
            # enough, too bad.
            encrypted_passphrase = 'x'
        else:
            encrypted_passphrase = self.encrypted_passphrase

        try:
            passphrase = gpg_decrypt_symmetric(config,
                                               encrypted_passphrase,
                                               user_passphrase)
        except ourgpg.GPGMEError:
            return None
        passphrase = utils.unbind_passphrase(passphrase)
        if passphrase is None:
            logging.warning('Unable to unbind passphrase')
        return passphrase

    def set_passphrase(self, config, key_passphrase, user_passphrase,
                       bind_params):
        key_passphrase = utils.bind_passphrase(config,
                                               key_passphrase,
                                               bind_params)
        self.encrypted_passphrase = gpg_encrypt_symmetric(config,
                                                          key_passphrase,
                                                          user_passphrase)


class KeyTypeEnum(enum.Enum):
    gnupg = 1
    ECC = 2


sa = sqlalchemy
_db_metadata = sa.MetaData()

_db_users_table = sa.Table(
    'users', _db_metadata,
    sa.Column('id',
              sa.Integer,
              sa.Sequence('users_id_seq', optional=True),
              primary_key=True),
    sa.Column('name',
              sa.Text,
              nullable=False,
              unique=True),
    sa.Column('sha512_password', sa.Binary),
    sa.Column('admin', sa.Boolean, nullable=False))

_db_keys_table = sa.Table(
    'keys', _db_metadata,
    sa.Column('id',
              sa.Integer,
              sa.Sequence('keys_id_seq', optional=True),
              primary_key=True),
    sa.Column('name',
              sa.Text,
              nullable=False,
              unique=True),
    sa.Column('keytype',
              sa.Enum(KeyTypeEnum),
              nullable=False),
    sa.Column('fingerprint',
              sa.Text,
              nullable=False,
              unique=True))

_db_key_accesses_table = sa.Table(
    'key_accesses', _db_metadata,
    sa.Column('id',
              sa.Integer,
              sa.Sequence('key_accesses_id_seq', optional=True),
              primary_key=True),
    sa.Column('key_id',
              sa.Integer,
              sa.ForeignKey('keys.id'),
              nullable=False),
    sa.Column('user_id',
              sa.Integer,
              sa.ForeignKey('users.id'),
              nullable=False),
    sa.Column('encrypted_passphrase',
              sa.Binary,
              nullable=False),
    sa.Column('key_admin',
              sa.Boolean,
              nullable=False),
    sa.UniqueConstraint('key_id', 'user_id'))
del sa

sa_orm = sqlalchemy.orm
sa_orm.mapper(User, _db_users_table, properties={
    'key_accesses': sa_orm.relation(KeyAccess, backref='user')
})
sa_orm.mapper(Key, _db_keys_table, properties={
    'key_accesses': sa_orm.relation(KeyAccess, backref='key')
})
sa_orm.mapper(KeyAccess, _db_key_accesses_table)
del sa_orm

_db_engine = None


def _db_get_engine(config):
    '''Return _db_engine, setting it up if necessary.'''
    global _db_engine

    if _db_engine is None:
        # Use echo=True for development
        _db_engine = sqlalchemy.create_engine('sqlite:///'
                                              + config.database_path)
    return _db_engine


def db_open(config):
    '''Open the database, return a session.'''
    return sqlalchemy.orm.sessionmaker(bind=_db_get_engine(config),
                                       autocommit=False)()


def db_create(config):
    '''Create database metadata.'''
    _db_metadata.create_all(_db_get_engine(config))

# OSTree utility


def call_ostree_helper(args, stdin=None):
    cmd = ['sigul-ostree-helper']
    cmd.extend(args)
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (stdout, stderr) = proc.communicate(stdin)
    if proc.returncode != 0:
        logging.error('Unexpected error from ostree helper. rc: %i, '
                      'stdout: %s, stderr: %s' % (proc.returncode,
                                                  stdout,
                                                  stderr))
        raise Exception('Error when calling ostree helper')
    return stdout

# GPG utilities


class GPGEditError(GPGError):
    '''Error performing a GPG edit operation.'''

    def __init__(self, msg, expected_state, actual_state, expected_arg,
                 actual_arg, *args):
        self.message = msg
        self.expected_state = expected_state
        self.actual_state = actual_state
        self.expected_arg = expected_arg
        self.actual_arg = actual_arg
        super(GPGEditError, self).__init__(msg, *args)

    def __str__(self):
        return ('<GPGEditError, msg: %s, expected state: %s, actual state: %s,'
                ' expected arg: %s, actual arg: %s>' % (self.message,
                                                        self.expected_state,
                                                        self.actual_state,
                                                        self.expected_arg,
                                                        self.actual_arg))


class GPGConfiguration(utils.Configuration):

    def _add_defaults(self, defaults):
        super(GPGConfiguration, self)._add_defaults(defaults)
        defaults.update({
            'gnupg-home': settings.default_gnupg_home,
            'gnupg-key-type': 'RSA',
            'gnupg-key-length': 2048,
            'gnupg-subkey-type': 'RSA',
            'gnupg-subkey-length': 2048,
            'gnupg-key-usage': 'sign',
        })

    def _add_sections(self, sections):
        super(GPGConfiguration, self)._add_sections(sections)
        sections.add('gnupg')

    def _read_configuration(self, parser):
        super(GPGConfiguration, self)._read_configuration(parser)
        self.gnupg_home = parser.get('gnupg', 'gnupg-home')
        self.gnupg_key_type = parser.get('gnupg', 'gnupg-key-type')
        self.gnupg_key_length = parser.getint('gnupg', 'gnupg-key-length')
        self.gnupg_subkey_type = parser.get('gnupg', 'gnupg-subkey-type')
        if self.gnupg_subkey_type == '':
            self.gnupg_subkey_type = None
        else:
            self.gnupg_subkey_length = parser.getint('gnupg',
                                                     'gnupg-subkey-length')
        self.gnupg_key_usage = parser.get('gnupg', 'gnupg-key-usage')


class KeysConfiguration(utils.Configuration):

    def _add_defaults(self, defaults):
        super(KeysConfiguration, self)._add_defaults(defaults)
        defaults.update({
            'allowed-key-types': 'ECC',
            'ecc-default-curve': 'SECP256R1',
            'keys-storage': settings.default_keys_storage,
        })

    def _add_sections(self, sections):
        super(KeysConfiguration, self)._add_sections(sections)
        sections.add('keys')

    def _read_configuration(self, parser):
        super(KeysConfiguration, self)._read_configuration(parser)
        self.keys_allowed = parser.get(
            'keys', 'allowed-key-types').strip().split(',')
        ecc_default_curve = parser.get('keys', 'ecc-default-curve')
        self.ecc_default_curve = getattr(
            cryptography.hazmat.primitives.asymmetric.ec, ecc_default_curve)
        self.keys_storage = parser.get('keys', 'keys-storage')


def generate_gpg_config(homedir):
    """
    Generate a GPG config to ensure loopback PIN is allowed.
    """
    try:
        pinfo = os.stat(homedir)
        if pinfo.st_mode & 0o077:
            raise Exception("gnupg home directory is openable by another user")
    except FileNotFoundError:
        os.makedirs(homedir, mode=0o700)

    if os.path.exists(os.path.join(homedir, "gpg.conf")):
        return
    with open(os.path.join(homedir, "gpg.conf"), "w") as confw:
        confw.write("use-agent\npinentry-mode loopback\n")
    with open(os.path.join(homedir, "gpg-agent.conf"), "w") as confw:
        confw.write(
            """
allow-loopback-pinentry
no-allow-external-cache
ignore-cache-for-signing
default-cache-ttl 1
default-cache-ttl-ssh 1
max-cache-ttl 1
max-cache-ttl-ssh 1
""")


def gpg_modify_environ(config):
    '''Modify os.envion based on config.

    Must be called before any other gpg_* function.

    '''
    if 'GPG_AGENT_INFO' in os.environ:
        # Otherwise the passphrase callbacks are ignored
        del os.environ['GPG_AGENT_INFO']
    os.environ['GNUPGHOME'] = config.gnupg_home
    generate_gpg_config(config.gnupg_home)


def _gpg_open(config):
    '''Return a configured gpgme context.'''
    ctx = ourgpg.Context()
    ctx.protocol = ourgpg.constants.PROTOCOL_OpenPGP
    ctx.set_engine_info(ourgpg.constants.PROTOCOL_OpenPGP, settings.gnupg_bin,
                        config.gnupg_home)
    if ctx.is_gpgv2:
        generate_gpg_config(config.gnupg_home)
        ctx.set_pinentry_mode(ourgpg.constants.PINENTRY_MODE_LOOPBACK)
    return ctx


def gpg_public_key(config, fingerprint):
    '''Return an ascii-armored public key.'''
    ctx = _gpg_open(config)
    ctx.armor = 1
    data = StringIO()
    ctx.export(fingerprint, data)
    return data.getvalue()


def gpg_delete_key(config, fingerprint):
    '''Delete the specified key.'''
    ctx = _gpg_open(config)
    key = ctx.get_key(fingerprint, True)
    ctx.delete(key, True)


def gpg_edit_key(config, fingerprint, input_states, ignored_states):
    '''Edit a GPG key

    This uses pygpgme.Context.edit, and implements a state machine to perform
    the full conversation.

    This code is insane, but it is what it is due to insanity at (py)gpg(me).

    input_states is a list of three-tuples, describing the expected state and
    argument at every point in the conversation, and the answer we are going to
    send.
    example: [(gpgme.STATUS_GET_LINE, 'keyedit.prompt', 'KEY 1')]

    ignored_states is a list of gpgme states that we ignore when they come up.
    This means we don't handle them at all.
    '''
    errors = []
    states = copy.copy(input_states)
    replies = []
    out_fd = StringIO()

    def update_out():
        out_fd.seek(0)
        replies.append(out_fd.read())
        out_fd.seek(0)
        out_fd.truncate()

    def edit_callback(status, arg):
        if status in ignored_states:
            return

        update_out()

        if len(states) == 0:
            error = GPGEditError('More states expected',
                                 None, status, None, arg)
            errors.append(error)
            raise error
        expected_status, expected_arg, answer = states.pop(0)
        if expected_status == ourgpg.constants.STATUS_EOF:
            expected_status = ''
        if expected_status != status:
            error = GPGEditError('Mismatched status',
                                 expected_status, status, expected_arg, arg)
            errors.append(error)
            raise error
        if expected_arg is not None and arg != expected_arg:
            error = GPGEditError('Mismatched argument',
                                 expected_status, status, expected_arg, arg)
            errors.append(error)
            raise error
        if answer is not None:
            return '{0!s}'.format(answer)

    # We are done setting everything up... Now let's do this
    ctx = _gpg_open(config)
    key = ctx.get_key(fingerprint, True)
    try:
        ctx.edit(key, edit_callback, out_fd)
    except ourgpg.GPGMEError as ex:
        # This is because gpgme hides all errors: every error we throw gets
        # thrown up to the edit call as gpgme.GpgmeError('General error')
        if len(errors) != 0:
            raise errors[0]
        else:
            raise ex
    return replies


def _restore_gnupg_home(config, backup_dir):
    '''Restore config.gnupg_home from a backup in backup_dir.'''
    tmp_dir = tempfile.mkdtemp(prefix=os.path.basename(config.gnupg_home),
                               dir=os.path.dirname(config.gnupg_home))
    os.rmdir(tmp_dir)
    shutil.copytree(backup_dir, tmp_dir)
    # This is racy.  In the worst case manual recovery is necessary anyway,
    # and backup_dir will be left around if we fail.
    shutil.rmtree(config.gnupg_home)
    os.rename(tmp_dir, config.gnupg_home)


def gpg_import_key(config, key_file):
    '''Import a public and secret key from key_file.

    Return a fingerprint.  Raise GPGError if key_file contents are unexpected.

    '''
    # We can't parse key_file to see whether it is acceptable, so just back
    # up the database and restore it if necessary.
    tmp_dir = tempfile.mkdtemp()
    keyfpr = None

    def ignore_sockets(path, names):
        to_ignore = []
        for name in names:
            if name.startswith('S.gpg-agent'):
                to_ignore.append(name)
        return to_ignore

    try:
        backup_dir = os.path.join(tmp_dir, 'gnupghome-backup')
        shutil.copytree(
            config.gnupg_home,
            backup_dir,
            ignore=ignore_sockets,
        )
        ctx = _gpg_open(config)
        keyfpr = ctx.sigul_import(key_file)
    finally:
        if keyfpr is None:
            _restore_gnupg_home(config, backup_dir)
        # If _restore_gnupg_home raises an exception, tmp_dir won't be removed.
        shutil.rmtree(tmp_dir)
    return keyfpr

# In LISP a nested function that modifies upper-level variables would be enough
# Python requires an object


class _ChangePasswordResponder(object):

    def __init__(self, old_passphrase, new_passphrase):
        self.old_passphrase = old_passphrase
        self.new_passphrase = new_passphrase
        self.passwd_cmd_sent = False
        self.quit_cmd_sent = False
        self.want_new_passphrase = None
        self.sent_old_pw = False
        # pygpgme overrides any exceptions in the callback, store them here
        self.exception = None

    def callback(self, status, args):
        try:
            if (status == ourgpg.constants.STATUS_GET_LINE
                    and args == 'keyedit.prompt'):
                if not self.passwd_cmd_sent:
                    self.passwd_cmd_sent = True
                    return "passwd"
                else:
                    self.quit_cmd_sent = True
                    return "save"
            elif status in (ourgpg.constants.STATUS_USERID_HINT,
                            ourgpg.constants.STATUS_GOOD_PASSPHRASE,
                            ourgpg.constants.STATUS_KEYEXPIRED,
                            ourgpg.constants.STATUS_SIGEXPIRED,
                            ourgpg.constants.STATUS_KEY_CONSIDERED,
                            ourgpg.constants.STATUS_INQUIRE_MAXLEN,
                            ourgpg.constants.STATUS_EOF,
                            ''  # The new STATUS_EOF
                            ):
                pass
            elif status == ourgpg.constants.STATUS_NEED_PASSPHRASE:
                self.want_new_passphrase = False
            elif status == ourgpg.constants.STATUS_GET_HIDDEN:
                if not self.want_new_passphrase:
                    self.sent_old_pw = True
                    return self.old_passphrase
                else:
                    return self.new_passphrase
            elif status == ourgpg.constants.STATUS_GOT_IT:
                # This is what GPG2 sends us
                if self.sent_old_pw:
                    self.want_new_passphrase = True
            elif status == ourgpg.constants.STATUS_NEED_PASSPHRASE_SYM:
                self.want_new_passphrase = True
            elif status == ourgpg.constants.STATUS_BAD_PASSPHRASE:
                raise GPGError("Invalid passphrase")
            else:
                logging.error('Unexpected GPG edit callback: (%s, %s)',
                              repr(status), repr(args))
                self.exception = NotImplementedError()
                raise NotImplementedError()
            return None
        except Exception as e:
            self.exception = e
            raise  # Will return gpgme.ERR_GENERAL


def gpg_change_password(config, fingerprint, old_passphrase, new_passphrase):
    '''Change a passphrase for the specified key.

    Raise GPGError if old_passphrase is invalid.

    '''
    ctx = _gpg_open(config)
    key = ctx.get_key(fingerprint, True)
    responder = _ChangePasswordResponder(old_passphrase, new_passphrase)
    try:
        ctx.edit(key, responder.callback, StringIO())
    except ourgpg.GPGMEError:
        if responder.exception is not None:
            raise responder.exception
        raise
    if (not responder.passwd_cmd_sent or not responder.want_new_passphrase
            or not responder.quit_cmd_sent):
        logging.error('Unexpected state when changing GPG key password')
        raise NotImplementedError()


def gpg_encrypt_symmetric(config, cleartext, passphrase):
    '''Return cleartext encrypted using passphrase.'''
    ctx = _gpg_open(config)
    return ctx.sigul_encrypt_symmetric(cleartext, passphrase)


def gpg_decrypt_symmetric(config, ciphertext, passphrase):
    '''Return ciphertext encrypted using passphrase.'''
    ctx = _gpg_open(config)
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode('utf-8')
    return ctx.sigul_decrypt_symmetric(ciphertext, passphrase)


def gpg_signature(config, signature_file, cleartext_file, fingerprint,
                  passphrase, armor):
    '''Create a normal signature.

    Sign contents of cleartext_file, write the signature to signature_file.
    Use key with fingerprint and passphrase.

    '''
    ctx = _gpg_open(config)
    ctx.sigul_set_passphrase(passphrase, fingerprint=fingerprint)
    key = ctx.get_key(fingerprint, True)
    ctx.signers = (key,)
    ctx.armor = armor
    ctx.textmode = False
    ctx.sign(cleartext_file, signature_file, ourgpg.constants.SIG_MODE_NORMAL)


def gpg_decrypt(config, cleartext_file, encrypted_file, fingerprint,
                passphrase):
    '''Decrypt an encrypted file.

    Decrypt contents of encrypyted_file, write the cleartext to cleartext_file.
    Use key with fingerprint and passphrase.

    '''
    errlist = []
    ctx = _gpg_open(config)
    ctx.sigul_set_passphrase(passphrase, fingerprint, errlist)
    ctx.get_key(fingerprint, True)
    ctx.textmode = False
    try:
        ctx.decrypt(encrypted_file, cleartext_file)
    except Exception:
        _handle_errlist(errlist)


def gpg_clearsign(
        config,
        signed_file,
        cleartext_file,
        fingerprint,
        passphrase):
    '''Create a cleartext signature.

    Sign contents of cleartext_file, write the signed text to signed_file.  Use
    key with fingerprint and passphrase.

    '''
    ctx = _gpg_open(config)
    ctx.sigul_set_passphrase(passphrase, fingerprint)
    key = ctx.get_key(fingerprint, True)
    ctx.signers = (key,)
    ctx.sign(cleartext_file, signed_file, ourgpg.constants.SIG_MODE_CLEAR)


def gpg_detached_signature(config, signature_file, cleartext_file, fingerprint,
                           passphrase, armor):
    '''Create a detachted signature.

    Sign contents of cleartext_file, write the signature to signature_file.
    Use key with fingerprint and passphrase.

    '''
    ctx = _gpg_open(config)
    ctx.sigul_set_passphrase(passphrase, fingerprint)
    key = ctx.get_key(fingerprint, True)
    ctx.signers = (key,)
    ctx.armor = armor
    ctx.textmode = False
    ctx.sign(cleartext_file, signature_file, ourgpg.constants.SIG_MODE_DETACH)
