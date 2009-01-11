# Copyright (C) 2008 Red Hat, Inc.  All rights reserved.
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

import cStringIO
import crypt
import os

import gpgme
import nss.nss
import sqlalchemy
import sqlalchemy.orm

import settings
import utils

 # Configuration

class ServerBaseConfiguration(utils.DaemonIDConfiguration,
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

    def _read_configuration(self, parser):
        super(ServerBaseConfiguration, self)._read_configuration(parser)
        self.database_path = parser.get('database', 'database-path')
        if (not self.__allow_missing_database_path and
            not os.path.isfile(self.database_path)):
            raise utils.ConfigurationError('[database] database-path \'%s\' is '
                                           'not an existing file' %
                                           self.database_path)

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
        for i in xrange(self.__salt_length):
            salt += self.__salt_characters[ord(random[i]) %
                                           len(self.__salt_characters)]
        self.sha512_password = crypt.crypt(clear_password, salt)
    clear_password = property(fset = __set_clear_password,
                              doc='Setting this attribute updates '
                              'sha512_password')

class Key(object):
    def __init__(self, name, fingerprint):
        self.name = name
        self.fingerprint = fingerprint

class KeyAccess(object):
    def __init__(self, key, user, key_admin=False):
        self.key = key
        self.user = user
        self.key_admin = key_admin

    def set_passphrase(self, config, key_passphrase, user_passphrase):
        self.encrypted_passphrase = gpg_encrypt_symmetric(config,
                                                          key_passphrase,
                                                          user_passphrase)

sa = sqlalchemy
_db_metadata = sa.MetaData()

_db_users_table = sa.Table('users', _db_metadata,
                           sa.Column('id', sa.Integer,
                                     sa.Sequence('users_id_seq', optional=True),
                                     primary_key=True),
                           sa.Column('name', sa.Text, nullable=False,
                                     unique=True),
                           sa.Column('sha512_password', sa.Binary),
                           sa.Column('admin', sa.Boolean, nullable=False))

_db_keys_table = sa.Table('keys', _db_metadata,
                          sa.Column('id', sa.Integer,
                                    sa.Sequence('keys_id_seq', optional=True),
                                    primary_key=True),
                          sa.Column('name', sa.Text, nullable=False,
                                    unique=True),
                          sa.Column('fingerprint', sa.Text, nullable=False,
                                    unique=True))

_db_key_accesses_table = sa.Table('key_accesses', _db_metadata,
                                  sa.Column('id', sa.Integer,
                                            sa.Sequence('key_accesses_id_seq',
                                                        optional=True),
                                            primary_key=True),
                                  sa.Column('key_id', sa.Integer,
                                            sa.ForeignKey('keys.id'),
                                            nullable=False),
                                  sa.Column('user_id', sa.Integer,
                                            sa.ForeignKey('users.id'),
                                            nullable=False),
                                  sa.Column('encrypted_passphrase', sa.Binary,
                                            nullable=False),
                                  sa.Column('key_admin', sa.Boolean,
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
        _db_engine = sqlalchemy.create_engine('sqlite:///' +
                                              config.database_path)
    return _db_engine

def db_open(config):
    '''Open the database, return a session.'''
    return sqlalchemy.orm.sessionmaker(bind=_db_get_engine(config),
                                       transactional=True)()

def db_create(config):
    '''Create database metadata.'''
    _db_metadata.create_all(_db_get_engine(config))

 # GPG utilities

class GPGConfiguration(utils.Configuration):

    def _add_defaults(self, defaults):
        super(GPGConfiguration, self)._add_defaults(defaults)
        defaults.update({'gnupg-home': settings.default_gnupg_home})

    def _read_configuration(self, parser):
        super(GPGConfiguration, self)._read_configuration(parser)
        self.gnupg_home = parser.get('gnupg', 'gnupg-home')

def gpg_modify_environ(config):
    '''Modify os.envion based on config.

    Must be called before any other gpg_* function.

    '''
    if 'GPG_AGENT_INFO' in os.environ:
        # Otherwise the passphrase callbacks are ignored
        del os.environ['GPG_AGENT_INFO']
    os.environ['GNUPGHOME'] = config.gnupg_home

def _gpg_open(config):
    '''Return a configured gpgme context.'''
    ctx = gpgme.Context()
    ctx.protocol = gpgme.PROTOCOL_OpenPGP
    ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, settings.gnupg_bin,
                        config.gnupg_home)
    return ctx

def _gpg_set_passphrase(ctx, passphrase):
    '''Let ctx use passphrase.'''
    def cb(unused_uid_int, unused_info, prev_was_bad, fd):
        if prev_was_bad:
            return gpgme.ERR_CANCELED
        data = passphrase + '\n'
        while len(data) > 0:
            run = os.write(fd, data)
            data = data[run:]
    ctx.passphrase_cb = cb

def gpg_public_key(config, fingerprint):
    '''Return an ascii-armored public key.'''
    ctx = _gpg_open(config)
    ctx.armor = 1
    data = cStringIO.StringIO()
    ctx.export(fingerprint, data)
    return data.getvalue()

def gpg_delete_key(config, fingerprint):
    '''Delete the specified key.'''
    ctx = _gpg_open(config)
    key = ctx.get_key(fingerprint, True)
    ctx.delete(key, True)

def gpg_encrypt_symmetric(config, cleartext, passphrase):
    '''Return cleartext encrypted using passphrase.'''
    ctx = _gpg_open(config)
    _gpg_set_passphrase(ctx, passphrase)
    data = cStringIO.StringIO()
    ctx.encrypt(None, 0, cStringIO.StringIO(cleartext),
                data)
    return data.getvalue()

def gpg_decrypt(config, ciphertext, passphrase):
    '''Return ciphertext encrypted using passphrase.'''
    ctx = _gpg_open(config)
    _gpg_set_passphrase(ctx, passphrase)
    data = cStringIO.StringIO()
    ctx.decrypt(cStringIO.StringIO(ciphertext), data)
    return data.getvalue()

def gpg_clearsign(config, signed_file, cleartext_file, fingerprint, passphrase):
    '''Create a cleartext signature.

    Sign contents of cleartext_file, write the signed text to signed_file.  Use
    key with fingerprint and passphrase.

    '''
    ctx = _gpg_open(config)
    _gpg_set_passphrase(ctx, passphrase)
    key = ctx.get_key(fingerprint, True)
    ctx.signers = (key,)
    ctx.sign(cleartext_file, signed_file, gpgme.SIG_MODE_CLEAR)

def gpg_detached_signature(config, signature_file, cleartext_file, fingerprint,
                           passphrase):
    '''Create a detachted signature.

    Sign contents of cleartext_file, write the signature to signature_file.
    Use key with fingerprint and passphrase.

    '''
    ctx = _gpg_open(config)
    _gpg_set_passphrase(ctx, passphrase)
    key = ctx.get_key(fingerprint, True)
    ctx.signers = (key,)
    ctx.armor = False
    ctx.textmode = False
    ctx.sign(cleartext_file, signature_file, gpgme.SIG_MODE_DETACH)
