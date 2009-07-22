# Copyright (C) 2008, 2009 Red Hat, Inc.  All rights reserved.
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

import binascii
import crypt
import logging
import os
import signal
import socket
import string
import struct
import subprocess
import sys
import tempfile
import time

import M2Crypto.EVP
import gpgme
import nss.error
import nss.nss
import pexpect

import double_tls
import errors
import server_common
import settings
import utils

# When trying to connect to the bridge, don't repeat the connections way too
# often.  Try MAX_FAST_RECONNECTIONS attempts FAST_RECONNECTION_SECONDS apart,
# then wait SLOW_RECONNECTION_SECONDS.  Then try again
MAX_FAST_RECONNECTIONS = 5
FAST_RECONNECTION_SECONDS = 5
SLOW_RECONNECTION_SECONDS = 60

 # Infrastructure

Key = server_common.Key
KeyAccess = server_common.KeyAccess
User = server_common.User

class ServerConfiguration(server_common.GPGConfiguration,
                          server_common.ServerBaseConfiguration):

    def _add_defaults(self, defaults):
        super(ServerConfiguration, self)._add_defaults(defaults)
        defaults.update({'bridge-port': 44333,
                         'gnupg-key-type': 'DSA',
                         'gnupg-key-length': 1024,
                         'gnupg-subkey-type': 'ELG-E',
                         'gnupg-subkey-length': 2048,
                         'gnupg-key-usage': 'encrypt, sign',
                         'max-file-payload-size': 1024 * 1024 * 1024,
                         'max-memory-payload-size': 1024 * 1024,
                         'passphrase-length': 64,
                         'server-cert-nickname': 'sigul-server-cert'})

    def _read_configuration(self, parser):
        super(ServerConfiguration, self)._read_configuration(parser)
        self.database_path = parser.get('database', 'database-path')
        self.gnupg_key_type = parser.get('gnupg', 'gnupg-key-type')
        self.gnupg_key_length = parser.getint('gnupg', 'gnupg-key-length')
        self.gnupg_subkey_type = parser.get('gnupg', 'gnupg-subkey-type')
        if self.gnupg_subkey_type == '':
            self.gnupg_subkey_type = None
        else:
            self.gnupg_subkey_length = parser.getint('gnupg',
                                                     'gnupg-subkey-length')
        self.gnupg_key_usage = parser.get('gnupg', 'gnupg-key-usage')
        self.passphrase_length = parser.getint('gnupg', 'passphrase-length')
        self.bridge_hostname = parser.get('server', 'bridge-hostname')
        self.bridge_port = parser.getint('server', 'bridge-port')
        self.max_file_payload_size = parser.getint('server',
                                                   'max-file-payload-size')
        self.max_memory_payload_size = parser.getint('server',
                                                     'max-memory-payload-size')
        self.server_cert_nickname = parser.get('server', 'server-cert-nickname')

class RequestHandled(Exception):
    '''Used to terminate further processing of the request.'''
    pass

class InvalidRequestError(Exception):
    pass

class RequestHandler(object):
    '''Information about a request type and its handler.'''

    PAYLOAD_NONE = 0
    PAYLOAD_MEMORY = 1
    PAYLOAD_FILE = 2

    def __init__(self, handler, payload_storage=PAYLOAD_NONE,
                 payload_auth_optional=False):
        self.handler = handler
        self.payload_storage = payload_storage
        self.payload_auth_optional = payload_auth_optional

# op value => (handler, expected payload type)
# Each handler raises RequestHandled, InvalidRequestError.  op value None means
# the default handler
request_handlers = {}

def request_handler(**kwargs):
    '''Register this function as a request handler, using kwargs.

    Function name must be cmd_request_name_with_dash_replaced_by_underscore,
    e.g. cmd_list_users for 'list-users'.  This decorator must be used with
    (possibly zero) parameters.

    '''
    def real_decorator(fn):
        assert fn.__name__.startswith('cmd_')
        request_handlers[fn.__name__[len('cmd_'):].replace('_', '-')] = \
            RequestHandler(fn, **kwargs)
        return fn
    return real_decorator

class ServerProxy(object):
    '''A proxy for double_tls.DoubleTLSClient that stores read outer data.'''

    def __init__(self, server):
        self.__server = server
        self.__stored = ''

    def stored_outer_read(self, bytes):
        data = self.__server.outer_read(bytes)
        self.__stored += data
        return data

    def stored_data(self):
        '''Return the currently stored data.

        Each piece of data is returned only once in repeated calls to this
        method.

        '''
        res = self.__stored
        self.__stored = ''
        return res

class ServersConnection(object):
    '''A connection to the bridge/client.'''

    def __init__(self, config):
        self.config = config
        self.__client = double_tls.DoubleTLSClient(config,
                                                   config.bridge_hostname,
                                                   config.bridge_port,
                                                   config.server_cert_nickname)
        self.payload_path = None
        self.payload_file = None
        utils.nss_init(config) # May raise utils.NSSInitError

    def outer_field(self, key, required=False):
        '''Return an outer field value, or None if not present.

        Raise InvalidRequestError if field is not present and required == True.

        '''
        v = self.__outer_fields.get(key)
        if required and v is None:
            raise InvalidRequestError('Required outer field %s missing' % key)
        return v

    def safe_outer_field(self, key, **kwargs):
        '''Return an outer field value, or None if not present.

        Raise InvalidRequestError if field is not a safe string.

        '''
        v = self.outer_field(key, **kwargs)
        if v is not None and not utils.string_is_safe(v):
            raise InvalidRequestError('Field %s has unsafe value' % repr(key))
        return v

    def outer_field_bool(self, key):
        '''Return outer field value as a bool or None if not present.

        Raise InvalidRequestError.

        '''
        v = self.__outer_fields.get(key)
        if v is not None:
            try:
                v = utils.u32_unpack(v)
            except struct.error:
                raise InvalidRequestError('Integer field has incorrect length')
            try:
                v = { 0: False, 1: True }[v]
            except KeyError:
                raise InvalidRequestError('Boolean field has invalid value')
        return v

    def inner_field(self, key, required=False):
        '''Return an inner field value, or None if not present.

        Raise InvalidRequestError if fiels is not present and required == True.

        '''
        v = self.__inner_fields.get(key)
        if required and v is None:
            raise InvalidRequestError('Required inner field %s missing.' % key)
        return v

    def read_request(self):
        '''Read a request.

        Return request handler.  Raise RequestHandled, InvalidRequestError,
        double_tls.InnerCertificateNotFound.

        '''
        proxy = ServerProxy(self.__client)
        buf = proxy.stored_outer_read(utils.u32_size)
        logging.debug('Started processing a request')
        client_version = utils.u32_unpack(buf)
        if client_version != utils.protocol_version:
            logging.warning('Unknown protocol version %d in request',
                            client_version)
            self.__client.inner_close()
            self.__client.outer_write(utils.u32_pack(errors.UNKNOWN_VERSION))
            raise RequestHandled()
        try:
            self.__outer_fields = utils.read_fields(proxy.stored_outer_read)
        except utils.InvalidFieldsError, e:
            raise InvalidRequestError(str(e))
        # print repr(self.__outer_fields)
        s = ', '.join(('%s = %s' % (repr(key), repr(value))
                       for (key, value) in self.__outer_fields.iteritems()))
        logging.info('Request: %s', s)
        header_data = proxy.stored_data()
        buf = self.__client.outer_read(utils.u32_size)
        payload_size = utils.u32_unpack(buf)

        request_op = self.safe_outer_field('op', required=True)
        if request_op not in request_handlers:
            request_op = None
        handler = request_handlers[request_op]

        if handler.payload_storage == RequestHandler.PAYLOAD_NONE:
            if payload_size != 0:
                raise InvalidRequestError('Unexpected payload')
            self.payload_sha512_digest = utils.sha512_digest('')
        elif handler.payload_storage == RequestHandler.PAYLOAD_MEMORY:
            if payload_size > self.config.max_memory_payload_size:
                raise InvalidRequestError('Payload too large')
            self.__payload = ''
            while payload_size > 0:
                run = self.__client.outer_read(min(payload_size, 4096))
                self.__payload += run
                payload_size -= len(run)
            self.payload_sha512_digest = utils.sha512_digest(self.__payload)
        else:
            assert handler.payload_storage == RequestHandler.PAYLOAD_FILE
            if payload_size > self.config.max_file_payload_size:
                raise InvalidRequestError('Payload too large')
            # FIXME? python-nss does not support incremental hash computation
            digest = M2Crypto.EVP.MessageDigest('sha512')

            (fd, self.payload_path) = tempfile.mkstemp(text=False)
            self.payload_file = os.fdopen(fd, 'w+b')
            while payload_size > 0:
                run = self.__client.outer_read(min(payload_size, 4096))
                self.payload_file.write(run)
                digest.update(run)
                payload_size -= len(run)
            self.payload_file.flush()
            self.payload_file.seek(0)
            self.payload_sha512_digest = digest.final()

        # FIXME? authenticate using the client's certificate as well?
        # May raise double_tls.InnerCertificateNotFound.
        self.__client.inner_open_server(self.config.server_cert_nickname)
        try:
            try:
                self.__inner_fields = utils.read_fields(self.__client.
                                                        inner_read)
            except utils.InvalidFieldsError, e:
                raise InvalidRequestError(str(e))
        finally:
            self.__client.inner_close()
        # print repr(self.__inner_fields)
        if (self.inner_field('header-auth-sha512', required=True) !=
            utils.sha512_digest(header_data)):
            raise InvalidRequestError('Header authentication failed')
        payload_auth = self.inner_field('payload-auth-sha512')
        if payload_auth is None:
            if not handler.payload_auth_optional:
                raise InvalidRequestError('Authentication hash missing')
        else:
            if payload_auth != self.payload_sha512_digest:
                raise InvalidRequestError('Payload authentication failed')
        self.payload_authenticated = payload_auth is not None

        # FIXME? python-nss does not support HMAC
        key = self.inner_field('header-auth-key', required=True)
        if len(key) < 64:
            raise InvalidRequestError('Header authentication key too small')
        self.__reply_header_hmac = M2Crypto.EVP.HMAC(key, algo='sha512')
        key = self.inner_field('payload-auth-key', required=True)
        if len(key) < 64:
            raise InvalidRequestError('Payload authentication key too small')
        self.__reply_payload_hmac = M2Crypto.EVP.HMAC(key, algo='sha512')

        return handler

    def __send_payload(self, data):
        '''Send data on outer stream as a part of the authenticated payload.'''
        self.__client.outer_write(data)
        self.__reply_payload_hmac.update(str(data))

    def send_reply_header(self, error_code, fields):
        '''Send a reply header to the client.'''
        data = utils.u32_pack(error_code)
        self.__client.outer_write(data)
        self.__reply_header_hmac.update(str(data))
        data = utils.format_fields(fields)
        self.__client.outer_write(data)
        self.__reply_header_hmac.update(str(data))
        auth = self.__reply_header_hmac.digest()
        assert len(auth) == 64
        self.__client.outer_write(auth)

    def __start_reply_payload(self, payload_len):
        '''Prepare for sending payload of payload_len to the client.'''
        self.__client.outer_write(utils.u32_pack(payload_len))

    def __send_reply_payload_auth(self):
        '''Send payload authenticator.'''
        auth = self.__reply_payload_hmac.digest()
        assert len(auth) == 64
        self.__client.outer_write(auth)

    def send_reply_payload(self, payload):
        '''Send payload to the client.'''
        self.__start_reply_payload(len(payload))
        self.__send_payload(payload)
        self.__send_reply_payload_auth()

    def send_reply_payload_from_file(self, file):
        '''Send contents of file to the client as payload.'''
        file.seek(0)
        file_size = os.fstat(file.fileno()).st_size
        self.__start_reply_payload(file_size)
        sent = 0
        while True:
            data = file.read(4096)
            if len(data) == 0:
                break
            self.__send_payload(data)
            sent += len(data)
        if sent != file_size:
            raise IOError('File size did not match size returned by fstat()')
        self.__send_reply_payload_auth()

    def send_reply_ok_only(self):
        '''Send an erorrs.OK reply with no fields or payload.'''
        self.send_reply_header(errors.OK, {})
        self.send_reply_payload('')

    def send_error(self, error_code, message=None, log_it=True):
        '''Send an erorr response with code and message.

        Raise RequestHandled at the end.

        '''
        if message is not None:
            f = {'message': message}
            if log_it:
                logging.info('Request error: %s, %s',
                             errors.message(error_code), message)
        else:
            f = {}
            if log_it:
                logging.info('Request error: %s', errors.message(error_code))
        self.send_reply_header(error_code, f)
        self.send_reply_payload('')
        raise RequestHandled()

    def close(self):
        '''Destroy non-garbage-collected state.

        Raise double_tls.ChildConnectionRefusedError,
        double_tls.ChildUnrecoverableError.

        '''
        if self.payload_file is not None:
            self.payload_file.close()
        if self.payload_path is not None:
            os.remove(self.payload_path)
        # May raise double_tls.ChildConnectionRefusedError,
        # double_tls.ChildUnrecoverableError.
        self.__client.outer_close()

    def auth_fail(self, reason):
        '''Report an authentication failure.

        Raise RequestHandled.

        '''
        logging.warning('Request authentication failed: %s', reason)
        self.send_error(errors.AUTHENTICATION_FAILED, log_it=False)

    def authenticate_admin(self, db):
        '''Check the request is a valid administration request.

        Raise RequestHandled (on permission denied), InvalidRequestError.
        '''


        user = self.safe_outer_field('user')
        if user is None:
            self.auth_fail('user field missing')
        password = self.inner_field('password')
        if password is None:
            self.auth_fail('password field missing')
        user = db.query(User).filter_by(name=user).first()
        if user is not None and user.sha512_password is not None:
            crypted_pw = str(user.sha512_password)
        else:
            # Perform the encryption anyway to make timing attacks more
            # difficult.
            crypted_pw = 'x'
        if crypt.crypt(password, crypted_pw) != crypted_pw:
            self.auth_fail('password does not match')
        if not user.admin:
            self.auth_fail('user is not a server administrator')
        # OK

    def __authenticate_admin_or_user(self, db):
        '''Check the request is a valid key access request.

        Allow server administrators to authenticate without having a key
        passphrase.  Return (user, key, access), with access None if a server
        administrator was authenticated.  Raise RequestHandled (on permission
        denied), InvalidRequestError.

        '''
        user = self.safe_outer_field('user')
        if user is None:
            self.auth_fail('user field missing')
        key = self.safe_outer_field('key')
        if key is None:
            self.auth_fail('key field missing')
        password = self.inner_field('password')
        user_passphrase = self.inner_field('passphrase')
        if password is None and user_passphrase is None:
            self.auth_fail('both password and passphrase fields missing')
        user = db.query(User).filter_by(name=user).first()
        key = db.query(Key).filter_by(name=key).first()
        access = None
        if password is not None:
            if user is not None and user.sha512_password is not None:
                crypted_pw = str(user.sha512_password)
            else:
                # Perform the encryption anyway to make timing attacks more
                # difficult.
                crypted_pw = 'x'
            if crypt.crypt(password, crypted_pw) != crypted_pw:
                self.auth_fail('password does not match')
            assert user is not None
            if not user.admin or key is None:
                self.auth_fail('user is not a server administrator')
        else:
            assert user_passphrase is not None
            encrypted_passphrase = None
            if user is not None and key is not None:
                access = (db.query(KeyAccess).filter_by(user=user, key=key).
                          first())
                if access is not None:
                    encrypted_passphrase = access.encrypted_passphrase
            if encrypted_passphrase is None:
                # Perform a decryption attempt anyway to make timing attacks
                # more difficult.  gpg will probably choke on the attempt
                # quickly enough, too bad.
                encrypted_passphrase = 'x'
            try:
                server_common.gpg_decrypt(self.config, encrypted_passphrase,
                                          user_passphrase)
            except gpgme.GpgmeError:
                self.auth_fail('passphrase does not match')
            assert user is not None and key is not None and access is not None
        return (user, key, access) # OK

    def authenticate_admin_or_user(self, db):
        '''Check the request is a valid key access request.

        Allow server administrators to authenticate without having a key
        passphrase.  Return (user, key).  Raise RequestHandled (on permission
        denied), InvalidRequestError.

        '''
        (user, key, _) = self.__authenticate_admin_or_user(db)
        return (user, key)

    def authenticate_admin_or_key_admin(self, db):
        '''Check the request is a valid key administration request.

        Allow server administrators to authenticate without having a key
        passphrase.  Return (user, key).  Raise RequestHandled (on permission
        denied), InvalidRequestError.

        '''
        (user, key, access) = self.__authenticate_admin_or_user(db)
        if access is not None and not access.key_admin:
            self.auth_fail('user is not a key administrator')
        return (user, key)

    def authenticate_user(self, db):
        '''Check the request is a valid key access request.

        Return a (access, key passphrase).  Raise RequestHandled (on permission
        denied), InvalidRequestError.

        '''
        user = self.safe_outer_field('user')
        if user is None:
            self.auth_fail('user field missing')
        key = self.safe_outer_field('key')
        if key is None:
            self.auth_fail('key field missing')
        user_passphrase = self.inner_field('passphrase')
        if user_passphrase is None:
            self.auth_fail('passphrase field missing')
        user = db.query(User).filter_by(name=user).first()
        key = db.query(Key).filter_by(name=key).first()
        encrypted_passphrase = None
        access = None
        if user is not None and key is not None:
            access = db.query(KeyAccess).filter_by(user=user, key=key).first()
            if access is not None:
                encrypted_passphrase = access.encrypted_passphrase
        if encrypted_passphrase is None:
            # Perform a decryption attempt anyway to make timing attacks more
            # difficult.  gpg will probably choke on the attempt quickly
            # enough, too bad.
            encrypted_passphrase = 'x'
        try:
            key_passphrase = server_common.gpg_decrypt(self.config,
                                                       encrypted_passphrase,
                                                       user_passphrase)
        except gpgme.GpgmeError:
            self.auth_fail('passphrase does not match')
        assert user is not None and key is not None and access is not None
        return (access, key_passphrase)

    def authenticate_key_admin(self, db):
        '''Check the request is a valid key administration request.

        Return a KeyAccess.  Raise RequestHandled (on permission denied),
        InvalidRequestError.

        '''
        (access, key_passphrase) = self.authenticate_user(db)
        if not access.key_admin:
            self.auth_fail('user is not a key administrator')
        return (access, key_passphrase)

def key_by_name(db, conn):
    '''Return a key specified by conn.safe_outer_field('key').

    Raise InvalidRequestError.

    '''
    name = conn.safe_outer_field('key', required=True)
    key = db.query(Key).filter_by(name=name).first()
    if key is None:
        conn.send_error(errors.KEY_NOT_FOUND)
    return key

def user_by_name(db, conn):
    '''Return an user specified by conn.safe_outer_field('name').

    Raise InvalidRequestError.

    '''
    name = conn.safe_outer_field('name', required=True)
    user = db.query(User).filter_by(name=name).first()
    if user is None:
        conn.send_error(errors.USER_NOT_FOUND)
    return user

def key_access_by_names(db, conn):
    '''Return a key access specified by conn.safe_outer_field('name'),
    conn.safe_outer_field('key').

    Raise InvalidRequestError.

    '''
    # Load user and key to provide full diagnostics
    user = user_by_name(db, conn)
    key = key_by_name(db, conn)
    access = db.query(KeyAccess).filter_by(user=user, key=key).first()
    if access is None:
        conn.send_error(errors.KEY_USER_NOT_FOUND)
    return access

_passphrase_characters = string.ascii_letters + string.digits
def random_passphrase(conn):
    '''Return a random passphrase.'''
    random = nss.nss.generate_random(conn.config.passphrase_length)
    return ''.join(_passphrase_characters[ord(c) % len(_passphrase_characters)]
                   for c in random)

 # Request handlers

@request_handler()
def cmd_list_users(db, conn):
    conn.authenticate_admin(db)
    # Order by name to hide database structure
    users = db.query(User).order_by(User.name).all()
    conn.send_reply_header(errors.OK, {'num-users': len(users)})
    payload = ''
    for user in users:
        payload += user.name + '\x00'
    conn.send_reply_payload(payload)

@request_handler()
def cmd_new_user(db, conn):
    conn.authenticate_admin(db)
    name = conn.safe_outer_field('name', required=True)
    # FIXME: is this check atomic?
    if db.query(User).filter_by(name=name).first() is not None:
        conn.send_error(errors.ALREADY_EXISTS)
    new_password = conn.inner_field('new-password')
    admin = conn.outer_field_bool('admin')
    if admin is None:
        admin = False
    user = User(name, clear_password=new_password, admin=admin)
    db.save(user)
    db.commit()
    conn.send_reply_ok_only()

@request_handler()
def cmd_delete_user(db, conn):
    conn.authenticate_admin(db)
    user = user_by_name(db, conn)
    if len(user.key_accesses) > 0:
        conn.send_error(errors.USER_HAS_KEY_ACCESSES)
    db.delete(user)
    db.commit()
    conn.send_reply_ok_only()

@request_handler()
def cmd_user_info(db, conn):
    conn.authenticate_admin(db)
    user = user_by_name(db, conn)
    conn.send_reply_header(errors.OK, {'admin': user.admin})
    conn.send_reply_payload('')

@request_handler()
def cmd_modify_user(db, conn):
    conn.authenticate_admin(db)
    user = user_by_name(db, conn)
    admin = conn.outer_field_bool('admin')
    if admin is not None:
        user.admin = admin
    new_name = conn.safe_outer_field('new-name')
    if new_name is not None:
        # FIXME: is this check atomic?
        if db.query(User).filter_by(name=new_name).first() is not None:
            conn.send_error(errors.ALREADY_EXISTS)
        user.name = new_name
    new_password = conn.inner_field('new-password')
    if new_password is not None:
        user.clear_password = new_password
    db.commit()
    conn.send_reply_ok_only()

@request_handler()
def cmd_key_user_info(db, conn):
    conn.authenticate_admin(db)
    access = key_access_by_names(db, conn)
    conn.send_reply_header(errors.OK, {'key-admin': access.key_admin})
    conn.send_reply_payload('')

@request_handler()
def cmd_modify_key_user(db, conn):
    conn.authenticate_admin(db)
    access = key_access_by_names(db, conn)
    key_admin = conn.outer_field_bool('key-admin')
    if key_admin is not None:
        access.key_admin = key_admin
    db.commit()
    conn.send_reply_ok_only()

@request_handler()
def cmd_list_keys(db, conn):
    conn.authenticate_admin(db)
    # Order by name to hide database structure
    keys = db.query(Key).order_by(Key.name).all()
    conn.send_reply_header(errors.OK, {'num-keys': len(keys)})
    payload = ''
    for user in keys:
        payload += user.name + '\x00'
    conn.send_reply_payload(payload)

@request_handler()
def cmd_new_key(db, conn):
    conn.authenticate_admin(db)
    key_name = conn.safe_outer_field('key', required=True)
    # FIXME: is this check atomic?
    if db.query(Key).filter_by(name=key_name).first() is not None:
        conn.send_error(errors.ALREADY_EXISTS)
    admin_name = conn.safe_outer_field('initial-key-admin')
    if admin_name is None:
        admin_name = conn.safe_outer_field('user', required=True)
    admin = db.query(User).filter_by(name=admin_name).first()
    if admin is None:
        conn.send_error(errors.USER_NOT_FOUND)
    key_attrs = ('Key-Type: %s\n' % conn.config.gnupg_key_type +
                 'Key-Length: %d\n' % conn.config.gnupg_key_length +
                 'Key-Usage: %s\n' % conn.config.gnupg_key_usage)
    if conn.config.gnupg_subkey_type is not None:
        key_attrs += ('Subkey-Type: %s\n' % conn.config.gnupg_subkey_type +
                      'Subkey-Length: %d\n' % conn.config.gnupg_subkey_length)
    key_passphrase = random_passphrase(conn)
    key_attrs += 'Passphrase: %s\n' % key_passphrase
    name = conn.safe_outer_field('name-real')
    if name is None:
        name = key_name
    key_attrs += 'Name-Real: %s\n' % name
    name = conn.safe_outer_field('name-comment')
    if name is not None:
        key_attrs += 'Name-Comment: %s\n' % name
    name = conn.safe_outer_field('name-email')
    if name is not None:
        key_attrs += 'Name-Email: %s\n' % name
    expire = conn.safe_outer_field('expire-date')
    if expire is not None:
        if not utils.yyyy_mm_dd_is_valid(expire):
            raise InvalidRequestError('Invalid expiration date')
        key_attrs += 'Expire-Date: %s\n' % expire
    user_passphrase = conn.inner_field('passphrase', required=True)

    env = dict(os.environ) # Shallow copy, uses our $GNUPGHOME
    env['LC_ALL'] = 'C'
    sub = subprocess.Popen((settings.gnupg_bin, '--gen-key', '--batch',
                            '--quiet', '--status-fd', '1'),
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, close_fds=True, env=env)
    (out, err) = sub.communicate(key_attrs)
    for line in err.split('\n'):
        if (line != '' and
            not line.startswith('gpg: WARNING: unsafe permissions on homedir')
            and not line.startswith('Not enough random bytes available.')
            and not line.startswith('the OS a chance to collect more entropy!')
            and not (line.startswith('gpg: key ') and
                     line.endswith('marked as ultimately trusted'))):
                logging.error('Unrecognized GPG stderr: %s', repr(line))
                conn.send_error(errors.UNKNOWN_ERROR)
    fingerprint = None
    for line in out.split('\n'):
        if (line == '' or line == '[GNUPG:] GOOD_PASSPHRASE' or
            line.startswith('[GNUPG:] PROGRESS')):
            continue
        if not line.startswith('[GNUPG:] KEY_CREATED'):
            logging.error('Unrecognized GPG stdout: %s', repr(line))
            conn.send_error(errors.UNKNOWN_ERROR)
        fingerprint = line.split(' ')[-1]
    if fingerprint is None:
        logging.error('Can not find fingerprint of a new key in gpg output')
        conn.send_error(errors.UNKNOWN_ERROR)

    try:
        key = Key(key_name, fingerprint)
        db.save(key)
        access = KeyAccess(key, admin, key_admin=True)
        access.set_passphrase(conn.config, key_passphrase=key_passphrase,
                              user_passphrase=user_passphrase)
        db.save(access)
        db.commit()
    except:
        server_common.gpg_delete_key(conn.config, fingerprint)
        raise
    payload = server_common.gpg_public_key(conn.config, fingerprint)
    conn.send_reply_header(errors.OK, {})
    conn.send_reply_payload(payload)

@request_handler(payload_storage=RequestHandler.PAYLOAD_FILE)
def cmd_import_key(db, conn):
    conn.authenticate_admin(db)
    key_name = conn.safe_outer_field('key', required=True)
    # FIXME: is this check atomic?
    if db.query(Key).filter_by(name=key_name).first() is not None:
        conn.send_error(errors.ALREADY_EXISTS)
    admin_name = conn.safe_outer_field('initial-key-admin')
    if admin_name is None:
        admin_name = conn.safe_outer_field('user', required=True)
    admin = db.query(User).filter_by(name=admin_name).first()
    if admin is None:
        conn.send_error(errors.USER_NOT_FOUND)
    new_key_passphrase = random_passphrase(conn)
    import_key_passphrase = conn.inner_field('passphrase', required=True)
    user_passphrase = conn.inner_field('new-passphrase', required=True)

    try:
        fingerprint = server_common.gpg_import_key(conn.config, conn.payload_file)
    except server_common.GPGError, e:
        conn.send_error(errors.INVALID_IMPORT, message=str(e))

    try:
        try:
            server_common.gpg_change_password(conn.config, fingerprint,
                                              import_key_passphrase,
                                              new_key_passphrase)
        except server_common.GPGError, e:
            conn.send_error(errors.IMPORT_PASSPHRASE_ERROR)

        key = Key(key_name, fingerprint)
        db.save(key)
        access = KeyAccess(key, admin, key_admin=True)
        access.set_passphrase(conn.config, key_passphrase=new_key_passphrase,
                              user_passphrase=user_passphrase)
        db.save(access)
        db.commit()
    except:
        server_common.gpg_delete_key(conn.config, fingerprint)
        raise
    conn.send_reply_ok_only()

@request_handler()
def cmd_delete_key(db, conn):
    conn.authenticate_admin(db)
    key = key_by_name(db, conn)
    server_common.gpg_delete_key(conn.config, key.fingerprint)
    for a in key.key_accesses:
        db.delete(a)
    db.delete(key)
    db.commit()
    conn.send_reply_ok_only()

@request_handler()
def cmd_modify_key(db, conn):
    conn.authenticate_admin(db)
    key = key_by_name(db, conn)
    new_name = conn.safe_outer_field('new-name')
    if new_name is not None:
        # FIXME: is this check atomic?
        if db.query(Key).filter_by(name=new_name).first() is not None:
            conn.send_error(errors.ALREADY_EXISTS)
        key.name = new_name
    db.commit()
    conn.send_reply_ok_only()

@request_handler()
def cmd_list_key_users(db, conn):
    (user, key) = conn.authenticate_admin_or_key_admin(db)
    # Order by name to hide database structure
    names = sorted(access.user.name for access in key.key_accesses)
    conn.send_reply_header(errors.OK, {'num-users': len(names)})
    payload = ''
    for name in names:
        payload += name + '\x00'
    conn.send_reply_payload(payload)

@request_handler()
def cmd_grant_key_access(db, conn):
    (access, key_passphrase) = conn.authenticate_key_admin(db)
    user = user_by_name(db, conn)
    new_passphrase = conn.inner_field('new-passphrase', required=True)
    # FIXME: is this check atomic?
    if (db.query(KeyAccess).filter_by(user=user, key=access.key).first() is not
        None):
        conn.send_error(errors.ALREADY_EXISTS)
    a2 = KeyAccess(access.key, user, key_admin=False)
    a2.set_passphrase(conn.config, key_passphrase=key_passphrase,
                      user_passphrase=new_passphrase)
    db.save(a2)
    db.commit()
    conn.send_reply_ok_only()

@request_handler()
def cmd_revoke_key_access(db, conn):
    (_, key) = conn.authenticate_admin_or_key_admin(db)
    user = user_by_name(db, conn)
    access = db.query(KeyAccess).filter_by(user=user, key=key).first()
    if access is None:
        conn.send_error(errors.KEY_USER_NOT_FOUND)
    if len(key.key_accesses) == 1:
        conn.send_error(errors.ONLY_ONE_KEY_USER)
    db.delete(access)
    db.commit()
    conn.send_reply_ok_only()

@request_handler()
def cmd_get_public_key(db, conn):
    (_, key) = conn.authenticate_admin_or_user(db)
    payload = server_common.gpg_public_key(conn.config, str(key.fingerprint))
    conn.send_reply_header(errors.OK, {})
    conn.send_reply_payload(payload)

@request_handler()
def cmd_change_passphrase(db, conn):
    (access, key_passphrase) = conn.authenticate_user(db)
    new_passphrase = conn.inner_field('new-passphrase', required=True)
    access.set_passphrase(conn.config, key_passphrase=key_passphrase,
                          user_passphrase=new_passphrase)
    db.commit()
    conn.send_reply_ok_only()

@request_handler(payload_storage=RequestHandler.PAYLOAD_FILE)
def cmd_sign_text(db, conn):
    (access, key_passphrase) = conn.authenticate_user(db)
    signed_file = tempfile.TemporaryFile()
    try:
        server_common.gpg_clearsign(conn.config, signed_file, conn.payload_file,
                                    access.key.fingerprint, key_passphrase)
        logging.info('Signed text %s with key %s',
                     binascii.b2a_hex(conn.payload_sha512_digest),
                     access.key.name)
        conn.send_reply_header(errors.OK, {})
        conn.send_reply_payload_from_file(signed_file)
    finally:
        signed_file.close()

@request_handler(payload_storage=RequestHandler.PAYLOAD_FILE)
def cmd_sign_data(db, conn):
    (access, key_passphrase) = conn.authenticate_user(db)
    signature_file = tempfile.TemporaryFile()
    try:
        server_common.gpg_detached_signature(conn.config, signature_file,
                                             conn.payload_file,
                                             access.key.fingerprint,
                                             key_passphrase)
        logging.info('Signed data %s with key %s',
                     binascii.b2a_hex(conn.payload_sha512_digest),
                     access.key.name)
        conn.send_reply_header(errors.OK, {})
        conn.send_reply_payload_from_file(signature_file)
    finally:
        signature_file.close()

@request_handler(payload_storage=RequestHandler.PAYLOAD_FILE,
                 payload_auth_optional=True)
def cmd_sign_rpm(db, conn):
    # Don't import rpm at the top of the file!  The rpm Python module calls
    # NSS_NoDB_Init() during its initialization, which breaks our attempts to
    # initialize nss with our certificate database.
    import rpm

    (access, key_passphrase) = conn.authenticate_user(db)
    # Use an external process to verify the file first, to prevent the attacker
    # from taking control of a process with an open network socket and
    # key_passphrase if a security bug in librpm* is exploitable.
    res = subprocess.call(('rpm', '--quiet', '--nosignature', '-K',
                           conn.payload_path),
                          # PIPE is used only to avoid inheriting our file
                          # descriptors
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, close_fds=True)
    if res != 0:
        conn.send_error(errors.CORRUPT_RPM)

    ts = rpm.ts()
    ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
    try:
        hdr = ts.hdrFromFdno(conn.payload_file.fileno())
    except rpm.error:
        conn.send_error(errors.CORRUPT_RPM)

    rpm_id = (hdr[rpm.RPMTAG_NAME], hdr[rpm.RPMTAG_EPOCH],
              hdr[rpm.RPMTAG_VERSION], hdr[rpm.RPMTAG_RELEASE],
              hdr[rpm.RPMTAG_ARCH],
              binascii.b2a_hex(conn.payload_sha512_digest))

    for (field, tag) in (('rpm-name', rpm.RPMTAG_NAME),
                         ('rpm-epoch', rpm.RPMTAG_EPOCH),
                         ('rpm-version', rpm.RPMTAG_VERSION),
                         ('rpm-release', rpm.RPMTAG_RELEASE),
                         ('rpm-arch', rpm.RPMTAG_ARCH)):
        field_value = conn.safe_outer_field(field)
        if field_value is None:
            continue
        rpm_value = hdr[tag]
        if rpm_value is None:
            rpm_value = ''
        if field_value != rpm_value:
            raise InvalidRequestError('RPM mismatch')
    field_value = conn.outer_field('rpm-sigmd5')
    if field_value is not None:
        rpm_value = hdr[rpm.RPMTAG_SIGMD5]
        if rpm_value is None or field_value != rpm_value:
            raise InvalidRequestError('RPM mismatch')
    elif not conn.payload_authenticated:
        conn.send_error(errors.UNAUTHENTICATED_RPM)

    env = dict(os.environ) # Shallow copy, uses our $GNUPGHOME
    env['LC_ALL'] = 'C'
    argv = ['--define', '_signature gpg',
            '--define', '_gpg_name %s' % access.key.fingerprint]
    field_value = conn.outer_field_bool('v3-signature')
    if field_value is not None and field_value:
        # Add --force-v3-sigs to the value in redhat-rpm-config-9.0.3-3.fc10
        argv += ['--define', '__gpg_sign_cmd %{__gpg} gpg --force-v3-sigs '
                 '--batch --no-verbose --no-armor --passphrase-fd 3 '
                 '--no-secmem-warning -u "%{_gpg_name}" -sbo '
                 '%{__signature_filename} %{__plaintext_filename}']
    child = pexpect.spawn('rpm', argv + ['--addsign', conn.payload_path],
                          env=env)
    child.expect('Enter pass phrase: ')
    child.sendline(key_passphrase)
    answer = child.expect(['Pass phrase is good\.',
                           'Pass phrase check failed'])
    child.expect(pexpect.EOF)
    child.close()
    if (not os.WIFEXITED(child.status) or
        os.WEXITSTATUS(child.status) != 0 or answer != 0):
        logging.error('Error signing %s: status %d, output %s',
                      repr(rpm_id), child.status, child.before)
    else:
        logging.info('Signed RPM %s with key %s', repr(rpm_id),
                     access.key.name)

    # Reopen to get the new file even if rpm doesn't overwrite the file in place
    f = open(conn.payload_path, 'rb')
    try:
        conn.send_reply_header(errors.OK, {})
        conn.send_reply_payload_from_file(f)
    finally:
        f.close()

def unknown_request_handler(unused_db, conn):
    conn.send_reply_header(errors.UNKNOWN_OP, {})
    conn.send_reply_payload('')
# Allow some payload in order to return errors.UNKNOWN_OP rather than fail with
# "payload too large"
request_handlers[None] = RequestHandler(unknown_request_handler,
                                        RequestHandler.PAYLOAD_MEMORY)



_CHILD_OK = 0                   # Handled a request
_CHILD_CONNECTION_REFUSED = 1   # Connection to the bridge was refused
_CHILD_BUG = 2                  # A bug in the child
# Undefined values are treated as _CHILD_BUG:

def request_handling_child(config):
    '''Handle a single request, runinng in a child process.

    Return one of the _CHILD_* exit codes.

    '''
    try:
        utils.set_regid(config)
        utils.set_reuid(config)
        utils.update_HOME_for_uid(config)
    except:
        # The failing function has already logged the exception
        return _CHILD_BUG

    db = server_common.db_open(config)
    child_exception = None
    try:
        conn = ServersConnection(config)
        try:
            logging.debug('Waiting for a request')
            handler = conn.read_request()
            handler.handler(db, conn)
        finally:
            try:
                conn.close()
            except (double_tls.ChildConnectionRefusedError,
                    double_tls.ChildUnrecoverableError), e:
                child_exception = e
    except RequestHandled:
        pass
    except InvalidRequestError, e:
        logging.warning('Invalid request: %s', str(e))
    except (IOError, socket.error), e:
        logging.info('I/O error: %s', repr(e))
    except nss.error.NSPRError, e:
        if e.errno == nss.error.PR_CONNECT_RESET_ERROR:
            logging.debug('NSPR error: Connection reset')
        else:
            logging.warning('NSPR error: %s', str(e))
    except EOFError, e:
        if isinstance(child_exception, double_tls.ChildConnectionRefusedError):
            logging.info('Connection to the bridge refused')
            return _CHILD_CONNECTION_REFUSED
        elif isinstance(child_exception, double_tls.ChildUnrecoverableError):
            logging.debug('Unrecoverable error in child')
            return _CHILD_BUG
        else:
            logging.info('Unexpected EOF')
    except (KeyboardInterrupt, SystemExit):
        pass # Don't consider this an unexpected exception
    except (utils.NSSInitError, double_tls.InnerCertificateNotFound), e:
        logging.error(str(e))
        return _CHILD_BUG
    except:
        logging.error('Unexpected exception', exc_info=True)
        return _CHILD_BUG
    logging.debug('Request handling finished')
    return _CHILD_OK

def main():
    options = utils.get_daemon_options('A signing server',
                                       '~/.sigul/server.conf')
    d = {}
    if settings.log_dir is not None:
        d['filename'] = os.path.join(settings.log_dir, 'sigul_server.log')
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                        level=utils.logging_level_from_options(options), **d)
    try:
        config = ServerConfiguration(options.config_file)
    except utils.ConfigurationError, e:
        sys.exit(str(e))

    server_common.gpg_modify_environ(config)

    if options.daemonize:
        utils.daemonize()

    signal.signal(signal.SIGTERM, utils.sigterm_handler)
    utils.create_pid_file('sigul_server')
    try:
        try:
            fast_reconnections_done = 0
            while True:
                child_pid = os.fork()
                if child_pid == 0:
                    try:
                        status = request_handling_child(config)
                        logging.shutdown()
                        os._exit(status)
                    finally:
                        try:
                            logging.shutdown()
                        finally:
                            os._exit(_CHILD_BUG)
                (_, status) = os.waitpid(child_pid, 0)
                if os.WIFEXITED(status) and os.WEXITSTATUS(status) == _CHILD_OK:
                    fast_reconnections_done = 0
                elif (os.WIFEXITED(status) and
                      os.WEXITSTATUS(status) == _CHILD_CONNECTION_REFUSED):
                    if fast_reconnections_done < MAX_FAST_RECONNECTIONS:
                        time.sleep(FAST_RECONNECTION_SECONDS)
                        fast_reconnections_done += 1
                    else:
                        time.sleep(SLOW_RECONNECTION_SECONDS)
                        fast_reconnections_done = 0
                else: # _CHILD_BUG, unknown status code or WIFSIGNALED
                    logging.error('Child died with status %d', status)
                    break
        except (KeyboardInterrupt, SystemExit):
            pass # Silence is golden
    finally:
        utils.delete_pid_file('sigul_server')

if __name__ == '__main__':
    main()
