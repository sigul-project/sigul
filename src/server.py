# Copyright (C) 2008-2016 Red Hat, Inc.  All rights reserved.
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

import base64
import binascii
import cStringIO
import ConfigParser
import crypt
import json
import hashlib
import logging
import os
import shutil
import signal
import socket
import struct
import subprocess
import shutil
import sys
import tempfile
import time

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
                         'gnupg-key-type': 'RSA',
                         'gnupg-key-length': 2048,
                         'gnupg-subkey-type': 'RSA',
                         'gnupg-subkey-length': 2048,
                         'gnupg-key-usage': 'sign',
                         'max-file-payload-size': 1024 * 1024 * 1024,
                         'max-memory-payload-size': 1024 * 1024,
                         'max-rpms-payloads-size': 10 * 1024 * 1024 * 1024,
                         'passphrase-length': 64,
                         'server-cert-nickname': 'sigul-server-cert',
                         'signing-timeout': 60,
                         'lenient-username-check': 'no',
                         'proxy-usernames': ''})

    def _add_sections(self, sections):
        super(ServerConfiguration, self)._add_sections(sections)
        sections.update(('gnupg','server'))

    def _read_configuration(self, parser):
        super(ServerConfiguration, self)._read_configuration(parser)
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
        self.max_rpms_payloads_size = parser.getint('server',
                                                    'max-rpms-payloads-size')
        self.server_cert_nickname = parser.get('server', 'server-cert-nickname')
        self.signing_timeout = parser.getint('server', 'signing-timeout')
        self.lenient_username_check = parser.getboolean('server', 'lenient-username-check')
        self.proxy_usernames = [us.strip() for us in
                                parser.get('server', 'proxy-usernames').split(',')]

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

    def peer_subject(self):
        return self.__client.peercert.subject

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

    def safe_inner_field(self, key, **kwargs):
        '''Return an inner field value, or None if not present.

        Raise InvalidRequestError if field is not a safe string.

        '''
        v = self.inner_field(key, **kwargs)
        if v is not None and not utils.string_is_safe(v):
            raise InvalidRequestError('Field %s has unsafe value' % repr(key))
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
        logging.info('Request: %s', utils.readable_fields(self.__outer_fields))
        header_data = proxy.stored_data()
        buf = self.__client.outer_read(utils.u32_size)
        payload_size = utils.u32_unpack(buf)

        request_op = self.safe_outer_field('op', required=True)
        if request_op not in request_handlers:
            request_op = None
        handler = request_handlers[request_op]

        reader = utils.SHA512Reader(self.__client.outer_read)
        if handler.payload_storage == RequestHandler.PAYLOAD_NONE:
            if payload_size != 0:
                raise InvalidRequestError('Unexpected payload')
        elif handler.payload_storage == RequestHandler.PAYLOAD_MEMORY:
            if payload_size > self.config.max_memory_payload_size:
                raise InvalidRequestError('Payload too large')
            f = cStringIO.StringIO()
            utils.copy_data(f.write, reader.read, payload_size)
            self.__payload = f.getvalue()
        else:
            assert handler.payload_storage == RequestHandler.PAYLOAD_FILE
            if payload_size > self.config.max_file_payload_size:
                raise InvalidRequestError('Payload too large')
            (fd, self.payload_path) = tempfile.mkstemp(text=False)
            f = os.fdopen(fd, 'w+b')
            try:
                utils.copy_data(f.write, reader.read, payload_size)
            finally:
                f.close()
            self.payload_file = open(self.payload_path, 'rb')
        self.payload_sha512_digest = reader.sha512()

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
            nss.nss.sha512_digest(header_data)):
            raise InvalidRequestError('Header authentication failed')
        payload_auth = self.inner_field('payload-auth-sha512')
        if payload_auth is None:
            if not handler.payload_auth_optional:
                raise InvalidRequestError('Authentication hash missing')
        else:
            if payload_auth != self.payload_sha512_digest:
                raise InvalidRequestError('Payload authentication failed')
        self.payload_authenticated = payload_auth is not None

        mech = nss.nss.CKM_SHA512_HMAC
        slot = nss.nss.get_best_slot(mech)
        buf = self.inner_field('header-auth-key', required=True)
        if len(buf) < 64:
            raise InvalidRequestError('Header authentication key too small')
        # "Unwrap" because the key was encrypted for transmission using TLS
        nss_key = nss.nss.import_sym_key(slot, mech, nss.nss.PK11_OriginUnwrap,
                                         nss.nss.CKA_SIGN, nss.nss.SecItem(buf))
        self.__reply_header_writer = \
            utils.SHA512HMACWriter(self.__client.outer_write, nss_key)
        buf = self.inner_field('payload-auth-key', required=True)
        if len(buf) < 64:
            raise InvalidRequestError('Payload authentication key too small')
        nss_key = nss.nss.import_sym_key(slot, mech, nss.nss.PK11_OriginUnwrap,
                                         nss.nss.CKA_SIGN, nss.nss.SecItem(buf))
        self.__reply_payload_writer = \
            utils.SHA512HMACWriter(self.__client.outer_write, nss_key)
        return handler

    def send_reply_header(self, error_code, fields):
        '''Send a reply header to the client.'''
        self.__reply_header_writer.write(utils.u32_pack(error_code))
        self.__reply_header_writer.write(utils.format_fields(fields))
        self.__reply_header_writer.write_64B_hmac()

    def __send_payload_size(self, payload_size):
        '''Prepare for sending payload of payload_size to the client.

        Valid both for the primary payload and for subreply payloads.

        '''
        self.__client.outer_write(utils.u32_pack(payload_size))

    def __send_payload_from_file(self, writer, fd):
        '''Send contents of fd to the client as payload, using writer.

        Valid both for the primary payload and for subreply payloads.

        '''
        fd.seek(0)
        file_size = os.fstat(fd.fileno()).st_size
        self.__send_payload_size(file_size)

        sent = 0
        while True:
            data = fd.read(4096)
            if len(data) == 0:
                break
            writer.write(data)
            sent += len(data)
        if sent != file_size:
            raise IOError('File size did not match size returned by fstat()')
        writer.write_64B_hmac()

    def send_reply_payload(self, payload):
        '''Send payload to the client.'''
        self.__send_payload_size(len(payload))
        self.__reply_payload_writer.write(payload)
        self.__reply_payload_writer.write_64B_hmac()

    def send_reply_payload_from_file(self, fd):
        '''Send contents of fd to the client as payload.'''
        self.__send_payload_from_file(self.__reply_payload_writer, fd)

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

    def read_subheader(self, nss_key):
        '''Read fields in a subrequest header authenticated using nss_key.

        Return the header.

        '''
        reader = utils.SHA512HMACReader(self.__client.outer_read, nss_key)
        try:
            fields = utils.read_fields(reader.read)
        except utils.InvalidFieldsError, e:
            raise InvalidRequestError('Invalid response format: %s' % str(e))
        if not reader.verify_64B_hmac_authenticator():
            raise InvalidRequestError('Subrequest header authentication failed')
        return fields

    def read_subpayload_to_file(self, nss_key, max_size, tmp_dir):
        '''Read a subpayload authenticated using nss_key.

        Return (path, file, payload digest, payload authenticated).  Limit file
        size to max_size.  Create the temporary file in tmp_dir.

        '''
        buf = self.__client.outer_read(utils.u32_size)
        payload_size = utils.u32_unpack(buf)
        if payload_size > self.config.max_file_payload_size:
            raise InvalidRequestError('Payload too large')
        if payload_size > max_size:
            raise InvalidRequestError('Total payload size too large')

        reader = utils.SHA512HashAndHMACReader(self.__client.outer_read,
                                               nss_key)
        (fd, payload_path) = tempfile.mkstemp(text=False, dir=tmp_dir)
        f = os.fdopen(fd, 'w+b')
        try:
            utils.copy_data(f.write, reader.read, payload_size)
        finally:
            f.close()
        payload_file = open(payload_path, 'rb')
        payload_sha512_digest = reader.sha512()
        auth = self.__client.outer_read(64)
        return (payload_path, payload_file, payload_sha512_digest,
                auth == reader.hmac())

    def send_subheader(self, fields, nss_key):
        '''Send fields in a subreply header authenticated using nss_key.'''
        writer = utils.SHA512HMACWriter(self.__client.outer_write, nss_key)
        writer.write(utils.format_fields(fields))
        writer.write_64B_hmac()

    def send_empty_subpayload(self, nss_key):
        '''Send an empty subreply payload authenticated using nss_key.'''
        self.__send_payload_size(0)
        writer = utils.SHA512HMACWriter(self.__client.outer_write, nss_key)
        writer.write_64B_hmac()

    def send_subpayload_from_file(self, fd, nss_key):
        '''Send a subreply payload from fd authenticated using nss_key.'''
        writer = utils.SHA512HMACWriter(self.__client.outer_write, nss_key)
        self.__send_payload_from_file(writer, fd)

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

    def _verify_username(self, outer_user):
        if self.config.lenient_username_check:
            # The admin disabled the strict user vs CN check
            return
        peeruser = self.peer_subject().common_name
        if peeruser in self.config.proxy_usernames:
            # This CN was explicitly authorized to use other usernames
            return
        if peeruser != outer_user:
            self.auth_fail('Cert CN and user differ')

    def authenticate_admin(self, db):
        '''Check the request is a valid administration request.

        Raise RequestHandled (on permission denied), InvalidRequestError.
        '''
        user = self.safe_outer_field('user')
        if user is None:
            self.auth_fail('user field missing')
        self._verify_username(user)
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
        self._verify_username(user)
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
            access = None
            if user is not None and key is not None:
                access = (db.query(KeyAccess).filter_by(user=user, key=key).
                          first())
            if access is None:
                access = KeyAccess(None, None)
            key_passphrase = access.get_passphrase(self.config,
                                                   user_passphrase)
            if not key_passphrase:
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
        self._verify_username(user)
        key = self.safe_outer_field('key')
        if key is None:
            self.auth_fail('key field missing')
        user_passphrase = self.inner_field('passphrase')
        if user_passphrase is None:
            self.auth_fail('passphrase field missing')
        user = db.query(User).filter_by(name=user).first()
        key = db.query(Key).filter_by(name=key).first()
        access = None
        if user is not None and key is not None:
            access = db.query(KeyAccess).filter_by(user=user, key=key).first()
        if access is None:
            access = KeyAccess(None, None)
        key_passphrase = access.get_passphrase(self.config,
                                               user_passphrase)
        if not key_passphrase:
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

class RPMFileError(Exception):
    pass

class RPMFile(object):
    '''A single RPM, to be signed.'''

    def __init__(self, path, sha512_digest, request_id=None):
        '''Initialize.

        sha512_digest is a SHA-512 digest of path, in binary form.
        self.status is set to None, to be updated by other operations with this
        RPM.

        '''
        self.path = path
        self.__sha512_digest = sha512_digest
        self.request_id = request_id
        self.status = None

    def verify(self):
        '''Verify validity of the file.

        Raise RPMFileError (setting self.status).

        '''
        # Use an external process to verify the file, to prevent the attacker
        # from taking control of a process with an open network socket and
        # key_passphrase if a security bug in librpm* is exploitable.
        res = subprocess.call(('rpm', '--quiet', '--nosignature', '-K',
                               self.path),
                              # PIPE is used only to avoid inheriting our file
                              # descriptors
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, close_fds=True)
        if res != 0:
            self.status = errors.CORRUPT_RPM
            raise RPMFileError('Corrupt RPM')

    def read_header(self, fd):
        '''Read file header from fd, which corresponds to self.path.

        Set self.rpm_id to a string identifying the RPM.  Raise RPMFileError
        (setting self.status).

        '''
        # Don't import rpm at the top of the file!  The rpm Python module calls
        # NSS_NoDB_Init() during its initialization, which breaks our attempts
        # to initialize nss with our certificate database.
        import rpm

        ts = rpm.ts()
        ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
        try:
            self.__header = ts.hdrFromFdno(fd.fileno())
        except rpm.error, e:
            self.status = errors.CORRUPT_RPM
            raise RPMFileError('Error reading RPM header: %s' % str(e))

        rpm_id = (self.__header[rpm.RPMTAG_NAME],
                  self.__header[rpm.RPMTAG_EPOCH],
                  self.__header[rpm.RPMTAG_VERSION],
                  self.__header[rpm.RPMTAG_RELEASE],
                  self.__header[rpm.RPMTAG_ARCH],
                  binascii.b2a_hex(self.__sha512_digest))
        self.rpm_id = repr(rpm_id)

    def authenticate(self, get_field, payload_authenticated):
        '''Verify the file corresponds to the request fields.

        Use get_field to read a request field (may return None if missing).
        Raise RPMFileError on missing authentication (setting self.status),
        InvalidRequestError on invalid authentication.

        '''
        # Don't import rpm at the top of the file!  The rpm Python module calls
        # NSS_NoDB_Init() during its initialization, which breaks our attempts
        # to initialize nss with our certificate database.
        import rpm

        for (field, tag) in (('rpm-name', rpm.RPMTAG_NAME),
                             ('rpm-epoch', rpm.RPMTAG_EPOCH),
                             ('rpm-version', rpm.RPMTAG_VERSION),
                             ('rpm-release', rpm.RPMTAG_RELEASE),
                             ('rpm-arch', rpm.RPMTAG_ARCH)):
            field_value = get_field(field)
            if field_value is None:
                continue
            if not utils.string_is_safe(field_value):
                raise InvalidRequestError('Field %s has unsafe value' %
                                          repr(field))
            if (tag == rpm.RPMTAG_ARCH and
                self.__header[rpm.RPMTAG_SOURCEPACKAGE] == 1):
                rpm_value = 'src'
            else:
                rpm_value = self.__header[tag]
                if rpm_value is None:
                    rpm_value = ''
            if field_value != str(rpm_value):
                raise InvalidRequestError('RPM mismatch')

        field_value = get_field('rpm-sigmd5')
        if field_value is not None:
            rpm_value = self.__header[rpm.RPMTAG_SIGMD5]
            if rpm_value is None or field_value != rpm_value:
                raise InvalidRequestError('RPM sigmd5 mismatch')
        elif not payload_authenticated:
            self.status = errors.UNAUTHENTICATED_RPM
            raise RPMFileError('RPM not authenticated')

class SigningContext(object):
    '''A tool for running rpm --addsign.'''

    _rpm_sign_args_gpg_workaround = None
    @staticmethod
    def _get_rpm_sign_args_gpg_workaround():
        """
        This function returns the --batch --passphrase-fd 3 arguments for the
        gpg_sign_cmd if the current version of rpm/gnupg1 needs those, and an
        empty string otherwise.
        """
        if SigningContext._rpm_sign_args_gpg_workaround is None:
            # Build
            # Don't import rpm at the top of the file!  The rpm Python module
            # calls NSS_NoDB_Init() during its initialization, which breaks our
            # attempts to initialize nss with our certificate database.
            import rpm
            SigningContext._rpm_sign_args_gpg_workaround = \
                '--batch' in rpm.expandMacro('%{__gpg_sign_cmd}')
        if SigningContext._rpm_sign_args_gpg_workaround:
            return '--batch --passphrase-fd 3 '
        else:
            return ''

    def __init__(self, conn, key, key_passphrase):
        self.__key = key
        self.__key_passphrase = key_passphrase
        self.__argv = ['--define', '_signature gpg',
                       '--define', '_gpg_name %s' % key.fingerprint,
                       '--define', '__gpg %s' % settings.gnupg_bin]
        field_value = conn.outer_field_bool('v3-signature')
        if field_value is not None and field_value:
            # Add --force-v3-sigs to the value in redhat-rpm-config-9.0.3-3.fc10
            self.__argv += ['--define',
                            '__gpg_sign_cmd %{__gpg} gpg --force-v3-sigs '
                            '--no-verbose --no-armor ' +
                            SigningContext._get_rpm_sign_args_gpg_workaround()
                            + '--no-secmem-warning -u "%{_gpg_name}" -sbo '
                            '%{__signature_filename} %{__plaintext_filename}']
        self.__env = dict(os.environ) # Shallow copy, uses our $GNUPGHOME
        self.__env['LC_ALL'] = 'C'

    def sign_rpm(self, config, rpm):
        '''Sign rpm, using config.

        Raise RPMFileError on error.

        '''
        try:
            child = pexpect.spawn('rpm', self.__argv + ['--addsign', rpm.path],
                                  env=self.__env,
                                  timeout=config.signing_timeout)
            child.expect(['Enter pass phrase: ',
                          'Enter passphrase: '])
            child.sendline(self.__key_passphrase)
            answer = child.expect(['Pass phrase is good\.',
                                   pexpect.EOF,
                                   # For some insane reason, rpmsign sometimes
                                   # asks the passphrase twice.
                                   'Enter passphrase:',
                                   'Pass phrase check failed',
                                   'bad passphrase'])
            if answer == 2:  # Passphrase asked again
                child.sendline(self.__key_passphrase)
                answer = child.expect(['Pass phrase is good\.',
                                       pexpect.EOF,
                                       # We don't expect this again, but to
                                       # keep the same indexes.
                                       'Enter passphrase:',
                                       'Pass phrase check failed',
                                       'bad passphrase'])

            child.expect(pexpect.EOF)
            child.close()
        except pexpect.ExceptionPexpect, e:
            msg = str(e).splitlines()[0] # We don't want all of the pexpect dump
            rpm.status = errors.UNKNOWN_ERROR
            raise RPMFileError('Error signing %s: %s, output %s' %
                               (rpm.rpm_id, msg, child.before))
        if (not os.WIFEXITED(child.status) or
            os.WEXITSTATUS(child.status) != 0 or answer not in [0, 1]):
            rpm.status = errors.UNKNOWN_ERROR
            raise RPMFileError('Error signing %s: status %d, output %s'
                               % (rpm.rpm_id, child.status, child.before))
        logging.info('Signed RPM %s with key %s', rpm.rpm_id, self.__key.name)

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
    db.add(user)
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
    key_passphrase = utils.random_passphrase(conn.config.passphrase_length)
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
        db.add(key)
        access = KeyAccess(key, admin, key_admin=True)
        access.set_passphrase(conn.config, key_passphrase=key_passphrase,
                              user_passphrase=user_passphrase,
                              bind_params=None)
        db.add(access)
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
    new_key_passphrase = utils.random_passphrase(conn.config.passphrase_length)
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
        db.add(key)
        access = KeyAccess(key, admin, key_admin=True)
        access.set_passphrase(conn.config, key_passphrase=new_key_passphrase,
                              user_passphrase=user_passphrase,
                              bind_params=None)
        db.add(access)
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
    server_binding = conn.safe_inner_field('server-binding', required=False)
    client_binding = conn.safe_inner_field('client-binding', required=False)
    try:
        if server_binding is not None:
            server_binding = json.loads(server_binding)
            logging.info('Server binding requested: %s' % server_binding)
        if client_binding is not None:
            client_binding = json.loads(client_binding)
            logging.info('Client binding used: %s' % client_binding)
    except Exception as ex:
        raise InvalidRequestError('Unable to decode binding args: %s' % ex)
    a2 = KeyAccess(access.key, user, key_admin=False)
    try:
        a2.set_passphrase(conn.config, key_passphrase=key_passphrase,
                          user_passphrase=new_passphrase,
                          bind_params=server_binding)
    except NotImplementedError():
        raise InvalidRequestError('Non-implemented binding mechanism requested')
    db.add(a2)
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
                          user_passphrase=new_passphrase, bind_params=None)
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
    armor = conn.outer_field_bool('armor')
    if armor is None:
        armor = False
    try:
        server_common.gpg_detached_signature(conn.config, signature_file,
                                             conn.payload_file,
                                             access.key.fingerprint,
                                             key_passphrase,
                                             armor=armor)
        logging.info('Signed data %s with key %s',
                     binascii.b2a_hex(conn.payload_sha512_digest),
                     access.key.name)
        conn.send_reply_header(errors.OK, {})
        conn.send_reply_payload_from_file(signature_file)
    finally:
        signature_file.close()

@request_handler(payload_storage=RequestHandler.PAYLOAD_FILE)
def cmd_sign_ostree(db, conn):
    (access, key_passphrase) = conn.authenticate_user(db)
    input_file = tempfile.TemporaryFile()
    signature_file = tempfile.TemporaryFile()
    file_hash = conn.safe_outer_field('ostree-hash')
    # Prepare the directory structure that libostree wants
    ostree_path = tempfile.mkdtemp()
    server_common.call_ostree_helper(['init-repo', ostree_path])
    os.mkdir(os.path.join(ostree_path, 'objects', file_hash[:2]))
    shutil.copyfile(conn.payload_file.name,
                    os.path.join(ostree_path, 'objects', file_hash[:2],
                                 '%s.commit' % file_hash[2:]))
    try:
        data = server_common.call_ostree_helper(['get-data', ostree_path,
                                                 file_hash])
        input_file.write(base64.b64decode(data))
        input_file.flush()
        input_file.seek(0)
        checksum = hashlib.sha256(input_file.read()).hexdigest()
        if checksum != file_hash:
            raise InvalidRequestError('ostree-hash does not match payload')
        input_file.seek(0)
        server_common.gpg_detached_signature(conn.config, signature_file,
                                             input_file,
                                             access.key.fingerprint,
                                             key_passphrase,
                                             armor=False)
        logging.info('Signed ostree hash %s with key %s',
                     file_hash,
                     access.key.name)
        signature_file.seek(0)
        server_common.call_ostree_helper(['import-signature', ostree_path,
                                          file_hash],
                                         stdin=base64.b64encode(signature_file.read()))
        with open(os.path.join(ostree_path, 'objects', file_hash[:2],
                               '%s.commitmeta' % file_hash[2:])) as metafile:
            conn.send_reply_header(errors.OK, {})
            conn.send_reply_payload_from_file(metafile)
    finally:
        shutil.rmtree(ostree_path)
        input_file.close()
        signature_file.close()

@request_handler(payload_storage=RequestHandler.PAYLOAD_FILE,
                 payload_auth_optional=True)
def cmd_sign_rpm(db, conn):
    (access, key_passphrase) = conn.authenticate_user(db)

    rpm = RPMFile(conn.payload_path, conn.payload_sha512_digest)
    try:
        rpm.verify()
        rpm.read_header(conn.payload_file)
        rpm.authenticate(conn.outer_field, conn.payload_authenticated)
    except RPMFileError:
        conn.send_error(rpm.status)

    ctx = SigningContext(conn, access.key, key_passphrase)
    try:
        ctx.sign_rpm(conn.config, rpm)
    except RPMFileError, e:
        logging.error(str(e))
        conn.send_error(rpm.status)

    # Reopen to get the new file even if rpm doesn't overwrite the file in place
    f = open(rpm.path, 'rb')
    try:
        conn.send_reply_header(errors.OK, {})
        conn.send_reply_payload_from_file(f)
    finally:
        f.close()

class SignRPMsRequestThread(utils.WorkerThread):
    '''A thread that handles sign-rpm requests.

    The requests are put into dest_queue as RPMFile objects, with None marking
    end of the requests.

    '''

    def __init__(self, conn, dest_queue, header_nss_key, payload_nss_key,
                 tmp_dir):
        super(SignRPMsRequestThread, self). \
            __init__('sign-rpms:requests', 'request thread',
                     output_queues=((dest_queue, None),))
        self.__conn = conn
        self.__dest = dest_queue
        self.__header_nss_key = header_nss_key
        self.__payload_nss_key = payload_nss_key
        self.__tmp_dir = tmp_dir

    def _real_run(self):
        total_size = 0
        server_idx = 0
        while True:
            (rpm, size) = self.__read_one_request \
                (server_idx,
                 self.__conn.config.max_rpms_payloads_size - total_size)
            if rpm is None:
                break
            server_idx += 1
            total_size += size
            self.__dest.put(rpm)

    def __read_one_request(self, server_idx, remaining_size):
        '''Read one request from self.__conn.

        Return (RPMFile, file size), (None, None) on EOF.  Raise
        InvalidRequestError, others.  Only allow remaining_size bytes for the
        payload.

        '''
        try:
            nss_key = utils.derived_key(self.__header_nss_key, server_idx)
            fields = self.__conn.read_subheader(nss_key)
        except EOFError:
            return (None, None)
        s = utils.readable_fields(fields)
        logging.debug('%s: Started handling %s', self.name, s)
        logging.info('Subrequest: %s', s)
        if 'id' not in fields:
            raise InvalidRequestError('Required subheader field id missing.')

        nss_key = utils.derived_key(self.__payload_nss_key, server_idx)
        (path, payload_file, sha512_digest, authenticated) \
            = self.__conn.read_subpayload_to_file(nss_key, remaining_size,
                                                  self.__tmp_dir)
        try:
            # Count whole blocks to avoid millions of 1-byte files filling the
            # hard drive due to internal fragmentation.
            size = utils.file_size_in_blocks(payload_file)

            rpm = RPMFile(path, sha512_digest, request_id=fields['id'])
            try:
                rpm.verify()
                rpm.read_header(payload_file)
            except RPMFileError:
                return (rpm, size)
        finally:
            payload_file.close()

        try:
            rpm.authenticate(fields.get, authenticated)
        except RPMFileError:
            return (rpm, size)

        return (rpm, size)

class SignRPMsSignerThread(utils.WorkerThread):
    '''A thread that actually performs the signing.

    The requests in dst_queue and src_queue are RPMFile objects, with None
    marking end of the requests.

    '''

    def __init__(self, config, dst_queue, src_queue, ctx):
        super(SignRPMsSignerThread, self).__init__ \
            ('sign-rpms:signing', 'signer thread',
             input_queues=((src_queue, None),),
             output_queues=((dst_queue, None),))
        self.__config = config
        self.__dst = dst_queue
        self.__src = src_queue
        self.__ctx = ctx

    def _real_run(self):
        while True:
            rpm = self.__src.get()
            if rpm is None:
                break
            try:
                try:
                    # FIXME: sign more at a time
                    self.__handle_one_rpm(rpm)
                except:
                    if rpm.status is None:
                        rpm.status = errors.UNKNOWN_ERROR
                    raise
            finally:
                self.__dst.put(rpm)

    def __handle_one_rpm(self, rpm):
        '''Handle an incoming request.'''
        logging.debug('%s: Started handling %s', self.name, rpm.rpm_id)
        if rpm.status is not None:
            return

        try:
            self.__ctx.sign_rpm(self.__config, rpm)
        except RPMFileError, e:
            logging.error(str(e))

class SignRPMsReplyThread(utils.WorkerThread):
    '''A thread that sends subrequest replies.

    The requests in src_queue are RPMFile objects, with None marking end of the
    requests.

    '''

    def __init__(self, conn, src_queue, header_nss_key, payload_nss_key):
        super(SignRPMsReplyThread, self). \
            __init__('sign-rpms:replies', 'reply thread',
                     input_queues=((src_queue, None),))
        self.__conn = conn
        self.__src = src_queue
        self.__header_nss_key = header_nss_key
        self.__payload_nss_key = payload_nss_key

    def _real_run(self):
        '''Read all results and send subreplies.'''
        server_idx = 0
        while True:
            rpm = self.__src.get()
            if rpm is None:
                break
            self.__handle_one_rpm(rpm, server_idx)
            server_idx += 1

    def __handle_one_rpm(self, rpm, server_idx):
        '''Send information based on rpm.'''
        logging.debug('%s: Started handling %s', self.name, rpm.rpm_id)
        f = {'id': rpm.request_id}
        if rpm.status is not None:
            f['status'] = rpm.status
            logging.info('Subrequest %d error: %s', server_idx,
                         errors.message(rpm.status))
        else:
            f['status'] = errors.OK
        nss_key = utils.derived_key(self.__header_nss_key, server_idx)
        self.__conn.send_subheader(f, nss_key)

        nss_key = utils.derived_key(self.__payload_nss_key, server_idx)
        if rpm.status is None:
            f = open(rpm.path, 'rb')
            try:
                self.__conn.send_subpayload_from_file(f, nss_key)
            finally:
                f.close()
        else:
            self.__conn.send_empty_subpayload(nss_key)


@request_handler()
def cmd_sign_rpms(db, conn):
    (access, key_passphrase) = conn.authenticate_user(db)
    mech = nss.nss.CKM_GENERIC_SECRET_KEY_GEN
    slot = nss.nss.get_best_slot(mech)
    buf = conn.inner_field('subrequest-header-auth-key', required=True)
    if len(buf) < 64:
        raise InvalidRequestError('Subrequest header authentication key too '
                                  'small')
    # "Unwrap" because the key was encrypted for transmission using TLS
    subrequest_header_nss_key = nss.nss.import_sym_key \
        (slot, mech, nss.nss.PK11_OriginUnwrap, nss.nss.CKA_DERIVE,
         nss.nss.SecItem(buf))
    buf = conn.inner_field('subrequest-payload-auth-key', required=True)
    if len(buf) < 64:
        raise InvalidRequestError('Subrequest payload authentication key too '
                                  'small')
    subrequest_payload_nss_key = nss.nss.import_sym_key \
        (slot, mech, nss.nss.PK11_OriginUnwrap, nss.nss.CKA_DERIVE,
         nss.nss.SecItem(buf))
    buf = conn.inner_field('subreply-header-auth-key', required=True)
    if len(buf) < 64:
        raise InvalidRequestError('Subreply header authentication key too '
                                  'small')
    subreply_header_nss_key = nss.nss.import_sym_key \
        (slot, mech, nss.nss.PK11_OriginUnwrap, nss.nss.CKA_DERIVE,
         nss.nss.SecItem(buf))
    buf = conn.inner_field('subreply-payload-auth-key', required=True)
    if len(buf) < 64:
        raise InvalidRequestError('Subreply payload authentication key too '
                                  'small')
    subreply_payload_nss_key = nss.nss.import_sym_key \
        (slot, mech, nss.nss.PK11_OriginUnwrap, nss.nss.CKA_DERIVE,
         nss.nss.SecItem(buf))
    signing_ctx = SigningContext(conn, access.key, key_passphrase)
    conn.send_reply_ok_only()

    tmp_dir = tempfile.mkdtemp()
    exception = None
    try:
        q1 = utils.WorkerQueue(100)
        q2 = utils.WorkerQueue(100)
        threads = []
        threads.append(SignRPMsRequestThread(conn, q1,
                                             subrequest_header_nss_key,
                                             subrequest_payload_nss_key,
                                             tmp_dir))
        threads.append(SignRPMsSignerThread(conn.config, q2, q1, signing_ctx))
        threads.append(SignRPMsReplyThread(conn, q2, subreply_header_nss_key,
                                           subreply_payload_nss_key))

        (_, exception) = utils.run_worker_threads(threads,
                                                  (InvalidRequestError,))
    finally:
        shutil.rmtree(tmp_dir)
    if exception is not None:
        raise exception[0], exception[1], exception[2]

@request_handler()
def cmd_list_binding_methods(db, conn):
    conn.authenticate_admin(db)
    methods = utils.BindingMethodRegistry.get_registered_methods()
    conn.send_reply_header(errors.OK, {'num-methods': len(methods)})
    payload = ''
    for method in methods:
        payload += method + '\x00'
    conn.send_reply_payload(payload)

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

    child_exception = None
    try:
        db = server_common.db_open(config)
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
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                        level=utils.logging_level_from_options(options),
                        filename=os.path.join(options.log_dir,
                                              'sigul_server.log'))
    try:
        config = ServerConfiguration(options.config_file)
    except utils.ConfigurationError, e:
        sys.exit(str(e))

    utils.BindingMethodRegistry.register_enabled_methods(config)

    server_common.gpg_modify_environ(config)

    if options.daemonize:
        utils.daemonize()

    signal.signal(signal.SIGTERM, utils.sigterm_handler)
    utils.create_pid_file(options, 'sigul_server')
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
        utils.delete_pid_file(options, 'sigul_server')

if __name__ == '__main__':
    main()
