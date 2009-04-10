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
import getpass
import hmac
import logging
import optparse
import os
import socket
import struct
import sys

import M2Crypto.EVP
import nss.nss

import double_tls
import errors
import settings
import utils

class ClientError(Exception):
    '''Any error in the client.'''
    pass

class InvalidResponseError(ClientError):
    '''The response received from the bridge/server is not valid.'''
    pass

 # Infrastructure

class ClientConfiguration(utils.NSSConfiguration, utils.Configuration):

    default_config_file = 'client.conf'

    def _add_defaults(self, defaults):
        super(ClientConfiguration, self)._add_defaults(defaults)
        defaults.update({'bridge-port': 44334,
                         'client-cert-nickname': 'sigul-client-cert',
                         'user-name': getpass.getuser()})

    def _read_configuration(self, parser):
        super(ClientConfiguration, self)._read_configuration(parser)
        self.bridge_hostname = parser.get('client', 'bridge-hostname')
        self.bridge_port = parser.getint('client', 'bridge-port')
        self.client_cert_nickname = parser.get('client', 'client-cert-nickname')
        self.server_hostname = parser.get('client', 'server-hostname')
        self.user_name = parser.get('client', 'user-name')
        self.batch_mode = False

def safe_string(s):
    '''Raise ClientError if s is not a safe string, otherwise return s.'''
    if not utils.string_is_safe(s):
        raise ClientError('\'%s\' (%s) contains prohibited characters' %
                          (s, repr(s)))
    return s

class ClientsConnection(object):
    '''A connection to the bridge/server.'''

    def __init__(self, config):
        self.config = config
        self.__client = None

    def connect(self, op, outer_fields):
        '''Connect and send outer_fields if op, outer_fields is not None.'''
        self.__client = double_tls.DoubleTLSClient(self.config,
                                                   self.config.bridge_hostname,
                                                   self.config.bridge_port,
                                                   self.config.
                                                   client_cert_nickname)
        try:
            utils.nss_init(self.config)
        except utils.NSSInitError, e:
            raise ClientError(str(e))
        # FIXME: python-nss does not support incremental hash computation
        self.__request_header_digest = M2Crypto.EVP.MessageDigest('sha512')
        self.__request_payload_digest = M2Crypto.EVP.MessageDigest('sha512')
        self.__send_header(utils.u32_pack(utils.protocol_version))
        if op is not None and outer_fields is not None:
            self.send_outer_fields(op, outer_fields)

    def send_outer_fields(self, op, outer_fields):
        '''Send outer_fields.'''
        fields = dict(outer_fields) # Shallow copy
        fields['op'] = safe_string(op)
        fields['user'] = safe_string(self.config.user_name)
        self.__send_header(utils.format_fields(fields))

    def __start_payload(self, payload_size):
        '''Prepare for sending payload of payload_size bytes.'''
        self.__client.outer_write(utils.u32_pack(payload_size))

    def __send_payload_part(self, data):
        '''Send a part of request payload.'''
        self.__client.outer_write(data)
        self.__request_payload_digest.update(data)

    def empty_payload(self):
        '''Send an empty payload.'''
        self.__start_payload(0)

    def send_payload(self, data):
        '''Send data as payload.'''
        self.__start_payload(len(data))
        self.__send_payload_part(data)

    def send_payload_from_file(self, file):
        '''Send contents of file as payload.'''
        file.seek(0)
        file_size = os.fstat(file.fileno()).st_size
        self.__start_payload(file_size)
        sent = 0
        while True:
            data = file.read(4096)
            if len(data) == 0:
                break
            self.__send_payload_part(data)
            sent += len(data)
        if sent != file_size:
            raise IOError('File size did not match size returned by fstat()')

    def send_inner(self, inner_fields, omit_payload_auth=False):
        '''Send the inner header, including inner_fields.'''
        # FIXME: handle errors.UNKNOWN_VERSION - there is no inner session and
        # outer session data is not all read
        fields = dict(inner_fields) # Shallow copy
        fields['header-auth-sha512'] = self.__request_header_digest.final()
        if not omit_payload_auth:
            fields['payload-auth-sha512'] = \
                self.__request_payload_digest.final()
        key = nss.nss.generate_random(64)
        fields['header-auth-key'] = key
        # FIXME: python-nss does not support HMAC
        self.__reply_header_hmac = \
            hmac.new(key, digestmod=utils.M2CryptoSHA512DigestMod)
        key = nss.nss.generate_random(64)
        fields['payload-auth-key'] = key
        self.__reply_payload_hmac = \
            hmac.new(key, digestmod=utils.M2CryptoSHA512DigestMod)
        try:
            self.__client.inner_open_client(self.config.server_hostname,
                                            self.config.client_cert_nickname)
        except double_tls.InnerCertificateNotFound, e:
            raise ClientError(str(e))
        try:
            self.__client.inner_write(utils.format_fields(fields))
        finally:
            self.__client.inner_close()

    def read_response(self, expected_errors = (), no_payload=False):
        '''Read server's response.

        Return an error code if OK or in expected_errors. Verify the response
        contains no payload if no_payload.  Raise InvalidResponseError.  Raise
        SystemExit on other reported error.

        '''
        buf = self.__read_header(utils.u32_size)
        error_code = utils.u32_unpack(buf)
        try:
            self.__response_fields = utils.read_fields(self.__read_header)
        except utils.InvalidFieldsError, e:
            raise InvalidResponseError('Invalid response format: %s' % str(e))
        auth = self.__client.outer_read(64)
        if auth != self.__reply_header_hmac.digest():
            raise InvalidResponseError('Header authentication failed')
        if error_code != errors.OK and error_code not in expected_errors:
            message = self.response_field('message')
            if message is not None:
                raise ClientError('Error: %s: %s' %
                                  (errors.message(error_code), message))
            else:
                raise ClientError('Error: %s' % (errors.message(error_code)))
        buf = self.__client.outer_read(utils.u32_size)
        self.__payload_size = utils.u32_unpack(buf)
        if no_payload:
            if self.__payload_size != 0:
                raise InvalidResponseError('Unexpected payload in response')
            self.__authenticate_reply_payload()
        return error_code

    def __authenticate_reply_payload(self):
        '''Read and verify reply payload authenticator.'''
        auth = self.__client.outer_read(64)
        if auth != self.__reply_payload_hmac.digest():
            raise InvalidResponseError('Payload authentication failed')

    def read_payload(self):
        '''Return and authenticate server's payload.'''
        data = self.__client.outer_read(self.__payload_size)
        self.__reply_payload_hmac.update(data)
        self.__authenticate_reply_payload()
        return data

    def write_payload_to_file(self, f):
        '''Write server's payload to f.'''
        while self.__payload_size > 0:
            run = self.__client.outer_read(min(self.__payload_size, 4096))
            f.write(run)
            self.__reply_payload_hmac.update(run)
            self.__payload_size -= len(run)
        self.__authenticate_reply_payload()

    def read_empty_unauthenticated_payload(self):
        '''Read zero-size payload and an incorrect payload authenticator.

        This is used for payloads dropped by the bridge for
        sign-rpm --koji-only.

        '''
        if self.__payload_size != 0:
            raise InvalidResponseError('Unexpected payload in response')
        self.__client.outer_read(64) # Ignore

    def response_field(self, key):
        '''Return a response field value or None if not present.'''
        return self.__response_fields.get(key)

    def response_field_int(self, key):
        '''Return a response field value as an int or None if not present.

        Raise InvalidResponseError.

        '''
        v = self.__response_fields.get(key)
        if v is not None:
            try:
                v = utils.u32_unpack(v)
            except struct.error:
                raise InvalidResponseError('Integer field has incorrect length')
        return v

    def response_field_bool(self, key):
        '''Return a response field value as a bool or None if not present.

        Raise InvalidResponseError.

        '''
        v = self.response_field_int(key)
        if v is not None:
            try:
                v = { 0: False, 1: True }[v]
            except KeyError:
                raise InvalidResponseError('Boolean field has invalid value')
        return v

    def __send_header(self, data):
        '''Send data as a part of the authenticated request header.'''
        self.__client.outer_write(data)
        self.__request_header_digest.update(data)

    def __read_header(self, bytes):
        '''Read bytes bytes as a part of the authenticated reply header.'''
        data = self.__client.outer_read(bytes)
        self.__reply_header_hmac.update(data)
        return data

    def close(self):
        '''Close the connection.

        Raise double_tls.ChildConnectionRefusedError,
        double_tls.ChildUnrecoverableError.

        '''
        if self.__client is not None:
            try:
                self.__client.outer_close()
            finally:
                self.__client = None

def read_password(config, prompt):
    '''Return a password.'''
    if not config.batch_mode:
        return getpass.getpass(prompt)
    password = ''
    while True:
        c = sys.stdin.read(1)
        if c == '\x00':
            break;
        password += c
    return password

def read_admin_password(config):
    '''Return an administrator's password.'''
    return read_password(config, 'Administrator\'s password: ')

def read_key_passphrase(config):
    '''Return a key passphrase.'''
    return read_password(config, 'Key passphrase: ')

def read_new_password(config, prompt1, prompt2):
    '''Return a new password (ask for it twice).'''
    password = read_password(config, prompt1)
    if not config.batch_mode:
        p2 = read_password(config, prompt2)
        if p2 != password:
            raise ClientError('Error: Input does not match')
    return password

def bool_to_text(val):
    '''Return an user-readable representation of a bool value.'''
    return {True: 'yes', False: 'no'}[val]

def print_list_in_payload(conn, num_field_name):
    '''Read payload from conn and print is as a list of strings.'''
    payload = conn.read_payload()
    start = 0
    for _ in xrange(conn.response_field_int(num_field_name)):
        try:
            i = payload.index('\x00', start)
        except ValueError:
            raise InvalidResponseError('Invalid payload format')
        e = payload[start:i]
        start = i + 1
        if not utils.string_is_safe(e):
            raise InvalidResponseError('Unprintable string in reply from '
                                       'server')
        print e

def key_user_add_password_option(p2):
    '''Add options for authenticating an administrator instead of key user.'''
    p2.add_option('--password', action='store_true',
                  help='Use a password to authenticate a server administrator')
    p2.set_defaults(password=False)

def key_user_passphrase_or_password(config, o2):
    '''Return inner_fields value for authenticating a key user or server
    administrator,

    Ask for a passphrase or password.

    '''
    if o2.password:
        password = read_password(config, 'User password: ')
        return {'password': password}
    passphrase = read_key_passphrase(config)
    return {'passphrase': passphrase}

 # Command handlers

def cmd_list_users(conn, args):
    p2 = optparse.OptionParser(usage='%prog list-users',
                               description='List users')
    (_, args) = p2.parse_args(args)
    if len(args) != 0:
        p2.error('unexpected arguments')
    password = read_admin_password(conn.config)

    conn.connect('list-users', {})
    conn.empty_payload()
    conn.send_inner({'password': password})
    conn.read_response()
    print_list_in_payload(conn, 'num-users')

def cmd_new_user(conn, args):
    p2 = optparse.OptionParser(usage='%prog new-user [options] user',
                               description='Add a user')
    p2.add_option('--admin', action='store_true',
                  help='Make the user an administrator '
                  '(implies --with-password)')
    p2.add_option('--with-password', action='store_true',
                  help='Define a password for the user')
    p2.set_defaults(admin=False, with_password=False)
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('user name expected')
    password = read_admin_password(conn.config)
    if o2.admin or o2.with_password:
        new_password = read_new_password(conn.config, 'New user\'s password: ',
                                         'New user\'s password (again): ')
    else:
        new_password = None

    conn.connect('new-user', {'name': safe_string(args[0]), 'admin': o2.admin})
    conn.empty_payload()
    f = {'password': password}
    if new_password is not None:
        f['new-password'] = new_password
    conn.send_inner(f)
    conn.read_response(no_payload=True)

def cmd_delete_user(conn, args):
    p2 = optparse.OptionParser(usage='%prog delete-user user',
                               description='Delete a user')
    (_, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('unexpected arguments')
    password = read_admin_password(conn.config)

    conn.connect('delete-user', {'name': safe_string(args[0])})
    conn.empty_payload()
    conn.send_inner({'password': password})
    conn.read_response(no_payload=True)

def cmd_user_info(conn, args):
    p2 = optparse.OptionParser(usage='%prog user-info user',
                               description='Show information about a user')
    (_, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('unexpected arguments')
    password = read_admin_password(conn.config)

    conn.connect('user-info', {'name': safe_string(args[0])})
    conn.empty_payload()
    conn.send_inner({'password': password})
    conn.read_response(no_payload=True)

    print ('Administrator: %s' %
           bool_to_text(conn.response_field_bool('admin')))

    # FIXME: list accessible keys?

def cmd_modify_user(conn, args):
    p2 = optparse.OptionParser(usage='%prog modify-user [options] user',
                               description='Modify a user')
    p2.add_option('--admin', choices=('yes', 'no'),
                  help='Is the user an administrator ("yes" or "no")?')
    p2.add_option('--new-name', metavar='USER',
                  help='Change user\'s name')
    p2.add_option('--change-password', action='store_true',
                  help='Change user\'s password')
    p2.set_defaults(change_password=False)
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('user name expected')
    if o2.admin is None and o2.new_name is None and not o2.change_password:
        p2.error('nothing to do')
    password = read_admin_password(conn.config)
    if o2.change_password:
        new_password = read_new_password(conn.config, 'New password: ',
                                         'New password (again): ')

    f = {'name': safe_string(args[0])}
    if o2.admin is not None:
        f['admin'] = o2.admin == 'yes'
    if o2.new_name is not None:
        f['new-name'] = safe_string(o2.new_name)
    conn.connect('modify-user', f)
    conn.empty_payload()
    f = {'password': password}
    if o2.change_password:
        f['new-password'] = new_password
    conn.send_inner(f)
    conn.read_response(no_payload=True)

def cmd_key_user_info(conn, args):
    p2 = optparse.OptionParser(usage='%prog key-user-info user key',
                               description='Show information about user\'s key '
                               'access')
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('user name and key name expected')
    password = read_admin_password(conn.config)

    conn.connect('key-user-info',
                 {'name': safe_string(args[0]), 'key': safe_string(args[1])})
    conn.empty_payload()
    conn.send_inner({'password': password})
    error_code = conn.read_response((errors.KEY_USER_NOT_FOUND,),
                                    no_payload=True)
    if error_code == errors.KEY_USER_NOT_FOUND:
        print 'No access defined'
    else:
        print ('Access defined, key administrator: %s' %
               bool_to_text(conn.response_field_bool('key-admin')))

def cmd_modify_key_user(conn, args):
    p2 = optparse.OptionParser(usage='%prog modify-key-user [options] user key',
                               description='Modify user\'s key access')
    p2.add_option('--key-admin', choices=('yes', 'no'),
                  help='Is the user a administrator of this key ("yes" or '
                  '"no")?')
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('user name and key name expected')
    if o2.key_admin is None:
        p2.error('nothing to do')
    password = read_admin_password(conn.config)

    f = {'name': safe_string(args[0]), 'key': safe_string(args[1])}
    if o2.key_admin is not None:
        f['key-admin'] = o2.key_admin == 'yes'
    conn.connect('modify-key-user', f)
    conn.empty_payload()
    conn.send_inner({'password': password})
    conn.read_response(no_payload=True)

def cmd_list_keys(conn, args):
    p2 = optparse.OptionParser(usage='%prog list-keys', description='List keys')
    (_, args) = p2.parse_args(args)
    if len(args) != 0:
        p2.error('unexpected arguments')
    password = read_admin_password(conn.config)

    conn.connect('list-keys', {})
    conn.empty_payload()
    conn.send_inner({'password': password})
    conn.read_response()
    print_list_in_payload(conn, 'num-keys')

def cmd_new_key(conn, args):
    p2 = optparse.OptionParser(usage='%prog new-key [options] key',
                               description='Add a key')
    p2.add_option('--key-admin', metavar='USER',
                  help='Initial key administrator')
    p2.add_option('--name-real', help='Real name of key subject')
    p2.add_option('--name-comment', help='A comment about of key subject')
    p2.add_option('--name-email', help='E-mail of key subject')
    p2.add_option('--expire-date', metavar='YYYY-MM-DD',
                  help='Key expiration date')
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('key name expected')
    if o2.expire_date is not None:
        if not utils.yyyy_mm_dd_is_valid(o2.expire_date):
            p2.error('invalid --expire-date')
    password = read_admin_password(conn.config)
    passphrase = read_new_password(conn.config, 'Passphrase for the new key: ',
                                   'Passphrase for the new key (again): ')

    f = {'key': safe_string(args[0])}
    if o2.key_admin is not None:
        f['initial-key-admin'] = safe_string(o2.key_admin)
    if o2.name_real is not None:
        f['name-real'] = safe_string(o2.name_real)
    if o2.name_comment is not None:
        f['name-comment'] = safe_string(o2.name_comment)
    if o2.name_email is not None:
        f['name-email'] = safe_string(o2.name_email)
    if o2.expire_date is not None:
        f['expire-date'] = o2.expire_date
    conn.connect('new-key', f)
    conn.empty_payload()
    conn.send_inner({'password': password, 'passphrase': passphrase})
    conn.read_response()
    pubkey = conn.read_payload()
    if not utils.string_is_safe(pubkey.replace('\n', '')):
        raise InvalidResponseError('Public key is not safely printable')
    print pubkey,

def cmd_import_key(conn, args):
    p2 = optparse.OptionParser(usage='%prog import-key [options] key',
                               description='Import a key')
    p2.add_option('--key-admin', metavar='USER',
                  help='Initial key administrator')
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and input file path expected')
    password = read_admin_password(conn.config)
    passphrase = read_key_passphrase(conn.config)
    new_passphrase = read_new_password(conn.config, 'New key passphrase: ',
                                       'New key passphrase (again): ')
    try:
        f = open(args[1], 'rb')
    except IOError, e:
        raise ClientError('Error opening %s: %s' % (args[1], e.strerror))

    try:
        fields = {'key': safe_string(args[0])}
        if o2.key_admin is not None:
            fields['initial-key-admin'] = safe_string(o2.key_admin)
        conn.connect('import-key', fields)
        conn.send_payload_from_file(f)
    finally:
        f.close()
    conn.send_inner({'password': password, 'passphrase': passphrase,
                     'new-passphrase': new_passphrase})
    conn.read_response(no_payload=True)

def cmd_delete_key(conn, args):
    p2 = optparse.OptionParser(usage='%prog delete-key key',
                               description='Delete a key')
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('key name expected')
    password = read_admin_password(conn.config)

    conn.connect('delete-key', {'key': safe_string(args[0])})
    conn.empty_payload()
    conn.send_inner({'password': password})
    conn.read_response(no_payload=True)

def cmd_modify_key(conn, args):
    p2 = optparse.OptionParser(usage='%prog modify-key [options] key',
                               description='Modify a key')
    p2.add_option('--new-name', metavar='KEY', help='Change name of the key')
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('key name expected')
    if o2.new_name is None:
        p2.error('nothing to do')
    password = read_admin_password(conn.config)

    f = {'key': safe_string(args[0])}
    if o2.new_name is not None:
        f['new-name'] = safe_string(o2.new_name)
    conn.connect('modify-key', f)
    conn.empty_payload()
    conn.send_inner({'password': password})
    conn.read_response(no_payload=True)

def cmd_list_key_users(conn, args):
    p2 = optparse.OptionParser(usage='%prog list-key-users [options] key',
                               description='List users that can access a key')
    key_user_add_password_option(p2)
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('key name expected')
    inner_f = key_user_passphrase_or_password(conn.config, o2)

    conn.connect('list-key-users', {'key': safe_string(args[0])})
    conn.empty_payload()
    conn.send_inner(inner_f)
    conn.read_response()
    print_list_in_payload(conn, 'num-users')

def cmd_grant_key_access(conn, args):
    p2 = optparse.OptionParser(usage='%prog grant-key-access key user',
                               description='Grant key access to a user')
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and user name expected')
    passphrase = read_key_passphrase(conn.config)
    new_passphrase = read_new_password(conn.config,
                                       'Key passphrase for the new user: ',
                                       'Key passphrase for the new user '
                                       '(again): ')

    conn.connect('grant-key-access',
                 {'key': safe_string(args[0]), 'name': safe_string(args[1])})
    conn.empty_payload()
    conn.send_inner({'passphrase': passphrase,
                     'new-passphrase': new_passphrase})
    conn.read_response(no_payload=True)

def cmd_revoke_key_access(conn, args):
    p2 = optparse.OptionParser(usage='%prog revoke-key-access [options] key '
                               'user',
                               description='Revoke key acess from a user')
    key_user_add_password_option(p2)
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and user name expected')
    inner_f = key_user_passphrase_or_password(conn.config, o2)

    conn.connect('revoke-key-access',
                 {'key': safe_string(args[0]), 'name': safe_string(args[1])})
    conn.empty_payload()
    conn.send_inner(inner_f)
    conn.read_response(no_payload=True)

def cmd_get_public_key(conn, args):
    p2 = optparse.OptionParser(usage='%prog get-public-key [options] key',
                               description='Output public part of the key')
    key_user_add_password_option(p2)
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('key name expected')
    inner_f = key_user_passphrase_or_password(conn.config, o2)

    conn.connect('get-public-key', {'key': safe_string(args[0])})
    conn.empty_payload()
    conn.send_inner(inner_f)
    conn.read_response()
    pubkey = conn.read_payload()
    if not utils.string_is_safe(pubkey.replace('\n', '')):
        raise InvalidResponseError('Public key is not safely printable')
    print pubkey,

def cmd_change_passphrase(conn, args):
    p2 = optparse.OptionParser(usage='%prog change-passphrase key',
                               description='Change key passphrase')
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('key name expected')
    passphrase = read_key_passphrase(conn.config)
    new_passphrase = read_new_password(conn.config,
                                       'New key passphrase: ',
                                       'New key passphrase (again): ')

    conn.connect('change-passphrase', {'key': safe_string(args[0])})
    conn.empty_payload()
    conn.send_inner({'passphrase': passphrase,
                     'new-passphrase': new_passphrase})
    conn.read_response(no_payload=True)

def cmd_sign_text(conn, args):
    p2 = optparse.OptionParser(usage='%prog sign-text [options] key input_file',
                               description='Output a cleartext signature of a '
                               'text')
    p2.add_option('-o', '--output', metavar='FILE',
                  help='Write output to this file')
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and input file path expected')
    passphrase = read_key_passphrase(conn.config)
    try:
        f = open(args[1])
    except IOError, e:
        raise ClientError('Error opening %s: %s' % (args[1], e.strerror))

    try:
        conn.connect('sign-text', {'key': safe_string(args[0])})
        conn.send_payload_from_file(f)
    finally:
        f.close()
    conn.send_inner({'passphrase': passphrase})
    conn.read_response()
    try:
        if o2.output is None:
            conn.write_payload_to_file(sys.stdout)
        else:
            utils.write_new_file(o2.output, conn.write_payload_to_file)
    except IOError, e:
        raise ClientError('Error writing to %s: %s' % (o2.output, e.strerror))

def cmd_sign_data(conn, args):
    p2 = optparse.OptionParser(usage='%prog sign-data [options] input_file',
                               description='Create a detached signature')
    p2.add_option('-o', '--output', metavar='FILE',
                  help='Write output to this file')
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and input file path expected')
    if o2.output is None and sys.stdout.isatty():
        p2.error('won\'t write output to a TTY, specify a file name')
    passphrase = read_key_passphrase(conn.config)
    try:
        f = open(args[1], 'rb')
    except IOError, e:
        raise ClientError('Error opening %s: %s' % (args[1], e.strerror))

    try:
        conn.connect('sign-data', {'key': safe_string(args[0])})
        conn.send_payload_from_file(f)
    finally:
        f.close()
    conn.send_inner({'passphrase': passphrase})
    conn.read_response()
    try:
        if o2.output is None:
            conn.write_payload_to_file(sys.stdout)
        else:
            utils.write_new_file(o2.output, conn.write_payload_to_file)
    except IOError, e:
        raise ClientError('Error writing to %s: %s' % (o2.output, e.strerror))

def cmd_sign_rpm(conn, args):
    p2 = optparse.OptionParser(usage='%prog sign-rpm [options] '
                               'key rpmfile-or-nevra',
                               description='Sign a RPM')
    p2.add_option('-o', '--output', metavar='FILE',
                  help='Write output to this file instead of overwriting the '
                  'input file')
    p2.add_option('--store-in-koji', action='store_true',
                  help='Store the generated RPM signature to Koji')
    p2.add_option('--koji-only', action='store_true',
                  help='Do not save the signed RPM locally, store it only to '
                  'Koji')
    p2.add_option('--v3-signature', action='store_true',
                  help='Create a v3 signature (currently necessary for RSA'
                  'keys)')
    p2.set_defaults(store_in_koji=False, koji_only=False, v3_signature=False)
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and RPM path or identification expected')
    if o2.koji_only and not o2.store_in_koji:
        p2.error('--koji-only is valid only with --store-in-koji')
    if not o2.koji_only and o2.output is None and sys.stdout.isatty():
        p2.error('won\'t write output to a TTY, specify a file name')
    passphrase = read_key_passphrase(conn.config)

    # See conn.send_outer_fields() later
    conn.connect(None, None)
    f = {'key': safe_string(args[0])}
    if o2.store_in_koji:
        f['import-signature'] = True
    if o2.koji_only:
        f['return-data'] = False
    if o2.v3_signature:
        f['v3-signature'] = True
    omit_payload_auth = False
    if os.path.exists(args[1]):
        try:
            rpm_file = open(args[1], 'rb')
        except IOError, e:
            raise ClientError('Error opening %s: %s' % (args[1], e.strerror))
    else:
        # Don't import koji before initializing ClientsConnection!  The rpm
        # Python module calls NSS_NoDB_Init() during its initialization, which
        # breaks our attempts to initialize nss with our certificate database.
        import koji

        rpm_file = None
        try:
            session = utils.koji_connect(utils.koji_read_config(),
                                         authenticate=False)
            try:
                rpm = session.getRPM(args[1])
                if rpm is None:
                    raise ClientError('%s does not exist in Koji' % args[1])
            finally:
                utils.koji_disconnect(session)
        except (utils.KojiError, koji.GenericError), e:
            raise ClientError(str(e))
        f['rpm-name'] = safe_string(rpm['name'])
        epoch = rpm['epoch']
        if epoch is None:
            epoch = ''
        f['rpm-epoch'] = safe_string(epoch)
        f['rpm-version'] = safe_string(rpm['version'])
        f['rpm-release'] = safe_string(rpm['release'])
        f['rpm-arch'] = safe_string(rpm['arch'])
        f['rpm-sigmd5'] = binascii.a2b_hex(rpm['payloadhash'])
        omit_payload_auth = True
    try:
        conn.send_outer_fields('sign-rpm', f)
        if rpm_file is not None:
            conn.send_payload_from_file(rpm_file)
        else:
            conn.empty_payload()
    finally:
        if rpm_file is not None:
            rpm_file.close()
    conn.send_inner({'passphrase': passphrase},
                    omit_payload_auth=omit_payload_auth)
    conn.read_response()
    if not o2.koji_only:
        if o2.output is None:
            o2.output = args[1]
        try:
            utils.write_new_file(o2.output, conn.write_payload_to_file)
        except IOError, e:
            raise ClientError('Error writing to %s: %s' %
                              (o2.output, e.strerror))
    else:
        conn.read_empty_unauthenticated_payload()

# name: (handler, help)
command_handlers = {
    'list-users': (cmd_list_users, 'List users'),
    'new-user': (cmd_new_user, 'Add a user'),
    'delete-user': (cmd_delete_user, 'Delete a user'),
    'user-info': (cmd_user_info, 'Show information about a user'),
    'modify-user': (cmd_modify_user, 'Modify a user'),
    'key-user-info': (cmd_key_user_info, 'Show information about user\'s key '
                      'access'),
    'modify-key-user': (cmd_modify_key_user, 'Modify user\'s key access'),
    'list-keys': (cmd_list_keys, 'List keys'),
    'modify-key': (cmd_modify_key, 'Modify a key'),
    'new-key': (cmd_new_key, 'Add a key'),
    'import-key': (cmd_import_key, 'Import a key'),
    'delete-key': (cmd_delete_key, 'Delete a key'),
    'modify-key': (cmd_modify_key, 'Modify a key'),
    'list-key-users': (cmd_list_key_users, 'List users that can access a key'),
    'grant-key-access': (cmd_grant_key_access, 'Grant key access to a user'),
    'revoke-key-access': (cmd_revoke_key_access,
                          'Revoke key acess from a user'),
    'get-public-key': (cmd_get_public_key, 'Output public part of the key'),
    'change-passphrase': (cmd_change_passphrase, 'Change key passphrase'),
    'sign-text': (cmd_sign_text, 'Output a cleartext signature of a text'),
    'sign-data': (cmd_sign_data, 'Create a detached signature'),
    'sign-rpm': (cmd_sign_rpm, 'Sign a RPM'),
    }



def handle_global_options():
    '''Handle global options.

    Return (configuration, command handler, its arguments).

    '''
    parser = optparse.OptionParser(usage='%prog [options] command '
                                   '[command-args...]',
                                   version='%%prog %s' % (settings.version),
                                   description='A signing server client')
    parser.add_option('--help-commands', action='store_true',
                      help='List supported commands')
    parser.add_option('--batch', action='store_true',
                      help='Communicate in batch-friendly mode (omit prompts, '
                      'expect NUL-terminated input)')
    utils.optparse_add_config_file_option(parser, '~/.sigul/client.conf')
    utils.optparse_add_verbosity_option(parser)
    parser.set_defaults(help_commands=False, batch=False)
    parser.disable_interspersed_args()
    (options, args) = parser.parse_args()

    if options.help_commands:
        # FIXME: order of the commands
        for (name, (_, help_string)) in command_handlers.iteritems():
            print '%-20s%s' % (name, help_string)
        sys.exit()
    if len(args) < 1:
        parser.error('missing command, see --help-commands')
    if args[0] not in command_handlers:
        parser.error('unknown command %s' % args[0])

    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=utils.logging_level_from_options(options))
    try:
        config = ClientConfiguration(options.config_file)
    except utils.ConfigurationError, e:
        raise ClientError(str(e))
    config.batch_mode = options.batch

    return (config, command_handlers[args[0]][0], args[1:])

def main():
    child_exception = None
    try:
        (config, handler, args) = handle_global_options()
        conn = ClientsConnection(config)
        try:
            handler(conn, args)
        finally:
            try:
                conn.close()
            except (double_tls.ChildConnectionRefusedError,
                    double_tls.ChildUnrecoverableError), e:
                child_exception = e
    except ClientError, e:
        sys.exit(str(e))
    except (IOError, EOFError, socket.error), e:
        logging.error('I/O error: %s', repr(e))
        sys.exit(1)
    except nss.error.NSPRError, e:
        if e.errno == nss.error.PR_CONNECT_RESET_ERROR:
            if child_exception is not None:
                if isinstance(child_exception,
                              double_tls.ChildConnectionRefusedError):
                    logging.error('Connection refused')
                elif isinstance(child_exception,
                                double_tls.ChildUnrecoverableError):
                    logging.debug('Unrecoverable error in child')
                else:
                    assert False, 'Unhandled child_exception type'
            else:
                logging.error('I/O error: NSPR connection reset')
        elif e.errno == nss.error.PR_END_OF_FILE_ERROR:
            logging.error('I/O error: Unexpected EOF in NSPR')
        else:
            logging.error('NSPR error', exc_info=True)
        sys.exit(1)
    except KeyboardInterrupt:
        logging.error('Interrupted')
        sys.exit(1)
    except SystemExit:
        raise # Don't consider this an unexpected exception
    except:
        logging.error('Unexpected exception', exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
