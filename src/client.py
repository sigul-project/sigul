# Copyright (C) 2008, 2009, 2010 Red Hat, Inc.  All rights reserved.
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
import errno
import getpass
import logging
import optparse
import os
import socket
import struct
import sys

import nss.nss

import double_tls
import errors
import settings
import utils

MAX_SIGN_RPMS_PAYLOAD_SIZE = 9 * 1024 * 1024 * 1024

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
        self.__request_header_writer = \
            utils.SHA512Writer(self.__client.outer_write)
        self.__request_payload_writer = \
            utils.SHA512Writer(self.__client.outer_write)
        buf = utils.u32_pack(utils.protocol_version)
        self.__request_header_writer.write(buf)
        if op is not None and outer_fields is not None:
            self.send_outer_fields(op, outer_fields)

    def send_outer_fields(self, op, outer_fields):
        '''Send outer_fields.'''
        fields = dict(outer_fields) # Shallow copy
        fields['op'] = safe_string(op)
        fields['user'] = safe_string(self.config.user_name)
        self.__request_header_writer.write(utils.format_fields(fields))

    def __send_payload_size(self, payload_size):
        '''Prepare for sending payload of payload_size.

        Valid both for the primary payload and for subrequest payloads.

        '''
        self.__client.outer_write(utils.u32_pack(payload_size))

    def __send_payload_from_file(self, writer, fd):
        '''Send contents of fd to the server as payload, using writer.

        Valid both for the primary payload and for subreply payloads.  Note that
        the subrequest HMAC, if any, is not sent!

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

    def empty_payload(self):
        '''Send an empty payload.'''
        self.__send_payload_size(0)

    def send_payload(self, data):
        '''Send data as payload.'''
        self.__send_payload_size(len(data))
        self.__request_payload_writer.write(data)

    def send_payload_from_file(self, fd):
        '''Send contents of file as payload.'''
        self.__send_payload_from_file(self.__request_payload_writer, fd)

    def send_inner(self, inner_fields, omit_payload_auth=False):
        '''Send the inner header, including inner_fields.'''
        # FIXME: handle errors.UNKNOWN_VERSION - there is no inner session and
        # outer session data is not all read
        fields = dict(inner_fields) # Shallow copy
        fields['header-auth-sha512'] = self.__request_header_writer.sha512()
        if not omit_payload_auth:
            fields['payload-auth-sha512'] = \
                self.__request_payload_writer.sha512()

        mech = nss.nss.CKM_SHA512_HMAC
        slot = nss.nss.get_best_slot(mech)
        nss_key = slot.key_gen(mech, None, 64)
        fields['header-auth-key'] = nss_key.key_data
        self.__reply_header_reader = \
            utils.SHA512HMACReader(self.__client.outer_read, nss_key)
        nss_key = slot.key_gen(mech, None, 64)
        fields['payload-auth-key'] = nss_key.key_data
        self.__reply_payload_reader = \
            utils.SHA512HMACReader(self.__client.outer_read, nss_key)

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
        buf = self.__reply_header_reader.read(utils.u32_size)
        error_code = utils.u32_unpack(buf)
        try:
            self.__response_fields = \
                utils.read_fields(self.__reply_header_reader.read)
        except utils.InvalidFieldsError, e:
            raise InvalidResponseError('Invalid response format: %s' % str(e))
        if not self.__reply_header_reader.verify_64B_hmac_authenticator():
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
        if not self.__reply_payload_reader.verify_64B_hmac_authenticator():
            raise InvalidResponseError('Payload authentication failed')

    def read_payload(self):
        '''Return and authenticate server's payload.'''
        data = self.__reply_payload_reader.read(self.__payload_size)
        self.__authenticate_reply_payload()
        return data

    def write_payload_to_file(self, f):
        '''Write server's payload to f.'''
        utils.copy_data(f.write, self.__reply_payload_reader.read,
                        self.__payload_size)
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

    def send_subheader(self, fields, nss_key):
        '''Send fields in a subrequest header authenticated using nss_key.'''
        writer = utils.SHA512HMACWriter(self.__client.outer_write, nss_key)
        writer.write(utils.format_fields(fields))
        writer.write_64B_hmac()

    def send_empty_subpayload(self, nss_key):
        '''Send an empty subrequest payload authenticated using nss_key.'''
        self.__send_payload_size(0)
        writer = utils.SHA512HMACWriter(self.__client.outer_write, nss_key)
        writer.write_64B_hmac()

    def send_subpayload_from_file(self, fd, nss_key):
        '''Send a subrequest payload from fd authenticated using key.'''
        writer = utils.SHA512HMACWriter(self.__client.outer_write, nss_key)
        self.__send_payload_from_file(writer, fd)
        writer.write_64B_hmac()

    def read_subheader(self, nss_key):
        '''Read fields in a subreply header authenticated using nss_key.'''
        reader = utils.SHA512HMACReader(self.__client.outer_read, nss_key)
        try:
            fields = utils.read_fields(reader.read)
        except utils.InvalidFieldsError, e:
            raise InvalidResponseError('Invalid response format: %s' % str(e))
        if not reader.verify_64B_hmac_authenticator():
            raise InvalidResponseError('Subreply header authentication failed')
        return fields

    def read_empty_subpayload(self, nss_key, ignore_auth=False):
        '''Read an empty subreply payload authenticated using nss_key.'''
        buf = self.__client.outer_read(utils.u32_size)
        if utils.u32_unpack(buf) != 0:
            raise InvalidResponseError('Unexpected payload in subreply')
        if not ignore_auth:
            reader = utils.SHA512HMACReader(self.__client.outer_read, nss_key)
            if not reader.verify_64B_hmac_authenticator():
                raise InvalidResponseError('Subreply payload authentication '
                                           'failed')
        else:
            self.__client.outer_read(64) # Ignore

    def write_subpayload_to_file(self, nss_key, f):
        '''Write server's payload to f, authenticate using nss_key.'''
        buf = self.__client.outer_read(utils.u32_size)
        payload_size = utils.u32_unpack(buf)
        reader = utils.SHA512HMACReader(self.__client.outer_read, nss_key)
        utils.copy_data(f.write, reader.read, payload_size)
        if not reader.verify_64B_hmac_authenticator():
            raise InvalidResponseError('Subreply payload authentication failed')

    def outer_shutdown_write(self):
        '''Shutdown the outer pipe for writing.'''
        self.__client.outer_shutdown(nss.io.PR_SHUTDOWN_SEND)

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

def read_admin_password(config):
    '''Return an administrator's password.'''
    return utils.read_password(config, 'Administrator\'s password: ')

def read_key_passphrase(config):
    '''Return a key passphrase.'''
    return utils.read_password(config, 'Key passphrase: ')

def read_new_password(config, prompt1, prompt2):
    '''Return a new password (ask for it twice).'''
    password = utils.read_password(config, prompt1)
    if not config.batch_mode:
        p2 = utils.read_password(config, prompt2)
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
        password = utils.read_password(config, 'User password: ')
        return {'password': password}
    passphrase = read_key_passphrase(config)
    return {'passphrase': passphrase}

class SignRPMArgumentExaminer(object):
    '''An object that can be used to analyze sign-rpm{s,} operands.'''

    def __init__(self):
        self.__koji_session = None

    def open_rpm(self, arg, fields):
        '''Get information about RPM specified by "arg".

        Return (open file or None, RPM file size on disk).  Update fields with
        RPM information if arg refers to koji.

        Raise ClientError, others.

        '''
        if os.path.exists(arg):
            try:
                rpm_file = open(arg, 'rb')
            except IOError, e:
                raise ClientError('Error opening %s: %s' % (arg, e.strerror))
            # Count whole blocks, that's what the bridge and server do.
            size = utils.file_size_in_blocks(rpm_file)
        else:
            # Don't import koji before initializing ClientsConnection!  The rpm
            # Python module calls NSS_NoDB_Init() during its initialization,
            # which breaks our attempts to initialize nss with our certificate
            # database.
            import koji

            try:
                if self.__koji_session is None:
                    self.__koji_session = \
                        utils.koji_connect(utils.koji_read_config(),
                                           authenticate=False)
                rpm = self.__koji_session.getRPM(arg)
            except (utils.KojiError, koji.GenericError), e:
                raise ClientError(str(e))
            if rpm is None:
                raise ClientError('%s does not exist in Koji' % arg)
            fields['rpm-name'] = safe_string(rpm['name'])
            epoch = rpm['epoch']
            if epoch is None:
                epoch = ''
            fields['rpm-epoch'] = safe_string(str(epoch))
            fields['rpm-version'] = safe_string(rpm['version'])
            fields['rpm-release'] = safe_string(rpm['release'])
            fields['rpm-arch'] = safe_string(rpm['arch'])
            fields['rpm-sigmd5'] = binascii.a2b_hex(rpm['payloadhash'])
            rpm_file = None
            size = rpm['size']
        return (rpm_file, size)

    def close(self):
        '''Close all permanent connections, if any.'''
        if self.__koji_session is not None:
            utils.koji_disconnect(self.__koji_session)
            self.__koji_session = None

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
    examiner = SignRPMArgumentExaminer()
    try:
        (rpm_file, _) = examiner.open_rpm(args[1], f)
    finally:
        examiner.close()
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
                    omit_payload_auth=rpm_file is None)
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

class SignRPMsRequestThread(utils.WorkerThread):
    '''A thread that sends sign-rpm subrequests.'''

    def __init__(self, conn, args, header_nss_key, payload_nss_key):
        super(SignRPMsRequestThread, self).__init__('sign-rpms:requests',
                                                    'request thread')
        self.results = {}
        self.__conn = conn
        self.__args = args
        self.__header_nss_key = header_nss_key
        self.__payload_nss_key = payload_nss_key

    def _real_run(self):
        examiner = SignRPMArgumentExaminer()
        try:
            self.__run_with_examiner(examiner)
        finally:
            try:
                self.__conn.outer_shutdown_write()
            finally:
                examiner.close()

    def __run_with_examiner(self, examiner):
        '''Send subrequests corresponding to self.__args using examiner.

        Store error messages in self.results for subrequests that were not
        sent.

        '''
        server_idx = 0
        total_size = 0
        for (arg_idx, arg) in enumerate(self.__args):
            logging.debug('%s: Started handling %s', self.name, repr(arg))
            fields = {'id': utils.u32_pack(arg_idx)}
            try:
                (rpm_file, size) = examiner.open_rpm(arg, fields)
                # Round up to 32k for good measure.
                size = (size + 32767) / 32768 * 32768
                if size > MAX_SIGN_RPMS_PAYLOAD_SIZE:
                    raise ClientError('%s is too large' % arg)
            except ClientError, e:
                self.results[arg_idx] = str(e)
                continue

            try:
                total_size += size
                if total_size > MAX_SIGN_RPMS_PAYLOAD_SIZE:
                    # This is pretty user-unfriendly - but we can't split the
                    # input automatically because we need to open the
                    # connections before using koji, and without koji we don't
                    # know how many connections we need.  We could guess, but
                    # our caller can guess just as well or better.
                    raise ClientError('Total payload size is too large, limit '
                                      'exceeded with %s', arg)

                nss_key = utils.derived_key(self.__header_nss_key, server_idx)
                self.__conn.send_subheader(fields, nss_key)

                nss_key = utils.derived_key(self.__payload_nss_key, server_idx)
                if rpm_file is not None:
                    self.__conn.send_subpayload_from_file(rpm_file, nss_key)
                else:
                    self.__conn.send_empty_subpayload(nss_key)
            finally:
                if rpm_file is not None:
                    rpm_file.close()
            server_idx += 1

class SignRPMsReplyThread(utils.WorkerThread):
    '''A thread that handles sign-rpm subreplies.'''

    def __init__(self, conn, args, o2, header_nss_key, payload_nss_key):
        super(SignRPMsReplyThread, self).__init__('sign-rpms:replies',
                                                  'reply thread')
        self.results = {}
        self.__conn = conn
        self.__args = args
        self.__o2 = o2
        self.__header_nss_key = header_nss_key
        self.__payload_nss_key = payload_nss_key

    def _real_run(self):
        server_idx = 0
        while True:
            try:
                nss_key = utils.derived_key(self.__header_nss_key, server_idx)
                fields = self.__conn.read_subheader(nss_key)
            except EOFError:
                break

            logging.debug('%s: Started handling %s', self.name,
                          utils.readable_fields(fields))
            try:
                buf = fields['id']
            except KeyError:
                raise InvalidResponseError('Required field id missing')
            try:
                arg_idx = utils.u32_unpack(buf)
            except struct.error:
                raise InvalidResponseError('Integer field has incorrect length')
            if arg_idx > len(self.__args):
                raise InvalidResponseError('Invalid subreply id')
            if arg_idx in self.results:
                raise InvalidResponseError('Duplicate subreply id %d' % arg_idx)

            try:
                buf = fields['status']
            except KeyError:
                raise InvalidResponseError('Required field status missing')
            try:
                error_code = utils.u32_unpack(buf)
            except struct.error:
                raise InvalidResponseError('Integer field has incorrect length')

            nss_key = utils.derived_key(self.__payload_nss_key, server_idx)
            if error_code != errors.OK:
                message = fields.get('message')
                if message is not None:
                    msg = '%s: %s' % (errors.message(error_code), message)
                else:
                    msg = errors.message(error_code)
                self.results[arg_idx] = msg
                self.__conn.read_empty_subpayload(nss_key)
                continue

            if not self.__o2.koji_only:
                arg = self.__args[arg_idx]
                if not arg.endswith('.rpm'):
                    arg += '.rpm'
                output_path = os.path.join(self.__o2.output,
                                           os.path.basename(arg))
                try:
                    writer = lambda f: \
                        self.__conn.write_subpayload_to_file(nss_key, f)
                    utils.write_new_file(output_path, writer)
                except IOError, e:
                    raise ClientError('Error writing to %s: %s' %
                                      (output_path, e.strerror))
            else:
                self.__conn.read_empty_subpayload(nss_key, ignore_auth=True)
            self.results[arg_idx] = None # Mark arg_idx as succesful
            logging.info('Signed %s', self.__args[arg_idx])
            server_idx += 1

def cmd_sign_rpms(conn, args):
    p2 = optparse.OptionParser(usage='%prog sign-rpms [options] '
                               'key rpmfile-or-nevra...',
                               description='Sign one or more RPMs')
    p2.add_option('-o', '--output', metavar='DIR',
                  help='Write output to this directory')
    p2.add_option('--store-in-koji', action='store_true',
                  help='Store the generated RPM signatures to Koji')
    p2.add_option('--koji-only', action='store_true',
                  help='Do not save the signed RPMs locally, store them only '
                  'to Koji')
    p2.add_option('--v3-signature', action='store_true',
                  help='Create v3 signatures (currently necessary for RSA'
                  'keys)')
    p2.set_defaults(store_in_koji=False, koji_only=False, v3_signature=False)
    (o2, args) = p2.parse_args(args)
    if len(args) < 2:
        p2.error('key name and at least one RPM path or identification '
                 'expected')
    if o2.koji_only and not o2.store_in_koji:
        p2.error('--koji-only is valid only with --store-in-koji')
    if o2.output is not None:
        try:
            os.mkdir(o2.output)
        except OSError, e:
            if e.errno != errno.EEXIST or not os.path.isdir(o2.output):
                raise ClientError('Error creating %s: %s' %
                                  (o2.output, e.strerror))
    elif not o2.koji_only:
        p2.error('--output is mandatory without --koji-only')
    passphrase = read_key_passphrase(conn.config)

    f = {'key': safe_string(args[0])}
    if o2.store_in_koji:
        f['import-signature'] = True
    if o2.koji_only:
        f['return-data'] = False
    if o2.v3_signature:
        f['v3-signature'] = True
    conn.connect('sign-rpms', f)
    conn.empty_payload()

    mech = nss.nss.CKM_GENERIC_SECRET_KEY_GEN
    slot = nss.nss.get_best_slot(mech)
    subrequest_header_nss_key = slot.key_gen(mech, None, 64)
    subrequest_payload_nss_key = slot.key_gen(mech, None, 64)
    subreply_header_nss_key = slot.key_gen(mech, None, 64)
    subreply_payload_nss_key = slot.key_gen(mech, None, 64)
    f = {'passphrase': passphrase,
         'subrequest-header-auth-key': subrequest_header_nss_key.key_data,
         'subrequest-payload-auth-key': subrequest_payload_nss_key.key_data,
         'subreply-header-auth-key': subreply_header_nss_key.key_data,
         'subreply-payload-auth-key': subreply_payload_nss_key.key_data}
    conn.send_inner(f)
    conn.read_response(no_payload=True)

    args = args[1:]
    request_thread = SignRPMsRequestThread \
        (conn, args, subrequest_header_nss_key, subrequest_payload_nss_key)
    reply_thread = SignRPMsReplyThread(conn, args, o2, subreply_header_nss_key,
                                       subreply_payload_nss_key)

    (ok, _) = utils.run_worker_threads((request_thread, reply_thread))

    results = request_thread.results.copy()
    for (k, v) in reply_thread.results.iteritems():
        # If the result was set by request_thread, server never saw the request
        # and there should be no reply.
        assert k not in results
        results[k] = v

    if ok:
        # Don't bother if exception in one of the threads was the primary cause
        for idx in xrange(len(args)):
            if idx not in results:
                results[idx] = 'No reply from server received'
    if any([v is not None for v in results.itervalues()]):
        for i in sorted(results.keys()):
            if results[i] is not None:
                logging.error('Error signing %s: %s', args[i], results[i])
        ok = False
    if not ok:
        raise ClientError('')


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
    'sign-rpms': (cmd_sign_rpms, 'Sign one or more RPMs'),
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
    utils.optparse_add_batch_option(parser)
    utils.optparse_add_config_file_option(parser, '~/.sigul/client.conf')
    utils.optparse_add_verbosity_option(parser)
    parser.set_defaults(help_commands=False)
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
        if str(e) != '':
            sys.exit(str(e))
        else:
            sys.exit(1)
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
