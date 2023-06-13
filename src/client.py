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

from __future__ import print_function

import binascii
import errno
import json
import getpass
import logging
import optparse
import os
import six
import socket
import struct
import subprocess
import sys

import nss.nss

import double_tls
import errors
import settings
import utils

koji = utils.lazy_load("koji")

MAX_SIGN_RPMS_PAYLOAD_SIZE = 9 * 1024 * 1024 * 1024


class ClientError(Exception):
    '''Any error in the client.'''
    pass


class InvalidResponseError(ClientError):
    '''The response received from the bridge/server is not valid.'''
    pass

# Infrastructure


class ClientConfiguration(utils.KojiConfiguration, utils.NSSConfiguration,
                          utils.BindingConfiguration, utils.Configuration):

    default_config_file = 'client.conf'

    def _add_defaults(self, defaults):
        super(ClientConfiguration, self)._add_defaults(defaults)
        defaults.update({'bridge-port': 44334,
                         'client-cert-nickname': 'sigul-client-cert',
                         'user-name': getpass.getuser(),
                         'passphrase-length': 128},)

    def _add_sections(self, sections):
        super(ClientConfiguration, self)._add_sections(sections)
        sections.add('client')

    def _read_configuration(self, parser):
        super(ClientConfiguration, self)._read_configuration(parser)
        self.bridge_hostname = parser.get('client', 'bridge-hostname')
        self.bridge_port = parser.getint('client', 'bridge-port')
        self.client_cert_nickname = parser.get(
            'client', 'client-cert-nickname')
        self.server_hostname = parser.get('client', 'server-hostname')
        self.user_name = parser.get('client', 'user-name')
        self.passphrase_length = parser.get('client', 'passphrase-length')
        self.batch_mode = False


def safe_string(s):
    '''Raise ClientError if s is not a safe string, otherwise return s.'''
    if not utils.string_is_safe(s):
        raise ClientError(
            '\'{0!s}\' ({1!s}) contains prohibited characters'.format(
                s, repr(s)))
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
        except utils.NSSInitError as e:
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
        fields = dict(outer_fields)  # Shallow copy
        fields['op'] = safe_string(op)
        fields['user'] = safe_string(self.config.user_name)
        self.__request_header_writer.write(utils.format_fields(fields))

    def __send_payload_size(self, payload_size):
        '''Prepare for sending payload of payload_size.

        Valid both for the primary payload and for subrequest payloads.

        '''
        self.__client.outer_write(utils.u64_pack(payload_size))

    def __send_payload_from_file(self, writer, fd):
        '''Send contents of fd to the server as payload, using writer.

        Valid both for the primary payload and for subreply payloads.  Note
        that the subrequest HMAC, if any, is not sent!

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
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.__send_payload_size(len(data))
        self.__request_payload_writer.write(data)

    def send_payload_from_file(self, fd):
        '''Send contents of file as payload.'''
        self.__send_payload_from_file(self.__request_payload_writer, fd)

    def send_inner(self, inner_fields, omit_payload_auth=False):
        '''Send the inner header, including inner_fields.'''
        # FIXME: handle errors.UNKNOWN_VERSION - there is no inner session and
        # outer session data is not all read
        fields = dict(inner_fields)  # Shallow copy
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
        except double_tls.InnerCertificateNotFound as e:
            raise ClientError(str(e))
        try:
            self.__client.inner_write(utils.format_fields(fields))
        finally:
            self.__client.inner_close()

    def read_response(self, expected_errors=(), no_payload=False):
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
        except utils.InvalidFieldsError as e:
            raise InvalidResponseError(
                'Invalid response format: {0!s}'.format(str(e)))
        if not self.__reply_header_reader.verify_64B_hmac_authenticator():
            raise InvalidResponseError('Header authentication failed')
        if error_code != errors.OK and error_code not in expected_errors:
            message = self.response_field('message')
            if message is not None:
                raise ClientError(
                    'Error: {0!s}: {1!s}'.format(
                        errors.message(error_code), message))
            else:
                raise ClientError(
                    'Error: {0!s}'.format(
                        (errors.message(error_code))))
        buf = self.__client.outer_read(utils.u64_size)
        self.__payload_size = utils.u64_unpack(buf)
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

    def write_payload_to_file(self, f, decoding=None):
        '''Write server's payload to f.'''
        def writer(out):
            if decoding is not None:
                out = out.decode("utf-8")
            f.write(out)
        utils.copy_data(writer, self.__reply_payload_reader.read,
                        self.__payload_size)
        self.__authenticate_reply_payload()

    def read_empty_unauthenticated_payload(self):
        '''Read zero-size payload and an incorrect payload authenticator.

        This is used for payloads dropped by the bridge for
        sign-rpm --koji-only.

        '''
        if self.__payload_size != 0:
            raise InvalidResponseError('Unexpected payload in response')
        self.__client.outer_read(64)  # Ignore

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
                raise InvalidResponseError(
                    'Integer field has incorrect length')
        return v

    def response_field_bool(self, key):
        '''Return a response field value as a bool or None if not present.

        Raise InvalidResponseError.

        '''
        v = self.__response_fields.get(key)
        if v is not None:
            try:
                v = utils.u8_unpack(v)
                v = {0: False, 1: True}[v]
            except KeyError:
                raise InvalidResponseError('Boolean field has invalid value')
            except struct.error:
                raise InvalidResponseError(
                    'Boolean field has incorrect length')
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
        except utils.InvalidFieldsError as e:
            raise InvalidResponseError(
                'Invalid response format: {0!s}'.format(str(e)))
        if not reader.verify_64B_hmac_authenticator():
            raise InvalidResponseError('Subreply header authentication failed')
        return fields

    def read_empty_subpayload(self, nss_key, ignore_auth=False):
        '''Read an empty subreply payload authenticated using nss_key.'''
        buf = self.__client.outer_read(utils.u64_size)
        if utils.u64_unpack(buf) != 0:
            raise InvalidResponseError('Unexpected payload in subreply')
        if not ignore_auth:
            reader = utils.SHA512HMACReader(self.__client.outer_read, nss_key)
            if not reader.verify_64B_hmac_authenticator():
                raise InvalidResponseError('Subreply payload authentication '
                                           'failed')
        else:
            self.__client.outer_read(64)  # Ignore

    def write_subpayload_to_file(self, nss_key, f):
        '''Write server's payload to f, authenticate using nss_key.'''
        buf = self.__client.outer_read(utils.u64_size)
        payload_size = utils.u64_unpack(buf)
        reader = utils.SHA512HMACReader(self.__client.outer_read, nss_key)
        utils.copy_data(f.write, reader.read, payload_size)
        if not reader.verify_64B_hmac_authenticator():
            raise InvalidResponseError(
                'Subreply payload authentication failed')

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
    if config.passphrase:
        return config.passphrase
    else:
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
    payload = conn.read_payload().decode('utf-8')
    start = 0
    for _ in range(conn.response_field_int(num_field_name)):
        try:
            i = payload.index('\x00', start)
        except ValueError:
            raise InvalidResponseError('Invalid payload format')
        e = payload[start:i]
        start = i + 1
        if not utils.string_is_safe(e):
            raise InvalidResponseError('Unprintable string in reply from '
                                       'server')
        print(e)


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


def get_bound_passphrase(config, filename):
    bound_passphrase = None
    with open(filename, 'r') as pwdfile:
        bound_passphrase = pwdfile.read()
    if not bound_passphrase:
        raise ClientError('No passphrase in file')
    passphrase = utils.unbind_passphrase(bound_passphrase)
    if passphrase is None:
        raise ClientError('Unable to unbind the passphrase on the client')
    if bound_passphrase == passphrase:
        # Please don't use this mechanism for unbound passphrases....
        raise ClientError('Passphrase file is unbound!')
    return passphrase


class SignRPMArgumentExaminer(object):
    '''An object that can be used to analyze sign-rpm{s,} operands.'''

    def __init__(self, config, koji_instance):
        self.__config = config
        self.__koji_instance = koji_instance
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
            except IOError as e:
                raise ClientError(
                    'Error opening {0!s}: {1!s}'.format(
                        arg, e.strerror))
            # Count whole blocks, that's what the bridge and server do.
            if os.fstat(rpm_file.fileno()).st_size == 0:
                raise ClientError(
                    'Error: Cannot sign zero-length RPM file {0!s}'.format(
                        arg))
            size = utils.file_size_in_blocks(rpm_file)
        else:
            try:
                if self.__koji_session is None:
                    kc = utils.koji_read_config(self.__config,
                                                self.__koji_instance)
                    self.__koji_session = utils.koji_connect(
                        kc, authenticate=False)
                rpm = self.__koji_session.getRPM(arg)
            except (utils.KojiError, koji.GenericError) as e:
                raise ClientError(str(e))
            if rpm is None:
                raise ClientError('{0!s} does not exist in Koji'.format(arg))
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
            size = int(rpm['size'])
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

    print('Administrator: {0!s}'.format(
          bool_to_text(conn.response_field_bool('admin'))))

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
    p2 = optparse.OptionParser(
        usage='%prog key-user-info user key',
        description="Show information about user's key access")
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
        print('No access defined')
    else:
        print('Access defined, key administrator: {0!s}'.format(
              bool_to_text(conn.response_field_bool('key-admin'))))


def cmd_modify_key_user(conn, args):
    p2 = optparse.OptionParser(
        usage='%prog modify-key-user [options] user key',
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
    p2 = optparse.OptionParser(
        usage='%prog list-keys',
        description='List keys')
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
    p2.add_option('--key-type', metavar='KEYTYPE',
                  help='Key type to create', default='gnupg')
    # GPG Key Type options
    p2.add_option('--gnupg-name-real', help='Real name of key subject')
    p2.add_option('--gnupg-name-comment',
                  help='A comment about of key subject')
    p2.add_option('--gnupg-name-email', help='E-mail of key subject')
    p2.add_option('--gnupg-expire-date', metavar='YYYY-MM-DD',
                  help='Key expiration date')
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('key name expected')
    if o2.gnupg_expire_date is not None:
        if not utils.yyyy_mm_dd_is_valid(o2.gnupg_expire_date):
            p2.error('invalid --expire-date')
    password = read_admin_password(conn.config)
    passphrase = read_new_password(conn.config, 'Passphrase for the new key: ',
                                   'Passphrase for the new key (again): ')

    f = {
        'key': safe_string(args[0]),
        'keytype': o2.key_type,
    }
    if o2.key_admin is not None:
        f['initial-key-admin'] = safe_string(o2.key_admin)
    if o2.gnupg_name_real is not None:
        f['name-real'] = safe_string(o2.gnupg_name_real)
    if o2.gnupg_name_comment is not None:
        f['name-comment'] = safe_string(o2.gnupg_name_comment)
    if o2.gnupg_name_email is not None:
        f['name-email'] = safe_string(o2.gnupg_name_email)
    if o2.gnupg_expire_date is not None:
        f['expire-date'] = o2.gnupg_expire_date
    conn.connect('new-key', f)
    conn.empty_payload()
    conn.send_inner({'password': password, 'passphrase': passphrase})
    conn.read_response()
    pubkey = conn.read_payload().decode('utf-8')
    if not utils.string_is_safe(pubkey.replace('\n', '')):
        raise InvalidResponseError('Public key is not safely printable')
    print(pubkey, end='')


def cmd_import_key(conn, args):
    p2 = optparse.OptionParser(usage='%prog import-key [options] key file',
                               description='Import a secret key')
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
    except IOError as e:
        raise ClientError(
            'Error opening {0!s}: {1!s}'.format(
                args[1], e.strerror))

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
    p2.add_option('-b', '--server-binding-method', action='append',
                  dest='server_binding_methods',
                  help=('Method used to bind this passphrase to server ('
                        'use sigul get-server-binding-methods to get '
                        'available methods)'))
    p2.add_option('-c', '--client-binding-method', action='append',
                  dest='client_binding_methods',
                  help=('client used to bind this passphrase to server ('
                        'use sigul get-binding-methods to get '
                        'available methods)'))
    p2.add_option('-w', '--write-passphrase-file', action='store',
                  dest='passphrase_file',
                  help=('File to store bound passphrase (works only with '
                        '--client-bind-method, and is required if used)'))
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and user name expected')
    if o2.passphrase_file is not None and o2.client_binding_methods is None:
        p2.error('Passphrase file only accepted with client-side binding')
    if o2.passphrase_file is None and o2.client_binding_methods is not None:
        p2.error('Client-side binding requires a passphrase file')
    if o2.passphrase_file is not None and os.path.exists(o2.passphrase_file):
        p2.error('Output passphrase file exists')
    try:
        client_binding = utils.bind_list_to_object(o2.client_binding_methods)
    except ValueError as ex:
        p2.error('Error in client binding config: {0!s}'.format(ex))
    try:
        server_binding = utils.bind_list_to_object(o2.server_binding_methods)
    except ValueError as ex:
        p2.error('Error in server binding config: {0!s}'.format(ex))

    passphrase = read_key_passphrase(conn.config)
    if o2.passphrase_file:
        new_passphrase = utils.random_passphrase(conn.config.passphrase_length)
        bound_passphrase = utils.bind_passphrase(conn.config,
                                                 new_passphrase,
                                                 client_binding)
    else:
        new_passphrase = read_new_password(conn.config,
                                           'Key passphrase for the new user: ',
                                           'Key passphrase for the new user '
                                           '(again): ')

    conn.connect('grant-key-access',
                 {'key': safe_string(args[0]), 'name': safe_string(args[1])})
    conn.empty_payload()
    inner_args = {'passphrase': passphrase,
                  'new-passphrase': new_passphrase}
    if client_binding is not None:
        inner_args['client-binding'] = json.dumps(client_binding)
    if server_binding is not None:
        inner_args['server-binding'] = json.dumps(server_binding)
    conn.send_inner(inner_args)
    conn.read_response(no_payload=True)
    if o2.passphrase_file is not None:
        with open(o2.passphrase_file, 'w') as ppfile:
            ppfile.write(bound_passphrase)


def cmd_change_key_expiration(conn, args):
    p2 = optparse.OptionParser(usage='%prog change-key-expiration key',
                               description='Change key expiration date')
    p2.add_option('--expire-date', metavar='YYYY-MM-DD',
                  help='Key expiration date')
    p2.add_option('--subkey', help='Subkey identifier')
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('key name expected')
    if o2.expire_date is not None:
        if not utils.yyyy_mm_dd_is_valid(o2.expire_date):
            p2.error('invalid --expire-date')
    if o2.subkey is not None:
        if not utils.is_int(o2.subkey):
            p2.error('invalid subkey identifier')

    passphrase = read_key_passphrase(conn.config)

    args = {'key': safe_string(args[0])}
    if o2.expire_date is not None:
        args['expire-date'] = o2.expire_date
    if o2.subkey is not None:
        args['subkey'] = o2.subkey
    conn.connect('change-key-expiration', args)
    conn.empty_payload()
    conn.send_inner({'passphrase': passphrase})
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
    pubkey = conn.read_payload().decode("utf-8")
    if not utils.string_is_safe(pubkey.replace('\n', '')):
        raise InvalidResponseError('Public key is not safely printable')
    print(pubkey, end='')


def cmd_change_passphrase(conn, args):
    p2 = optparse.OptionParser(usage='%prog change-passphrase key',
                               description='Change key passphrase')
    p2.add_option('-b', '--server-binding-method', action='append',
                  dest='server_binding_methods',
                  help=('Method used to bind this passphrase to server ('
                        'use sigul get-server-binding-methods to get '
                        'available methods)'))
    p2.add_option('-c', '--client-binding-method', action='append',
                  dest='client_binding_methods',
                  help=('client used to bind this passphrase to server ('
                        'use sigul get-binding-methods to get '
                        'available methods)'))
    p2.add_option('-w', '--write-passphrase-file', action='store',
                  dest='passphrase_file',
                  help=('File to store bound passphrase (works only with '
                        '--client-bind-method, and is required if used)'))
    (o2, args) = p2.parse_args(args)
    if len(args) != 1:
        p2.error('key name expected')
    if o2.passphrase_file is not None and o2.client_binding_methods is None:
        p2.error('Passphrase file only accepted with client-side binding')
    if o2.passphrase_file is None and o2.client_binding_methods is not None:
        p2.error('Client-side binding requires a passphrase file')
    if o2.passphrase_file is not None and os.path.exists(o2.passphrase_file):
        p2.error('Output passphrase file exists')
    try:
        client_binding = utils.bind_list_to_object(o2.client_binding_methods)
    except ValueError as ex:
        p2.error('Error in client binding config: {0!s}'.format(ex))
    try:
        server_binding = utils.bind_list_to_object(o2.server_binding_methods)
    except ValueError as ex:
        p2.error('Error in server binding config: {0!s}'.format(ex))

    passphrase = read_key_passphrase(conn.config)
    if o2.passphrase_file:
        new_passphrase = utils.random_passphrase(conn.config.passphrase_length)
        bound_passphrase = utils.bind_passphrase(conn.config,
                                                 new_passphrase,
                                                 client_binding)
    else:
        new_passphrase = read_new_password(conn.config,
                                           'Key passphrase for the new user: ',
                                           'Key passphrase for the new user '
                                           '(again): ')

    conn.connect('change-passphrase', {'key': safe_string(args[0])})
    conn.empty_payload()
    inner_args = {'passphrase': passphrase,
                  'new-passphrase': new_passphrase}
    if client_binding is not None:
        inner_args['client-binding'] = json.dumps(client_binding)
    if server_binding is not None:
        inner_args['server-binding'] = json.dumps(server_binding)
    conn.send_inner(inner_args)
    conn.read_response(no_payload=True)
    if o2.passphrase_file is not None:
        with open(o2.passphrase_file, 'w') as ppfile:
            ppfile.write(bound_passphrase)


def cmd_sign_text(conn, args):
    p2 = optparse.OptionParser(
        usage='%prog sign-text [options] key input_file',
        description='Output a cleartext signature of a text')
    p2.add_option('-o', '--output', metavar='FILE',
                  help='Write output to this file')
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and input file path expected')

    passphrase = read_key_passphrase(conn.config)
    try:
        f = open(args[1], "rb")
    except IOError as e:
        raise ClientError(
            'Error opening {0!s}: {1!s}'.format(
                args[1], e.strerror))

    try:
        conn.connect('sign-text', {'key': safe_string(args[0])})
        conn.send_payload_from_file(f)
    finally:
        f.close()
    conn.send_inner({'passphrase': passphrase})
    conn.read_response()
    try:
        if o2.output is None:
            conn.write_payload_to_file(sys.stdout, decoding="utf-8")
        else:
            utils.write_new_file(o2.output, conn.write_payload_to_file)
    except IOError as e:
        raise ClientError(
            'Error writing to {0!s}: {1!s}'.format(
                o2.output, e.strerror))


def cmd_sign_data(conn, args):
    p2 = optparse.OptionParser(usage='%prog sign-data [options] input_file',
                               description='Create a detached signature')
    p2.add_option('-o', '--output', metavar='FILE',
                  help='Write output to this file')
    p2.add_option('-a', '--armor', action='store_true',
                  help='Enable GnuPG armoring of the result')
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and input file path expected')
    if o2.output is None and sys.stdout.isatty() and not o2.armor:
        p2.error('won\'t write output to a TTY, specify a file name')

    passphrase = read_key_passphrase(conn.config)
    try:
        f = open(args[1], 'rb')
    except IOError as e:
        raise ClientError(
            'Error opening {0!s}: {1!s}'.format(
                args[1], e.strerror))

    try:
        conn.connect('sign-data', {'key': safe_string(args[0]),
                                   'armor': o2.armor or False})
        conn.send_payload_from_file(f)
    finally:
        f.close()
    conn.send_inner({'passphrase': passphrase})
    conn.read_response()
    try:
        if o2.output is None:
            conn.write_payload_to_file(sys.stdout, decoding="utf-8")
        else:
            utils.write_new_file(o2.output, conn.write_payload_to_file)
    except IOError as e:
        raise ClientError(
            'Error writing to {0!s}: {1!s}'.format(
                o2.output, e.strerror))


def cmd_decrypt(conn, args):
    p2 = optparse.OptionParser(usage='%prog decrypt [options] input_file',
                               description='Decrypt a file')
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
    except IOError as e:
        raise ClientError(
            'Error opening {0!s}: {1!s}'.format(
                args[1], e.strerror))

    try:
        conn.connect('decrypt', {'key': safe_string(args[0])})
        conn.send_payload_from_file(f)
    finally:
        f.close()
    conn.send_inner({'passphrase': passphrase})
    conn.read_response()
    try:
        if o2.output is None:
            conn.write_payload_to_file(sys.stdout, decoding="utf-8")
        else:
            utils.write_new_file(o2.output, conn.write_payload_to_file)
    except IOError as e:
        raise ClientError(
            'Error writing to {0!s}: {1!s}'.format(
                o2.output, e.strerror))


def call_git(args, stdin=None, ignore_error=False, strip_newline=False):
    cmd = ['git']
    cmd.extend(args)
    proc = subprocess.Popen(cmd,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (stdout, stderr) = proc.communicate(stdin)
    if proc.returncode != 0:
        if ignore_error:
            return None
        raise ClientError('Error while calling git, args %s, return code %d, '
                          'stdout %s, stderr %s' % (args,
                                                    proc.returncode,
                                                    stdout,
                                                    stderr))
    stdout = stdout.decode("utf-8")
    if strip_newline:
        stdout = stdout.replace('\n', '')
    return stdout


def cmd_sign_git_tag(conn, args):
    p2 = optparse.OptionParser(usage='%prog sign-git-tag [options] tagname',
                               description='Sign a GPG tag')
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and tag name expected')

    if not call_git(['status'], ignore_error=True):
        p2.error('Please run this inside a git repo directory')

    passphrase = read_key_passphrase(conn.config)

    unsigned_oid = call_git(
        ['show-ref', '-s', 'refs/tags/{0!s}'.format(args[1])],
        strip_newline=True)
    unsigned_obj = call_git(['cat-file', '-p', unsigned_oid])

    conn.connect('sign-git-tag', {'key': safe_string(args[0])})
    conn.send_payload(unsigned_obj)
    conn.send_inner({'passphrase': passphrase})
    conn.read_response()

    signature = conn.read_payload()
    signed_obj = unsigned_obj.encode("utf-8") + signature
    signed_oid = call_git(['hash-object', '-t', 'tag', '-w', '--stdin'],
                          stdin=signed_obj, strip_newline=True)
    call_git(['update-ref', 'refs/tags/{0!s}'.format(args[1]), signed_oid,
              unsigned_oid])


def cmd_sign_container(conn, args):
    p2 = optparse.OptionParser(
        usage='%prog sign-container [options] key manifest tag',
        description='Sign a Docker container')
    p2.add_option('-o', '--output', metavar='FILE',
                  help='Write output to this file')
    (o2, args) = p2.parse_args(args)
    if len(args) != 3:
        p2.error('key name, manifest file and tag name expected')
    if o2.output is None and sys.stdout.isatty():
        p2.error('won\'t write output to a TTY, specify a file name')

    passphrase = read_key_passphrase(conn.config)

    try:
        f = open(args[1], 'rb')
    except IOError as e:
        raise ClientError(
            'Error opening {0!s}: {1!s}'.format(
                args[1], e.strerror))

    try:
        conn.connect(
            'sign-container',
            {'key': safe_string(args[0]),
             'docker-reference': safe_string(args[2])})
        conn.send_payload_from_file(f)
    finally:
        f.close()
    conn.send_inner({'passphrase': passphrase})
    conn.read_response()
    try:
        if o2.output is None:
            conn.write_payload_to_file(sys.stdout, decoding="utf-8")
        else:
            utils.write_new_file(o2.output, conn.write_payload_to_file)
    except IOError as e:
        raise ClientError(
            'Error writing to {0!s}: {1!s}'.format(
                o2.output, e.strerror))


def cmd_sign_ostree(conn, args):
    p2 = optparse.OptionParser(
        usage='%prog sign-ostree [options] key hash input_file',
        description='Sign an OSTree commit object')
    p2.add_option('-o', '--output', metavar='FILE',
                  help='Write output to this file')
    (o2, args) = p2.parse_args(args)
    if len(args) != 3:
        p2.error('key name, commit hash and input file path expected')
    if o2.output is None and sys.stdout.isatty():
        p2.error('won\'t write output to a TTY, specify a file name')

    passphrase = read_key_passphrase(conn.config)
    try:
        f = open(args[2], 'rb')
    except IOError as e:
        raise ClientError(
            'Error opening {0!s}: {1!s}'.format(
                args[1], e.strerror))

    try:
        conn.connect('sign-ostree', {'key': safe_string(args[0]),
                                     'ostree-hash': args[1]})
        conn.send_payload_from_file(f)
    finally:
        f.close()
    conn.send_inner({'passphrase': passphrase})
    conn.read_response()
    try:
        if o2.output is None:
            conn.write_payload_to_file(sys.stdout, decoding="utf-8")
        else:
            utils.write_new_file(o2.output, conn.write_payload_to_file)
    except IOError as e:
        raise ClientError(
            'Error writing to {0!s}: {1!s}'.format(
                o2.output, e.strerror))


def cmd_sign_rpm(conn, args):
    p2 = optparse.OptionParser(usage='%prog sign-rpm [options] '
                               'key rpmfile-or-nevra',
                               description='Sign a RPM')
    p2.add_option('-o', '--output', metavar='FILE',
                  help='Write output to this file instead of overwriting the '
                  'input file')
    p2.add_option('--file-signing-key', metavar='FILE_SIGNING_KEY',
                  help='Add file signatures to the RPM contents '
                       '(this needs to be a non-gnupg key)')
    p2.add_option('--file-signing-key-passphrase-file',
                  metavar='FILENAME',
                  help='File with bound passphrase for file signing key')
    p2.add_option('--store-in-koji', action='store_true',
                  help='Store the generated RPM signature to Koji')
    p2.add_option('--koji-only', action='store_true',
                  help='Do not save the signed RPM locally, store it only to '
                  'Koji')
    p2.add_option('-k', '--koji-instance', metavar='INSTANCE',
                  help='Use the specified Koji instance')
    p2.add_option('--v3-signature', action='store_true',
                  help='Create a v3 signature (currently necessary for RSA'
                  'keys)')
    p2.set_defaults(store_in_koji=False, koji_only=False, v3_signature=False)
    (o2, args) = p2.parse_args(args)
    if len(args) != 2:
        p2.error('key name and RPM path or identification expected')
    if o2.koji_only:
        if not o2.store_in_koji:
            p2.error('--koji-only is valid only with --store-in-koji')
        if o2.output is not None:
            p2.error('--output can not be used together with --koji-only')
    if not o2.koji_only and o2.output is None and sys.stdout.isatty():
        p2.error('won\'t write output to a TTY, specify a file name')

    passphrase = read_key_passphrase(conn.config)

    # See conn.send_outer_fields() later
    conn.connect(None, None)
    inner = {'passphrase': passphrase}
    f = {'key': safe_string(args[0])}
    if o2.file_signing_key:
        f['file-signing-key'] = o2.file_signing_key
        if o2.file_signing_key_passphrase_file:
            file_signing_key_passphrase = get_bound_passphrase(
                conn.config,
                o2.file_signing_key_passphrase_file,
            )
        else:
            file_signing_key_passphrase = utils.read_password(
                conn.config, 'Key passphrase: ')
        inner['file-signing-key-passphrase'] = file_signing_key_passphrase
    if o2.store_in_koji:
        f['import-signature'] = True
    if o2.koji_only:
        f['return-data'] = False
    if o2.koji_instance is not None:
        f['koji-instance'] = safe_string(o2.koji_instance)
    if o2.v3_signature:
        f['v3-signature'] = True
    examiner = SignRPMArgumentExaminer(conn.config, o2.koji_instance)
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
    conn.send_inner(inner,
                    omit_payload_auth=rpm_file is None)
    conn.read_response()
    if not o2.koji_only:
        if o2.output is None:
            o2.output = args[1]
        try:
            utils.write_new_file(o2.output, conn.write_payload_to_file)
        except IOError as e:
            raise ClientError(
                'Error writing to {0!s}: {1!s}'.format(
                    o2.output, e.strerror))
    else:
        conn.read_empty_unauthenticated_payload()


class SignRPMsRequestThread(utils.WorkerThread):
    '''A thread that sends sign-rpm subrequests.'''

    def __init__(self, conn, args, koji_instance, header_nss_key,
                 payload_nss_key):
        super(SignRPMsRequestThread, self).__init__('sign-rpms:requests',
                                                    'request thread')
        self.results = {}
        self.__conn = conn
        self.__args = args
        self.__koji_instance = koji_instance
        self.__header_nss_key = header_nss_key
        self.__payload_nss_key = payload_nss_key

    def _real_run(self):
        examiner = SignRPMArgumentExaminer(self.__conn.config,
                                           self.__koji_instance)
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
                    raise ClientError('{0!s} is too large'.format(arg))
            except ClientError as e:
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
                raise InvalidResponseError(
                    'Integer field has incorrect length')
            if arg_idx > len(self.__args):
                raise InvalidResponseError('Invalid subreply id')
            if arg_idx in self.results:
                raise InvalidResponseError(
                    'Duplicate subreply id {0:d}'.format(arg_idx))

            try:
                buf = fields['status']
            except KeyError:
                raise InvalidResponseError('Required field status missing')
            try:
                error_code = utils.u32_unpack(buf)
            except struct.error:
                raise InvalidResponseError(
                    'Integer field has incorrect length')

            nss_key = utils.derived_key(self.__payload_nss_key, server_idx)
            if error_code != errors.OK:
                message = fields.get('message')
                if message is not None:
                    msg = '{0!s}: {1!s}'.format(
                        errors.message(error_code), message)
                else:
                    msg = errors.message(error_code)
                self.results[arg_idx] = msg
                self.__conn.read_empty_subpayload(nss_key)
                continue

            if not self.__o2.koji_only:
                if self.__o2.head_signing:
                    self._splice_rpm_results(nss_key, arg_idx)
                else:
                    self._store_rpm_result(nss_key, arg_idx)

            else:
                self.__conn.read_empty_subpayload(nss_key, ignore_auth=True)
            self.results[arg_idx] = None  # Mark arg_idx as succesful
            logging.info('Signed %s', self.__args[arg_idx])
            server_idx += 1

    def _splice_rpm_results(self, nss_key, arg_idx):
        arg = self.__args[arg_idx]
        if not arg.endswith('.rpm'):
            arg += '.rpm'
        output_path = os.path.join(self.__o2.output,
                                   os.path.basename(arg))
        output_sighdr_path = output_path + '.sighdr'
        try:
            def writer(f):
                self.__conn.write_subpayload_to_file(nss_key, f)
            utils.write_new_file(output_sighdr_path, writer)
        except IOError as e:
            raise ClientError(
                'Error writing to {0!s}: {1!s}'.format(
                    output_path, e.strerror))
        with open(output_sighdr_path, 'rb') as f:
            sighdr = f.read()
        koji.splice_rpm_sighdr(sighdr, arg, output_path)
        os.remove(output_sighdr_path)

    def _store_rpm_result(self, nss_key, arg_idx):
        arg = self.__args[arg_idx]
        if not arg.endswith('.rpm'):
            arg += '.rpm'
        output_path = os.path.join(
            self.__o2.output,
            os.path.basename(arg)
        )
        try:
            def writer(f):
                self.__conn.write_subpayload_to_file(nss_key, f)
            utils.write_new_file(output_path, writer)
        except IOError as e:
            raise ClientError(
                'Error writing to {0!s}: {1!s}'.format(
                    output_path, e.strerror))


def cmd_sign_rpms(conn, args):
    p2 = optparse.OptionParser(usage='%prog sign-rpms [options] '
                               'key rpmfile-or-nevra...',
                               description='Sign one or more RPMs')
    p2.add_option('-o', '--output', metavar='DIR',
                  help='Write output to this directory')
    p2.add_option('--file-signing-key', metavar='FILE_SIGNING_KEY',
                  help='Add file signatures to the RPM contents '
                       '(this needs to be a non-gnupg key)')
    p2.add_option('--file-signing-key-passphrase-file',
                  metavar='FILENAME',
                  help='File with bound passphrase for file signing key')
    p2.add_option('--head-signing', action='store_true',
                  help='Use RPM head-only signing (avoids copying the full '
                  'RPM between bridge and server)')
    p2.add_option('--store-in-koji', action='store_true',
                  help='Store the generated RPM signatures to Koji')
    p2.add_option('--koji-only', action='store_true',
                  help='Do not save the signed RPMs locally, store them only '
                  'to Koji')
    p2.add_option('-k', '--koji-instance', metavar='INSTANCE',
                  help='Use the specified Koji instance')
    p2.add_option('--v3-signature', action='store_true',
                  help='Create v3 signatures (currently necessary for RSA'
                  'keys)')
    p2.set_defaults(store_in_koji=False, koji_only=False, v3_signature=False)
    (o2, args) = p2.parse_args(args)
    if len(args) < 2:
        p2.error('key name and at least one RPM path or identification '
                 'expected')
    if o2.koji_only:
        if not o2.store_in_koji:
            p2.error('--koji-only is valid only with --store-in-koji')
        if o2.output is not None:
            p2.error('--output can not be used together with --koji-only')
    if o2.output is not None:
        try:
            os.mkdir(o2.output)
        except OSError as e:
            if e.errno != errno.EEXIST or not os.path.isdir(o2.output):
                raise ClientError(
                    'Error creating {0!s}: {1!s}'.format(
                        o2.output, e.strerror))
    elif not o2.koji_only:
        p2.error('--output is mandatory without --koji-only')

    passphrase = read_key_passphrase(conn.config)

    f = {'key': safe_string(args[0])}
    inner = {'passphrase': passphrase}
    if o2.file_signing_key:
        f['file-signing-key'] = o2.file_signing_key
        if o2.file_signing_key_passphrase_file:
            file_signing_key_passphrase = get_bound_passphrase(
                conn.config,
                o2.file_signing_key_passphrase_file,
            )
        else:
            file_signing_key_passphrase = utils.read_password(
                conn.config, 'Key passphrase: ')
        inner['file-signing-key-passphrase'] = file_signing_key_passphrase
    if o2.store_in_koji:
        f['import-signature'] = True
    if o2.koji_only:
        f['return-data'] = False
    if o2.koji_instance is not None:
        f['koji-instance'] = safe_string(o2.koji_instance)
    if o2.v3_signature:
        f['v3-signature'] = True
    if o2.head_signing:
        f['head-signing'] = True
        if o2.v3_signature:
            raise Exception(
                "Can't use head_signing together with v3-signature"
            )
    conn.connect('sign-rpms', f)
    conn.empty_payload()

    mech = nss.nss.CKM_GENERIC_SECRET_KEY_GEN
    slot = nss.nss.get_best_slot(mech)
    subrequest_header_nss_key = slot.key_gen(mech, None, 64)
    subrequest_payload_nss_key = slot.key_gen(mech, None, 64)
    subreply_header_nss_key = slot.key_gen(mech, None, 64)
    subreply_payload_nss_key = slot.key_gen(mech, None, 64)
    inner.update({
        'subrequest-header-auth-key': subrequest_header_nss_key.key_data,
        'subrequest-payload-auth-key': subrequest_payload_nss_key.key_data,
        'subreply-header-auth-key': subreply_header_nss_key.key_data,
        'subreply-payload-auth-key': subreply_payload_nss_key.key_data
    })
    conn.send_inner(inner)
    conn.read_response(no_payload=True)

    args = args[1:]
    request_thread = SignRPMsRequestThread(conn, args, o2.koji_instance,
                                           subrequest_header_nss_key,
                                           subrequest_payload_nss_key)
    reply_thread = SignRPMsReplyThread(conn, args, o2, subreply_header_nss_key,
                                       subreply_payload_nss_key)

    (ok, _) = utils.run_worker_threads((request_thread, reply_thread))

    results = request_thread.results.copy()
    for (k, v) in six.iteritems(reply_thread.results):
        # If the result was set by request_thread, server never saw the request
        # and there should be no reply.
        if k in results:
            raise Exception('Got multiple results for the same subrequest')
        results[k] = v

    if ok:
        # Don't bother if exception in one of the threads was the primary cause
        for idx in range(len(args)):
            if idx not in results:
                results[idx] = 'No reply from server received'
    if any(v is not None for v in six.itervalues(results)):
        for i in sorted(results.keys()):
            if results[i] is not None:
                logging.error('Error signing %s: %s', args[i], results[i])
        ok = False
    if not ok:
        raise ClientError('')


def cmd_list_binding_methods(conn, args):
    p2 = optparse.OptionParser(usage='%prog list-binding-methods',
                               description=('List binding methods supported '
                                            'by client'))
    (_, args) = p2.parse_args(args)
    if len(args) != 0:
        p2.error('unexpected arguments')
    for method in utils.BindingMethodRegistry.get_registered_methods():
        print(method)


def cmd_list_server_binding_methods(conn, args):
    p2 = optparse.OptionParser(usage='%prog list-server-binding-methods',
                               description=('List binding methods supported '
                                            'by the server'))
    (_, args) = p2.parse_args(args)
    if len(args) != 0:
        p2.error('unexpected arguments')
    password = read_admin_password(conn.config)

    conn.connect('list-binding-methods', {})
    conn.empty_payload()
    conn.send_inner({'password': password})
    conn.read_response()
    print_list_in_payload(conn, 'num-methods')


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
    'new-key': (cmd_new_key, 'Add a key'),
    'import-key': (cmd_import_key, 'Import a key'),
    'delete-key': (cmd_delete_key, 'Delete a key'),
    'modify-key': (cmd_modify_key, 'Modify a key'),
    'list-key-users': (cmd_list_key_users, 'List users that can access a key'),
    'grant-key-access': (cmd_grant_key_access, 'Grant key access to a user'),
    'change-key-expiration': (cmd_change_key_expiration,
                              'Change key expiration date'),
    'revoke-key-access': (cmd_revoke_key_access,
                          'Revoke key acess from a user'),
    'get-public-key': (cmd_get_public_key, 'Output public part of the key'),
    'change-passphrase': (cmd_change_passphrase, 'Change key passphrase'),
    'sign-text': (cmd_sign_text, 'Output a cleartext signature of a text'),
    'sign-data': (cmd_sign_data, 'Create a detached signature'),
    'decrypt': (cmd_decrypt, 'Decrypt an encrypted file'),
    'sign-git-tag': (cmd_sign_git_tag, 'Sign a git tag'),
    'sign-container': (cmd_sign_container, 'Sign an atomic docker container'),
    'sign-ostree': (cmd_sign_ostree, 'Sign an OSTree commit object'),
    'sign-rpm': (cmd_sign_rpm, 'Sign a RPM'),
    'sign-rpms': (cmd_sign_rpms, 'Sign one or more RPMs'),
    'list-binding-methods': (cmd_list_binding_methods,
                             'List bind methods supported by client'),
    'list-server-binding-methods': (cmd_list_server_binding_methods,
                                    'List bind methods supported by server'),
}


def handle_global_options():
    '''Handle global options.

    Return (configuration, command handler, its arguments).

    '''
    parser = optparse.OptionParser(
        usage='%prog [options] command '
        '[command-args...]',
        version='%prog {0!s}'.format(
            (settings.version)),
        description='A signing server client')
    parser.add_option('--internal-protocol-version',
                      help=optparse.SUPPRESS_HELP)
    parser.add_option('--help-commands', action='store_true',
                      help='List supported commands')
    utils.optparse_add_batch_option(parser)
    utils.optparse_add_config_file_option(parser, '~/.sigul/client.conf')
    parser.add_option('-u', '--user-name', metavar='USER',
                      help='User name sent to the server')
    parser.add_option('-f', '--passphrase-file', action='store',
                      dest='passphrase_file',
                      help='File with bound passphrase')
    utils.optparse_add_verbosity_option(parser)
    parser.set_defaults(help_commands=False)
    parser.disable_interspersed_args()
    (options, args) = parser.parse_args()

    if options.internal_protocol_version:
        # This is only for the test suite. It's a bad idea to use this.
        utils.protocol_version = int(options.internal_protocol_version)

    if options.help_commands:
        # FIXME: order of the commands
        for (name, (_, help_string)) in six.iteritems(command_handlers):
            print('{0!s:<20}{1!s}'.format(name, help_string))
        sys.exit()
    if len(args) < 1:
        parser.error('missing command, see --help-commands')
    if args[0] not in command_handlers:
        parser.error('unknown command {0!s}'.format(args[0]))

    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=utils.logging_level_from_options(options))
    try:
        config = ClientConfiguration(options.config_file)
    except utils.ConfigurationError as e:
        raise ClientError(str(e))
    config.batch_mode = options.batch
    if options.user_name:
        config.user_name = options.user_name

    utils.BindingMethodRegistry.register_enabled_methods(config)
    if options.passphrase_file:
        config.passphrase = get_bound_passphrase(config,
                                                 options.passphrase_file)
    else:
        config.passphrase = None

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
                    double_tls.ChildUnrecoverableError) as e:
                child_exception = e
    except ClientError as e:
        if str(e) != '':
            sys.exit(str(e))
        else:
            sys.exit(1)
    except (IOError, EOFError, socket.error) as e:
        logging.error('I/O error: %s', repr(e))
        sys.exit(1)
    except nss.error.NSPRError as e:
        if e.errno == nss.error.PR_CONNECT_RESET_ERROR:
            if child_exception is not None:
                if isinstance(child_exception,
                              double_tls.ChildConnectionRefusedError):
                    logging.error('Connection refused')
                elif isinstance(child_exception,
                                double_tls.ChildUnrecoverableError):
                    logging.debug('Unrecoverable error in child')
                else:
                    raise Exception('Unhandled child_exception type')
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
        raise  # Don't consider this an unexpected exception
    except Exception:
        logging.error('Unexpected exception', exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
