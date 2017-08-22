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

import ConfigParser
import base64
import binascii
import errors
import logging
import os
import signal
import shutil
import socket
import sys
import tempfile
import threading

try:
    import fedora.client
    have_fas = True
except:
    have_fas = False
import nss.error
import nss.io
import nss.nss
import nss.ssl
import requests

import double_tls
import settings
import utils

# Infrastructure

class BridgeError(Exception):
    pass

class BridgeConfiguration(utils.DaemonIDConfiguration, utils.KojiConfiguration,
                          utils.NSSConfiguration, utils.Configuration):

    default_config_file = 'bridge.conf'

    def _add_defaults(self, defaults):
        super(BridgeConfiguration, self)._add_defaults(defaults)
        defaults.update({'bridge-cert-nickname': 'sigul-bridge-cert',
                         'client-listen-port': 44334,
                         'max-rpms-payloads-size': 10 * 1024 * 1024 * 1024,
                         'required-fas-group': '',
                         'server-listen-port': 44333})
        # Override NSSConfiguration default
        defaults.update({'nss-dir': settings.default_server_nss_path})

    def _add_sections(self, sections):
        super(BridgeConfiguration, self)._add_sections(sections)
        sections.update(('bridge', 'koji'))

    def _read_configuration(self, parser):
        super(BridgeConfiguration, self)._read_configuration(parser)
        self.bridge_cert_nickname = parser.get('bridge', 'bridge-cert-nickname')
        self.client_listen_port = parser.getint('bridge', 'client-listen-port')
        self.required_fas_group = parser.get('bridge', 'required-fas-group')
        if self.required_fas_group == '':
            self.required_fas_group = None
        else:
            if not have_fas:
                raise utils.ConfigurationError('Fedora Account system '
                                               'authentication not supported')
            self.fas_user_name = parser.get('bridge', 'fas-user-name')
            self.fas_password = parser.get('bridge', 'fas-password')
        self.max_rpms_payloads_size = parser.getint('bridge',
                                                    'max-rpms-payloads-size')
        self.server_listen_port = parser.getint('bridge', 'server-listen-port')

        self.koji_fas_groups = {}
        for v in self.koji_instances.iterkeys():
            name = 'required-fas-group-' + v
            try:
                group = parser.get('koji', name)
                if group == '':
                    group = None
            except ConfigParser.NoOptionError:
                group = None
            self.koji_fas_groups[v] = group

def create_listen_sock(config, port):
    sock = nss.ssl.SSLSocket(nss.io.PR_AF_INET)
    # FIXME? does this belong in a finished product?
    sock.set_socket_option(nss.io.PR_SockOpt_Reuseaddr, True)
    sock.set_ssl_option(nss.ssl.SSL_REQUEST_CERTIFICATE, True)
    sock.set_ssl_option(nss.ssl.SSL_REQUIRE_CERTIFICATE, True)
    try:
        cert = nss.nss.find_cert_from_nickname(config.bridge_cert_nickname)
    except nss.error.NSPRError as e:
        if e.errno == nss.error.SEC_ERROR_BAD_DATABASE:
            raise BridgeError('Certificate \'{0!s}\' is not available'.format(
                              config.bridge_cert_nickname))
        raise
    sock.config_secure_server(cert, nss.nss.find_key_by_any_cert(cert),
                              cert.find_kea_type())
    sock.bind(nss.io.NetworkAddress(nss.io.PR_IpAddrAny, port))
    sock.listen()
    return sock

class InvalidRequestError(Exception):
    '''The client's request was invalid.'''
    pass

class InvalidReplyError(Exception):
    '''The server's reply was invalid.'''
    pass

class ForwardingError(Exception):
    '''An error was detected while forwarding or modifying the communication.'''
    pass

def copy_file_data(dest, src, size):
    '''Copy size bytes from file-like src to file-like dst.'''
    utils.copy_data(dest.write, src.read, size)

_fas_connection = None
def fas_user_is_in_group(config, user_name, group_name):
    '''Return True if user_name is in group.'''
    global _fas_connection

    try:
        if _fas_connection is None:
            logging.debug('Logging into FAS')
            _fas_connection = \
                fedora.client.AccountSystem(username=config.fas_user_name,
                                            password=config.fas_password)
        logging.debug('Authenticating user in FAS')
        person = _fas_connection.person_by_username(user_name)
        if len(person) == 0: # Not found
            return False
        for group in person.approved_memberships:
            if str(group['name']) == group_name:
                return True
        return False
    except (fedora.client.FedoraClientError,
            fedora.client.FedoraServiceError) as e:
        raise BridgeError('Error communicating with FAS: {0!s}'.format(str(e)))

def urlopen(url):
    '''Open url.

    Return (file, file size).  Raise ForwardingError.

    '''
    r = requests.get(url, stream=True)
    try:
        size = int(r.headers['content-length'])
    except KeyError:
        raise ForwardingError('Content-Length not returned for {0!s}'.format(
                              url))
    return (r, size)

class RPMObject(object):
    '''Data about a single 'sign-rpms' subrequest.'''

    def __init__(self, request_fields, request_header_data,
                 request_payload_size):
        self.request_fields = request_fields
        self.request_header_data = request_header_data
        self.request_payload_size = request_payload_size
        self.request_payload_url = None
        self.request_payload_digest = None
        self.reply_fields = None
        self.reply_header_data = None
        self.reply_payload_size = None
        self.reply_payload_digest = None
        self.tmp_path = None
        self.__koji_rpm_info = None

    def remove_tmp_path(self):
        '''If self.tmp_path is not None, delete it and set to None.'''
        if self.tmp_path is not None:
            os.remove(self.tmp_path)
            self.tmp_path = None

    def get_rpm_info(self, koji_client):
        '''Return information from koji, perhaps using koji_client.'''
        if self.__koji_rpm_info is None:
            self.__koji_rpm_info = koji_client.get_rpm_info(self.request_fields)
        return self.__koji_rpm_info

    def compute_payload_url(self, koji_client):
        '''Compute self.request_payload_url using koji_client.'''
        rpm_info = self.get_rpm_info(koji_client)
        self.request_payload_url = koji_client.get_rpm_url(rpm_info)

    def add_signature_to_koji(self, koji_client):
        '''Add signature from self.tmp_path to koji_client.'''
        rpm_info = self.get_rpm_info(koji_client)
        koji_client.add_signature(rpm_info, self.tmp_path)

# Header and payload size validation

class Field(object):
    '''A field.'''

    def __init__(self, name, optional=False):
        self.name = name
        self.__optional = optional

    def validate(self, value):
        '''Validate field value value.

        value is None if field is not present.

        '''
        if not self.__optional and value is None:
            raise InvalidRequestError('Required field {0!s} missing'.format(self.name))

class StringField(Field):
    '''A string field.'''

    def validate(self, value):
        super(StringField, self).validate(value)
        if value is not None and not utils.string_is_safe(value):
            raise InvalidRequestError('Field {0!s} is not printable'.format(self.name))

class BoolField(Field):
    '''A bool field.'''

    def validate(self, value):
        super(BoolField, self).validate(value)
        if value is not None and (len(value) != utils.u8_size or
                                  utils.u8_unpack(value) not in (0, 1)):
            raise InvalidRequestError('Field {0!s} is not a boolean'.format(self.name))

class YYYYMMDDField(Field):
    '''A date field, using the yyyy-mm-dd format.'''

    def validate(self, value):
        super(YYYYMMDDField, self).validate(value)
        if value is not None and not utils.yyyy_mm_dd_is_valid(value):
            raise InvalidRequestError('Field {0!s} is not a valid date'.format(
                                      self.name))

class RequestValidator(object):
    '''A validator of header fields and payload size.'''

    def __init__(self, fields, max_payload):
        self.__fields = fields
        self.__known_fields = set()
        for f in self.__fields:
            self.__known_fields.add(f.name)
        self.__max_payload = max_payload

    def validate(self, fields, payload_size):
        '''Validate fiels and payload_size.'''
        for key in fields.iterkeys():
            if key not in self.__known_fields:
                raise InvalidRequestError('Unexpected field {0!s}'.format(repr(key)))
        for f in self.__fields:
            f.validate(fields.get(f.name))
        if payload_size > self.__max_payload:
            raise InvalidRequestError('Payload too large')

# Request type-specific code

class RequestHandler(object):
    '''Request type-specific connection handling.'''

    def forward_request_payload(self, conn):
        '''Forward (optionally modify) request payload in conn.'''
        conn.server_buf.write(utils.u64_pack(conn.request_payload_size))
        copy_file_data(conn.server_buf, conn.client_buf,
                       conn.request_payload_size)

    def forward_reply_payload(self, conn):
        '''Forward (optionally modify) reply payload in conn.'''
        conn.client_buf.write(utils.u64_pack(conn.reply_payload_size))
        copy_file_data(conn.client_buf, conn.server_buf,
                       conn.reply_payload_size)

    def post_request_phase(self, conn):
        '''Optional additional actions on conn.'''
        pass

    def close(self):
        '''Deinitialize any costly state.'''
        pass

class KojiClient(object):
    '''Utilities for working with Koji.

    The client will create one Koji session per connection, reusing it for all
    subrequests.

    '''
    def __init__(self, conn):
        '''Initialize for conn.'''
        self.__conn = conn
        if not utils.string_is_safe(conn.user_name):
            raise InvalidRequestError('Client certificate CN is not printable')
        self.__koji_session = None
        self.__koji_config = None
        self.__koji_pathinfo = None

    def __get_session(self):
        '''Return a koji session, creating it if necessary.

        Also make sure self.__koji_config and self.__koji_pathinfo is set up.
        Raise ForwardingError.

        '''
        # Don't import koji before opening sockets!  The rpm Python module
        # calls NSS_NoDB_Init() during its initialization, which breaks our
        # attempts to initialize nss with our certificate database.
        import koji

        if self.__koji_config is None:
            instance = self.__conn.request_fields.get('koji-instance')
            StringField('koji-instance', optional=True).validate(instance)
            try:
                self.__koji_config = utils.koji_read_config(self.__conn.config,
                                                            instance)
            except utils.KojiError as e:
                raise ForwardingError('Error preparing Koji configuration: {0!s}'.format(
                                      str(e)))
            self.__koji_pathinfo = koji.PathInfo(self.__koji_config['topurl'])
        if self.__koji_session is None:
            try:
                if settings.koji_do_proxy_auth:
                    self.__koji_session = utils.koji_connect \
                        (self.__koji_config, authenticate=True,
                         proxyuser=self.__conn.user_name)
                else:
                    self.__koji_session = utils.koji_connect(self.__koji_config,
                                                             authenticate=True)
            except (utils.KojiError, koji.GenericError) as e:
                raise ForwardingError('Koji connection failed: {0!s}'.format(str(e)))
        return self.__koji_session

    __rpm_info_map = {'name': StringField('rpm-name'),
                      'version': StringField('rpm-version'),
                      'release': StringField('rpm-release'),
                      'arch': StringField('rpm-arch')}
    def get_rpm_info(self, fields):
        '''Return information about a rpm specified by fields.

        Raise ForwardingError.

        '''
        # Don't import koji before opening sockets!  The rpm Python module
        # calls NSS_NoDB_Init() during its initialization, which breaks our
        # attempts to initialize nss with our certificate database.
        import koji

        session = self.__get_session()
        d = {}
        for (key, field) in self.__rpm_info_map.iteritems():
            v = fields.get(field.name)
            field.validate(v)
            d[key] = v
        try:
            info = session.getRPM(d)
        except (utils.KojiError, koji.GenericError) as e:
            raise ForwardingError('Koji connection failed: {0!s}'.format(str(e)))
        if info is None:
            raise ForwardingError('RPM not found')
        return info

    def get_rpm_url(self, rpm_info):
        '''Return an URL for the specified rpm_info.

        Raise ForwardingError.

        '''
        # Don't import koji before opening sockets!  The rpm Python module
        # calls NSS_NoDB_Init() during its initialization, which breaks our
        # attempts to initialize nss with our certificate database.
        import koji

        session = self.__get_session()
        try:
            build = session.getBuild(rpm_info['build_id'])
            if build is None:
                raise ForwardingError('RPM has no build')
        except (utils.KojiError, koji.GenericError) as e:
            raise ForwardingError('Koji connection failed: {0!s}'.format(str(e)))
        return (self.__koji_pathinfo.build(build) + '/' +
                self.__koji_pathinfo.rpm(rpm_info))

    def add_signature(self, rpm_info, path):
        '''Add signature for rpm_info from path using session.

        Raise ForwardingError.

        '''
        # Don't import koji or rpm before opening sockets!  The rpm Python
        # module calls NSS_NoDB_Init() during its initialization, which breaks
        # our attempts to initialize nss with our certificate database.
        import koji
        import rpm

        session = self.__get_session()
        try:
            header_fields = koji.get_header_fields(path, ('siggpg', 'sigpgp'))
        except rpm.error:
            raise ForwardingError('Corrupt RPM returned by server')

        sigkey = header_fields['siggpg']
        if sigkey is None:
            sigkey = header_fields['sigpgp']
            if sigkey is None:
                raise ForwardingError('Missing signature')
        sigkey = koji.get_sigpacket_key_id(sigkey)
        sighdr = koji.rip_rpm_sighdr(path)
        sighdr_digest = binascii.b2a_hex(nss.nss.md5_digest(sighdr))

        try:
            sigs = session.queryRPMSigs(rpm_id=rpm_info['id'], sigkey=sigkey)
            assert len(sigs) <= 1
            if len(sigs) > 0 and sigs[0]['sighash'] != sighdr_digest:
                raise ForwardingError('A different signature was already '
                                      'imported')
            if len(sigs) == 0:
                session.addRPMSig(rpm_info['id'], base64.encodestring(sighdr))
        except (utils.KojiError, koji.GenericError) as e:
            raise ForwardingError('Koji connection failed: {0!s}'.format(str(e)))

    def close(self):
        '''Disconnect from koji.'''
        if self.__koji_session is not None:
            utils.koji_disconnect(self.__koji_session)
            self.__koji_session = None

class SignRPMRequestHandler(RequestHandler):
    '''A specialized handler for the 'sign-rpm' request.'''

    def __init__(self, *args, **kwargs):
        super(SignRPMRequestHandler, self).__init__(*args, **kwargs)
        self.__koji_client = None
        self.__rpm = None

    def forward_request_payload(self, conn):
        self.__koji_client = KojiClient(conn)
        self.__rpm = RPMObject(conn.request_fields, None,
                               conn.request_payload_size)
        if conn.request_payload_size != 0:
            return super(SignRPMRequestHandler, self) \
                .forward_request_payload(conn)

        self.__rpm.compute_payload_url(self.__koji_client)
        url = self.__rpm.request_payload_url
        try:
            (src, payload_size) = urlopen(url)
            try:
                conn.server_buf.write(utils.u64_pack(payload_size))
                utils.copy_data(conn.server_buf.write, src.iter_content(4096),
                                payload_size)
            finally:
                src.close()
        except requests.RequestException as e:
            raise ForwardingError('Error reading {0!s}: {1!s}'.format(url, str(e)))

    def forward_reply_payload(self, conn):
        # Zero-length response should happen only on error.
        if (conn.reply_payload_size != 0 and
            conn.request_fields.get('import-signature') == utils.u8_pack(1)):
            (fd, self.__rpm.tmp_path) = tempfile.mkstemp(text=False)
            try:
                tmp_file = os.fdopen(fd, 'w+')
                try:
                    copy_file_data(tmp_file, conn.server_buf,
                                   conn.reply_payload_size)
                finally:
                    tmp_file.close()

                self.__rpm.add_signature_to_koji(self.__koji_client)

                if conn.request_fields.get('return-data') != utils.u8_pack(0):
                    payload_size = conn.reply_payload_size
                    src = open(self.__rpm.tmp_path, 'rb')
                else:
                    payload_size = 0
                    src = None
                try:
                    conn.client_buf.write(utils.u64_pack(payload_size))
                    if src is not None:
                        copy_file_data(conn.client_buf, src, payload_size)
                finally:
                    if src is not None:
                        src.close()
            finally:
                self.__rpm.remove_tmp_path()
        elif conn.request_fields.get('return-data') != utils.u8_pack(0):
            super(SignRPMRequestHandler, self).forward_reply_payload(conn)
        else:
            conn.client_buf.write(utils.u8_pack(0))

    def close(self):
        super(SignRPMRequestHandler, self).close()
        if self.__koji_client is not None:
            self.__koji_client.close()

class SubrequestMap(object):
    '''A map of subrequest ID => RPMObject, internally serialized.'''

    def __init__(self):
        self.__map = {}
        self.__lock = threading.Lock()

    def add(self, rpm):
        '''Add a RPMObject to the map.'''
        self.__lock.acquire()
        try:
            id_ = rpm.request_fields['id']
            assert id_ not in self.__map
            self.__map[id_] = rpm
        finally:
            self.__lock.release()

    def get(self, id_):
        '''Return an RPMObject matching id_.  Raise KeyError.'''
        self.__lock.acquire()
        try:
            return self.__map[id_]
        finally:
            self.__lock.release()

class SignRPMsReadRequestThread(utils.WorkerThread):
    '''A thread that reads sign-rpm subrequests.

    The requests are put into dest_queue as RPMObject objects, with None
    marking end of the requests.

    '''

    __subheader_validator = \
        RequestValidator((Field('id'),
                          StringField('rpm-name', optional=True),
                          StringField('rpm-epoch', optional=True),
                          StringField('rpm-version', optional=True),
                          StringField('rpm-release', optional=True),
                          StringField('rpm-arch', optional=True),
                          Field('rpm-sigmd5', optional=True)),
                         max_payload=1024*1024*1024*1024)

    def __init__(self, conn, dest_queue, subrequest_map, tmp_dir):
        super(SignRPMsReadRequestThread, self). \
            __init__('sign-rpms:read requests', 'read request thread',
                     output_queues=((dest_queue, None),))
        self.__conn = conn
        self.__dest = dest_queue
        self.__subrequest_map = subrequest_map
        self.__tmp_dir = tmp_dir

    def _real_run(self):
        total_size = 0
        while True:
            (rpm, size) = self.__read_one_request \
                (self.__conn.config.max_rpms_payloads_size - total_size)
            if rpm is None:
                break
            total_size += size
            self.__subrequest_map.add(rpm)
            self.__dest.put(rpm)

    def __read_one_request(self, remaining_size):
        '''Read one request from self.__conn.

        Return (RPMObject, file size), (None, None) on EOF.  Raise
        InvalidRequestError, others.  Only allow remaining_size bytes for the
        payload.

        '''
        client_proxy = StoringProxy(self.__conn.client_buf)
        try:
            fields = utils.read_fields(client_proxy.stored_read)
        except EOFError:
            return (None, None)
        except utils.InvalidFieldsError as e:
            raise InvalidRequestError(str(e))
        s = utils.readable_fields(fields)
        logging.debug('%s: Started handling %s', self.name, s)
        logging.info('Subrequest: %s', s)
        client_proxy.stored_read(64) # Ignore value

        buf = self.__conn.client_buf.read(utils.u64_size)
        payload_size = utils.u64_unpack(buf)

        self.__subheader_validator.validate(fields, payload_size)
        rpm = RPMObject(fields, client_proxy.stored_data(), payload_size)

        if payload_size == 0:
            size = 0
        else:
            if payload_size > remaining_size:
                raise InvalidRequestError('Total payload size too large')
            (fd, rpm.tmp_path) = tempfile.mkstemp(text=False,
                                                  dir=self.__tmp_dir)
            dst = os.fdopen(fd, 'w+')
            try:
                copy_file_data(dst, self.__conn.client_buf, payload_size)
                # Count whole blocks to avoid millions of 1-byte files filling
                # the hard drive due to internal fragmentation.
                size = utils.file_size_in_blocks(dst)
            finally:
                dst.close()
        rpm.request_payload_digest = self.__conn.client_buf.read(64)
        return (rpm, size)

class SignRPMsKojiRequestThread(utils.WorkerThread):
    '''A thread that talks to koji for sign-rpm subrequests.

    The requests in dest_queue and src_queue are RPMObject objects, with None
    marking end of the requests.

    '''

    def __init__(self, conn, dest_queue, src_queue):
        super(SignRPMsKojiRequestThread, self). \
            __init__('sign-rpms:koji requests', 'koji request thread',
                     input_queues=((src_queue, None),),
                     output_queues=((dest_queue, None),))
        self.__conn = conn
        self.__dest = dest_queue
        self.__src = src_queue

    def _real_run(self):
        '''Read and handle all koji subrequests.'''
        koji_client = KojiClient(self.__conn)
        try:
            total_size = 0
            while True:
                rpm = self.__src.get()
                if rpm is None:
                    break
                size = self.__handle_one_request_rpm(rpm, koji_client)
                total_size += size
                if total_size > self.__conn.config.max_rpms_payloads_size:
                    raise InvalidRequestError('Total payload size too large')
                self.__dest.put(rpm)
        finally:
            koji_client.close()

    def __handle_one_request_rpm(self, rpm, koji_client):
        '''Handle an incoming request using koji_client.

        Return RPM size.

        '''
        logging.debug('%s: Started handling request %s', self.name,
                      utils.readable_fields(rpm.request_fields))
        if rpm.request_payload_size == 0:
            rpm.compute_payload_url(koji_client)
            rpm_info = rpm.get_rpm_info(koji_client)
            size = int(rpm_info['size'])
        else:
            # Count whole blocks to avoid millions of 1-byte files
            # filling the hard drive due to internal fragmentation.
            size = utils.path_size_in_blocks(rpm.tmp_path)
        return size

class SignRPMsSendRequestThread(utils.WorkerThread):
    '''A thread that forwards sign-rpm subrequests.

    The requests in src_queue are RPMObject objects, with None marking end of
    the requests.

    '''

    def __init__(self, src_queue, server_buf):
        super(SignRPMsSendRequestThread, self). \
            __init__('sign-rpms:send requests', 'send request thread',
                     input_queues=((src_queue, None),))
        self.__src = src_queue
        self.__server_buf = server_buf

    def _real_run(self):
        try:
            while True:
                rpm = self.__src.get()
                if rpm is None:
                    break
                self.__handle_one_rpm(rpm)
        finally:
            self.__server_buf.send_outer_eof()

    def __handle_one_rpm(self, rpm):
        '''Send an incoming request.'''
        logging.debug('%s: Started handling %s', self.name,
                      utils.readable_fields(rpm.request_fields))

        self.__server_buf.write(rpm.request_header_data)

        payload_size = rpm.request_payload_size
        try:
            if payload_size != 0:
                src = open(rpm.tmp_path, 'rb')
                readfn = src.read
            else:
                (src, payload_size) = urlopen(rpm.request_payload_url)
                readfn = src.iter_content(4096)
            try:
                self.__server_buf.write(utils.u64_pack(payload_size))
                utils.copy_data(self.__server_buf.write, readfn, payload_size)
            finally:
                src.close()
        except requests.RequestException as e:
            if payload_size != 0:
                # This exception was not expected, let the default handling
                # handle it
                raise
            raise ForwardingError('Error reading {0!s}: {1!s}'.format(rpm.request_payload_url, str(e)))
        self.__server_buf.write(rpm.request_payload_digest)

        rpm.remove_tmp_path()

class SignRPMsReadReplyThread(utils.WorkerThread):
    '''A thread that reads sign-rpm subreplies.

    The replies are put into dest_queue as RPMObject objects, with None marking
    end of the replies.

    '''
    def __init__(self, dest_queue, server_buf, subrequest_map, tmp_dir):
        super(SignRPMsReadReplyThread, self). \
            __init__('sign-rpms:read replies', 'read reply thread',
                     output_queues=((dest_queue, None),))
        self.__dest = dest_queue
        self.__server_buf = server_buf
        self.__subrequest_map = subrequest_map
        self.__tmp_dir = tmp_dir

    def _real_run(self):
        try:
            while True:
                rpm = self.__read_one_reply()
                if rpm is None:
                    break
                self.__dest.put(rpm)
        except:
            # This is a pretty horrible hack. If we stop reading replies from
            # the server (e.g. because this thread or one of its consumers
            # fails), the server will eventually block when the TCP buffers
            # for the server->bridge connection fill, but as long as bridge
            # keeps replying with zero-window ACKs, the connection will never
            # time out and our request-side threads will not terminate.
            #
            # Ideally we would studown(SHUT_RD), and the kernel would send a RST
            # to the server about the unread data, but the Linux kernel actually
            # ignores SHUT_RD for TCP.
            #
            # Instead, shut down the server socket also for writing; this will
            # cause SignRPMsSendRequestThread to terminate, and we are not even
            # waiting for the server to notice: after all our threads
            # terminate, the socket will be closed bu ys (probably with a RST
            # because this thread has not handled all data).
            #
            # Finally, use socket.socket instead of the equivalent NSPR call to
            # avoid any possible multithreading/locking issues within NSPR and
            # NSS; the NSS socket is still in full-duplex mode, so touching the
            # sending side might not be a good idea.
            try:
                logging.debug('%s: Exception, shutting down write side as well',
                              self.name)
                fd = self.__server_buf.socket.fileno()
                sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                finally:
                    sock.close()
            except Exception as e:
                logging.debug('%s: Shut down failed: %s', self.name, repr(e))
                # But otherwise ignore this, raise the original one
            raise

    def __read_one_reply(self):
        '''Read one reply from self.__server_buf.

        Return the relevant RPMObject or None.  Raise InvalidReplyError.

        '''
        server_proxy = StoringProxy(self.__server_buf)
        try:
            fields = utils.read_fields(server_proxy.stored_read)
        except EOFError:
            return None
        except utils.InvalidFieldsError as e:
            raise InvalidReplyError(str(e))
        logging.debug('%s: Started handling %s', self.name,
                      utils.readable_fields(fields))
        if 'id' not in fields:
            raise InvalidReplyError('Required field id missing')
        # We add the RPMObject into self.__subrequest_map as soon as the
        # request is read - before sending it to the server, so if we are
        # reading a reply from the server, the RPMObject must have already been
        # inserted into the map and there is no race.
        try:
            rpm = self.__subrequest_map.get(fields['id'])
        except KeyError:
            raise InvalidReplyError('Invalid subreply ID {0!s}'.format(
                                    repr(fields['id'])))

        try:
            buf = fields['status']
        except KeyError:
            raise InvalidReplyError('Required field status missing')
        if len(buf) != utils.u32_size:
            raise InvalidReplyError('Invalid field status')
        error_code = utils.u32_unpack(buf)
        if error_code != errors.OK:
            msg = fields.get('message')
            if msg is not None:
                logging.info('Subreply %s error: %s, %s', fields['id'],
                             errors.message(error_code), msg)
            else:
                logging.info('Subreply %s error: %s', fields['id'],
                             errors.message(error_code))
        logging.debug('Subreply: %s', utils.readable_fields(fields))

        rpm.reply_fields = fields
        server_proxy.stored_read(64) # Ignore value
        rpm.reply_header_data = server_proxy.stored_data()

        buf = self.__server_buf.read(utils.u64_size)
        rpm.reply_payload_size = utils.u64_unpack(buf)
        assert rpm.tmp_path is None
        (fd, rpm.tmp_path) = tempfile.mkstemp(text=False, dir=self.__tmp_dir)
        dst = os.fdopen(fd, 'w+')
        try:
            copy_file_data(dst, self.__server_buf, rpm.reply_payload_size)
        finally:
            dst.close()
        rpm.reply_payload_digest = self.__server_buf.read(64)
        return rpm

class SignRPMsKojiReplyThread(utils.WorkerThread):
    '''A thread that talks to koji for sign-rpm subreplies.

    The requests in dest_queue and src_queue are RPMObject objects, with None
    marking end of the requests.

    '''

    def __init__(self, conn, dest_queue, src_queue):
        super(SignRPMsKojiReplyThread, self). \
            __init__('sign-rpms:koji replies', 'koji reply thread',
                     input_queues=((src_queue, None),),
                     output_queues=((dest_queue, None),))
        self.__conn = conn
        self.__dest = dest_queue
        self.__src = src_queue

    def _real_run(self):
        '''Read and handle all koji subreplies.'''
        koji_client = KojiClient(self.__conn)
        try:
            while True:
                rpm = self.__src.get()
                if rpm is None:
                    break
                self.__handle_one_reply_rpm(rpm, koji_client)
                self.__dest.put(rpm)
        finally:
            koji_client.close()

    def __handle_one_reply_rpm(self, rpm, koji_client):
        '''Handle an incoming reply using koji_client.

        Raise ForwardingError.

        '''
        logging.debug('%s: Started handling reply %s', self.name,
                      utils.readable_fields(rpm.reply_fields))
        # Zero-length response should happen only on error.
        if (rpm.reply_payload_size != 0 and
            (self.__conn.request_fields.get('import-signature') ==
             utils.u8_pack(1))):
            rpm.add_signature_to_koji(koji_client)

class SignRPMsSendReplyThread(utils.WorkerThread):
    '''A thread that forwards sign-rpm subreplies.

    The replies in src_queue are RPMObject objects, with None marking end of
    the replies.

    '''

    def __init__(self, conn, src_queue):
        super(SignRPMsSendReplyThread, self). \
            __init__('sign-rpms:send replies', 'send reply thread',
                     input_queues=((src_queue, None),))
        self.__conn = conn
        self.__src = src_queue

    def _real_run(self):
        while True:
            rpm = self.__src.get()
            if rpm is None:
                break
            self.__handle_one_rpm(rpm)

    def __handle_one_rpm(self, rpm):
        '''Send an incoming request.'''
        logging.debug('%s: Started handling %s', self.name,
                      utils.readable_fields(rpm.reply_fields))
        self.__conn.client_buf.write(rpm.reply_header_data)

        if self.__conn.request_fields.get('return-data') != utils.u8_pack(0):
            payload_size = rpm.reply_payload_size
            src = open(rpm.tmp_path, 'rb')
        else:
            payload_size = 0
            src = None
        try:
            self.__conn.client_buf.write(utils.u64_pack(payload_size))
            if src is not None:
                copy_file_data(self.__conn.client_buf, src, payload_size)
        finally:
            if src is not None:
                src.close()
        self.__conn.client_buf.write(rpm.reply_payload_digest)

        rpm.remove_tmp_path()

class SignRPMsRequestHandler(RequestHandler):
    '''A specialized handler for the 'sign-rpms' request.'''

    def post_request_phase(self, conn):
        logging.debug('In post_request_phase')
        subrequest_map = SubrequestMap()

        tmp_dir = tempfile.mkdtemp()
        exception = None
        try:
            conn.client_buf.set_full_duplex(True)
            conn.server_buf.set_full_duplex(True)

            q1 = utils.WorkerQueue(100)
            q2 = utils.WorkerQueue(100)
            q3 = utils.WorkerQueue(100)
            q4 = utils.WorkerQueue(100)

            threads = []
            threads.append(SignRPMsReadRequestThread(conn, q1,
                                                     subrequest_map, tmp_dir))
            threads.append(SignRPMsKojiRequestThread(conn, q2, q1))
            threads.append(SignRPMsSendRequestThread(q2, conn.server_buf))
            threads.append(SignRPMsReadReplyThread(q3, conn.server_buf,
                                                   subrequest_map, tmp_dir))
            threads.append(SignRPMsKojiReplyThread(conn, q4, q3))
            threads.append(SignRPMsSendReplyThread(conn, q4))

            (_, exception) = utils.run_worker_threads(threads,
                                                      (InvalidRequestError,
                                                       InvalidReplyError,
                                                       ForwardingError))
        finally:
            shutil.rmtree(tmp_dir)
            conn.client_buf.set_full_duplex(False)
            conn.server_buf.set_full_duplex(False)
        if exception is not None:
            raise exception[0], exception[1], exception[2]

class RT(object):
    '''Request type description.'''

    def __init__(self, fields, max_payload=0, handler=RequestHandler):
        fields += (StringField('user'), StringField('op'))
        self.validator = RequestValidator(fields, max_payload)
        self.handler = handler

SF = StringField
request_types = {
    'list-users': RT(()),
    'new-user': RT((SF('name'), BoolField('admin', optional=True))),
    'delete-user': RT((SF('name'),)),
    'user-info': RT((SF('name'),)),
    'modify-user': RT((SF('name'), BoolField('admin', optional=True,),
                       SF('new-name', optional=True))),
    'key-user-info': RT((SF('name'), SF('key'))),
    'modify-key-user': RT((SF('name'), SF('key'),
                           BoolField('key-admin', optional=True))),
    'list-keys': RT(()),
    'new-key': RT((SF('key'), SF('initial-key-admin', optional=True),
                   SF('name-real', optional=True),
                   SF('name-comment', optional=True),
                   SF('name-email', optional=True),
                   YYYYMMDDField('expire-date', optional=True))),
    'import-key': RT((SF('key'), SF('initial-key-admin', optional=True)),
                     max_payload=1024*1024),
    'delete-key': RT((SF('key'),)),
    'modify-key': RT((SF('key'), SF('new-name', optional=True))),
    'list-key-users': RT((SF('key'),)),
    'grant-key-access': RT((SF('key'), SF('name'))),
    'change-key-expiration': RT((SF('key'),
                                 SF('subkey', optional=True),
                                 YYYYMMDDField('expire-date', optional=True))),
    'revoke-key-access': RT((SF('key'), SF('name'))),
    'get-public-key': RT((SF('key'),)),
    'change-passphrase': RT((SF('key'),)),
    'sign-text': RT((SF('key'),), max_payload=1024*1024*1024),
    'sign-data': RT((SF('key'),
                     BoolField('armor', optional=True)),
                    max_payload=1024*1024*1024*1024),
    'sign-git-tag': RT((SF('key'),),
                       max_payload=1024*1024*1024),
    'sign-container': RT((SF('key'),
                          SF('docker-reference')),
                         max_payload=1024*1024*1024),
    'sign-ostree': RT((SF('key'),
                       SF('ostree-hash')),
                      max_payload=1024*1024*1024),
    'sign-rpm': RT((SF('key'), SF('rpm-name', optional=True),
                    SF('rpm-epoch', optional=True),
                    SF('rpm-version', optional=True),
                    SF('rpm-release', optional=True),
                    SF('rpm-arch', optional=True),
                    Field('rpm-sigmd5', optional=True),
                    BoolField('import-signature', optional=True),
                    BoolField('return-data', optional=True),
                    SF('koji-instance', optional=True),
                    BoolField('v3-signature', optional=True)),
                   max_payload=1024*1024*1024, handler=SignRPMRequestHandler),
    'sign-rpms': RT((SF('key'), BoolField('import-signature', optional=True),
                     BoolField('return-data', optional=True),
                     SF('koji-instance', optional=True),
                     BoolField('v3-signature', optional=True)),
                    handler=SignRPMsRequestHandler),
    'list-binding-methods': RT(()),
    }
del RT
del SF

# Request handling

class StoringProxy(object):
    '''A proxy for a double_tls.OuterBuffer that stores read outer data.'''

    def __init__(self, buf):
        self.__buf = buf
        self.__stored = ''

    def stored_read(self, size):
        '''Read size bytes from the buffer and store the result.'''
        data = self.__buf.read(size)
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

class BridgeConnection(object):
    '''State and handling of a single connection.'''

    @staticmethod
    def handle_connection(config, client_sock, server_sock):
        '''Handle a single connection using client_sock and server_sock.'''
        client_sock.force_handshake()
        cert = client_sock.get_peer_certificate()
        assert cert is not None
        user_name = cert.subject_common_name
        logging.info('Client with CN %s connected', repr(user_name))
        if (config.required_fas_group is not None and
            not fas_user_is_in_group(config, user_name,
                                     config.required_fas_group)):
            raise InvalidRequestError('User {0!s} not allowed to connect'.format(repr(user_name)))

        client_buf = double_tls.OuterBuffer(client_sock)
        server_buf = double_tls.OuterBuffer(server_sock)

        conn = BridgeConnection(config, user_name, client_buf, server_buf)
        try:
            conn.__forward_request_headers()
            conn.__handler.forward_request_payload(conn)

            double_tls.bridge_inner_stream(conn.client_buf, conn.server_buf)

            conn.__forward_reply_headers()
            conn.__forward_reply_payload()

            conn.__handler.post_request_phase(conn)

            conn.__terminate_client_connection()
        finally:
            conn.__finalize()

    def __init__(self, config, user_name, client_buf, server_buf):
        self.config = config
        self.user_name = user_name
        self.client_buf = client_buf
        self.server_buf = server_buf
        self.__handler = None

    def __forward_request_headers(self):
        '''Read and forward request data up to the request payload size.

        Note that request payload size is read and validated, but not forwarded!
        Also enforce self.config.koji_fas_groups.

        Set self.__handler, self.request_fields and self.request_payload_size.

        Raise InvalidRequestError.

        '''
        # FIXME: handle server's reporting of unknown protocol version - there
        # is no inner session
        proxy = StoringProxy(self.client_buf)
        buf = proxy.stored_read(utils.u32_size)
        client_version = utils.u32_unpack(buf)
        if client_version != utils.protocol_version:
            raise InvalidRequestError('Unknown protocol version {0:d}'.format(
                                      client_version))
        try:
            self.request_fields = utils.read_fields(proxy.stored_read)
        except utils.InvalidFieldsError as e:
            raise InvalidRequestError(str(e))

        logging.info('Request: %s', utils.readable_fields(self.request_fields))
        try:
            op = self.request_fields['op']
        except KeyError:
            raise InvalidRequestError('op field missing')
        try:
            rt = request_types[op]
        except KeyError:
            raise InvalidRequestError('Unknown op value')
        self.__handler = rt.handler()

        buf = self.client_buf.read(utils.u64_size) # Not using proxy
        self.request_payload_size = utils.u64_unpack(buf)

        rt.validator.validate(self.request_fields, self.request_payload_size)
        self.__check_koji_instance_access()

        self.server_buf.write(proxy.stored_data())

    def __check_koji_instance_access(self):
        '''Verify FAS group required for the specified Koji instance.'''
        instance = self.request_fields.get('koji-instance')
        StringField('koji-instance', optional=True).validate(instance)
        if instance is not None and instance in self.config.koji_fas_groups:
            group = self.config.koji_fas_groups[instance]
            if (group is not None and
                not fas_user_is_in_group(self.config, self.user_name, group)):
                raise InvalidRequestError('User %s not allowed to use Koji '
                                          'instance %s' % (repr(self.user_name),
                                                           repr(instance)))

    def __forward_reply_headers(self):
        '''Read and forward reply data up to (and including) the reply header.

        Raise InvalidReplyError.

        '''
        proxy = StoringProxy(self.server_buf)
        buf = proxy.stored_read(utils.u32_size)
        try:
            fields = utils.read_fields(proxy.stored_read)
        except utils.InvalidFieldsError as e:
            raise InvalidReplyError(str(e))
        error_code = utils.u32_unpack(buf)
        if error_code != errors.OK:
            msg = fields.get('message')
            if msg is not None:
                logging.info('Request error: %s, %s',
                             errors.message(error_code), msg)
            else:
                logging.info('Request error: %s', errors.message(error_code))
        proxy.stored_read(64) # Ignore value
        self.client_buf.write(proxy.stored_data())

    def __forward_reply_payload(self):
        '''Read and forward reply payload, including related metadata.'''
        buf = self.server_buf.read(utils.u64_size)
        self.reply_payload_size = utils.u64_unpack(buf)
        self.__handler.forward_reply_payload(self)
        buf = self.server_buf.read(64)
        self.client_buf.write(buf)

    def __terminate_client_connection(self):
        '''Correctly terminate the client's connection.'''
        # Closing the socket should technically be enough, but make sure the
        # client is not waiting for more input...
        self.client_buf.send_outer_eof()
        # ... because we need to wait until client closes the connection.  The
        # client might have already shut down the write end of the connection,
        # sending a TLS close_notify alert.  If we don't read this alert and
        # close() the client connection, the kernel may send a RST, and the
        # client would discard data sent by the bridge even if the client
        # wanted to read them.  See
        # http://blog.netherlabs.nl/articles/2009/01/18/ \
        # the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable for
        # detailed discussion.
        #
        # Therefore: read from the client, expecting an EOF.  If the client has
        # already shut the connection down, this will read the close_notify
        # alert, preventing the kernel form sending a RST immediately.  If the
        # client has not shut the conection, this will wait until the client
        # processes the data we sent and exits, closing the connection.
        #
        # Note that the server->bridge connection does not have the same
        # problem because the bridge first processes all data from the server,
        # (then it sends it to the client and closes connection to the client)
        # and only then does the brige close the socket to the server, sending
        # a TLS close_notify - in fact the server often closes the connection
        # and starts waiting for the next one long before the bridge is done
        # with it.
        try:
            self.client_buf.read(1)
        except EOFError:
            pass

    def __finalize(self):
        '''Drop per-connection state.'''
        if self.__handler is not None:
            self.__handler.close()

def bridge_one_request(config, server_listen_sock, client_listen_sock):
    '''Forward one request and reply.'''

    try:
        client_sock = None
        logging.debug('Waiting for the server to connect')
        (server_sock, _) = server_listen_sock.accept()
        # FIXME? authenticate the server
        try:
            logging.debug('Waiting for the client to connect')
            (client_sock, _) = client_listen_sock.accept()
            try:
                BridgeConnection.handle_connection(config, client_sock,
                                                   server_sock)
            finally:
                client_sock.close()
        finally:
            server_sock.close()
    except InvalidRequestError as e:
        logging.warning('Invalid request: %s', str(e))
    except InvalidReplyError as e:
        logging.warning('Invalid reply: %s', str(e))
    except ForwardingError as e:
        logging.warning('Error working with request data: %s', str(e))
    except IOError as e:
        logging.info('I/O error: %s', repr(e))
    except EOFError as e:
        logging.info('Unexpected EOF: %s', repr(e))
    except nss.error.NSPRError as e:
        if e.errno == nss.error.SEC_ERROR_EXPIRED_CERTIFICATE:
            logging.warning("Peer's certificate has expired, rejecting "
                            "connection")
        else:
            logging.info('NSPR I/O error: %s', str(e), exc_info=True)
    except BridgeError as e:
        logging.warning(str(e))
    logging.debug('Request handling finished')

def main():
    options = utils.get_daemon_options('A signing server bridge',
                                       '~/.sigul/bridge.conf')
    utils.setup_logging(options, 'bridge')
    try:
        config = BridgeConfiguration(options.config_file)
    except utils.ConfigurationError as e:
        sys.exit(str(e))

    if options.daemonize:
        utils.daemonize()

    signal.signal(signal.SIGTERM, utils.sigterm_handler)
    utils.create_pid_file(options, 'sigul_bridge')

    utils.set_regid(config)
    if config.daemon_uid is not None:
        try:
            # Keep real UID unchanged to be able to restore EUID and remove the
            # PID file
            os.seteuid(config.daemon_uid)
            utils.update_HOME_for_uid(config)
            # Ugly hack: FAS uses $HOME at time of import
            fedora.client.baseclient.SESSION_DIR = \
                os.path.expanduser('~/.fedora')
            fedora.client.baseclient.SESSION_FILE = \
                os.path.join(fedora.client.baseclient.SESSION_DIR,
                             '.fedora_session')
        except:
            logging.error('Error switching to user %d: %s', config.daemon_uid,
                          sys.exc_info()[1])
            sys.exit(1)

    try:
        try:
            try:
                utils.nss_init(config)
            except utils.NSSInitError as e:
                logging.error(str(e))
                sys.exit(1)
            try:
                server_listen_sock = \
                    create_listen_sock(config, config.server_listen_port)
                client_listen_sock = \
                    create_listen_sock(config, config.client_listen_port)
            except nss.error.NSPRError as e:
                logging.error('NSPR error: {0!s}'.format(str(e)))
                sys.exit(1)
            except BridgeError as e:
                logging.error(str(e))
                sys.exit(1)

            while True:
                # This loop can unfortunately not be interrupted using SIGINT,
                # see https://bugzilla.redhat.com/show_bug.cgi?id=707382 for
                # an explanation.
                bridge_one_request(config, server_listen_sock,
                                   client_listen_sock)
        except (KeyboardInterrupt, SystemExit):
            pass # Silence is golden
        except:
            logging.error('Unexpected exception', exc_info=True)
            sys.exit(1)
    finally:
        if config.daemon_uid is not None:
            os.seteuid(os.getuid())
        utils.delete_pid_file(options, 'sigul_bridge')

if __name__ == '__main__':
    main()
