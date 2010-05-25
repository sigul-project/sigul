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

import base64
import binascii
import errors
import logging
import os
import signal
import sys
import tempfile

try:
    import fedora.client
    have_fas = True
except:
    have_fas = False
import nss.error
import nss.io
import nss.nss
import nss.ssl
import urlgrabber.grabber

import double_tls
import settings
import utils

 # Infrastructure

class BridgeError(Exception):
    pass

class BridgeConfiguration(utils.DaemonIDConfiguration, utils.NSSConfiguration,
                          utils.Configuration):

    default_config_file = 'bridge.conf'

    def _add_defaults(self, defaults):
        super(BridgeConfiguration, self)._add_defaults(defaults)
        defaults.update({'bridge-cert-nickname': 'sigul-bridge-cert',
                         'client-listen-port': 44334,
                         'required-fas-group': '',
                         'server-listen-port': 44333})
        # Override NSSConfiguration default
        defaults.update({'nss-dir': settings.default_server_nss_path})

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
        self.server_listen_port = parser.getint('bridge', 'server-listen-port')

def create_listen_sock(config, port):
    sock = nss.ssl.SSLSocket()
    # FIXME? does this belong in a finished product?
    sock.set_socket_option(nss.io.PR_SockOpt_Reuseaddr, True)
    sock.set_ssl_option(nss.ssl.SSL_REQUEST_CERTIFICATE, True)
    sock.set_ssl_option(nss.ssl.SSL_REQUIRE_CERTIFICATE, True)
    try:
        cert = nss.nss.find_cert_from_nickname(config.bridge_cert_nickname)
    except nss.error.NSPRError, e:
        if e.errno == nss.error.SEC_ERROR_BAD_DATABASE:
            raise BridgeError('Certificate \'%s\' is not available' %
                              config.bridge_cert_nickname)
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

def urlgrabber_open(url):
    '''Open url.

    Return (file, file size).  Raise ForwardingError.

    '''
    fd = urlgrabber.grabber.urlopen(url)
    try:
        try:
            size = fd.size # urlgrabber using pycurl
        except AttributeError:
            try:
                size = int(fd.hdr['Content-Length']) # Older urlgrabber
            except KeyError:
                raise ForwardingError('Content-Length not returned for %s' %
                                      url)
    except:
        fd.close()
        raise
    return (fd, size)

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

 # Request verification

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
            raise InvalidRequestError('Required field %s missing' % self.name)

class StringField(Field):
    '''A string field.'''

    def validate(self, value):
        super(StringField, self).validate(value)
        if value is not None and not utils.string_is_safe(value):
            raise InvalidRequestError('Field %s is not printable' % self.name)

class BoolField(Field):
    '''A bool field.'''

    def validate(self, value):
        super(BoolField, self).validate(value)
        if value is not None and (len(value) != utils.u32_size or
                                  utils.u32_unpack(value) not in (0, 1)):
            raise InvalidRequestError('Field %s is not a boolean' % self.name)

class YYYYMMDDField(Field):
    '''A date field, using the yyyy-mm-dd format.'''

    def validate(self, value):
        super(YYYYMMDDField, self).validate(value)
        if value is not None and not utils.yyyy_mm_dd_is_valid(value):
            raise InvalidRequestError('Field %s is not a valid date' %
                                      self.name)

class RequestType(object):
    '''A supported request type.'''

    def __init__(self, fields, max_payload=0):
        self.__fields = fields + (StringField('user'), StringField('op'))
        self.__known_fields = set()
        for f in self.__fields:
            self.__known_fields.add(f.name)
        self.__max_payload = max_payload

    def validate(self, fields, payload_size):
        '''Validate fields.'''
        for key in fields.iterkeys():
            if key not in self.__known_fields:
                raise InvalidRequestError('Unexpected field %s' % repr(key))
        for f in self.__fields:
            f.validate(fields.get(f.name))
        if payload_size > self.__max_payload:
            raise InvalidRequestError('Payload too large')

    def forward_request_payload(self, server_buf, client_buf, payload_size,
                                unused_fields):
        '''Forward (optionally modify) payload from client_buf to server_buf.'''
        server_buf.write(utils.u32_pack(payload_size))
        copy_file_data(server_buf, client_buf, payload_size)

    def forward_reply_payload(self, client_buf, server_buf, payload_size):
        '''Forward (optionally modify) payload from server_buf to client_buf.'''
        client_buf.write(utils.u32_pack(payload_size))
        copy_file_data(client_buf, server_buf, payload_size)

    def close(self):
        '''Deinitialize any costly state.'''
        pass

class KojiClient(object):
    '''Utilities for working with koji.

    The client will create only one koji session, reusing it for all requests.

    '''
    def __init__(self, request_fields):
        '''Initialize, using request_fields for user identification.'''
        self.__koji_session = None
        self.__koji_config = None
        self.__request_fields = request_fields

    def __get_session(self):
        '''Return a koji session, creating it if necessary.

        Also make sure self.__koji_config is set up.  Raise ForwardingError.

        '''
        # Don't import koji before opening sockets!  The rpm Python module
        # calls NSS_NoDB_Init() during its initialization, which breaks our
        # attempts to initialize nss with our certificate database.
        import koji

        if self.__koji_config is None:
            self.__koji_config = utils.koji_read_config()
        if self.__koji_session is None:
            try:
                if settings.koji_do_proxy_auth:
                    user = self.__request_fields.get('user')
                    StringField('user').validate(user)
                    self.__koji_session = utils.koji_connect \
                        (self.__koji_config, authenticate=True, proxyuser=user)
                else:
                    self.__koji_session = utils.koji_connect(self.__koji_config,
                                                             authenticate=True)
            except (utils.KojiError, koji.GenericError), e:
                raise ForwardingError('Koji connection failed: %s' % str(e))
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
        except (utils.KojiError, koji.GenericError), e:
            raise ForwardingError('Koji connection failed: %s' % str(e))
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
        except (utils.KojiError, koji.GenericError), e:
            raise ForwardingError('Koji connection failed: %s' % str(e))
        return '/'.join((self.__koji_config['pkgurl'], build['package_name'],
                         build['version'], build['release'],
                         koji.pathinfo.rpm(rpm_info)))

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
        except (utils.KojiError, koji.GenericError), e:
            # FIXME: restore
            # raise ForwardingError('Koji connection failed: %s' % str(e))
            logging.warning('Koji error: %s' % str(e))

    def close(self):
        '''Disconnect from koji.'''
        if self.__koji_session is not None:
            utils.koji_disconnect(self.__koji_session)
            self.__koji_session = None

class SignRPMRequestType(RequestType):
    '''A specialized handler for the 'sign-rpm' request.'''

    def __init__(self, *args, **kwargs):
        super(SignRPMRequestType, self).__init__(*args, **kwargs)
        self.__request_fields = None
        self.__koji_client = None
        self.__rpm = None

    def forward_request_payload(self, server_buf, client_buf, payload_size,
                                fields):
        '''Forward (optionally modify) payload from client_buf to server_buf.'''
        self.__request_fields = fields
        self.__koji_client = KojiClient(fields)
        self.__rpm = RPMObject(fields, None, payload_size)
        if payload_size != 0:
            return super(SignRPMRequestType, self). \
                forward_request_payload(server_buf, client_buf, payload_size,
                                        fields)

        self.__rpm.compute_payload_url(self.__koji_client)
        (src, payload_size) = urlgrabber_open(self.__rpm.request_payload_url)
        try:
            server_buf.write(utils.u32_pack(payload_size))
            copy_file_data(server_buf, src, payload_size)
        finally:
            src.close()

    def forward_reply_payload(self, client_buf, server_buf, payload_size):
        # Zero-length response should happen only on error.
        if (payload_size != 0 and
            self.__request_fields.get('import-signature') == utils.u32_pack(1)):
            (fd, self.__rpm.tmp_path) = tempfile.mkstemp(text=False)
            try:
                tmp_file = os.fdopen(fd, 'w+')
                try:
                    copy_file_data(tmp_file, server_buf, payload_size)
                finally:
                    tmp_file.close()

                self.__rpm.add_signature_to_koji(self.__koji_client)

                if (self.__request_fields.get('return-data') ==
                    utils.u32_pack(0)):
                    client_buf.write(utils.u32_pack(0))
                else:
                    client_buf.write(utils.u32_pack(payload_size))
                    tmp_file = open(self.__rpm.tmp_path, 'rb')
                    try:
                        copy_file_data(client_buf, tmp_file, payload_size)
                    finally:
                        tmp_file.close()
            finally:
                self.__rpm.remove_tmp_path()
        elif self.__request_fields.get('return-data') != utils.u32_pack(0):
            super(SignRPMRequestType, self).forward_reply_payload(client_buf,
                                                                  server_buf,
                                                                  payload_size)
        else:
            client_buf.write(utils.u32_pack(0))

    def close(self):
        super(SignRPMRequestType, self).close()
        self.__request_fields = None
        if self.__koji_client is not None:
            self.__koji_client.close()
            self.__koji_client = None
        self.__rpm = None

RT = RequestType
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
    'revoke-key-access': RT((SF('key'), SF('name'))),
    'get-public-key': RT((SF('key'),)),
    'change-passphrase': RT((SF('key'),)),
    'sign-text': RT((SF('key'),), max_payload=1024*1024*1024),
    'sign-data': RT((SF('key'),), max_payload=1024*1024*1024),
    'sign-rpm': SignRPMRequestType((SF('key'), SF('rpm-name', optional=True),
                                    SF('rpm-epoch', optional=True),
                                    SF('rpm-version', optional=True),
                                    SF('rpm-release', optional=True),
                                    SF('rpm-arch', optional=True),
                                    Field('rpm-sigmd5', optional=True),
                                    BoolField('import-signature',
                                              optional=True),
                                    BoolField('return-data', optional=True),
                                    BoolField('v3-signature', optional=True)),
                                   max_payload=1024*1024*1024),
    }
del RT

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

def handle_connection(client_buf, server_buf):
    '''Handle a single connection.'''
    # FIXME: handle server's reporting of unknown protocol version - there
    # is no inner session
    client_proxy = StoringProxy(client_buf)
    buf = client_proxy.stored_read(utils.u32_size)
    client_version = utils.u32_unpack(buf)
    if client_version != utils.protocol_version:
        raise InvalidRequestError('Unknown protocol version %d' %
                                  client_version)
    try:
        fields = utils.read_fields(client_proxy.stored_read)
    except utils.InvalidFieldsError, e:
        raise InvalidRequestError(str(e))
    buf = client_buf.read(utils.u32_size)
    payload_size = utils.u32_unpack(buf)

    logging.info('Request: %s', utils.readable_fields(fields))
    try:
        op = fields['op']
    except KeyError:
        raise InvalidRequestError('op field missing')
    try:
        rt = request_types[op]
    except KeyError:
        raise InvalidRequestError('Unknown op value')

    try:
        rt.validate(fields, payload_size)
        server_buf.write(client_proxy.stored_data())
        rt.forward_request_payload(server_buf, client_buf, payload_size, fields)

        double_tls.bridge_inner_stream(client_buf, server_buf)

        server_proxy = StoringProxy(server_buf)
        buf = server_proxy.stored_read(utils.u32_size)
        try:
            fields = utils.read_fields(server_proxy.stored_read)
        except utils.InvalidFieldsError, e:
            raise InvalidReplyError(str(e))
        error_code = utils.u32_unpack(buf)
        if error_code != errors.OK:
            msg = fields.get('message')
            if msg is not None:
                logging.info('Request error: %s, %s',
                             errors.message(error_code), msg)
            else:
                logging.info('Request error: %s', errors.message(error_code))
        # print repr(fields)
        server_proxy.stored_read(64) # Ignore value
        client_buf.write(server_proxy.stored_data())

        buf = server_buf.read(utils.u32_size)
        payload_size = utils.u32_unpack(buf)
        rt.forward_reply_payload(client_buf, server_buf, payload_size)
        buf = server_buf.read(64)
        client_buf.write(buf)

        # Closing the socket should technically be enough, but make sure the
        # client is not waiting for more input...
        client_buf.send_outer_eof()
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
        try:
            client_buf.read(1)
        except EOFError:
            pass

    finally:
        rt.close()


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
            fedora.client.FedoraServiceError), e:
        raise BridgeError('Error communicating with FAS: %s' % str(e))

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

            client_sock.force_handshake()
            cert = client_sock.get_peer_certificate()
            assert cert is not None
            user_name = cert.subject_common_name
            logging.info('Client with CN %s connected', repr(user_name))
            if (config.required_fas_group is not None and
                not fas_user_is_in_group(config, user_name,
                                         config.required_fas_group)):
                raise InvalidRequestError('User %s not allowed to connect'
                                          % repr(user_name))

            client_buf = double_tls.OuterBuffer(client_sock)
            server_buf = double_tls.OuterBuffer(server_sock)

            handle_connection(client_buf, server_buf)
        finally:
            if client_sock is not None:
                client_sock.close()
                server_sock.close()
    except InvalidRequestError, e:
        logging.warning('Invalid request: %s', str(e))
    except InvalidReplyError, e:
        logging.warning('Invalid reply: %s', str(e))
    except ForwardingError, e:
        logging.warning('Error working with request data: %s', str(e))
    except IOError, e:
        logging.info('I/O error: %s', repr(e))
    except EOFError, e:
        logging.info('Unexpected EOF: %s', repr(e))
    except nss.error.NSPRError, e:
        logging.info('NSPR I/O error: %s', str(e))
    except BridgeError, e:
        logging.warning(str(e))
    logging.debug('Request handling finished')

def main():
    options = utils.get_daemon_options('A signing server bridge',
                                       '~/.sigul/bridge.conf')
    d = {}
    if settings.log_dir is not None:
        d['filename'] = os.path.join(settings.log_dir, 'sigul_bridge.log')
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                        level=utils.logging_level_from_options(options), **d)
    try:
        config = BridgeConfiguration(options.config_file)
    except utils.ConfigurationError, e:
        sys.exit(str(e))

    if options.daemonize:
        utils.daemonize()

    signal.signal(signal.SIGTERM, utils.sigterm_handler)
    utils.create_pid_file('sigul_bridge')

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
            except utils.NSSInitError, e:
                logging.error(str(e))
                sys.exit(1)
            try:
                server_listen_sock = \
                    create_listen_sock(config, config.server_listen_port)
                client_listen_sock = \
                    create_listen_sock(config, config.client_listen_port)
            except nss.error.NSPRError, e:
                logging.error('NSPR error: %s' % str(e))
                sys.exit(1)
            except BridgeError, e:
                logging.error(str(e))
                sys.exit(1)

            while True:
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
        utils.delete_pid_file('sigul_bridge')

if __name__ == '__main__':
    main()
