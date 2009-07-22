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

class ForwardingError(Exception):
    '''An error was detected while forwarding or modifying the communication.'''
    pass

def copy_data(dest, src, bytes):
    '''Copy bytes bytes from file-like src to file-like dst.'''
    while bytes > 0:
        data = src.read(min(bytes, 4096))
        dest.write(data)
        bytes -= len(data)

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
        copy_data(server_buf, client_buf, payload_size)

    def forward_reply_payload(self, client_buf, server_buf, payload_size):
        '''Forward (optionally modify) payload from server_buf to client_buf.'''
        client_buf.write(utils.u32_pack(payload_size))
        copy_data(client_buf, server_buf, payload_size)

    def close(self):
        '''Deinitialize any costly state.'''
        pass


class SignRpmRequestType(RequestType):
    '''A specialized handler for the 'sign-rpm' request.'''

    def __init__(self, *args, **kwargs):
        super(SignRpmRequestType, self).__init__(*args, **kwargs)
        self.__koji_session = None
        self.__koji_rpm_info = None
        self.__rpm = None

    def forward_request_payload(self, server_buf, client_buf, payload_size,
                                fields):
        '''Forward (optionally modify) payload from client_buf to server_buf.'''
        # Don't import koji before opening sockets!  The rpm Python module
        # calls NSS_NoDB_Init() during its initialization, which breaks our
        # attempts to initialize nss with our certificate database.
        import koji

        self.__request_fields = fields
        if payload_size != 0:
            return super(SignRpmRequestType, self). \
                forward_request_payload(server_buf, client_buf, payload_size,
                                        fields)
        session = self.__koji_get_session()
        rpm = self.__koji_get_rpm_info(session)
        try:
            build = session.getBuild(rpm['build_id'])
            if build is None:
                raise ForwardingError('RPM has no build')
        except (utils.KojiError, koji.GenericError), e:
            raise ForwardingError('Koji connection failed: %s' % str(e))
        url = '/'.join((self.__koji_config['pkgurl'], build['package_name'],
                        build['version'], build['release'],
                        koji.pathinfo.rpm(rpm)))

        src = urlgrabber.grabber.urlopen(url)
        try:
            try:
                payload_size = int(src.hdr['Content-Length'])
            except KeyError:
                raise ForwardingError('Content-Length not returned for %s' %
                                      url)
            server_buf.write(utils.u32_pack(payload_size))
            copy_data(server_buf, src, payload_size)
        finally:
            src.close()

    def forward_reply_payload(self, client_buf, server_buf, payload_size):
        # Don't import koji before opening sockets!  The rpm Python module
        # calls NSS_NoDB_Init() during its initialization, which breaks our
        # attempts to initialize nss with our certificate database.
        import koji

        if self.__request_fields.get('import-signature') == utils.u32_pack(1):
            (fd, tmp_path) = tempfile.mkstemp(text=False)
            tmp_file = None
            try:
                tmp_file = os.fdopen(fd, 'w+')
                copy_data(tmp_file, server_buf, payload_size)
                tmp_file.flush()
                header_fields = koji.get_header_fields(tmp_path,
                                                       ('siggpg', 'sigpgp'))
                sigkey = header_fields['siggpg']
                if sigkey is None:
                    sigkey = header_fields['sigpgp']
                    if sigkey is None:
                        raise ForwardingError('Missing signature')
                # FIXME? This is not actually a key ID, but it is what Koji
                # uses.
                sigkey = koji.get_sigpacket_key_id(sigkey)
                sighdr = koji.rip_rpm_sighdr(tmp_path)
                sighdr_digest = binascii.b2a_hex(utils.md5_digest(sighdr))

                session = self.__koji_get_session()
                rpm = self.__koji_get_rpm_info(session)
                try:
                    sigs = session.queryRPMSigs(rpm_id=rpm['id'], sigkey=sigkey)
                    assert len(sigs) <= 1
                    if len(sigs) > 0 and sigs[0]['sighash'] != sighdr_digest:
                        raise ForwardingError('A different signature was '
                                              'already imported')
                    if len(sigs) == 0:
                        session.addRPMSig(rpm['id'],
                                          base64.encodestring(sighdr))
                except (utils.KojiError, koji.GenericError), e:
                    raise ForwardingError('Koji connection failed: %s' % str(e))

                if (self.__request_fields.get('return-data') ==
                    utils.u32_pack(0)):
                    client_buf.write(utils.u32_pack(0))
                else:
                    tmp_file.seek(0)
                    client_buf.write(utils.u32_pack(payload_size))
                    copy_data(client_buf, tmp_file, payload_size)
            finally:
                if tmp_file is not None:
                    tmp_file.close()
                os.remove(tmp_path)
        elif self.__request_fields.get('return-data') != utils.u32_pack(0):
            super(SignRpmRequestType, self).forward_reply_payload(client_buf,
                                                                  server_buf,
                                                                  payload_size)
        else:
            client_buf.write(utils.u32_pack(0))

    def __koji_get_session(self):
        '''Return a koji session, creating it if necessary.

        Also set up self.__koji_config.

        '''
        # Don't import koji before opening sockets!  The rpm Python module
        # calls NSS_NoDB_Init() during its initialization, which breaks our
        # attempts to initialize nss with our certificate database.
        import koji

        if self.__koji_session is None:
            try:
                self.__koji_config = utils.koji_read_config()
                # self.__request_fields['user'] safety was verified by
                # self.validate
                # FIXME FIXME: authenticate should be True, but that needs a
                # koji account that is allowed to use proxyuser
                self.__koji_session = \
                    utils.koji_connect(self.__koji_config,
                                       authenticate=False,
                                       proxyuser=self.__request_fields['user'])
            except (utils.KojiError, koji.GenericError), e:
                raise ForwardingError('Koji connection failed: %s' % str(e))
        return self.__koji_session

    def __koji_get_rpm_info(self, session):
        '''Return information about a rpm specified by self.__request_fields.'''
        # Don't import koji before opening sockets!  The rpm Python module
        # calls NSS_NoDB_Init() during its initialization, which breaks our
        # attempts to initialize nss with our certificate database.
        import koji

        if self.__koji_rpm_info is None:
            try:
                d = {'name': self.__request_fields['rpm-name'],
                     'version': self.__request_fields['rpm-version'],
                     'release': self.__request_fields['rpm-release'],
                     'arch': self.__request_fields['rpm-arch']}
            except KeyError:
                raise InvalidRequestError('Incomplete RPM identification')
            # String safety in d was verified by self.validate
            try:
                self.__koji_rpm_info = session.getRPM(d)
            except (utils.KojiError, koji.GenericError), e:
                raise ForwardingError('Koji connection failed: %s' % str(e))
            if self.__koji_rpm_info is None:
                raise ForwardingError('RPM not found')
        return self.__koji_rpm_info

    def close(self):
        if self.__koji_session is not None:
            utils.koji_disconnect(self.__koji_session)
            self.__koji_session = None

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
    'sign-rpm': SignRpmRequestType((SF('key'), SF('rpm-name', optional=True),
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

    def stored_read(self, bytes):
        '''Read bytes bytes from the buffer and store the result.'''
        data = self.__buf.read(bytes)
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

    s = ', '.join(('%s = %s' % (repr(key), repr(value))
                   for (key, value) in fields.iteritems()))
    logging.info('Request: %s', s)
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
            raise InvalidRequestError(str(e))
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
    finally:
        rt.close()

    buf = server_buf.read(64)
    client_buf.write(buf)

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
