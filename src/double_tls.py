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

import logging
import os
import socket

import nss.error
import nss.io
import nss.ssl

import utils

# A helper for debug prints
__next_id = 0
__ids = {}
def _id(obj):
    global __next_id, __ids
    try:
        return __ids[obj]
    except KeyError:
        counter = __next_id
        __next_id += 1
        new_id = ''
        while True:
            new_id = chr(ord('A') + counter % 26) + new_id
            counter /= 26
            if counter == 0:
                break
        __ids[obj] = new_id
        return new_id

# _debug_file = None
# _debug_pid = None
def _debug(fmt, *args):
    # global _debug_pid, _debug_file
    # pid = os.getpid()
    # if _debug_pid != pid:
    #     _debug_pid = pid
    #     _debug_file = open('/tmp/debug%d' % os.getpid(), 'w', 0)
    # print >> _debug_file, fmt % args
    pass

class ChildConnectionRefusedError(Exception):
    '''Child could not connect.'''
    pass

class ChildUnrecoverableError(Exception):
    '''We don't know how to recover from an error in the child.'''
    pass

class InnerCertificateNotFound(Exception):
    '''inner_open_* certificate was not found.'''
    pass

def _nspr_poll(descs, timeout):
    '''Poll for descs.

    descs is a dictionary of {nss.io.Socket: flags}.  On return, flags are
    updated with poll results.

    '''
    # FIXME: implement this in nss-python instead?
    flat = descs.items()
    res = nss.io.Socket.poll(flat, timeout)
    for (i, desc) in enumerate(flat):
        descs[desc[0]] = res[i]

def _tcp_socketpair():
    '''Like socket.socketpair(), but using AF_INET sockets.

    This is necessary because NSS uses getsockname() to create session
    identifiers and it does not support AF_UNIX sockets created by
    socket.socketpair().'''

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                           socket.IPPROTO_TCP)
    server.bind(('', 0))
    server.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                           socket.IPPROTO_TCP)
    client.connect(server.getsockname())
    (server2, _) = server.accept()
    server.close()
    return (client, server2)

_POLL_PROBLEM = nss.io.PR_POLL_ERR | nss.io.PR_POLL_HUP

_chunk_inner_mask = 1 << 31

class _ForwardingBuffer(object):
    '''A buffer that can be used for forwarding data between sockets.'''

    _BUFFER_LEN = 4096

    @property
    def _active(self):
        '''True if some work is still possible.'''
        raise NotImplementedError

    def _prepare_poll(self, poll_descs):
        '''Update the poll_descs dictionary.

        Must add something to watch if self._active is True.

        '''
        raise NotImplementedError

    def _handle_errors(self, poll_descs):
        '''Handle errors reported in poll_descs.'''
        # Only consider the input an error if PR_POLL_READ is not set, to give
        # self._receive() chance to handle pending data, if any.  We'll see the
        # error state in self._receive(), or in the next iteration.
        raise NotImplementedError

    def _send(self, poll_descs):
        '''Send buffered data, if necessary and possible.'''
        raise NotImplementedError

    def _receive(self, poll_descs):
        '''Receive data to buffer, if necessary and possible.'''
        # Ignore PR_POLL_ERR and PR_POLL_HUP in implementations: It is possible
        # to get e.g. PR_POLL_IN | PR_POLL_HUP on a closed socket if data is
        # still pending.  Instead, make sure to handle
        # nss.error.PR_CONNECT_RESET_ERROR gracefully.
        raise NotImplementedError

    def _check_shutdown(self):
        '''Shutdown self.__dst if necessary.'''
        raise NotImplementedError

    @staticmethod
    def forward_two_way(buf_1, buf_2):
        '''Forward data in parallel using buf_1 and buf_2.

        Stop when neither is active.

        '''
        # The poll loop is simply two unidirectional forwarding poll loops
        # combined into one.
        while buf_1._active or buf_2._active:
            poll_descs = {}
            buf_1._prepare_poll(poll_descs)
            buf_2._prepare_poll(poll_descs)

            _debug('Poll: %s',
                   ', '.join(['{0!s}:{1!s}'.format(_id(o), v)
                              for (o, v) in poll_descs.iteritems()]))
            _nspr_poll(poll_descs, nss.io.PR_INTERVAL_NO_TIMEOUT)
            _debug('-> %s', ', '.join(['{0!s}:{1!s}'.format(_id(o), v)
                                       for (o, v) in poll_descs.iteritems()]))

            # Handle I/O errors.
            buf_1._handle_errors(poll_descs)
            buf_2._handle_errors(poll_descs)
            # Send data.  First send, then receive - assuming the buffer is
            # completelly filled by a receive, sending first allows forwarding
            # BUFFER_LEN bytes in one iteration; receiving first would require
            # two iterations per BUFFER_LEN bytes.
            buf_1._send(poll_descs)
            buf_2._send(poll_descs)
            # Receive data.
            buf_1._receive(poll_descs)
            buf_2._receive(poll_descs)
            # Shut down the sending ends on EOF
            buf_1._check_shutdown()
            buf_2._check_shutdown()


class _CombiningBuffer(_ForwardingBuffer):
    '''A buffer that combines data from an inner and outer stream.'''

    def __init__(self, inner_src, outer_src, dst):
        super(_CombiningBuffer, self).__init__()
        self.__inner_src = inner_src
        self.__outer_src = outer_src
        self.__dst = dst
        self.__buffer = ''
        self.__buffer_dropped = False
        self.__inner_src_open = True
        self.__outer_src_open = True
        self.__dst_shut_down = False
        self.__receive_inner_first = True

    @property
    def _active(self):
        _debug('b%s active: inner open:%s, outer open:%s, len:%s', _id(self),
               self.__inner_src_open, self.__outer_src_open, len(self.__buffer))
        return (self.__inner_src_open or self.__outer_src_open or
                len(self.__buffer) > 0)

    def _prepare_poll(self, poll_descs):
        _debug('b%s poll: inner open:%s, outer open:%s, len:%s', _id(self),
               self.__inner_src_open, self.__outer_src_open, len(self.__buffer))
        if len(self.__buffer) + utils.u32_size < self._BUFFER_LEN:
            if self.__inner_src_open:
                _debug(' => read inner %s', _id(self.__inner_src))
                poll_descs[self.__inner_src] = \
                    poll_descs.get(self.__inner_src, 0) | nss.io.PR_POLL_READ
            if self.__outer_src_open:
                _debug(' => read outer %s', _id(self.__outer_src))
                poll_descs[self.__outer_src] = \
                    poll_descs.get(self.__outer_src, 0) | nss.io.PR_POLL_READ
        if len(self.__buffer) > 0:
            _debug(' => write %s', _id(self.__dst))
            poll_descs[self.__dst] = (poll_descs.get(self.__dst, 0) |
                                      nss.io.PR_POLL_WRITE)

    def _handle_errors(self, poll_descs):
        v = poll_descs.get(self.__inner_src, 0)
        if (v & _POLL_PROBLEM) != 0 and (v & nss.io.PR_POLL_READ) == 0:
            if self.__inner_src_open:
                _debug('b%s: inner src %s problem, adding EOF', _id(self),
                       _id(self.__inner_src))
                self.__inner_src_open = False
                # Append the EOF even if the buffer is too large - this can only
                # happen once per source.
                self.__buffer += utils.u32_pack(_chunk_inner_mask)
            else:
                _debug('b%s: inner src %s problem after EOF, ignoring',
                       _id(self), _id(self.__inner_src))
        v = poll_descs.get(self.__outer_src, 0)
        if (v & _POLL_PROBLEM) != 0 and (v & nss.io.PR_POLL_READ) == 0:
            if self.__outer_src_open:
                _debug('b%s: outer src %s problem, adding EOF', _id(self),
                       _id(self.__outer_src))
                self.__outer_src_open = False
                # Append the EOF even if the buffer is too large - this can only
                # happen once per source.
                self.__buffer += utils.u32_pack(0)
            else:
                _debug('b%s: outer src %s problem after EOF, ignoring',
                       _id(self), _id(self.__outer_src))
        if (poll_descs.get(self.__dst, 0) & _POLL_PROBLEM) != 0:
            _debug('b%s: dst %s problem', _id(self), _id(self.__dst))
            if len(self.__buffer) > 0:
                if not self.__buffer_dropped:
                    self.__buffer_dropped = True
                    logging.debug('_CombiningBuffer: data dropped')
                self.__buffer = ''

    def _send(self, poll_descs):
        if (poll_descs.get(self.__dst, 0) &
            (nss.io.PR_POLL_WRITE | _POLL_PROBLEM)) == nss.io.PR_POLL_WRITE:
            _debug('b%s: sending to %s: %d', _id(self), _id(self.__dst),
                   len(self.__buffer))
            sent = self.__dst.send(self.__buffer)
            self.__buffer = self.__buffer[sent:]
            _debug('=> %d', sent)

    def __receive_inner(self, poll_descs):
        '''Receive data from self.__inner_src if necessary and possible.

        Return True if something was received.

        '''
        if (poll_descs.get(self.__inner_src, 0) & nss.io.PR_POLL_READ) == 0:
            return False
        assert len(self.__buffer) + utils.u32_size < self._BUFFER_LEN
        _debug('b%s: reading inner %s: %d', _id(self), _id(self.__inner_src),
               self._BUFFER_LEN - len(self.__buffer))
        try:
            data = self.__inner_src.recv(self._BUFFER_LEN - len(self.__buffer))
        except nss.error.NSPRError as e:
            if e.errno == nss.error.PR_CONNECT_RESET_ERROR:
                _debug('...!exception, closing src: %s', repr(e))
                data = ''
            elif e.errno == nss.error.PR_WOULD_BLOCK_ERROR:
                _debug('...!would block: %s', repr(e))
                return False
            else:
                raise
        _debug('=> %d', len(data))
        # This automatically sends EOF if len(data) == 0
        assert len(data) < _chunk_inner_mask
        self.__buffer += utils.u32_pack(_chunk_inner_mask | len(data))
        self.__buffer += data
        if len(data) == 0:
            _debug('... was inner EOF')
            self.__inner_src_open = False
        return True

    def __receive_outer(self, poll_descs):
        '''Receive data from self.__outer_src if necessary and possible.

        Return True if something was received.

        '''
        if (poll_descs.get(self.__outer_src, 0) & nss.io.PR_POLL_READ) == 0:
            return False
        _debug('b%s: reading outer %s: %d', _id(self), _id(self.__outer_src),
               self._BUFFER_LEN - len(self.__buffer))
        assert len(self.__buffer) + utils.u32_size < self._BUFFER_LEN
        try:
            data = self.__outer_src.recv(self._BUFFER_LEN - len(self.__buffer))
        except nss.error.NSPRError as e:
            if e.errno == nss.error.PR_CONNECT_RESET_ERROR:
                _debug('...!exception, closing src: %s', repr(e))
                data = ''
            elif e.errno == nss.error.PR_WOULD_BLOCK_ERROR:
                _debug('...!would block: %s', repr(e))
                return False
            else:
                raise
        _debug('=> %d', len(data))
        # This automatically sends EOF if len(data) == 0
        assert len(data) < _chunk_inner_mask
        self.__buffer += utils.u32_pack(len(data))
        self.__buffer += data
        if len(data) == 0:
            _debug('... was outer EOF')
            self.__outer_src_open = False
        return True

    def _receive(self, poll_descs):
        r2 = False
        # Alternate between sources to make sure no data gets starved.
        # Short-time reordering (if data is available from sources) is
        # acceptable, hanging the protocol is not.
        if self.__receive_inner_first:
            r1 = self.__receive_inner(poll_descs)
            if len(self.__buffer) + utils.u32_size < self._BUFFER_LEN:
                r2 = self.__receive_outer(poll_descs)
        else:
            r1 = self.__receive_outer(poll_descs)
            if len(self.__buffer) + utils.u32_size < self._BUFFER_LEN:
                r2 = self.__receive_inner(poll_descs)
        if r1 or r2:
            self.__receive_inner_first = not self.__receive_inner_first

    def _check_shutdown(self):
        '''Shutdown self.__dst if necessary.'''
        if not self._active:
            _debug('b%s: inactive, shut down: %s', _id(self),
                   self.__dst_shut_down)
            if not self.__dst_shut_down:
                try:
                    _debug('... shutting down %s', _id(self.__dst))
                    self.__dst.shutdown(nss.io.PR_SHUTDOWN_SEND)
                except nss.error.NSPRError as e:
                    # The other side might have closed the socket before us
                    if e.errno != nss.error.PR_NOT_CONNECTED_ERROR:
                        raise
                self.__dst_shut_down = True

class _SplittingBuffer(_ForwardingBuffer):
    '''A buffer that splits data into an inner and outer stream.'''

    def __init__(self, src, inner_dst, outer_dst):
        super(_SplittingBuffer, self).__init__()
        self.__src = src
        self.__inner_dst = inner_dst
        self.__outer_dst = outer_dst
        self.__inner_bytes_left = 0
        self.__outer_bytes_left = 0
        self.__header_buffer = ''
        self.__inner_buffer = ''
        self.__outer_buffer = ''
        self.__inner_buffer_dropped = False
        self.__outer_buffer_dropped = False
        self.__src_open = True
        self.__got_inner_eof = False
        self.__got_outer_eof = False
        self.__inner_dst_shut_down = False
        self.__outer_dst_shut_down = False

    @property
    def _active(self):
        _debug('b%s active: open:%s, inner:%s/%s, outer: %s/%s', _id(self),
               self.__src_open, self.__got_inner_eof, len(self.__inner_buffer),
               self.__got_outer_eof, len(self.__outer_buffer))
        return ((self.__src_open and
                 not (self.__got_inner_eof and self.__got_outer_eof)) or
                len(self.__inner_buffer) > 0 or len(self.__outer_buffer) > 0)

    def _prepare_poll(self, poll_descs):
        _debug('b%s poll: open:%s, inner:%s, outer: %s', _id(self),
               self.__src_open, len(self.__inner_buffer),
               len(self.__outer_buffer))
        if (self.__src_open and
            (max(len(self.__inner_buffer), len(self.__outer_buffer)) <
             self._BUFFER_LEN)):
            _debug(' => read %s', _id(self.__src))
            poll_descs[self.__src] = (poll_descs.get(self.__src, 0) |
                                      nss.io.PR_POLL_READ)
        if len(self.__inner_buffer) > 0:
            _debug(' => write inner %s', _id(self.__inner_dst))
            poll_descs[self.__inner_dst] = \
                poll_descs.get(self.__inner_dst, 0) | nss.io.PR_POLL_WRITE
        if len(self.__outer_buffer) > 0:
            _debug(' => write outer %s', _id(self.__outer_dst))
            poll_descs[self.__outer_dst] = \
                poll_descs.get(self.__outer_dst, 0) | nss.io.PR_POLL_WRITE

    def _handle_errors(self, poll_descs):
        v = poll_descs.get(self.__src, 0)
        if (v & _POLL_PROBLEM) != 0 and (v & nss.io.PR_POLL_READ) == 0:
            _debug('b%s: src %s problem', _id(self), _id(self.__src))
            self.__src_open = False
        if (poll_descs.get(self.__inner_dst, 0) & _POLL_PROBLEM) != 0:
            _debug('b%s: inner dst %s problem', _id(self),
                   _id(self.__inner_dst))
            if len(self.__inner_buffer) > 0:
                if not self.__inner_buffer_dropped:
                    self.__inner_buffer_dropped = True
                    logging.debug('_SplittingBuffer: inner data dropped')
                self.__inner_buffer = ''
        if (poll_descs.get(self.__outer_dst, 0) & _POLL_PROBLEM) != 0:
            _debug('b%s: outer dst %s problem', _id(self),
                   _id(self.__outer_dst))
            if len(self.__outer_buffer) > 0:
                if not self.__outer_buffer_dropped:
                    self.__outer_buffer_dropped = True
                    logging.debug('_SplittingBuffer: outer data dropped')
                self.__outer_buffer = ''

    def _send(self, poll_descs):
        if (poll_descs.get(self.__inner_dst, 0) &
            (nss.io.PR_POLL_WRITE | _POLL_PROBLEM)) == nss.io.PR_POLL_WRITE:
            _debug('b%s: sending inner %s: %d', _id(self),
                   _id(self.__inner_dst), len(self.__inner_buffer))
            sent = self.__inner_dst.send(self.__inner_buffer)
            self.__inner_buffer = self.__inner_buffer[sent:]
            _debug('=> %d', sent)
        if (poll_descs.get(self.__outer_dst, 0) &
            (nss.io.PR_POLL_WRITE | _POLL_PROBLEM)) == nss.io.PR_POLL_WRITE:
            _debug('b%s: sending outer %s: %d', _id(self),
                   _id(self.__outer_dst), len(self.__outer_buffer))
            sent = self.__outer_dst.send(self.__outer_buffer)
            self.__outer_buffer = self.__outer_buffer[sent:]
            _debug('=> %d', sent)

    def _receive(self, poll_descs):
        if (poll_descs.get(self.__src, 0) & nss.io.PR_POLL_READ) == 0:
            return
        left = (self._BUFFER_LEN -
                max(len(self.__inner_buffer), len(self.__outer_buffer)))
        assert left > 0
        try:
            _debug('b%s: reading from %s: %d', _id(self), _id(self.__src), left)
            data = self.__src.recv(left)
        except nss.error.NSPRError as e:
            if e.errno == nss.error.PR_CONNECT_RESET_ERROR:
                _debug('...!exception, closing src: %s', repr(e))
                data = ''
            elif e.errno == nss.error.PR_WOULD_BLOCK_ERROR:
                _debug('...!would block: %s', repr(e))
                return
            else:
                raise
        _debug('=> %s', len(data))
        if len(data) == 0:
            _debug('...!eof, closing src')
            self.__src_open = False
        while len(data) > 0:
            if self.__inner_bytes_left != 0:
                run = min(self.__inner_bytes_left, len(data))
                self.__inner_buffer += data[:run]
                self.__inner_bytes_left -= run
                data = data[run:]
                _debug('... stored %d inner', run)
            if self.__outer_bytes_left != 0:
                run = min(self.__outer_bytes_left, len(data))
                self.__outer_buffer += data[:run]
                self.__outer_bytes_left -= run
                data = data[run:]
                _debug('... stored %d outer', run)
            if self.__inner_bytes_left == 0 and self.__outer_bytes_left == 0:
                run = min(utils.u32_size - len(self.__header_buffer), len(data))
                self.__header_buffer += data[:run]
                data = data[run:]
                _debug('... consumed %d header', run)
                assert len(self.__header_buffer) <= utils.u32_size
                if len(self.__header_buffer) == utils.u32_size:
                    v = utils.u32_unpack(self.__header_buffer)
                    self.__header_buffer = ''
                    _debug('... header: %08x', v)
                    if (v & _chunk_inner_mask) != 0:
                        self.__inner_bytes_left = v & ~_chunk_inner_mask
                        if self.__inner_bytes_left == 0:
                            _debug('... got inner EOF')
                            self.__got_inner_eof = True
                    else:
                        self.__outer_bytes_left = v
                        if self.__outer_bytes_left == 0:
                            _debug('... got outer EOF')
                            self.__got_outer_eof = True

    def _check_shutdown(self):
        _debug('b%s: shutdown: src:%s, inner:%s/%s, outer: %s/%s', _id(self),
               self.__src_open, self.__got_inner_eof, len(self.__inner_buffer),
               self.__got_outer_eof, len(self.__outer_buffer))
        if (((not self.__src_open) or self.__got_inner_eof) and
            len(self.__inner_buffer) == 0):
            _debug('...inner inactive, shut down: %s',
                   self.__inner_dst_shut_down)
            if not self.__inner_dst_shut_down:
                try:
                    _debug('...shutting down inner')
                    self.__inner_dst.shutdown(nss.io.PR_SHUTDOWN_SEND)
                except nss.error.NSPRError as e:
                    # The other side might have closed the socket before us
                    if e.errno != nss.error.PR_NOT_CONNECTED_ERROR:
                        raise
                self.__inner_dst_shut_down = True
        if (((not self.__src_open) or self.__got_outer_eof) and
            len(self.__outer_buffer) == 0):
            _debug('...outer inactive, shut down: %s',
                   self.__outer_dst_shut_down)
            if not self.__outer_dst_shut_down:
                try:
                    _debug('...shutting down outer')
                    self.__outer_dst.shutdown(nss.io.PR_SHUTDOWN_SEND)
                except nss.error.NSPRError as e:
                    # The other side might have closed the socket before us
                    if e.errno != nss.error.PR_NOT_CONNECTED_ERROR:
                        raise
                self.__outer_dst_shut_down = True

class DoubleTLSClient(object):
    '''A client "socket" that allows creating a nested TLS session.

    Its users can communicate alternately using the outer and inner TLS
    channel.

    '''

    __connection_refused_exit_code = 43 # universe and everything... +1!
    __unrecoverable_error_exit_code = 44

    def __init__(self, config, hostname, port, cert_nickname):
        '''Prepare for implementing the nested TLS session.

        Must be called before initializing NSS.

        '''
        self.__config = config
        self.__hostname = hostname
        self.__port = port
        self.__cert_nickname = cert_nickname
        self.peercert = None
        # The connection between child and parent is called a "pipe" although
        # it is a pair of sockets.  "socket" is the network socket used for
        # the outer TLS session.
        (parent_inner_pipe, child_inner_pipe) = _tcp_socketpair()
        (parent_outer_pipe, child_outer_pipe) = _tcp_socketpair()
        self.__child_pid = os.fork()
        if self.__child_pid == 0:
            parent_inner_pipe.close()
            parent_outer_pipe.close()
            try:
                self.__child(child_inner_pipe, child_outer_pipe)
            finally:
                try:
                    logging.shutdown()
                finally:
                    os._exit(127)
        child_inner_pipe.close()
        child_outer_pipe.close()
        self.__inner_pipe = parent_inner_pipe
        self.__outer_pipe = parent_outer_pipe
        self.__inner = None

    def outer_read(self, buf_size):
        '''Read exactly buf_size bytes from the outer TLS session.

        The inner TLS session must not be active.  Raise EOFError.

        '''
        return self.__recv_exact(self.__outer_pipe, buf_size)

    def outer_write(self, data):
        '''Write data to the outer TLS session.

        The inner TLS session must not be active.  This function handles short
        writes.

        '''
        self.__outer_pipe.sendall(data)

    def outer_shutdown(self, flags):
        '''Shut down the outer TLS session.'''
        self.__outer_pipe.shutdown(flags)

    def inner_read(self, buf_size):
        '''Read up to buf_size bytes from the inner TLS session.

        The inner TLS session must be active.

        '''
        return self.__recv_exact(self.__inner, buf_size)

    def inner_write(self, data):
        '''Write data to the inner TLS session.

        The inner TLS session must be active.  This function handles short
        writes.

        '''
        self.__inner.send(data)

    def inner_open_client(self, hostname, cert_nickname):
        '''Open the inner TLS session as a client.

        Raise InnerCertificateNotFound.

        '''
        fd = os.dup(self.__inner_pipe.fileno())
        try:
            self.__inner = nss.ssl.SSLSocket.import_tcp_socket(fd)
        except:
            os.close(fd)
            raise
        try:
            self.__inner.set_ssl_option(nss.ssl.SSL_REQUEST_CERTIFICATE, True)
            self.__inner.set_ssl_option(nss.ssl.SSL_REQUIRE_CERTIFICATE, True)
            try:
                cert = nss.nss.find_cert_from_nickname(cert_nickname)
            except nss.error.NSPRError as e:
                if e.errno == nss.error.SEC_ERROR_BAD_DATABASE:
                    raise InnerCertificateNotFound('Certificate \'%s\' is not '
                                                   'available' % cert_nickname)
                raise
            self.__inner.set_client_auth_data_callback \
                (utils.nss_client_auth_callback_single, cert)
            self.__inner.set_hostname(hostname)
            self.__inner.reset_handshake(False)
            self.__inner.force_handshake()
        except:
            self.__inner.close()
            self.__inner = None
            raise

    def inner_open_server(self, cert_nickname):
        '''Open the inner TLS session as a server.

        Raise InnerCertificateNotFound.

        '''
        fd = os.dup(self.__inner_pipe.fileno())
        try:
            self.__inner = nss.ssl.SSLSocket.import_tcp_socket(fd)
        except:
            os.close(fd)
            raise
        try:
            self.__inner.set_ssl_option(nss.ssl.SSL_REQUEST_CERTIFICATE, True)
            self.__inner.set_ssl_option(nss.ssl.SSL_REQUIRE_CERTIFICATE, True)
            try:
                cert = nss.nss.find_cert_from_nickname(cert_nickname)
            except nss.error.NSPRError as e:
                if e.errno == nss.error.SEC_ERROR_BAD_DATABASE:
                    raise InnerCertificateNotFound('Certificate \'%s\' is not '
                                                   'available' % cert_nickname)
                raise
            self.__inner.config_secure_server(cert, nss.nss.
                                              find_key_by_any_cert(cert),
                                              cert.find_kea_type())
            self.__inner.reset_handshake(True)
            self.__inner.force_handshake()
            self.peercert = self.__inner.get_peer_certificate()
            assert self.peercert is not None
            logging.info('Connection from {0!s}'.format(repr(self.peercert.subject)))
        except:
            self.__inner.close()
            self.__inner = None
            raise

    def inner_close(self):
        '''Close the inner TLS session.'''
        if self.__inner is not None:
            # self.__inner was created using
            # os.dup(self.__inner_pipe.fileno()), so self.__inner_pipe is still
            # usable.
            self.__inner.close()
        self.__inner_pipe.close()
        # Close notify may yet come on self.__inner_pipe, just ignore it.

    def outer_close(self):
        '''Close the outer TLS session.

        The inner TLS session should be closed.  Raise
        ChildConnectionRefusedError.

        '''
        self.__inner_pipe.close()
        self.__outer_pipe.close()
        (_, status) = os.waitpid(self.__child_pid, 0)
        if status != 0:
            logging.debug('Child exited with status %d', status)
        if os.WIFEXITED(status):
            if os.WEXITSTATUS(status) == self.__connection_refused_exit_code:
                raise ChildConnectionRefusedError()
            if os.WEXITSTATUS(status) == self.__unrecoverable_error_exit_code:
                raise ChildUnrecoverableError()

    @staticmethod
    def __recv_exact(socket, buf_size):
        '''Return exactly buf_size bytes of data from socket.

        Raise EOFError.

        '''
        res = ''
        while len(res) < buf_size:
            run = socket.recv(buf_size - len(res))
            if len(run) == 0:
                raise EOFError
            res += run
        return res

    def __child(self, child_inner_pipe, child_outer_pipe):
        '''Forward the inner and outer pipes.

        End using os._exit().

        '''
        try:
            # Yuck, handlers is private...
            fmt = logging.Formatter('%(asctime)s %(levelname)s: (child) '
                                    '%(message)s')
            logging.getLogger().handlers[0].setFormatter(fmt)

            inner_pipe_fd = nss.io.Socket.import_tcp_socket(child_inner_pipe.
                                                            fileno())
            outer_pipe_fd = nss.io.Socket.import_tcp_socket(child_outer_pipe.
                                                            fileno())
            utils.nss_init(self.__config) # May raise utils.NSSInitError
            socket_fd = nss.ssl.SSLSocket(nss.io.PR_AF_INET)
            socket_fd.set_ssl_option(nss.ssl.SSL_REQUEST_CERTIFICATE, True)
            socket_fd.set_ssl_option(nss.ssl.SSL_REQUIRE_CERTIFICATE, True)
            try:
                cert = nss.nss.find_cert_from_nickname(self.__cert_nickname)
            except nss.error.NSPRError as e:
                if e.errno == nss.error.SEC_ERROR_BAD_DATABASE:
                    raise utils.NSSInitError('Certificate \'%s\' is not '
                                             'available' % self.__cert_nickname)
                raise
            socket_fd.set_client_auth_data_callback \
                (utils.nss_client_auth_callback_single, cert)
            socket_fd.set_hostname(self.__hostname)
            addr_info = nss.io.AddrInfo(self.__hostname, nss.io.PR_AF_INET,
                                        nss.io.PR_AI_ADDRCONFIG)
            first_error = None
            for net_addr in addr_info:
                net_addr.port = self.__port
                try:
                    socket_fd.connect(net_addr)
                except Exception as e:
                    if first_error is None:
                        first_error = e
            if first_error is not None:
                if (isinstance(first_error, nss.error.NSPRError) and
                    first_error.errno == nss.error.PR_CONNECT_RESET_ERROR):
                    raise ChildConnectionRefusedError()
                raise first_error
            socket_fd.force_handshake()

            inner_pipe_fd.set_socket_option(nss.io.PR_SockOpt_Nonblocking, True)
            outer_pipe_fd.set_socket_option(nss.io.PR_SockOpt_Nonblocking, True)
            socket_fd.set_socket_option(nss.io.PR_SockOpt_Nonblocking, True)
            buf_1 = _CombiningBuffer(inner_pipe_fd, outer_pipe_fd, socket_fd)
            buf_2 = _SplittingBuffer(socket_fd, inner_pipe_fd, outer_pipe_fd)
            _ForwardingBuffer.forward_two_way(buf_1, buf_2)
            inner_pipe_fd.close()
            outer_pipe_fd.close()
            socket_fd.close()

            logging.shutdown()
            os._exit(0)
        except ChildConnectionRefusedError:
            logging.debug('Connection refused')
            logging.shutdown()
            os._exit(self.__connection_refused_exit_code)
        except nss.error.NSPRError as e:
            if e.errno == nss.error.PR_CONNECT_RESET_ERROR:
                logging.debug('NSPR error: Connection reset')
            elif e.errno == nss.error.SSL_ERROR_EXPIRED_CERT_ALERT:
                logging.error('Our certificate has been rejected as expired')
                logging.shutdown()
                os._exit(self.__unrecoverable_error_exit_code)
            else:
                logging.warning('Exception in child', exc_info=True)
            logging.shutdown()
            os._exit(1) # Nothing that extraordinary
        except utils.NSSInitError as e:
            logging.error(str(e))
            logging.shutdown()
            os._exit(self.__unrecoverable_error_exit_code)
        except (KeyboardInterrupt, SystemExit):
            # No error message
            logging.shutdown()
            os._exit(self.__unrecoverable_error_exit_code)
        except:
            logging.warning('Exception in child', exc_info=True)
            logging.shutdown()
            os._exit(self.__unrecoverable_error_exit_code)

class OuterBuffer(object):

    '''A buffer allowing access to the outer stream of a _DoubleTLS socket.'''

    def __init__(self, socket):
        self.__socket = socket
        self.__inner_packets = ''
        self.__outer_data = ''

    @property
    def socket(self):
        '''The socket used by this buffer.'''
        return self.__socket

    def __recv_exact(self, buf_size):
        '''Return exactly buf_size bytes of data from self.socket.

        Raise EOFError.

        '''
        res = ''
        while len(res) < buf_size:
            run = self.__socket.recv(buf_size - len(res))
            if len(run) == 0:
                raise EOFError, 'Unexpected EOF on _DoubleTLS'
            res += run
        return res

    def read(self, buf_size):
        '''Return exactly buf_size bytes from the outer packet.

        Raise EOFError on EOF.

        '''
        res = ''
        while len(res) < buf_size:
            run = min(buf_size - len(res), len(self.__outer_data))
            _debug('o%s: consuming %d outer data bytes', _id(self), run)
            res += self.__outer_data[:run]
            self.__outer_data = self.__outer_data[run:]
            if len(res) == buf_size:
                break
            assert len(self.__outer_data) == 0
            header = self.__recv_exact(utils.u32_size)
            v = utils.u32_unpack(header)
            _debug('o%s: header %08X', _id(self), v)
            if (v & _chunk_inner_mask) != 0:
                self.__inner_packets += header
                self.__inner_packets += self.__recv_exact(v &
                                                          ~_chunk_inner_mask)
                _debug('o%s: added %d inner bytes, total %d', _id(self),
                       v & ~_chunk_inner_mask, len(self.__inner_packets))
            else:
                if v == 0:
                    raise EOFError, 'Unexpected EOF on outer stream'
                self.__outer_data += self.__recv_exact(v)
                _debug('o%s: received %d outer data bytes', _id(self), v)
        return res

    def write(self, data):
        '''Send data over the outer stream.

        The caller must make sure not to interrupt any pending packet.

        '''
        assert len(data) < _chunk_inner_mask
        _debug('o%s: sending %d bytes', _id(self), len(data))
        self.__socket.send(utils.u32_pack(len(data)))
        self.__socket.send(data)

    def set_full_duplex(self, value):
        '''Set full duplex status of the socket to value.'''
        self.__socket.set_ssl_option(nss.ssl.SSL_ENABLE_FDX, value)

    def send_outer_eof(self):
        '''Send an EOF on the outer stream.'''
        _debug('o%s: sending EOF', _id(self))
        self.__socket.send(utils.u32_pack(0))

    def pending_inner_packets(self):
        '''Return inner stream packets that need handling.

        Repeated calls of this method always return only newly received
        packets.

        '''
        _debug('o%s: %d bytes of pending inner packets returned', _id(self),
               len(self.__inner_packets))
        res = self.__inner_packets
        self.__inner_packets = ''
        return res

    def add_outer_data(self, data):
        '''Add data to be read as coming from the outer stream.'''
        self.__outer_data += data
        _debug('o%s: accepted %d bytes of outer data (total %d)', _id(self),
               len(data), len(self.__outer_data))

class _InnerBridgingBuffer(_ForwardingBuffer):
    '''A buffer that forwards the inner stream, saving outer stream packets.'''

    def __init__(self, src, dst, inner_packets):
        super(_InnerBridgingBuffer, self).__init__()
        self.__src = src
        self.__dst = dst
        self.__inner_bytes_left = 0
        self.__outer_bytes_left = 0
        self.__header_buffer = ''
        self.__buffer = inner_packets
        self.__buffer_dropped = False
        self.__src_open = True # FIXME: closed in inner_packets?
        self.__dst_shut_down = False
        self.__outer_data = ''

    def pending_outer_data(self):
        '''Return outer stream data that needs handling.

        Repeated calls of this method always return only newly received data.
        '''
        res = self.__outer_data
        self.__outer_data = ''
        return res

    @property
    def _active(self):
        _debug('b%s active: open:%s, len:%s', _id(self), self.__src_open,
               len(self.__buffer))
        return self.__src_open or len(self.__buffer) > 0

    def _prepare_poll(self, poll_descs):
        _debug('b%s poll: open:%s, len:%s', _id(self), self.__src_open,
               len(self.__buffer))
        if self.__src_open and len(self.__buffer) < self._BUFFER_LEN:
            _debug(' => read %s', _id(self.__src))
            poll_descs[self.__src] = (poll_descs.get(self.__src, 0) |
                                      nss.io.PR_POLL_READ)
        if len(self.__buffer) > 0:
            _debug(' => write %s', _id(self.__dst))
            poll_descs[self.__dst] = (poll_descs.get(self.__dst, 0) |
                                      nss.io.PR_POLL_WRITE)

    def _handle_errors(self, poll_descs):
        v = poll_descs.get(self.__src, 0)
        if (v & _POLL_PROBLEM) != 0 and (v & nss.io.PR_POLL_READ) == 0:
            _debug('b%s: src %s problem', _id(self), _id(self.__src))
            self.__src_open = False
        if (poll_descs.get(self.__dst, 0) & _POLL_PROBLEM) != 0:
            _debug('b%s: dst %s problem', _id(self), _id(self.__dst))
            if len(self.__buffer) > 0:
                if not self.__buffer_dropped:
                    self.__buffer_dropped = True
                    logging.debug('_InnerBridgingBuffer: data dropped')
                self.__buffer = ''

    def _send(self, poll_descs):
        if (poll_descs.get(self.__dst, 0) &
            (nss.io.PR_POLL_WRITE | _POLL_PROBLEM)) == nss.io.PR_POLL_WRITE:
            _debug('b%s: sending to %s: %d', _id(self), _id(self.__dst),
                   len(self.__buffer))
            sent = self.__dst.send(self.__buffer)
            self.__buffer = self.__buffer[sent:]
            _debug('=> %d', sent)

    def _receive(self, poll_descs):
        if (poll_descs.get(self.__src, 0) & nss.io.PR_POLL_READ) == 0:
            return
        assert len(self.__buffer) < self._BUFFER_LEN
        _debug('b%s: reading from %s: %d', _id(self), _id(self.__src),
               self._BUFFER_LEN - len(self.__buffer))
        try:
            data = self.__src.recv(self._BUFFER_LEN - len(self.__buffer))
        except nss.error.NSPRError as e:
            if e.errno == nss.error.PR_CONNECT_RESET_ERROR:
                _debug('...!exception, closing src: %s', repr(e))
                data = ''
            elif e.errno == nss.error.PR_WOULD_BLOCK_ERROR:
                _debug('...!would block: %s', repr(e))
                return
            else:
                raise
        _debug('=> %d', len(data))
        if len(data) == 0:
            _debug('... closing src')
            self.__src_open = False
        while len(data) > 0:
            if self.__inner_bytes_left != 0:
                run = min(self.__inner_bytes_left, len(data))
                self.__buffer += data[:run]
                self.__inner_bytes_left -= run
                data = data[run:]
                _debug('... stored %d inner', run)
            if self.__outer_bytes_left != 0:
                run = min(self.__outer_bytes_left, len(data))
                self.__outer_data += data[:run]
                self.__outer_bytes_left -= run
                data = data[run:]
                _debug('... deferred %d outer', run)
            if self.__inner_bytes_left == 0 and self.__outer_bytes_left == 0:
                run = min(utils.u32_size - len(self.__header_buffer), len(data))
                self.__header_buffer += data[:run]
                data = data[run:]
                _debug('... consumed %d header', run)
                assert len(self.__header_buffer) <= utils.u32_size
                if len(self.__header_buffer) == utils.u32_size:
                    v = utils.u32_unpack(self.__header_buffer)
                    _debug('... header: %08x', v)
                    if (v & _chunk_inner_mask) != 0:
                        self.__buffer += self.__header_buffer
                        self.__inner_bytes_left = v & ~_chunk_inner_mask
                        if self.__inner_bytes_left == 0:
                            _debug('... got inner EOF')
                            self.__src_open = False
                            # Don't send additional EOF
                            self.__dst_shut_down = True
                    else:
                        self.__outer_bytes_left = v
                    self.__header_buffer = ''

    def _check_shutdown(self):
        if not self._active:
            _debug('b%s: inactive, shut down: %s', _id(self),
                   self.__dst_shut_down)
            if not self.__dst_shut_down:
                _debug('... sending inner EOF')
                self.__buffer += utils.u32_pack(_chunk_inner_mask)
                self.__dst_shut_down = True

def bridge_inner_stream(client_buf, server_buf):
    '''Transfer data between until the inner stream ends.'''
    # FIXME: recover from I/O errors?
    client_fd = client_buf.socket
    server_fd = server_buf.socket

    # The poll loop is simply two unidirectional forwarding poll loops
    # combined into one.
    client_fd.set_socket_option(nss.io.PR_SockOpt_Nonblocking, True)
    server_fd.set_socket_option(nss.io.PR_SockOpt_Nonblocking, True)
    buf_1 = _InnerBridgingBuffer(client_fd, server_fd,
                                 client_buf.pending_inner_packets())
    buf_2 = _InnerBridgingBuffer(server_fd, client_fd,
                                 server_buf.pending_inner_packets())
    _InnerBridgingBuffer.forward_two_way(buf_1, buf_2)
    client_fd.set_socket_option(nss.io.PR_SockOpt_Nonblocking, False)
    server_fd.set_socket_option(nss.io.PR_SockOpt_Nonblocking, False)

    client_buf.add_outer_data(buf_2.pending_outer_data())
    server_buf.add_outer_data(buf_1.pending_outer_data())
