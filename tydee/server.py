from __future__ import print_function, unicode_literals
import errno
import logging
import signal
import socket
import struct
import sys
import threading

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from .message import (
    Message, Request, Response,
    NXDomainResponse, FormErrResponse, ServFailResponse, NotImpResponse,
)
from .util.addr import IPv6Address
from .util.config import RRDB, valid_domain_name


DEFAULT_BIND_IP = '127.0.0.1'
DEFAULT_BIND_PORT = 5354
RETRIES = 2
LOGGER = logging.getLogger('tydee.server')


def recvall(sock, bufsize):
    '''Read bufsize bytes from a socket

    ...or raise a socket error; whichever comes first'''
    buf = []
    sz = 0
    while sz < bufsize:
        buf.append(sock.recv(bufsize - sz))
        sz += len(buf[-1])
        if not buf[-1]:
            raise socket.error(errno.ECONNRESET, 'Incomplete read: %r' % buf)
    return b''.join(buf)


class BaseServer(object):
    def __init__(self, conf_file):
        self.conf_file = conf_file
        self.bind_ip = self.bind_port = None
        self.db = None
        self.running_event = threading.Event()
        self.own_thread = threading.Thread(
            target=self.run,
            name='%s-server-thread' % self.protocol)
        self.own_thread.daemon = True
        self.reload()

    @property
    def protocol(self):
        raise NotImplemented

    @property
    def timeout(self):
        raise NotImplemented

    def handle_data(self, data):
        try:
            request = Message.from_wire(data)
        except (ValueError, struct.error):
            if len(data) < 2:  # not even enough for an id
                return None
            # Create a dummy request that will FormErr
            request = Request(req_id=data[:2])
        try:
            return self.handle(request)
        except Exception:
            LOGGER.exception('Error handling request %r', request)
            return ServFailResponse(request)

    def handle(self, req):
        LOGGER.debug('Received request %r', req)
        if req.op_code_name != 'Query' or len(req.questions) > 1:
            return NotImpResponse(req)
        if not req.questions:
            return FormErrResponse(req)
        q = req.questions[0]
        if q.qclass_name != 'IN' or q.qtype_name not in (
                'A', 'AAAA', 'CNAME', 'TXT', '*'):
            return NotImpResponse(req)
        if not valid_domain_name(req.questions[0].name):
            return FormErrResponse(req)

        rrs = self.db.lookup(req.questions[0].name)

        if rrs is not None:
            # Maybe this belongs in lookup?
            cnames = [rr for rr in rrs if rr.rrtype_name == 'CNAME']
            if cnames and q.qtype_name in ('A', 'AAAA'):
                for cname in cnames:
                    more_rrs = self.db.lookup(cname.data)
                    if more_rrs:
                        rrs += more_rrs
            return Response(req, answers=tuple(
                rr for rr in rrs
                if q.qtype_name == '*' or q.qtype == rr.rrtype
                or (q.qtype_name in ('A', 'AAAA') and
                    rr.rrtype_name == 'CNAME')))

        return NXDomainResponse(req)

    def start(self):
        self.own_thread.start()
        if not self.running_event.wait(0.1):
            raise RuntimeError('Server failed to start after 0.1s')

    def is_alive(self):
        self.own_thread.join(0.01)
        return self.own_thread.is_alive()

    def shutdown(self, signum=None, frame=None):
        self.running_event.clear()
        self.own_thread.join(0.1)
        if self.own_thread.is_alive():
            raise RuntimeError('Server failed to stop after 0.1s')

    def reload(self):
        if not self.db:
            LOGGER.debug('Loading config from %s (%s)',
                         self.conf_file, self.protocol)
        else:
            LOGGER.debug('Reloading config from %s (%s)',
                         self.conf_file, self.protocol)
        parser = configparser.RawConfigParser()
        try:
            if sys.version_info >= (3,):
                parser.read(self.conf_file, encoding='latin1')
            else:
                parser.read(self.conf_file)
        except configparser.MissingSectionHeaderError:
            raise ValueError

        try:
            bind_ip = parser.get('dns-server', 'bind_ip')
        except (configparser.NoSectionError, configparser.NoOptionError):
            bind_ip = DEFAULT_BIND_IP
        try:
            socket.inet_pton(
                socket.AF_INET6 if ':' in bind_ip else socket.AF_INET, bind_ip)
        except socket.error:
            raise ValueError

        try:
            bind_port = parser.getint('dns-server', 'bind_port')
        except (configparser.NoSectionError, configparser.NoOptionError):
            bind_port = DEFAULT_BIND_PORT

        if self.db:
            if bind_ip != self.bind_ip:
                LOGGER.warning('bind_ip changed from %s to %s; restart '
                               'required', self.bind_ip, bind_ip)
            if bind_port and bind_port != self.bind_port:
                LOGGER.warning('bind_port changed from %s to %s; restart '
                               'required', self.bind_port, bind_port)
        else:
            self.bind_ip = bind_ip
            self.bind_port = bind_port

        try:
            new_db = RRDB.from_parser(parser)
        except Exception as e:
            LOGGER.error('Error loading db: %s', e)
            if not self.db:
                raise
        else:
            self.db = new_db


class UDPServer(BaseServer):
    protocol = 'udp'
    timeout = 0.05

    def run(self):
        if ':' in self.bind_ip:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            if IPv6Address(self.bind_ip) == IPv6Address('::'):
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((self.bind_ip, self.bind_port))
        s.settimeout(self.timeout)
        self.bind_ip, self.bind_port = s.getsockname()[:2]
        self.running_event.set()
        LOGGER.info('Listening on udp://[%s]:%d',
                    self.bind_ip, self.bind_port)

        # Done with setup, let's handle requests
        while self.running_event.is_set():
            try:
                data, addr = s.recvfrom(1024)
            except socket.timeout:
                continue
            except socket.error as e:
                if errno.errorcode[e.errno] == 'EINTR':
                    continue
                raise

            response = self.handle_data(data)

            if response:
                for _ in range(RETRIES):
                    try:
                        s.sendto(response.to_wire(), addr)
                    except socket.timeout:
                        continue
                    else:
                        break
            # else, no response warranted
        s.close()


class TCPServer(BaseServer):
    protocol = 'tcp'
    timeout = 0.1

    def run(self):
        if ':' in self.bind_ip:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            if IPv6Address(self.bind_ip) == IPv6Address('::'):
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.bind_ip, self.bind_port))
        s.settimeout(0.05)
        s.listen(1)
        self.bind_ip, self.bind_port = s.getsockname()[:2]
        self.running_event.set()
        LOGGER.info('Listening on tcp://[%s]:%d',
                    self.bind_ip, self.bind_port)

        # Done with setup, let's handle requests
        while self.running_event.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            conn.settimeout(self.timeout)
            LOGGER.debug('Accepted connection from %r', addr)

            while True:
                try:
                    sz = recvall(conn, 2)
                    sz = struct.unpack('!H', sz)[0]
                except (socket.timeout, socket.error):
                    break

                if sz < 2:
                    break
                try:
                    req_id = recvall(conn, 2)
                except (socket.timeout, socket.error):
                    break

                try:
                    data = recvall(conn, sz - 2)
                except (socket.timeout, socket.error):
                    response = FormErrResponse(Request(req_id=req_id))
                    response = response.to_wire()
                    try:
                        conn.sendall(struct.pack('!H', len(response)))
                        conn.sendall(response)
                    except socket.error as e:
                        pass  # best effort
                    break

                response = self.handle_data(req_id + data)
                LOGGER.debug('Sending response %r', response)
                response = response.to_wire()
                try:
                    conn.sendall(struct.pack('!H', len(response)))
                    conn.sendall(response)
                except (socket.timeout, socket.error):
                    break
            LOGGER.debug('Closing connection to %r', addr)
            conn.close()
        s.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        LOGGER.error('Expected at least one argument: conf_file')
        exit(1)
    servers = [
        UDPServer(sys.argv[1]),
        TCPServer(sys.argv[1]),
    ]

    def shutdown(signum=None, frame=None):
        for server in servers:
            server.shutdown()

    def reload(signum=None, frame=None):
        for server in servers:
            try:
                server.reload()
            except Exception as err:
                LOGGER.exception('Failed to reload config: %s', err)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGHUP, reload)

    for server in servers:
        server.start()
    while any(server.is_alive() for server in servers):
        # Note that thread.join() is not interrupted for signal handling!
        # Since we only expect thread live-ness to change as a result of
        # SIGTERM/SIGINT, wait for at least one signal before checking
        # thread statuses.
        signal.pause()
