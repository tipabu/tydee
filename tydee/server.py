from __future__ import print_function, unicode_literals
import errno
import logging
import signal
import socket
import string
import struct
import sys
import threading

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from .message import (
    Message, ResourceRecord, Domain, Request, Response,
    NXDomainResponse, FormErrResponse, ServFailResponse, NotImpResponse,
)


def valid_domain_name(name, allow_wildcard=True):
    ld = string.ascii_letters + string.digits
    ldh = ld + '-'
    if isinstance(name, bytes):
        try:
            name = name.decode('ascii')
        except UnicodeDecodeError:
            return False
    if isinstance(name, type('')):  # go-go unicode literals!
        name = name.split('.')
    if allow_wildcard and name and name[0] == '*':
        name = name[1:]
    return all(
        label and all(c in ldh for c in label) and
        label[0] in string.ascii_letters and label[-1] in ld
        for label in name)


def load_cname_records(parser):
    records = []
    if not parser.has_section('cname'):
        return records
    for name, cname in parser.items('cname'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        if not valid_domain_name(cname, allow_wildcard=False):
            raise ValueError('invalid canonical name %r' % cname)
        records.append((name, Domain(cname)))
    return records


def load_a_records(parser):
    records = []
    if not parser.has_section('ipv4'):
        return records
    for name, addrs in parser.items('ipv4'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        for addr in addrs.strip().split('\n'):
            try:
                socket.inet_pton(socket.AF_INET, addr)
            except socket.error:
                raise ValueError('invalid IPv4 address %r' % addr)
            records.append((name, addr))
    return records


def load_aaaa_records(parser):
    records = []
    if not parser.has_section('ipv6'):
        return records
    for name, addrs in parser.items('ipv6'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        for addr in addrs.strip().split('\n'):
            try:
                socket.inet_pton(socket.AF_INET6, addr)
            except socket.error:
                raise ValueError('invalid IPv6 address %r' % addr)
            records.append((name, addr))
    return records


def load_txt_records(parser):
    records = []
    if not parser.has_section('txt'):
        return records
    for name, txt in parser.items('txt'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        if not isinstance(txt, bytes):
            txt = txt.encode('latin1')
        records.extend((name, (x,)) for x in txt.strip().split(b'\n'))
    return records


DEFAULT_BIND_IP = '127.0.0.1'
DEFAULT_BIND_PORT = 5354
RETRIES = 2
LOGGER = logging.getLogger('tydee.server')


class RRDB(object):
    def __init__(self, data=None):
        self.tree = {}
        if data:
            for rr_type, entries in data.items():
                for name, data in entries:
                    t = self.tree
                    for label in reversed(name.split('.')):
                        t = t.setdefault(label, {})
                    # TODO: maybe make these proper ResourceRecords?
                    t.setdefault('.', []).append((rr_type, data))

    def lookup(self, name):
        t = self.tree
        wildcard = t.get('*')
        for i, label in enumerate(reversed(name)):
            if '*' in t:
                wildcard = t['*']
            if label not in t:
                break
            t = t[label]
        else:  # found node
            if '.' not in t:  # have records *under* it, but nothing *here*
                return ()
            else:  # exact match
                return tuple(
                    ResourceRecord(name, rrtype, 'IN', 300, data)
                    for rrtype, data in t['.'])
        if wildcard:
            return tuple(
                ResourceRecord(name, rrtype, 'IN', 300, data)
                for rrtype, data in wildcard['.'])
        else:
            return None


class Server(object):
    def __init__(self, conf_file):
        self.conf_file = conf_file
        self.bind_ip = self.bind_port = None
        self.running = False
        self.db = None
        self.bound_event = threading.Event()
        self.reload()

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

    def run(self):
        self.running = True
        try:
            signal.signal(signal.SIGTERM, self.shutdown)
            signal.signal(signal.SIGINT, self.shutdown)
            signal.signal(signal.SIGHUP, self.reload)
        except ValueError:
            pass  # Non-main thread, probably
        if ':' in self.bind_ip:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((self.bind_ip, self.bind_port))
        s.settimeout(0.05)
        self.bind_ip, self.bind_port = s.getsockname()[:2]
        self.bound_event.set()
        LOGGER.info('Listening on udp://[%s]:%d',
                    self.bind_ip, self.bind_port)

        # Done with setup, let's handle requests
        while self.running:
            request = None
            try:
                data, addr = s.recvfrom(1024)
            except socket.timeout:
                continue
            except socket.error as e:
                if errno.errorcode[e.errno] == 'EINTR':
                    continue
                raise
            try:
                request = Message.from_wire(data)
            except (ValueError, struct.error):
                if len(data) < 2:  # not even enough for an id
                    continue
                # Create a dummy request that will FormErr
                request = Request(req_id=data[:2])
            try:
                response = self.handle(request)
            except Exception:
                LOGGER.exception('Error handling request %r', request)
                response = ServFailResponse(request)
            if response:
                for x in range(RETRIES):
                    try:
                        s.sendto(response.to_wire(), addr)
                    except socket.timeout:
                        continue
                    else:
                        break
            # else, no response warranted
        self.bound_event.clear()
        s.close()

    def shutdown(self, signum=None, frame=None):
        self.running = False

    def reload(self, signum=None, frame=None):
        if not self.db:
            LOGGER.debug('Loading config from %s', self.conf_file)
        else:
            LOGGER.debug('Reloading config from %s', self.conf_file)
        parser = configparser.RawConfigParser()
        if sys.version_info >= (3,):
            parser.read(self.conf_file, encoding='latin1')
        else:
            parser.read(self.conf_file)

        try:
            bind_ip = parser.get('dns-server', 'bind_ip')
        except (configparser.NoSectionError, configparser.NoOptionError):
            bind_ip = DEFAULT_BIND_IP
        try:
            bind_port = parser.getint('dns-server', 'bind_port')
        except (configparser.NoSectionError, configparser.NoOptionError):
            bind_port = DEFAULT_BIND_PORT

        try:
            new_db = {
                'CNAME': load_cname_records(parser),
                'A': load_a_records(parser),
                'AAAA': load_aaaa_records(parser),
                'TXT': load_txt_records(parser),
            }
        except Exception as e:
            LOGGER.error('Error loading db: %s', e)
            if not self.db:
                raise
        else:
            LOGGER.debug('Loaded db %r', new_db)
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
            self.db = RRDB(new_db)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        LOGGER.error('Expected at least one argument: conf_file')
        exit(1)
    Server(sys.argv[1]).run()
