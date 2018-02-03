from __future__ import print_function, unicode_literals
import errno
import logging
import signal
import socket
import string
import sys

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from message import (
    Message, ResourceRecord, Domain, typeNameToValue, Response,
    NXDomainResponse, FormErrResponse, ServFailResponse, NotImpResponse,
)


def valid_domain_name(name, allow_wildcard=True):
    ld = string.ascii_letters + string.digits
    ldh = ld + '-'
    if isinstance(name, str):
        name = name.split('.')
    if allow_wildcard and name and name[0] in ('*', '**'):
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
        for addr in addrs.split('\n'):
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
        for addr in addrs.split('\n'):
            try:
                socket.inet_pton(socket.AF_INET6, addr)
            except socket.error:
                raise ValueError('invalid IPv6 address %r' % addr)
            records.append((name, addr))
    return records


BIND_IP = '127.0.0.1'
BIND_PORT = 5354
RETRIES = 2


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
        wildcard = t.get('**')
        for i, label in enumerate(reversed(name)):
            if '**' in t:
                wildcard = t['**']
            if label not in t:
                break
            t = t[label]
        else:  # found node
            if '.' not in t:  # have records *under* it, but nothing *here*
                return ()
            else:  # exact match
                return tuple(
                    ResourceRecord(name, typeNameToValue[rrtype], 1, 300, data)
                    for rrtype, data in t['.'])
        if '*' in t and i + 1 == len(name):
            return tuple(
                ResourceRecord(name, typeNameToValue[rrtype], 1, 300, data)
                for rrtype, data in t['*']['.'])
        elif wildcard:
            return tuple(
                ResourceRecord(name, typeNameToValue[rrtype], 1, 300, data)
                for rrtype, data in wildcard['.'])
        else:
            return None


class Server(object):
    def __init__(self, conf_file):
        self.conf_file = conf_file
        self.running = False
        self.db = None
        self.reload()

    def handle(self, req):
        logging.debug('Received request %r', req)
        if req.op_code_name != 'Query' or len(req.questions) != 1:
            return NotImpResponse(req)
        q = req.questions[0]
        if q.qclass_name != 'IN' or q.qtype_name not in ('A', 'AAAA', 'CNAME'):
            return NotImpResponse(req)
        if not valid_domain_name(req.questions[0].name):
            return FormErrResponse(req)

        rrs = self.db.lookup(req.questions[0].name)

        if rrs is not None:
            # Maybe this belongs in lookup?
            cnames = [rr for rr in rrs if rr.rrtype_name == 'CNAME']
            for cname in cnames:
                more_rrs = self.db.lookup(cname.data)
                if more_rrs:
                    rrs += more_rrs
            return Response(req, answers=tuple(
                rr for rr in rrs
                if q.qtype == rr.rrtype or rr.rrtype_name in ('CNAME', 'TXT')))

        return NXDomainResponse(req)

    def run(self):
        self.running = True
        try:
            signal.signal(signal.SIGTERM, self.shutdown)
            signal.signal(signal.SIGINT, self.shutdown)
            signal.signal(signal.SIGHUP, self.reload)
        except ValueError:
            pass  # Non-main thread, probably
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((BIND_IP, BIND_PORT))
        s.settimeout(0.05)
        logging.info('Listening on udp://[%s]:%d' % (BIND_IP, BIND_PORT))
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
            request = Message.from_wire(data)
            try:
                response = self.handle(request)
            except Exception:
                logging.exception('Error handling request %r', request)
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
        s.close()

    def shutdown(self, signum=None, frame=None):
        self.running = False

    def reload(self, signum=None, frame=None):
        if not self.db:
            logging.debug('Loading config from %s', self.conf_file)
        else:
            logging.debug('Reloading config from %s', self.conf_file)
        parser = configparser.RawConfigParser()
        parser.read(self.conf_file)
        try:
            new_db = {
                'CNAME': load_cname_records(parser),
                'A': load_a_records(parser),
                'AAAA': load_aaaa_records(parser),
            }
        except Exception as e:
            logging.error('Error loading db: %s', e)
            if not self.db:
                raise
        else:
            logging.debug('Loaded db %r', new_db)
            self.db = RRDB(new_db)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        logging.error('Expected at least one argument: conf_file')
        exit(1)
    Server(sys.argv[1]).run()
