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
    Message, ResourceRecord, rcodeNameToValue, typeNameToValue,
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
    for name, cname in parser.items('cname'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        if not valid_domain_name(cname, allow_wildcard=False):
            raise ValueError('invalid canonical name %r' % cname)
        records.append((name, cname.split('.')))
    return records


def load_a_records(parser):
    records = []
    for name, addr in parser.items('ipv4'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        try:
            socket.inet_pton(socket.AF_INET, addr)
        except socket.error:
            raise ValueError('invalid IPv4 address %r' % addr)
        records.append((name, addr))
    return records


def load_aaaa_records(parser):
    records = []
    for name, addr in parser.items('ipv6'):
        if not valid_domain_name(name):
            raise ValueError('invalid domain name %r' % name)
        try:
            socket.inet_pton(socket.AF_INET6, addr)
        except socket.error:
            raise ValueError('invalid IPv6 address %r' % addr)
        records.append((name, addr))
    return records


BIND_IP = '127.0.0.1'
BIND_PORT = 5354


def NotImpResponse(req):
    return Message(
        b'', req.id, is_response=True, op_code=req.op_code,
        is_authoritative=False,
        is_truncated=False,  # TODO: when is this supposed to be true?
        recursion_desired=False, recursion_available=False,
        reserved=0,
        authentic_data=False, checking_disabled=False,
        response_code=rcodeNameToValue['NotImp'],
        questions=req.questions,
        answers=(), name_servers=(), additional_records=(),
    )


def ServFailResponse(req):
    return Message(
        b'', req.id, is_response=True, op_code=req.op_code,
        is_authoritative=False,
        is_truncated=False,  # TODO: when is this supposed to be true?
        recursion_desired=False, recursion_available=False,
        reserved=0,
        authentic_data=False, checking_disabled=False,
        response_code=rcodeNameToValue['ServFail'],
        questions=req.questions,
        answers=(), name_servers=(), additional_records=(),
    )


def FormErrResponse(req):
    return Message(
        b'', req.id, is_response=True, op_code=req.op_code,
        is_authoritative=False,
        is_truncated=False,  # TODO: when is this supposed to be true?
        recursion_desired=False, recursion_available=False,
        reserved=0,
        authentic_data=False, checking_disabled=False,
        response_code=rcodeNameToValue['FormErr'],
        questions=req.questions,
        answers=(), name_servers=(), additional_records=(),
    )


def Response(req, answers):
    return Message(
        b'', req.id, is_response=True, op_code=req.op_code,
        is_authoritative=False,
        is_truncated=False,  # TODO: when is this supposed to be true?
        recursion_desired=False, recursion_available=False,
        reserved=0,
        authentic_data=False, checking_disabled=False,
        response_code=rcodeNameToValue['NoError'],
        questions=req.questions,
        answers=answers, name_servers=(), additional_records=(),
    )


def CNAMEResponse(req, cname):
    return Response(req, (
        ResourceRecord(req.questions[0].name, 5, 1, 300, cname),
    ))


def NXDOMAINResponse(req):
    return Message(
        b'', req.id, is_response=True, op_code=req.op_code,
        is_authoritative=False,
        is_truncated=False,  # TODO: when is this supposed to be true?
        recursion_desired=False, recursion_available=False,
        reserved=0,
        authentic_data=False, checking_disabled=False,
        response_code=rcodeNameToValue['NXDomain'],
        questions=req.questions,
        answers=(), name_servers=(), additional_records=(),
    )


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
        self.reload(None, None)

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
            # TODO: if any rr is a CNAME, follow and look for A or AAAA
            # records, too -- or maybe that belongs in lookup?
            return Response(req, tuple(
                rr for rr in rrs
                if q.qtype == rr.rrtype or rr.rrtype_name in ('CNAME', 'TXT')))

        return NXDOMAINResponse(req)

    def run(self):
        self.running = True
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGHUP, self.reload)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((BIND_IP, BIND_PORT))
        logging.info('Listening on udp://[%s]:%d' % (BIND_IP, BIND_PORT))
        while self.running:
            request = None
            try:
                data, addr = s.recvfrom(1024)
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
                s.sendto(response.to_wire(), addr)
            # else, no response warranted
        s.close()

    def shutdown(self, signum, frame):
        self.running = False

    def reload(self, signum, frame):
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
