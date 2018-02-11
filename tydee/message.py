from __future__ import print_function, unicode_literals
from collections import namedtuple
import random
import socket
import struct
import sys

try:
    basestring
except NameError:
    basestring = str

typeNameToValue = {
    'A':           1,  # a host address
    'NS':          2,  # an authoritative name server
    'MD':          3,  # a mail destination (Obsolete - use MX)
    'MF':          4,  # a mail forwarder (Obsolete - use MX)
    'CNAME':       5,  # the canonical name for an alias
    'SOA':         6,  # marks the start of a zone of authority
    'MB':          7,  # a mailbox domain name (EXPERIMENTAL)
    'MG':          8,  # a mail group member (EXPERIMENTAL)
    'MR':          9,  # a mail rename domain name (EXPERIMENTAL)
    'NULL':       10,  # a null RR (EXPERIMENTAL)
    'WKS':        11,  # a well known service description
    'PTR':        12,  # a domain name pointer
    'HINFO':      13,  # host information
    'MINFO':      14,  # mailbox or mail list information
    'MX':         15,  # mail exchange
    'TXT':        16,  # text strings
    'RP':         17,  # responsible person
    'AFSDB':      18,
    'X25':        19,
    'ISDN':       20,
    'RT':         21,
    'NSAP':       22,
    'NSAP-PTR':   23,
    'SIG':        24,
    'KEY':        25,
    'PX':         26,
    'GPOS':       27,
    'AAAA':       28,  # IP6 address
    'LOC':        29,
    'NXT':        30,
    'EID':        31,
    'NIMLOC':     32,
    'SRV':        33,
    'ATMA':       34,
    'NAPTR':      35,
    'KX':         36,
    'CERT':       37,
    'A6':         38,
    'DNAME':      39,
    'SINK':       40,
    'OPT':        41,
    'APL':        42,
    'DS':         43,
    'SSHFP':      44,
    'IPSECKEY':   45,
    'RRSIG':      46,
    'NSEC':       47,
    'DNSKEY':     48,
    'DHCID':      49,
    'NSEC3':      50,
    'NSEC3PARAM': 51,
    'TLSA':       52,
    'SMIMEA':     53,
    # 54 is unassigned
    'HIP':        55,
    'NINFO':      56,
    'RKEY':       57,
    'TALINK':     58,
    'CDS':        59,
    'CDNSKEY':    60,
    'OPENPGPKEY': 61,
    'CSYNC':      62,
    # 63-98 unassigned
    'SPF':        99,
    'UINFO':     100,
    'UID':       101,
    'GID':       102,
    'UNSPEC':    103,
    'NID':       104,
    'L32':       105,
    'L64':       106,
    'LP':        107,
    'EUI48':     108,
    'EUI64':     109,
    # 110-248 unassigned
    'TKEY':      249,
    'TSIG':      250,
    'IXFR':      251,
}
typeValueToName = {v: k for k, v in typeNameToValue.items()}
qTypeNameToValue = {
    'AXFR':  252,  # A request for a transfer of an entire zone
    'MAILB': 253,  # A request for mailbox-related records (MB, MG or MR)
    'MAILA': 254,  # A request for mail agent RRs (Obsolete - see MX)
    '*':     255,  # A request for all records
}
qTypeNameToValue.update(typeNameToValue)
qTypeValueToName = {v: k for k, v in qTypeNameToValue.items()}
classNameToValue = {
    'IN': 1,  # the internet
    'CS': 2,  # the CSNET class
    'CH': 3,  # the CHAOS class
    'HS': 4,  # Hesiod
}
classValueToName = {v: k for k, v in classNameToValue.items()}
qClassNameToValue = {
    'NONE': 254,
    '*':    255,  # any class
}
qClassNameToValue.update(classNameToValue)
qClassValueToName = {v: k for k, v in qClassNameToValue.items()}
opcodeNameToValue = {
    'Query':  0,
    'IQuery': 1,
    'Status': 2,
    # 3 is not assigned
    'Notify': 4,
    'Update': 5,
}
opcodeValueToName = {v: k for k, v in opcodeNameToValue.items()}
rcodeNameToValue = {
    'NoError':  0,
    'FormErr':  1,
    'ServFail': 2,
    'NXDomain': 3,
    'NotImp':   4,
    'Refused':  5,
    'YXDomain': 6,
    'YXRRSet':  7,
    'NXRRSet':  8,
    'NotAuth':  9,
    'NotZone': 10,
}
rcodeValueToName = {v: k for k, v in rcodeNameToValue.items()}


def readByte(data, offset):
    if sys.version_info < (3,):
        return ord(data[offset])
    return data[offset]


def isLabelRef(data, offset):
    return readByte(data, offset) & 0xc0 == 0xc0


def readLabel(data, offset):
    n = readByte(data, offset) + 1
    if n > 64:
        raise NotImplementedError('got %02x at offset %d' % (n, offset))
    label = data[offset + 1:offset + n].decode('ascii')
    return label, n


def writeLabel(label):
    return struct.pack('B', len(label)) + label.encode('ascii')


def readName(data, offset, jumps=()):
    i = [offset]

    def doRead():
        s = True
        while s:
            if isLabelRef(data, i[0]):
                ref_offset = 0x3fff & struct.unpack(
                    '!H', data[i[0]:i[0] + 2])[0]
                if ref_offset in jumps:
                    raise ValueError('Name loop detected')
                for lbl in readName(data, ref_offset,
                                    jumps + (ref_offset,))[0]:
                    yield lbl
                n = 2
                s = False
            else:
                s, n = readLabel(data, i[0])
                if s:
                    yield s
            i[0] += n
    result = Domain(doRead()), i[0] - offset
    return result


def writeName(name, label_cache, offset):
    tail = b'\x00'
    buf = []
    for i, x in enumerate(name):
        if name[i:] in label_cache:
            tail = label_cache[name[i:]]
            break
        if offset < (1 << 14):  # else, oh boy...
            label_cache[name[i:]] = struct.pack('!H', 0xc000 | offset)
        buf.append(writeLabel(x))
        offset += len(buf[-1])
    buf.append(tail)
    return b''.join(buf)


def readStrings(data):
    result = []
    while data:
        n = struct.unpack('B', data[:1])[0]
        if len(data) < n + 1:
            raise ValueError
        result.append(data[1:n + 1])
        data = data[n + 1:]
    return tuple(result)


def writeStrings(data):
    return b''.join(struct.pack('B', len(x)) + x for x in data)


class Domain(tuple):
    __slots__ = ()

    def __new__(cls, name):
        if isinstance(name, basestring):
            name = name.split('.')
        return super(Domain, cls).__new__(cls, name)

    def __repr__(self):
        return self.__class__.__name__ + super(Domain, self).__repr__()

    def __str__(self):
        return '.'.join(self)


class Question(namedtuple('Question', ('name', 'qtype', 'qclass'))):
    __slots__ = ()

    def __new__(cls, name, qtype, qclass):
        if isinstance(name, basestring):
            name = Domain(name)
        if isinstance(qtype, basestring):
            qtype = qTypeNameToValue[qtype]
        if isinstance(qclass, basestring):
            qclass = qClassNameToValue[qclass]
        return super(Question, cls).__new__(cls, name, qtype, qclass)

    @classmethod
    def from_wire(cls, data, offset):
        name, n = readName(data, offset)
        qtype, qclass = struct.unpack('!2H', data[offset + n:offset + n + 4])
        return cls(name, qtype, qclass), n + 4

    def to_wire(self, label_cache, offset):
        return writeName(self.name, label_cache, offset) + struct.pack(
            '!2H', self.qtype, self.qclass)

    @property
    def qtype_name(self):
        return qTypeValueToName[self.qtype]

    @property
    def qclass_name(self):
        return qClassValueToName[self.qclass]


class ResourceRecord(namedtuple('ResourceRecord', (
        'rrname', 'rrtype', 'rrclass', 'ttl', 'data'))):
    __slots__ = ()

    def __new__(cls, rrname, rrtype, rrclass, ttl, data):
        if isinstance(rrname, basestring):
            rrname = Domain(rrname)
        if isinstance(rrtype, basestring):
            rrtype = typeNameToValue[rrtype]
        if isinstance(rrclass, basestring):
            rrclass = classNameToValue[rrclass]
        return super(ResourceRecord, cls).__new__(
            cls, rrname, rrtype, rrclass, ttl, data)

    @classmethod
    def from_wire(cls, data, offset):
        name, n = readName(data, offset)
        rrtype, rrclass, ttl, data_length = struct.unpack(
            '!2HIH', data[offset + n:offset + n + 10])
        rrdata = data[offset + n + 10:offset + n + 10 + data_length]
        transform = {
            'CNAME': lambda: readName(data, offset + n + 10)[0],
            'NS': lambda: readName(data, offset + n + 10)[0],
            'MX': lambda: struct.unpack('!H', rrdata[:2]) + (
                readName(data, offset + n + 12)[0],),
            'TXT': lambda: readStrings(rrdata),
            'A': lambda: socket.inet_ntop(socket.AF_INET, rrdata),
            'AAAA': lambda: socket.inet_ntop(socket.AF_INET6, rrdata),
        }.get(typeValueToName[rrtype], lambda: rrdata)
        rrdata = transform()
        return cls(
            name, rrtype, rrclass, ttl, rrdata
        ), n + 10 + data_length

    def to_wire(self, label_cache, offset):
        buf = [writeName(self.rrname, label_cache, offset)]
        offset += len(buf[0])
        transform = {
            'CNAME': lambda: writeName(self.data, label_cache, offset),
            'NS': lambda: writeName(self.data, label_cache, offset),
            'MX': lambda: struct.pack('!H', self.data[0]) + writeName(
                self.data[1], label_cache, offset + 2),
            'TXT': lambda: writeStrings(self.data),
            'A': lambda: socket.inet_pton(socket.AF_INET, self.data),
            'AAAA': lambda: socket.inet_pton(socket.AF_INET6, self.data),
        }.get(typeValueToName[self.rrtype], lambda: self.data)
        offset += 10  # for the packing, below
        data = transform()
        buf.append(struct.pack(
            '!2HIH', self.rrtype, self.rrclass, self.ttl, len(data)))
        buf.append(data)
        return b''.join(buf)

    @property
    def rrtype_name(self):
        return typeValueToName[self.rrtype]

    @property
    def rrclass_name(self):
        return classValueToName[self.rrclass]


class Message(namedtuple('Message', (
        'id', 'is_response', 'op_code', 'is_authoritative',
        'is_truncated', 'recursion_desired', 'recursion_available',
        'reserved', 'authentic_data', 'checking_disabled', 'response_code',
        'questions', 'answers', 'name_servers', 'additional_records'))):
    __slots__ = ()

    @classmethod
    def from_wire(cls, data):
        offset = 12
        (_id, x, y, num_questions, num_answers, num_name_servers,
         num_additional) = struct.unpack('!H2B4H', data[:offset])
        is_response = bool(x & 0x80)
        op_code = (x & 0x78) >> 3
        is_authoritative = bool(x & 0x04)
        is_truncated = bool(x & 0x02)
        recursion_desired = bool(x & 0x01)
        recursion_available = bool(y & 0x80)
        _reserved = (y & 0x40) >> 6
        authentic_data = bool(y & 0x20)
        checking_disabled = bool(y & 0x10)
        response_code = y & 0x0f

        questions = []
        for _ in range(num_questions):
            q, n = Question.from_wire(data, offset)
            questions.append(q)
            offset += n

        answers = []
        for _ in range(num_answers):
            rr, n = ResourceRecord.from_wire(data, offset)
            answers.append(rr)
            offset += n

        name_servers = []
        for _ in range(num_name_servers):
            rr, n = ResourceRecord.from_wire(data, offset)
            name_servers.append(rr)
            offset += n

        additional_records = []
        for _ in range(num_additional):
            rr, n = ResourceRecord.from_wire(data, offset)
            additional_records.append(rr)
            offset += n

        result = cls(
            _id, is_response, op_code, is_authoritative,
            is_truncated, recursion_desired, recursion_available, _reserved,
            authentic_data, checking_disabled, response_code,
            tuple(questions), tuple(answers), tuple(name_servers),
            tuple(additional_records))
        if data[offset:]:
            raise ValueError('Extra data after reading %r: %r' % (
                result, data[offset:]))
        return result

    def to_wire(self):
        buf = [struct.pack(
            '!H2B4H',
            self.id,
            (self.is_response << 7) |
            (self.op_code << 3) |
            (self.is_authoritative << 2) |
            (self.is_truncated << 1) |
            self.recursion_desired,
            (self.recursion_available << 7) |
            (self.reserved << 6) |
            (self.authentic_data << 5) |
            (self.checking_disabled << 4) |
            self.response_code,
            len(self.questions),
            len(self.answers),
            len(self.name_servers),
            len(self.additional_records),
        )]
        label_cache = {}
        offset = len(buf[0])
        for section in (self.questions, self.answers, self.name_servers,
                        self.additional_records):
            for record in section:
                buf.append(record.to_wire(label_cache, offset))
                offset += len(buf[-1])
        return b''.join(buf)

    @property
    def op_code_name(self):
        return opcodeValueToName[self.op_code]

    @property
    def response_code_name(self):
        return rcodeValueToName[self.response_code]


def Request(questions=(), op_code='Query', req_id=None):
    if isinstance(questions, Question):
        questions = (questions, )
    if req_id is None:
        req_id = random.randrange(1 << 16)
    if isinstance(req_id, bytes):
        req_id = struct.unpack('!H', req_id[:2])[0]
    return Message(
        req_id, is_response=False,
        op_code=opcodeNameToValue[op_code],
        is_authoritative=False, is_truncated=False,
        recursion_desired=False, recursion_available=False,
        reserved=0, authentic_data=False, checking_disabled=False,
        response_code=0,
        questions=questions,
        answers=(), name_servers=(), additional_records=(),
    )


def Response(req, rcode='NoError', answers=()):
    return Message(
        req.id, is_response=True, op_code=req.op_code,
        is_authoritative=False,
        is_truncated=False,  # TODO: when is this supposed to be true?
        recursion_desired=False, recursion_available=False,
        reserved=0,
        authentic_data=False, checking_disabled=False,
        response_code=rcodeNameToValue[rcode],
        questions=req.questions,
        answers=answers, name_servers=(), additional_records=(),
    )


def NotImpResponse(req):
    return Response(req, 'NotImp')


def ServFailResponse(req):
    return Response(req, 'ServFail')


def FormErrResponse(req):
    return Response(req, 'FormErr')


def NXDomainResponse(req):
    return Response(req, 'NXDomain')
