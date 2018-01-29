from __future__ import print_function, unicode_literals
from collections import namedtuple
import socket
import struct
import sys

from barray import barray

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


def readName(data, offset):
    i = [offset]

    def doRead():
        s = True
        while s:
            if isLabelRef(data, i[0]):
                ref_offset = ((readByte(data, i[0]) & 0x3f) << 8) + \
                    readByte(data, i[0] + 1)
                for lbl in readName(data, ref_offset)[0]:
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


def writeName(name):
    if not name:
        return b'\x00'
    buf = [writeLabel(x) for x in name]
    buf.append(b'\x00')
    return b''.join(buf)


class Domain(tuple):
    def __repr__(self):
        return self.__class__.__name__ + super(Domain, self).__repr__()

    def __str__(self):
        return '.'.join(self)


class Question(namedtuple('Question', ('name', 'qtype', 'qclass'))):
    @classmethod
    def from_wire(cls, data, offset):
        name, n = readName(data, offset)
        qtype, qclass = struct.unpack('!2H', data[offset + n:offset + n + 4])
        return cls(name, qtype, qclass), n + 4

    def to_wire(self):
        buf = [writeLabel(x) for x in self.name]
        buf.append(b'\x00')
        buf.append(struct.pack('!2H', self.qtype, self.qclass))
        return b''.join(buf)

    @property
    def qtype_name(self):
        return qTypeValueToName[self.qtype]

    @property
    def qclass_name(self):
        return qClassValueToName[self.qclass]


class ResourceRecord(namedtuple('ResourceRecord', (
        'rrname', 'rrtype', 'rrclass', 'ttl', 'data'))):
    @classmethod
    def from_wire(cls, data, offset):
        name, n = readName(data, offset)
        rrtype, rrclass, ttl, data_length = struct.unpack(
            '!2HIH', data[offset + n:offset + n + 10])
        rrdata = data[offset + n + 10:offset + n + 10 + data_length]
        print(rrtype, rrclass, data_length, rrdata)
        transform = {
            'CNAME': lambda: readName(data, offset + n + 10)[0],
            'A': lambda: socket.inet_ntop(socket.AF_INET, rrdata),
            'AAAA': lambda: socket.inet_ntop(socket.AF_INET6, rrdata),
        }.get(typeValueToName[rrtype], lambda: rrdata)
        rrdata = transform()
        return cls(
            name, rrtype, rrclass, ttl, rrdata
        ), n + 10 + data_length

    def to_wire(self):
        buf = [writeName(self.rrname)]
        transform = {
            'CNAME': lambda: writeName(self.data),
            'A': lambda: socket.inet_pton(socket.AF_INET, self.data),
            'AAAA': lambda: socket.inet_pton(socket.AF_INET6, self.data),
        }.get(typeValueToName[self.rrtype], lambda: self.data)
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
        'raw_data', 'id', 'is_response', 'op_code', 'is_authoritative',
        'is_truncated', 'recursion_desired', 'recursion_available',
        'reserved', 'authentic_data', 'checking_disabled', 'response_code',
        'questions', 'answers', 'name_servers', 'additional_records'))):
    @classmethod
    def from_wire(cls, data):
        offset = 12
        header = barray(data[:offset])
        _id = header[:16].as_int()
        is_response = header[16]
        op_code = header[17:21].as_int()
        is_authoritative = header[21]
        is_truncated = header[22]
        recursion_desired = header[23]
        recursion_available = header[24]
        _reserved = int(header[25])
        authentic_data = header[26]
        checking_disabled = header[27]
        response_code = header[28:32].as_int()
        num_questions = header[32:48].as_int()
        num_answers = header[48:64].as_int()
        num_name_servers = header[64:80].as_int()
        num_additional = header[80:96].as_int()

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
            data, _id, is_response, op_code, is_authoritative,
            is_truncated, recursion_desired, recursion_available, _reserved,
            authentic_data, checking_disabled, response_code,
            tuple(questions), tuple(answers), tuple(name_servers),
            tuple(additional_records))
        if data[offset:]:
            raise ValueError('Extra data after reading %r: %r' % (
                result, data[offset:]))
        return result

    def to_wire(self):
        header = barray(b'\x00' * 12)
        header[:16] = self.id
        header[16] = self.is_response
        header[17:21] = self.op_code
        header[21] = self.is_authoritative
        header[22] = self.is_truncated
        header[23] = self.recursion_desired
        header[24] = self.recursion_available
        header[25] = self.reserved
        header[26] = self.authentic_data
        header[27] = self.checking_disabled
        header[28:32] = self.response_code
        header[32:48] = len(self.questions)
        header[48:64] = len(self.answers)
        header[64:80] = len(self.name_servers)
        header[80:96] = len(self.additional_records)
        buf = [header.as_bytes()]
        buf.extend(x.to_wire() for x in self.questions)
        buf.extend(x.to_wire() for x in self.answers)
        buf.extend(x.to_wire() for x in self.name_servers)
        buf.extend(x.to_wire() for x in self.additional_records)
        return b''.join(buf)

    @property
    def op_code_name(self):
        return opcodeValueToName[self.op_code]

    @property
    def response_code_name(self):
        return rcodeValueToName[self.response_code]
