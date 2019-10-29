import errno
import socket
import struct
import unittest

from tydee.message import Message, Request, Question, ResourceRecord, Domain
import tydee.server

from . import BaseTestWithServer


class TestServer(BaseTestWithServer):
    @classmethod
    def setUpClass(cls):
        super(TestServer, cls).setUpClass()
        server_address = cls.get_server_address()
        if ':' in server_address:
            cls.client_socket = socket.socket(socket.AF_INET6,
                                              socket.SOCK_DGRAM)
        else:
            cls.client_socket = socket.socket(socket.AF_INET,
                                              socket.SOCK_DGRAM)
        cls.client_socket.connect((server_address, cls.server.bind_port))
        cls.client_socket.settimeout(cls.server.timeout * 1.1)

    @classmethod
    def tearDownClass(cls):
        cls.client_socket.close()
        cls.client_socket = None
        super(TestServer, cls).tearDownClass()

    def make_request(self, req):
        if not isinstance(req, bytes):
            req = req.to_wire()
        self.client_socket.sendall(req)
        data = self.client_socket.recv(1024)
        # Check that ids match
        self.assertEqual(req[:2], data[:2])
        resp = Message.from_wire(data)
        return resp

    def test_bad_request(self):
        resp = self.make_request(
            Request(Question('this does not make sense', 'A', 'IN')))
        self.assertEqual(resp.response_code_name, 'FormErr')
        self.assertEqual(resp.answers, ())
        self.assertEqual(resp.name_servers, ())
        self.assertEqual(resp.additional_records, ())

    def assert_form_err(self, resp):
        self.assertEqual(resp.response_code_name, 'FormErr')
        self.assertEqual(resp.questions, ())  # !!
        self.assertEqual(resp.answers, ())
        self.assertEqual(resp.name_servers, ())
        self.assertEqual(resp.additional_records, ())

    def test_short_request(self):
        msg = b'w\xb7'  # Just an id
        resp = self.make_request(msg)
        self.assert_form_err(resp)

        msg = b'w'  # Not even an id
        with self.assertRaises(socket.timeout):
            self.make_request(msg)

    def test_infinite_recursion(self):
        # See
        #   - http://www.kb.cert.org./vuls/id/23495
        #   - https://nvd.nist.gov/vuln/detail/CVE-2000-0333
        msg = (b'w\xb7\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
               b'\x03foo\x03bar\xc0\x0c\x00\x01\x00\x01')
        resp = self.make_request(msg)
        self.assert_form_err(resp)

    def test_bad_reference(self):
        msg = (b'w\xb7\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
               b'\x03foo\x03bar\xcf\x0c\x00\x01\x00\x01')
        resp = self.make_request(msg)
        self.assert_form_err(resp)

    def test_label_too_long(self):
        msg = (b'w\xb7\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
               b'\x03foo\x3fbar\xcf\x0c\x00\x01\x00\x01')
        resp = self.make_request(msg)
        self.assert_form_err(resp)

    def test_bad_label_length(self):
        msg = (b'w\xb7\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
               b'\x03foo\x40' + (b'a' * 64) + b'\x00\x00\x01\x00\x01')
        resp = self.make_request(msg)
        self.assert_form_err(resp)

    def test_extra_data(self):
        msg = (b'w\xb7\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
               b'\x03foo\x03bar\x00\x00\x01\x00\x01too much data!')
        resp = self.make_request(msg)
        self.assert_form_err(resp)

    def test_not_enough_queries(self):
        msg = (b'w\xb7\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00'
               b'\x03foo\x03bar\x00\x00\x01\x00\x01')
        resp = self.make_request(msg)
        self.assert_form_err(resp)

    def test_not_implemented(self):
        def assertNotImpl(resp):
            self.assertEqual(resp.response_code_name, 'NotImp')
            self.assertEqual(resp.answers, ())
            self.assertEqual(resp.name_servers, ())
            self.assertEqual(resp.additional_records, ())

        assertNotImpl(self.make_request(
            Request(Question('some.crazy.domain', 'MX', 'IN'))))
        assertNotImpl(self.make_request(
            Request((Question('some.crazy.domain', 'A', 'IN'),
                     Question('some.other.domain', 'A', 'IN')))))

    def test_all_does_not_recurse(self):
        resp = self.make_request(
            Request(Question('some.crazy.domain', '*', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual(set(resp.answers), {
            ResourceRecord(Domain('some.crazy.domain'), 'CNAME', 'IN', 300,
                           Domain('container.auth-test.swift.dev')),
            ResourceRecord(Domain('some.crazy.domain'), 'TXT', 'IN', 300,
                           (b'foo=bar',)),
            ResourceRecord(Domain('some.crazy.domain'), 'TXT', 'IN', 300,
                           (b'baz=quux',)),
        })

    def test_txt_only(self):
        resp = self.make_request(
            Request(Question('some.crazy.domain', 'TXT', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual(set(resp.answers), {
            ResourceRecord(Domain('some.crazy.domain'), 'TXT', 'IN', 300,
                           (b'foo=bar',)),
            ResourceRecord(Domain('some.crazy.domain'), 'TXT', 'IN', 300,
                           (b'baz=quux',)),
        })

    def test_cname_only(self):
        resp = self.make_request(
            Request(Question('some.crazy.domain', 'CNAME', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual(resp.answers, (ResourceRecord(
            Domain('some.crazy.domain'), 'CNAME', 'IN', 300,
            Domain('container.auth-test.swift.dev')),))

    def test_cname_ipv4(self):
        resp = self.make_request(
            Request(Question('some.other.domain', 'A', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual(resp.answers, (ResourceRecord(
            Domain('some.other.domain'), 'CNAME', 'IN', 300,
            Domain('somewhere.else.entirely')),))

    def test_cname_ipv4_recurses(self):
        resp = self.make_request(
            Request(Question('some.crazy.domain', 'A', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual(resp.answers[0], ResourceRecord(
            Domain('some.crazy.domain'), 'CNAME', 'IN', 300,
            Domain('container.auth-test.swift.dev')))
        self.assertEqual({
            (str(rr.rrname), rr.rrtype_name, rr.rrclass_name, str(rr.data))
            for rr in resp.answers[1:]
        }, {
            ('container.auth-test.swift.dev', 'A', 'IN', '127.0.0.1'),
            ('container.auth-test.swift.dev', 'A', 'IN', '127.0.1.1'),
        })

    def test_cname_ipv6(self):
        resp = self.make_request(
            Request(Question('some.crazy.domain', 'AAAA', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual(resp.answers, (
            ResourceRecord(Domain('some.crazy.domain'), 'CNAME', 'IN', 300,
                           Domain('container.auth-test.swift.dev')),
            ResourceRecord(Domain('container.auth-test.swift.dev'),
                           'AAAA', 'IN', 300, '::1'),
        ))

    def test_wildcard_ipv4(self):
        resp = self.make_request(
            Request(Question('blah.swift.dev', 'A', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual({
            (str(rr.rrname), rr.rrtype_name, rr.rrclass_name, str(rr.data))
            for rr in resp.answers
        }, {
            ('blah.swift.dev', 'A', 'IN', '127.0.0.1'),
            ('blah.swift.dev', 'A', 'IN', '127.0.1.1'),
        })

    def test_wildcard_ipv6(self):
        resp = self.make_request(
            Request(Question('blah.swift.dev', 'AAAA', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual(resp.answers, (ResourceRecord(
            Domain('blah.swift.dev'), 'AAAA', 'IN', 300, '::1'),))

    def test_nxdomain_ipv4(self):
        resp = self.make_request(
            Request(Question('non.existent.domain', 'A', 'IN')))
        self.assertEqual(resp.response_code_name, 'NXDomain')
        self.assertEqual(resp.answers, ())

    def test_nxdomain_ipv6(self):
        resp = self.make_request(
            Request(Question('non.existent.domain', 'AAAA', 'IN')))
        self.assertEqual(resp.response_code_name, 'NXDomain')
        self.assertEqual(resp.answers, ())

    def test_no_records_but_subrecords(self):
        resp = self.make_request(
            Request(Question('swift.dev', 'A', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual(resp.answers, ())

        resp = self.make_request(
            Request(Question('crazy.domain', 'AAAA', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual(resp.answers, ())

        resp = self.make_request(
            Request(Question('other.domain', 'CNAME', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual(resp.answers, ())


class TestServerWithIPv4Client(TestServer):
    @classmethod
    def get_server_address(cls):
        return '127.0.0.1'


class TestServerWithIPv6Client(TestServer):
    @classmethod
    def get_server_address(cls):
        return '::1'

    @classmethod
    def check_can_run(cls):
        if ':' not in cls.server.bind_ip:
            raise unittest.SkipTest('%s requires an IPv6 bind_ip' % (
                cls.__name__, ))


class TestTCPServer(TestServer):
    server_class = tydee.server.TCPServer
    client_socket = None

    @classmethod
    def setUpClass(cls):
        # NB: skip TestServer's setUpClass!
        super(TestServer, cls).setUpClass()
        cls.reconnect()

    @classmethod
    def reconnect(cls):
        server_address = cls.get_server_address()
        if cls.client_socket:
            cls.client_socket.close()
        if ':' in server_address:
            cls.client_socket = socket.socket(socket.AF_INET6,
                                              socket.SOCK_STREAM)
        else:
            cls.client_socket = socket.socket(socket.AF_INET,
                                              socket.SOCK_STREAM)
        cls.client_socket.connect((server_address, cls.server.bind_port))
        cls.client_socket.settimeout(cls.server.timeout * 1.1)

    def make_request(self, req, includes_length=False):
        if not isinstance(req, bytes):
            req = req.to_wire()
        if not includes_length:
            req = struct.pack('!H', len(req)) + req
        self.client_socket.sendall(req)
        sz = struct.unpack('!H', tydee.server.recvall(
            self.client_socket, 2))[0]
        data = tydee.server.recvall(self.client_socket, sz)
        # Check that ids match
        self.assertEqual(req[2:4], data[:2])
        resp = Message.from_wire(data)
        return resp

    def test_short_request(self):
        # TCP gets some special forms of short requests
        msg = b'w\xb7'  # Just an id
        resp = self.make_request(msg)
        self.assert_form_err(resp)

        msg = b'w'  # Not even a whole id
        with self.assertRaises(socket.error) as raised:
            self.make_request(msg)
        self.assertEqual(raised.exception.errno, errno.ECONNRESET)
        self.reconnect()

        msg = b''  # Not even any id!
        with self.assertRaises(socket.error) as raised:
            self.make_request(msg)
        self.assertEqual(raised.exception.errno, errno.ECONNRESET)
        self.reconnect()

        msg = b'\xff\xff'  # Very much not the right length
        with self.assertRaises(socket.error) as raised:
            self.make_request(msg, True)
        self.assertEqual(raised.exception.errno, errno.ECONNRESET)
        self.reconnect()

        msg = b'\x01'  # Not even enough for a length
        with self.assertRaises(socket.error) as raised:
            self.make_request(msg, True)
        self.assertEqual(raised.exception.errno, errno.ECONNRESET)
        self.reconnect()
