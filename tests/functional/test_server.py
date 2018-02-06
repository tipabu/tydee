import os
import socket
import threading
import time
import unittest
import dns.resolver
import dns.reversename

import tydee.server
from tydee.message import Message, Request, Question


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        conf_file = os.path.join(os.path.dirname(__file__), 'dns.conf')
        cls.server = tydee.server.Server(conf_file)
        cls.server_thread = threading.Thread(target=cls.server.run)
        cls.server_thread.daemon = True
        cls.server_thread.start()

        time.sleep(0.01)  # Give the server a chance to start
        cls.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls.client_socket.connect(('127.0.0.1', 5354))
        cls.client_socket.settimeout(1.0)

        cls.resolver = dns.resolver.Resolver()
        cls.resolver.nameservers = ['127.0.0.1']
        cls.resolver.nameserver_ports = {'127.0.0.1': 5354}

    @classmethod
    def tearDownClass(cls):
        cls.client_socket.close()
        cls.client_socket = None
        cls.server.shutdown()
        cls.server_thread.join()

    def setUp(self):
        if not self.server_thread.is_alive():
            self.fail('Server is not running.')

    def make_request(self, req):
        self.client_socket.sendall(req.to_wire())
        data = self.client_socket.recv(1024)
        resp = Message.from_wire(data)
        self.assertEqual(req.id, resp.id)
        return resp

    def test_bad_request(self):
        resp = self.make_request(
            Request(Question('this does not make sense', 'A', 'IN')))
        self.assertEqual(resp.response_code_name, 'FormErr')

    def test_cname_only(self):
        result = self.resolver.query('some.crazy.domain', 'CNAME')
        self.assertEqual({x.to_text() for x in result.rrset.items},
                         {'container.auth-test.swift.dev.'})

    def test_cname_ipv4(self):
        resp = self.make_request(
            Request(Question('some.other.domain', 'A', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual([
            (str(rr.rrname), rr.rrtype_name, rr.rrclass_name, str(rr.data))
            for rr in resp.answers], [
                ('some.other.domain', 'CNAME', 'IN',
                 'somewhere.else.entirely'),
            ])

    def test_cname_ipv4_recurses(self):
        resp = self.make_request(
            Request(Question('some.crazy.domain', 'A', 'IN')))
        self.assertEqual(resp.response_code_name, 'NoError')
        self.assertEqual([
            (str(rr.rrname), rr.rrtype_name, rr.rrclass_name, str(rr.data))
            for rr in resp.answers], [
                ('some.crazy.domain', 'CNAME', 'IN',
                 'container.auth-test.swift.dev'),
                ('container.auth-test.swift.dev', 'A', 'IN', '127.0.0.1'),
                ('container.auth-test.swift.dev', 'A', 'IN', '127.0.1.1'),
            ])

    def test_cname_ipv6(self):
        result = self.resolver.query('some.crazy.domain', 'AAAA')
        self.assertEqual({x.to_text() for x in result.rrset.items},
                         {'::1'})

    def test_wildcard_ipv4(self):
        result = self.resolver.query('blah.swift.dev', 'A')
        self.assertEqual({x.to_text() for x in result.rrset.items},
                         {'127.0.0.1', '127.0.1.1'})

    def test_wildcard_ipv6(self):
        result = self.resolver.query('blah.swift.dev', 'AAAA')
        self.assertEqual({x.to_text() for x in result.rrset.items}, {'::1'})

    def test_nxdomain_ipv4(self):
        with self.assertRaises(dns.resolver.NXDOMAIN):
            self.resolver.query('non.existent.domain', 'A')

    def test_nxdomain_ipv6(self):
        with self.assertRaises(dns.resolver.NXDOMAIN):
            self.resolver.query('non.existent.domain', 'AAAA')

    def test_no_records_but_subrecords(self):
        with self.assertRaises(dns.resolver.NoAnswer):
            self.resolver.query('swift.dev', 'A')
        with self.assertRaises(dns.resolver.NoAnswer):
            self.resolver.query('crazy.domain', 'AAAA')
        with self.assertRaises(dns.resolver.NoAnswer):
            self.resolver.query('other.domain', 'CNAME')
