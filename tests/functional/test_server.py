import os
import threading
import unittest
import dns.resolver
import dns.reversename
import tydee.server


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        conf_file = os.path.join(os.path.dirname(__file__), 'dns.conf')
        cls.server = tydee.server.Server(conf_file)
        cls.server_thread = threading.Thread(target=cls.server.run)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        cls.resolver = dns.resolver.Resolver()
        cls.resolver.nameservers = ['127.0.0.1']
        cls.resolver.nameserver_ports = {'127.0.0.1': 5354}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server_thread.join()

    def test_cname_only(self):
        result = self.resolver.query('some.crazy.domain', 'CNAME')
        self.assertEqual({x.to_text() for x in result.rrset.items},
                         {'container.auth-test.swift.dev.'})

    def test_cname_ipv4(self):
        result = self.resolver.query('some.crazy.domain', 'A')
        self.assertEqual({x.to_text() for x in result.rrset.items},
                         {'127.0.0.1', '127.0.1.1'})

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
