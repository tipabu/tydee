import os
import threading
import time
import unittest
try:
    import dns.resolver
    dnspython_installed = True
except ImportError:
    dnspython_installed = False

import tydee.server


class TestServer(unittest.TestCase):
    @classmethod
    @unittest.skipIf(not dnspython_installed, 'dnspython is not installed')
    def setUpClass(cls):
        conf_file = os.path.join(os.path.dirname(__file__), 'dns.conf')
        cls.server = tydee.server.Server(conf_file)
        cls.server_thread = threading.Thread(target=cls.server.run)
        cls.server_thread.daemon = True
        cls.server_thread.start()

        time.sleep(0.01)  # Give server a chance to start
        cls.resolver = dns.resolver.Resolver()
        cls.resolver.timeout = 0.1
        cls.resolver.lifetime = 0.1
        cls.resolver.nameservers = [cls.server.bind_ip]
        cls.resolver.nameserver_ports = {
            cls.server.bind_ip: cls.server.bind_port}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server_thread.join()

    def setUp(self):
        if not self.server_thread.is_alive():
            self.fail('Server is not running.')

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
