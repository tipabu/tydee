import unittest
try:
    import dns.resolver
    dnspython_installed = True
except ImportError:
    dnspython_installed = False

from . import BaseTestWithServer


class TestServer(BaseTestWithServer):
    @classmethod
    @unittest.skipIf(not dnspython_installed, 'dnspython is not installed')
    def setUpClass(cls):
        super(TestServer, cls).setUpClass()
        cls.resolver = dns.resolver.Resolver()
        cls.resolver.timeout = 0.1
        cls.resolver.lifetime = 0.1
        server_address = cls.get_server_address()
        cls.resolver.nameservers = [server_address]
        cls.resolver.nameserver_ports = {server_address: cls.server.bind_port}

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
