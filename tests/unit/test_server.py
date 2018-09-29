from __future__ import unicode_literals
import functools
import io
import tempfile
import textwrap
import unittest

import tydee.server


def with_temp_file(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        tmp_file = None
        try:
            tmp_file = tempfile.NamedTemporaryFile()
            args += (tmp_file,)
            return func(*args, **kwargs)
        finally:
            if tmp_file:
                tmp_file.close()
    return wrapper


class TestIPAddresses(unittest.TestCase):
    def test_ipv4(self):
        a = tydee.server.IPv4Address('127.0.0.1')
        self.assertEqual(a.__bytes__(), b'\x7f\x00\x00\x01')
        self.assertEqual(str(a), '127.0.0.1')
        self.assertEqual(int(a), 0x7f000001)

        a = tydee.server.IPv4Address(0x7f000001)
        self.assertEqual(a.__bytes__(), b'\x7f\x00\x00\x01')
        self.assertEqual(str(a), '127.0.0.1')
        self.assertEqual(int(a), 0x7f000001)

        a = tydee.server.IPv4Address(b'\x0a\x00\x00\x00')
        self.assertEqual(a.__bytes__(), b'\x0a\x00\x00\x00')
        self.assertEqual(str(a), '10.0.0.0')
        self.assertEqual(str(tydee.server.IPv4Address(int(a))), '10.0.0.0')
        self.assertEqual(str(a | ((1 << 16) - 1)), '10.0.255.255')

    def test_ipv6(self):
        a = tydee.server.IPv6Address('2001:db8::')
        self.assertEqual(a.__bytes__(), b'\x20\x01\x0d\xb8' + 12 * b'\x00')
        self.assertEqual(str(a), '2001:db8::')
        self.assertEqual(int(a), 0x20010db8000000000000000000000000)

        a = tydee.server.IPv6Address(0x20010db8000000000000000000000000)
        self.assertEqual(a.__bytes__(), b'\x20\x01\x0d\xb8' + 12 * b'\x00')
        self.assertEqual(str(a), '2001:db8::')
        self.assertEqual(int(a), 0x20010db8000000000000000000000000)

        a = tydee.server.IPv6Address(b'\x20\x01\x0d\xb8' + 12 * b'\x00')
        self.assertEqual(a.__bytes__(), b'\x20\x01\x0d\xb8' + 12 * b'\x00')
        self.assertEqual(str(a), '2001:db8::')
        self.assertEqual(int(a), 0x20010db8000000000000000000000000)

        addr = '::ffff:127.0.0.1'
        self.assertEqual(len(addr), tydee.server.IPv6Address.WIDTH)
        a = tydee.server.IPv6Address(addr)
        self.assertEqual(a.__bytes__(),
                         b'\x00' * 10 + b'\xff' * 2 + b'\x7f\x00\x00\x01')
        self.assertEqual(str(a), '::ffff:127.0.0.1')
        self.assertEqual(int(a), 0x00000000000000000000ffff7f000001)

    def test_comparisons(self):
        addrs = [tydee.server.IPv4Address(x) for x in (
            '127.0.0.0', '127.0.0.1', '127.0.0.255')]

        self.assertTrue(addrs[0] <= addrs[0])
        self.assertTrue(addrs[0] >= addrs[0])
        self.assertFalse(addrs[0] < addrs[0])
        self.assertFalse(addrs[0] > addrs[0])

        self.assertTrue(addrs[0] < addrs[1])
        self.assertFalse(addrs[2] < addrs[1])
        self.assertFalse(addrs[0] > addrs[1])
        self.assertTrue(addrs[2] > addrs[1])

        self.assertTrue(addrs[0] < addrs[1] < addrs[2])
        self.assertTrue(addrs[2] > addrs[1] > addrs[0])

        a4 = tydee.server.IPv4Address('127.0.0.1')
        a6 = tydee.server.IPv6Address('::1')
        with self.assertRaises(TypeError):
            a4 < a6
        with self.assertRaises(TypeError):
            a4 > a6
        with self.assertRaises(TypeError):
            a6 < a4
        with self.assertRaises(TypeError):
            a6 > a4


class TestValidDomainName(unittest.TestCase):
    def test_bytes(self):
        self.assertTrue(tydee.server.valid_domain_name(b'some.domain.name'))
        self.assertTrue(tydee.server.valid_domain_name(
            b'some.very.very.truly.really.absolutely.very-deeply.nested.'
            b'domain.name.that.would.pretty.much.never.be.seen.in.real.life'))
        self.assertFalse(tydee.server.valid_domain_name(b'has_bad.chars'))
        self.assertFalse(tydee.server.valid_domain_name(b'non\xffascii.chars'))
        self.assertTrue(tydee.server.valid_domain_name(b'ca1n.have2.numbers'))
        self.assertFalse(tydee.server.valid_domain_name(b'1but.not.in.front'))
        self.assertTrue(tydee.server.valid_domain_name(b'can.have-dashes'))
        self.assertTrue(tydee.server.valid_domain_name(b'even--con.sec.utive'))
        self.assertFalse(tydee.server.valid_domain_name(b'-not.in.front'))
        self.assertFalse(tydee.server.valid_domain_name(b'not.-in.front'))
        self.assertFalse(tydee.server.valid_domain_name(b'not.in-.back'))
        self.assertFalse(tydee.server.valid_domain_name(b'no.double..dots'))

    def test_unicode(self):
        self.assertTrue(tydee.server.valid_domain_name(u'some.domain.name'))
        self.assertTrue(tydee.server.valid_domain_name(
            u'some.very.very.truly.really.absolutely.very-deeply.nested.'
            u'domain.name.that.would.pretty.much.never.be.seen.in.real.life'))
        self.assertFalse(tydee.server.valid_domain_name(u'has_bad.chars'))
        self.assertFalse(tydee.server.valid_domain_name(u'non\xffascii.chars'))
        self.assertTrue(tydee.server.valid_domain_name(u'ca1n.have2.numbers'))
        self.assertFalse(tydee.server.valid_domain_name(u'1but.not.in.front'))
        self.assertTrue(tydee.server.valid_domain_name(u'can.have-dashes'))
        self.assertTrue(tydee.server.valid_domain_name(u'even--con.sec.utive'))
        self.assertFalse(tydee.server.valid_domain_name(u'-not.in.front'))
        self.assertFalse(tydee.server.valid_domain_name(u'not.-in.front'))
        self.assertFalse(tydee.server.valid_domain_name(u'not.in-.back'))
        self.assertFalse(tydee.server.valid_domain_name(u'no.double..dots'))


class TestConfigParsing(unittest.TestCase):
    valid_config = textwrap.dedent('''
        [cname]
        some.valid.domain = the.canonical.name
        some.other.domain = another.name

        [ipv4]
        a.ipv4.name = 1.2.3.4
        another.ipv4.name = 255.255.255.255
        multi.ipv4.name = 1.2.3.5
                          1.2.3.6

        [ipv6]
        a.ipv6.name = 1:2::3:4
        another.ipv6.name = ffff:ffff::ffff
        multi.ipv6.name = ::1
                          ::2

        [txt]
        txt.enabled.domain =
            we can put all sorts of stuff in here!
            whatever we want, honest
        another.domain =
            key=value pairs;
            all=sorts=of=stuff
    ''')

    @classmethod
    def setUpClass(cls):
        cls.parser = cls.make_parser(cls.valid_config)

    @staticmethod
    def make_parser(config):
        parser = tydee.server.configparser.RawConfigParser()
        parser.readfp(io.StringIO(config))
        return parser

    def test_load_cname(self):
        self.assertEqual(tydee.server.load_cname_records(self.parser), [
            ('some.valid.domain', ('the', 'canonical', 'name')),
            ('some.other.domain', ('another', 'name')),
        ])

    def test_load_a(self):
        self.assertEqual(tydee.server.load_a_records(self.parser), [
            ('a.ipv4.name', '1.2.3.4'),
            ('another.ipv4.name', '255.255.255.255'),
            ('multi.ipv4.name', '1.2.3.5'),
            ('multi.ipv4.name', '1.2.3.6'),
        ])

    def test_load_aaaa(self):
        self.assertEqual(tydee.server.load_aaaa_records(self.parser), [
            ('a.ipv6.name', '1:2::3:4'),
            ('another.ipv6.name', 'ffff:ffff::ffff'),
            ('multi.ipv6.name', '::1'),
            ('multi.ipv6.name', '::2'),
        ])

    def test_load_txt(self):
        self.assertEqual(tydee.server.load_txt_records(self.parser), [
            ('txt.enabled.domain', (
                b'we can put all sorts of stuff in here!',)),
            ('txt.enabled.domain', (b'whatever we want, honest',)),
            ('another.domain', (b'key=value pairs;',)),
            ('another.domain', (b'all=sorts=of=stuff',)),
        ])

    def test_load_empty_config(self):
        parser = self.make_parser('')
        self.assertEqual(tydee.server.load_cname_records(parser), [])
        self.assertEqual(tydee.server.load_a_records(parser), [])
        self.assertEqual(tydee.server.load_aaaa_records(parser), [])
        self.assertEqual(tydee.server.load_txt_records(parser), [])

    @with_temp_file
    def test_valid_server_options(self, tmp_file):
        tmp_file.write('''
[dns-server]
bind_ip = 123.45.67.89
bind_port = 9876
        '''.strip().encode('ascii'))
        tmp_file.flush()
        server = tydee.server.UDPServer(tmp_file.name)
        self.assertEqual(server.bind_ip, '123.45.67.89')
        self.assertEqual(server.bind_port, 9876)

    @with_temp_file
    def test_invalid_server_options(self, tmp_file):
        def do_test(conf_line):
            tmp_file.truncate(0)
            conf = '[dns-server]\n' + conf_line
            tmp_file.write(conf.encode('ascii'))
            tmp_file.flush()
            with self.assertRaises(ValueError):
                tydee.server.UDPServer(tmp_file.name)

        do_test('bind_ip = ')
        do_test('bind_ip = asdf')
        do_test('bind_ip = 1.2.3.4.5')
        do_test('bind_ip = 1:::2')
        do_test('bind_port = asdf')
        do_test('bind_port = 100000')
        do_test('bind_port = -1')
