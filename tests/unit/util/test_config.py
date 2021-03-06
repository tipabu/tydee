from __future__ import unicode_literals
import functools
import io
import tempfile
import textwrap
import unittest

# Piggy-back some py2/py3 compat
from tydee.server import configparser
import tydee.util.config


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


class TestValidDomainName(unittest.TestCase):
    def test_bytes(self):
        self.assertTrue(tydee.util.config.valid_domain_name(
            b'some.domain.name'))
        self.assertTrue(tydee.util.config.valid_domain_name(
            b'some.very.very.truly.really.absolutely.very-deeply.nested.'
            b'domain.name.that.would.pretty.much.never.be.seen.in.real.life'))
        self.assertFalse(tydee.util.config.valid_domain_name(b'has_bad.chars'))
        self.assertFalse(tydee.util.config.valid_domain_name(
            b'non\xffascii.chars'))
        self.assertTrue(tydee.util.config.valid_domain_name(
            b'ca1n.have2.numbers'))
        self.assertFalse(tydee.util.config.valid_domain_name(
            b'1but.not.in.front'))
        self.assertTrue(tydee.util.config.valid_domain_name(
            b'can.have-dashes'))
        self.assertTrue(tydee.util.config.valid_domain_name(
            b'even--con.sec.utive'))
        self.assertFalse(tydee.util.config.valid_domain_name(b'-not.in.front'))
        self.assertFalse(tydee.util.config.valid_domain_name(b'not.-in.front'))
        self.assertFalse(tydee.util.config.valid_domain_name(b'not.in-.back'))
        self.assertFalse(tydee.util.config.valid_domain_name(
            b'no.double..dots'))

    def test_unicode(self):
        self.assertTrue(tydee.util.config.valid_domain_name(
            u'some.domain.name'))
        self.assertTrue(tydee.util.config.valid_domain_name(
            u'some.very.very.truly.really.absolutely.very-deeply.nested.'
            u'domain.name.that.would.pretty.much.never.be.seen.in.real.life'))
        self.assertFalse(tydee.util.config.valid_domain_name(u'has_bad.chars'))
        self.assertFalse(tydee.util.config.valid_domain_name(
            u'non\xffascii.chars'))
        self.assertTrue(tydee.util.config.valid_domain_name(
            u'ca1n.have2.numbers'))
        self.assertFalse(tydee.util.config.valid_domain_name(
            u'1but.not.in.front'))
        self.assertTrue(tydee.util.config.valid_domain_name(
            u'can.have-dashes'))
        self.assertTrue(tydee.util.config.valid_domain_name(
            u'even--con.sec.utive'))
        self.assertFalse(tydee.util.config.valid_domain_name(u'-not.in.front'))
        self.assertFalse(tydee.util.config.valid_domain_name(u'not.-in.front'))
        self.assertFalse(tydee.util.config.valid_domain_name(u'not.in-.back'))
        self.assertFalse(tydee.util.config.valid_domain_name(
            u'no.double..dots'))


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
        parser = configparser.RawConfigParser()
        if hasattr(parser, 'read_file'):
            # python >= 3.2
            parser.read_file(io.StringIO(config))
        else:
            parser.readfp(io.StringIO(config))
        return parser

    def test_load_cname(self):
        self.assertEqual(tydee.util.config.load_cname_records(self.parser), [
            ('some.valid.domain', ('the', 'canonical', 'name')),
            ('some.other.domain', ('another', 'name')),
        ])

    def test_load_a(self):
        self.assertEqual(tydee.util.config.load_a_records(self.parser), [
            ('a.ipv4.name', '1.2.3.4'),
            ('another.ipv4.name', '255.255.255.255'),
            ('multi.ipv4.name', '1.2.3.5'),
            ('multi.ipv4.name', '1.2.3.6'),
        ])

    def test_load_aaaa(self):
        self.assertEqual(tydee.util.config.load_aaaa_records(self.parser), [
            ('a.ipv6.name', '1:2::3:4'),
            ('another.ipv6.name', 'ffff:ffff::ffff'),
            ('multi.ipv6.name', '::1'),
            ('multi.ipv6.name', '::2'),
        ])

    def test_load_txt(self):
        self.assertEqual(tydee.util.config.load_txt_records(self.parser), [
            ('txt.enabled.domain', (
                b'we can put all sorts of stuff in here!',)),
            ('txt.enabled.domain', (b'whatever we want, honest',)),
            ('another.domain', (b'key=value pairs;',)),
            ('another.domain', (b'all=sorts=of=stuff',)),
        ])

    def test_load_empty_config(self):
        parser = self.make_parser('')
        self.assertEqual(tydee.util.config.load_cname_records(parser), [])
        self.assertEqual(tydee.util.config.load_a_records(parser), [])
        self.assertEqual(tydee.util.config.load_aaaa_records(parser), [])
        self.assertEqual(tydee.util.config.load_txt_records(parser), [])
