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
        if hasattr(parser, 'read_file'):
            # python >= 3.2
            parser.read_file(io.StringIO(config))
        else:
            parser.readfp(io.StringIO(config))
        return parser

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
