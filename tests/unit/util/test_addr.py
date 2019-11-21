import unittest

import tydee.util.addr


class TestIPAddresses(unittest.TestCase):
    def test_ipv4(self):
        a = tydee.util.addr.IPv4Address('127.0.0.1')
        self.assertEqual(bytes(a), b'\x7f\x00\x00\x01')
        self.assertEqual(str(a), '127.0.0.1')
        self.assertEqual(int(a), 0x7f000001)

        a = tydee.util.addr.IPv4Address(0x7f000001)
        self.assertEqual(bytes(a), b'\x7f\x00\x00\x01')
        self.assertEqual(str(a), '127.0.0.1')
        self.assertEqual(int(a), 0x7f000001)

        a = tydee.util.addr.IPv4Address(b'\x0a\x00\x00\x00')
        self.assertEqual(bytes(a), b'\x0a\x00\x00\x00')
        self.assertEqual(str(a), '10.0.0.0')
        self.assertEqual(str(tydee.util.addr.IPv4Address(int(a))), '10.0.0.0')
        self.assertEqual(str(a | ((1 << 16) - 1)), '10.0.255.255')

    def test_ipv6(self):
        a = tydee.util.addr.IPv6Address('2001:db8::')
        self.assertEqual(bytes(a), b'\x20\x01\x0d\xb8' + 12 * b'\x00')
        self.assertEqual(str(a), '2001:db8::')
        self.assertEqual(int(a), 0x20010db8000000000000000000000000)

        a = tydee.util.addr.IPv6Address(0x20010db8000000000000000000000000)
        self.assertEqual(bytes(a), b'\x20\x01\x0d\xb8' + 12 * b'\x00')
        self.assertEqual(str(a), '2001:db8::')
        self.assertEqual(int(a), 0x20010db8000000000000000000000000)

        a = tydee.util.addr.IPv6Address(b'\x20\x01\x0d\xb8' + 12 * b'\x00')
        self.assertEqual(bytes(a), b'\x20\x01\x0d\xb8' + 12 * b'\x00')
        self.assertEqual(str(a), '2001:db8::')
        self.assertEqual(int(a), 0x20010db8000000000000000000000000)

        addr = '::ffff:127.0.0.1'
        self.assertEqual(len(addr), tydee.util.addr.IPv6Address.WIDTH)
        a = tydee.util.addr.IPv6Address(addr)
        self.assertEqual(bytes(a),
                         b'\x00' * 10 + b'\xff' * 2 + b'\x7f\x00\x00\x01')
        self.assertEqual(str(a), '::ffff:127.0.0.1')
        self.assertEqual(int(a), 0x00000000000000000000ffff7f000001)

    def test_comparisons(self):
        addrs = [tydee.util.addr.IPv4Address(x) for x in (
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

        a4 = tydee.util.addr.IPv4Address('127.0.0.1')
        a6 = tydee.util.addr.IPv6Address('::1')
        with self.assertRaises(TypeError):
            a4 < a6
        with self.assertRaises(TypeError):
            a4 > a6
        with self.assertRaises(TypeError):
            a6 < a4
        with self.assertRaises(TypeError):
            a6 > a4
