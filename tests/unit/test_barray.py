import unittest
from tydee.barray import barray


class TestBarray(unittest.TestCase):
    def test_types(self):
        barray(b'\x00')
        barray(b'\x00', 4)
        barray([0])
        barray([0], 0)
        barray(0, 16)
        with self.assertRaises(TypeError):
            barray(None)
        with self.assertRaises(TypeError):
            barray(u'foo')

    def test_eq(self):
        x = barray(b'\xff\x00')
        y = barray(b'\xff\x00')
        self.assertFalse(x is y)
        # reflexivity
        self.assertTrue(x == x)
        self.assertFalse(x != x)
        # symmetry
        self.assertTrue(x == y)
        self.assertFalse(x != y)

        y = barray(b'\xff\x00', 12)
        # short-circuit on different lengths
        self.assertFalse(x == y)
        self.assertTrue(x != y)

        with self.assertRaises(NotImplementedError):
            x == 'foo'
        with self.assertRaises(NotImplementedError):
            x != 'bar'

    def test_16_bits(self):
        x = barray(b'\xff\x00')
        self.assertEqual(x.length, 16)
        self.assertIs(x[0], True)
        self.assertIs(x[7], True)
        self.assertIs(x[8], False)
        self.assertIs(x[15], False)
        with self.assertRaises(IndexError):
            x[16]
        self.assertIs(x[-1], False)
        self.assertIs(x[-8], False)
        self.assertIs(x[-9], True)
        self.assertIs(x[-16], True)
        with self.assertRaises(IndexError):
            x[-17]
        self.assertEqual(x.as_int(), 0xff00)

    def test_init_with_length(self):
        with self.assertRaises(ValueError):
            barray(b'\xff\x00', 17)
        barray(b'\xff\x00', 16)
        barray(b'\xff\x00', 15)
        barray(b'\xff\x00', 9)
        with self.assertRaises(ValueError):
            barray(b'\xff\x00', 8)
        with self.assertRaises(ValueError):
            barray(b'\xff', 9)
        barray(b'\xff', 8)
        barray(b'\xff', 1)
        with self.assertRaises(ValueError):
            barray(b'\xff', 0)
        barray(b'', 0)
        with self.assertRaises(ValueError):
            barray(b'', -1)

    def test_11_bits(self):
        x = barray(b'\xff\x00', 11)
        self.assertEqual(x.length, 11)
        self.assertIs(x[0], True)
        self.assertIs(x[7], True)
        self.assertIs(x[8], False)
        self.assertIs(x[10], False)
        with self.assertRaises(IndexError):
            x[11]
        self.assertIs(x[-1], False)
        self.assertIs(x[-3], False)
        self.assertIs(x[-4], True)
        self.assertIs(x[-11], True)
        with self.assertRaises(IndexError):
            x[-12]
        self.assertEqual(x[4:12], barray(b'\xf0', 7))
        self.assertEqual(x[:4], barray(b'\xf0', 4))
        self.assertEqual(x[-8:], barray(b'\xf8'))
        self.assertEqual(x[-4:], barray(b'\x80', 4))
        self.assertEqual(x[-20:], x)
        self.assertEqual(x[20:], barray(b''))
        self.assertEqual(x[20:30], barray(b''))
        self.assertEqual(x, barray(b'\xff\x0f', 11))
        self.assertEqual(x.as_int(), 0x7f8)

    def test_init_from_list_errors(self):
        with self.assertRaises(ValueError):
            barray([0] * 4, -1)
        with self.assertRaises(ValueError):
            barray([0] * 4, 5)
        with self.assertRaises(TypeError):
            barray(['foo'])
        with self.assertRaises(TypeError):
            barray([0], 'foo')

    def test_init_from_list(self):
        x = barray([])
        self.assertEqual(len(x), 0)

        x = barray([True, True, False, True, False, False, True, False])
        self.assertEqual(len(x), 8)
        self.assertIs(x[0], True)
        self.assertIs(x[1], True)
        self.assertIs(x[2], False)
        self.assertIs(x[3], True)
        self.assertIs(x[4], False)
        self.assertIs(x[5], False)
        self.assertIs(x[6], True)
        self.assertIs(x[7], False)

        x = barray((0, 0, 1, 1, 1, 1, 0, 0, 0))
        self.assertEqual(len(x), 9)
        self.assertIs(x[0], False)
        self.assertIs(x[1], False)
        self.assertIs(x[2], True)
        self.assertIs(x[3], True)
        self.assertIs(x[4], True)
        self.assertIs(x[5], True)
        self.assertIs(x[6], False)
        self.assertIs(x[7], False)
        self.assertIs(x[8], False)

        x = barray((0, 0, 1, 1, 1, 1, 0, 0, 0), 5)
        self.assertEqual(len(x), 5)
        self.assertIs(x[0], False)
        self.assertIs(x[1], False)
        self.assertIs(x[2], True)
        self.assertIs(x[3], True)
        self.assertIs(x[4], True)

        x = barray((0, 0, 1, 1, 1, 1, 0, 0, 0), 0)
        self.assertEqual(len(x), 0)

    def test_init_from_int_error(self):
        with self.assertRaises(ValueError):
            barray(12)  # But how wide??
        with self.assertRaises(ValueError):
            barray(12, -1)  # I... what? How can it be negative bits wide?
        with self.assertRaises(ValueError):
            barray(12, 1024)  # Too big! Too big!
        with self.assertRaises(ValueError):
            barray(1, 0)
        with self.assertRaises(ValueError):
            barray(-12, 24)  # I have no interest in dealing with complements

    def test_init_from_int(self):
        self.assertEqual(barray(0, 0), barray(b''))
        self.assertEqual(barray(0, 16), barray(b'\x00\x00'))
        self.assertEqual(barray(1, 16), barray(b'\x00\x01'))
        self.assertEqual(barray(1, 8), barray(b'\x01'))
        self.assertEqual(barray(1, 4), barray(b'\x10', 4))
        self.assertEqual(
            barray(0x0123456789abcdef, 64),
            barray(b'\x01\x23\x45\x67\x89\xab\xcd\xef'))
        self.assertEqual(barray(7, 4), barray(b'\x70', 4))
        self.assertEqual(barray(7, 3), barray(b'\xe0', 3))
        with self.assertRaises(ValueError):
            barray(7, 2)
        with self.assertRaises(ValueError):
            barray(8, 3)

    def test_set_item(self):
        x = barray(0, 9)
        x[0] = 1
        self.assertEqual(x, barray(b'\x80\x00', 9))
        with self.assertRaises(ValueError):
            x[0] = 7
        x[-3] = True
        self.assertEqual(x, barray(b'\x82\x00', 9))
        x[3:9] = True
        self.assertEqual(x, barray(b'\x9f\x80', 9))
        with self.assertRaises(IndexError):
            x[9] = True
        x[-3:] = 0
        self.assertEqual(x, barray(b'\x9c\x00', 9))
        x[1:-1] = 0x3a
        self.assertEqual(x, barray(b'\xba\x00', 9))
        with self.assertRaises(ValueError):
            x[1:3] = 4
        x[2:5] = 5
        self.assertEqual(x, barray(b'\xaa\x00', 9))

        y = barray(0, 8)
        y[-5:-3] = True
        self.assertEqual(y, barray(b'\x18'))
        y[-7] = True
        self.assertEqual(y, barray(b'\x58'))
        y[4:] = True
        self.assertEqual(y, barray(b'\x5f'))
        y[:2] = True
        self.assertEqual(y, barray(b'\xdf'))
        y[:] = False
        self.assertEqual(y, barray(b'\x00'))

    def test_slicing_errors(self):
        x = barray(b'\x00')
        with self.assertRaises(TypeError):
            x['foo']
        with self.assertRaises(NotImplementedError):
            x[::-1]
        with self.assertRaises(TypeError):
            x['foo'] = True
        with self.assertRaises(NotImplementedError):
            x[::-1] = True
