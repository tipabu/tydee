from __future__ import print_function, unicode_literals
import socket
import struct

try:
    int_types = (int, long)
except NameError:
    int_types = (int, )


class BaseIPAddress(object):
    __slots__ = ('_packed',)

    def __init__(self, address):
        if isinstance(address, int_types):
            self._packed = b''.join(
                struct.pack('!I', (address >> (
                    (self.WIDTH - 4 - x) * 8)) & 0xffffffff)
                for x in range(0, self.WIDTH, 4))
            return

        try:
            self._packed = socket.inet_pton(self.AF, address)
        except (socket.error, TypeError):
            if isinstance(address, bytes) and len(address) == self.WIDTH:
                self._packed = address
            else:
                raise ValueError('Bad IP address %r' % (address, ))

    @property
    def WIDTH(self):
        raise NotImplementedError

    @property
    def AF(self):
        raise NotImplementedError

    def __bytes__(self):
        return self._packed

    def __str__(self):
        return socket.inet_ntop(self.AF, self._packed)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, str(self))

    def __int__(self):
        result = 0
        for x in range(0, self.WIDTH, 4):
            result = (result << 32) + struct.unpack(
                '!I', self._packed[x:x + 4])[0]
        return result

    def __and__(self, other):
        return type(self)(int(self) & other)

    def __or__(self, other):
        return type(self)(int(self) | other)

    def __bool__(self):
        return any(struct.unpack('B' * len(self._packed), self._packed))

    __nonzero__ = __bool__

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self._packed == other._packed

    def __lt__(self, other):
        if not isinstance(other, type(self)):
            raise TypeError('unorderable types')
        return self._packed < other._packed

    def __le__(self, other):
        if not isinstance(other, type(self)):
            raise TypeError('unorderable types')
        return self._packed <= other._packed

    def __gt__(self, other):
        if not isinstance(other, type(self)):
            raise TypeError('unorderable types')
        return self._packed > other._packed

    def __ge__(self, other):
        if not isinstance(other, type(self)):
            raise TypeError('unorderable types')
        return self._packed >= other._packed


class IPv4Address(BaseIPAddress):
    WIDTH = 4
    AF = socket.AF_INET


class IPv6Address(BaseIPAddress):
    WIDTH = 16
    AF = socket.AF_INET6
