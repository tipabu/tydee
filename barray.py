import struct


class barray(object):
    def __init__(self, data, length=None):
        if isinstance(data, int):
            if length is None:
                raise ValueError('Need a length for int data')
            if length < 0 or length > 64:
                raise ValueError('int data must be 0-64 bits')
            if data < 0:
                raise ValueError('int data must be positive')
            if data >= 1 << length:
                raise ValueError('int data must fit in length bits')
            self.length = length
            data = struct.pack('>Q', data << (64 - length))
            self.data = bytearray(data[:(length - 1) // 8 + 1])
        elif isinstance(data, bytes):
            self.length = len(data) * 8 if length is None else length
            if self.length < 0:
                raise ValueError('length must not be negative')
            if self.length > len(data) * 8:
                raise ValueError('length is longer than data')
            self.data = bytearray(data)
        elif isinstance(data, (list, tuple)):
            self.length = len(data) if length is None else length
            if self.length < 0:
                raise ValueError('length must not be negative')
            if self.length > len(data):
                raise ValueError('length is longer than data')
            data = data[:self.length]
            if any(x not in (0, 1, False, True) for x in data):
                raise TypeError('All items must be 0, 1, True, or False')
            extra = len(data) % 8
            if extra:
                data += type(data)((0,) * (8 - extra))

            self.data = bytearray(
                sum(datum * (1 << (7 - bit))
                    for datum, bit in zip(data[i:i + 8], range(8)))
                for i in range(0, len(data), 8))
        else:
            raise TypeError

        if (len(self.data) - 1) * 8 >= self.length:
            raise ValueError('data too long for length')
        if len(self.data) * 8 < self.length:
            raise ValueError('data too short for length')

    def __repr__(self):
        return '%s(%r, length=%d)' % (
            self.__class__.__name__, self.as_bytes(), self.length)

    def __len__(self):
        return self.length

    def __getitem__(self, pos):
        if isinstance(pos, int):
            if pos >= self.length or -pos > self.length + 1:
                raise IndexError
            if pos < 0:
                # throw away the extra bits at the end
                extra = self.length % 8
                if extra:
                    pos -= 8 - extra
            i, b = divmod(pos, 8)
            return bool(self.data[i] & (0x80 >> b))
        if isinstance(pos, slice):
            if pos.step not in (None, 1):
                raise NotImplementedError

            if pos.start is None:
                start = 0
            elif pos.start < 0:
                start = max(pos.start + self.length, 0)
            else:
                start = min(pos.start, self.length)

            if pos.stop is None:
                stop = self.length
            elif pos.stop < 0:
                stop = max(pos.stop + self.length, 0)
            else:
                stop = min(pos.stop, self.length)
            # TODO: this can probably be optimized...
            return barray([self[j] for j in range(start, stop)])
        raise TypeError

    def __setitem__(self, pos, val):
        if isinstance(pos, int):
            if val not in (0, 1, True, False):
                raise ValueError('Bit values must be 0, 1, True, or False')
            if pos >= self.length or -pos > self.length + 1:
                raise IndexError
            if pos < 0:
                # throw away the extra bits at the end
                extra = self.length % 8
                if extra:
                    pos -= 8 - extra
            i, b = divmod(pos, 8)
            if val:
                self.data[i] |= 0x80 >> b
            else:
                self.data[i] &= ~(0x80 >> b)
            return
        if isinstance(pos, slice):
            if pos.step not in (None, 1):
                raise NotImplementedError

            if pos.start is None:
                start = 0
            elif pos.start < 0:
                start = max(pos.start + self.length, 0)
            else:
                start = min(pos.start, self.length)

            if pos.stop is None:
                stop = self.length
            elif pos.stop < 0:
                stop = max(pos.stop + self.length, 0)
            else:
                stop = min(pos.stop, self.length)

            if val is False:
                val = 0
            if val is True:
                val = (1 << (stop - start)) - 1
            if not isinstance(val, int):
                raise TypeError('Slice values must be True, False, or ints')
            if val >= (1 << (stop - start)):
                raise ValueError('Slice value is too wide for length')

            # TODO: this can probably be optimized...
            for i in range(stop - 1, start - 1, -1):
                self[i] = bool(val & (1 << (stop - 1 - i)))
            return
        raise TypeError

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            raise NotImplementedError
        if len(self) != len(other):
            return False
        return all(x == y for x, y in zip(self, other))

    def as_int(self):
        return sum(
            datum * (1 << (self.length - bit))
            for bit, datum in enumerate(self, start=1))

    def as_bytes(self):
        return bytes(self.data)
