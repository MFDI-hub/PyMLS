import unittest

from rfc9420.codec.tls import (
    TLSDecodeError,
    read_opaque8,
    read_opaque16,
    read_opaque24,
    read_uint8,
    read_uint16,
    read_uint24,
    read_uint32,
    read_uint64,
    read_vector,
    write_opaque8,
    write_opaque16,
    write_opaque24,
    write_uint8,
    write_uint16,
    write_uint24,
    write_uint32,
    write_uint64,
    write_vector,
)


class TestUnitCodecTLS(unittest.TestCase):
    def test_integer_roundtrips(self):
        for val in [0, 1, 255]:
            out, off = read_uint8(write_uint8(val), 0)
            self.assertEqual((out, off), (val, 1))
        for val in [0, 1, 65535]:
            out, off = read_uint16(write_uint16(val), 0)
            self.assertEqual((out, off), (val, 2))
        for val in [0, 1, 0xFFFFFF]:
            out, off = read_uint24(write_uint24(val), 0)
            self.assertEqual((out, off), (val, 3))
        for val in [0, 1, 0xFFFFFFFF]:
            out, off = read_uint32(write_uint32(val), 0)
            self.assertEqual((out, off), (val, 4))
        for val in [0, 1, 0xFFFFFFFFFFFFFFFF]:
            out, off = read_uint64(write_uint64(val), 0)
            self.assertEqual((out, off), (val, 8))

    def test_opaque_roundtrips(self):
        data = b"hello"
        self.assertEqual(read_opaque8(write_opaque8(data), 0)[0], data)
        self.assertEqual(read_opaque16(write_opaque16(data), 0)[0], data)
        self.assertEqual(read_opaque24(write_opaque24(data), 0)[0], data)

    def test_vector_roundtrip(self):
        buf = write_vector(b"data", 2)
        data, off = read_vector(buf, 0, 2)
        self.assertEqual(data, b"data")
        self.assertEqual(off, len(buf))

    def test_errors(self):
        with self.assertRaises(TLSDecodeError):
            read_uint16(b"\x00", 0)
        with self.assertRaises(ValueError):
            write_opaque8(b"x" * 256)


if __name__ == "__main__":
    unittest.main()
