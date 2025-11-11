import unittest

from src.pymls.codec.tls import (
    write_uint8,
    read_uint8,
    write_uint16,
    read_uint16,
    write_uint24,
    read_uint24,
    write_opaque16,
    read_opaque16,
)


class TestTLSCodec(unittest.TestCase):
    def test_uint_roundtrip(self):
        for val in [0, 1, 255]:
            self.assertEqual(read_uint8(write_uint8(val), 0)[0], val)
        for val in [0, 1, 65535]:
            self.assertEqual(read_uint16(write_uint16(val), 0)[0], val)
        for val in [0, 1, 0xFFFFFF]:
            self.assertEqual(read_uint24(write_uint24(val), 0)[0], val)

    def test_opaque16_roundtrip(self):
        data = b"hello world"
        buf = write_opaque16(data)
        out, off = read_opaque16(buf, 0)
        self.assertEqual(off, len(buf))
        self.assertEqual(out, data)


if __name__ == "__main__":
    unittest.main()

