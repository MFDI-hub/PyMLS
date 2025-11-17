import unittest

from pymls.codec.tls import (
    TLSDecodeError,
    write_uint8,
    read_uint8,
    write_uint16,
    read_uint16,
    write_uint24,
    read_uint24,
    write_uint32,
    read_uint32,
    write_uint64,
    read_uint64,
    write_opaque8,
    read_opaque8,
    write_opaque16,
    read_opaque16,
    write_opaque24,
    read_opaque24,
    write_vector,
    read_vector,
)


class TestTLSCodec(unittest.TestCase):
    def test_uint8_roundtrip(self):
        """Test uint8 encoding and decoding roundtrip."""
        for val in [0, 1, 127, 128, 255]:
            encoded = write_uint8(val)
            decoded, offset = read_uint8(encoded, 0)
            self.assertEqual(decoded, val)
            self.assertEqual(offset, 1)
            self.assertEqual(len(encoded), 1)

    def test_uint16_roundtrip(self):
        """Test uint16 encoding and decoding roundtrip."""
        for val in [0, 1, 255, 256, 32767, 32768, 65535]:
            encoded = write_uint16(val)
            decoded, offset = read_uint16(encoded, 0)
            self.assertEqual(decoded, val)
            self.assertEqual(offset, 2)
            self.assertEqual(len(encoded), 2)

    def test_uint24_roundtrip(self):
        """Test uint24 encoding and decoding roundtrip."""
        for val in [0, 1, 255, 256, 65535, 65536, 0xFFFFFF]:
            encoded = write_uint24(val)
            decoded, offset = read_uint24(encoded, 0)
            self.assertEqual(decoded, val)
            self.assertEqual(offset, 3)
            self.assertEqual(len(encoded), 3)

    def test_uint32_roundtrip(self):
        """Test uint32 encoding and decoding roundtrip."""
        for val in [0, 1, 255, 256, 65535, 65536, 0xFFFFFFFF]:
            encoded = write_uint32(val)
            decoded, offset = read_uint32(encoded, 0)
            self.assertEqual(decoded, val)
            self.assertEqual(offset, 4)
            self.assertEqual(len(encoded), 4)

    def test_uint64_roundtrip(self):
        """Test uint64 encoding and decoding roundtrip."""
        for val in [0, 1, 255, 256, 65535, 65536, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF]:
            encoded = write_uint64(val)
            decoded, offset = read_uint64(encoded, 0)
            self.assertEqual(decoded, val)
            self.assertEqual(offset, 8)
            self.assertEqual(len(encoded), 8)

    def test_read_uint_with_offset(self):
        """Test reading integers from non-zero offsets."""
        buf = write_uint8(42) + write_uint16(12345) + write_uint32(987654321)
        val1, off1 = read_uint8(buf, 0)
        val2, off2 = read_uint16(buf, off1)
        val3, off3 = read_uint32(buf, off2)
        self.assertEqual(val1, 42)
        self.assertEqual(val2, 12345)
        self.assertEqual(val3, 987654321)
        self.assertEqual(off3, len(buf))

    def test_read_uint_insufficient_data(self):
        """Test that reading from insufficient buffer raises TLSDecodeError."""
        with self.assertRaises(TLSDecodeError):
            read_uint8(b"", 0)
        with self.assertRaises(TLSDecodeError):
            read_uint16(b"\x00", 0)
        with self.assertRaises(TLSDecodeError):
            read_uint24(b"\x00\x00", 0)
        with self.assertRaises(TLSDecodeError):
            read_uint32(b"\x00\x00\x00", 0)
        with self.assertRaises(TLSDecodeError):
            read_uint64(b"\x00" * 7, 0)

    def test_opaque8_roundtrip(self):
        """Test opaque8 encoding and decoding roundtrip."""
        for data in [b"", b"a", b"hello", b"x" * 255]:
            encoded = write_opaque8(data)
            decoded, offset = read_opaque8(encoded, 0)
            self.assertEqual(decoded, data)
            self.assertEqual(offset, len(encoded))
            self.assertEqual(len(encoded), 1 + len(data))

    def test_opaque16_roundtrip(self):
        """Test opaque16 encoding and decoding roundtrip."""
        for data in [b"", b"a", b"hello world", b"x" * 65535]:
            encoded = write_opaque16(data)
            decoded, offset = read_opaque16(encoded, 0)
            self.assertEqual(decoded, data)
            self.assertEqual(offset, len(encoded))
            self.assertEqual(len(encoded), 2 + len(data))

    def test_opaque24_roundtrip(self):
        """Test opaque24 encoding and decoding roundtrip."""
        for data in [b"", b"a", b"hello world", b"x" * 1000]:
            encoded = write_opaque24(data)
            decoded, offset = read_opaque24(encoded, 0)
            self.assertEqual(decoded, data)
            self.assertEqual(offset, len(encoded))
            self.assertEqual(len(encoded), 3 + len(data))

    def test_opaque_length_limits(self):
        """Test that opaque encodings enforce length limits."""
        with self.assertRaises(ValueError):
            write_opaque8(b"x" * 256)
        with self.assertRaises(ValueError):
            write_opaque16(b"x" * 65536)
        with self.assertRaises(ValueError):
            write_opaque24(b"x" * 0x1000000)

    def test_vector_roundtrip(self):
        """Test vector encoding and decoding roundtrip."""
        data = b"test data"
        for length_bytes in [1, 2, 3]:
            if length_bytes == 1 and len(data) > 0xFF:
                continue
            if length_bytes == 2 and len(data) > 0xFFFF:
                continue
            encoded = write_vector(data, length_bytes)
            decoded, offset = read_vector(encoded, 0, length_bytes)
            self.assertEqual(decoded, data)
            self.assertEqual(offset, length_bytes + len(data))

    def test_vector_length_limits(self):
        """Test that vector encoding enforces length limits."""
        with self.assertRaises(ValueError):
            write_vector(b"x" * 256, 1)
        with self.assertRaises(ValueError):
            write_vector(b"x" * 65536, 2)
        with self.assertRaises(ValueError):
            write_vector(b"x" * 0x1000000, 3)

    def test_vector_invalid_length_bytes(self):
        """Test that invalid length_bytes raises ValueError."""
        with self.assertRaises(ValueError):
            write_vector(b"data", 0)
        with self.assertRaises(ValueError):
            write_vector(b"data", 4)
        with self.assertRaises(ValueError):
            read_vector(b"data", 0, 0)
        with self.assertRaises(ValueError):
            read_vector(b"data", 0, 4)

    def test_read_vector_insufficient_data(self):
        """Test that reading vector from insufficient buffer raises TLSDecodeError."""
        # Valid length prefix but insufficient data
        buf = write_uint16(100)  # Says 100 bytes but only 2 bytes available
        with self.assertRaises(TLSDecodeError):
            read_vector(buf, 0, 2)

    def test_multiple_vectors(self):
        """Test reading multiple vectors sequentially."""
        v1 = write_opaque8(b"first")
        v2 = write_opaque16(b"second")
        v3 = write_opaque24(b"third")
        combined = v1 + v2 + v3
        
        d1, off1 = read_opaque8(combined, 0)
        d2, off2 = read_opaque16(combined, off1)
        d3, off3 = read_opaque24(combined, off2)
        
        self.assertEqual(d1, b"first")
        self.assertEqual(d2, b"second")
        self.assertEqual(d3, b"third")
        self.assertEqual(off3, len(combined))


if __name__ == "__main__":
    unittest.main()

