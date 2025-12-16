"""Comprehensive tests for pymls.crypto.utils module."""

import unittest

from rfc9420.crypto.utils import secure_wipe


class TestCryptoUtils(unittest.TestCase):
    def test_secure_wipe_empty(self):
        """Test secure_wipe with empty bytearray."""
        buf = bytearray()
        secure_wipe(buf)
        self.assertEqual(len(buf), 0)

    def test_secure_wipe_small(self):
        """Test secure_wipe with small bytearray."""
        buf = bytearray(b"hello")
        secure_wipe(buf)
        self.assertEqual(buf, bytearray(b"\x00" * 5))
        self.assertEqual(len(buf), 5)

    def test_secure_wipe_large(self):
        """Test secure_wipe with large bytearray."""
        original = b"x" * 1000
        buf = bytearray(original)
        secure_wipe(buf)
        self.assertEqual(buf, bytearray(b"\x00" * 1000))
        self.assertNotEqual(buf, original)

    def test_secure_wipe_in_place(self):
        """Test that secure_wipe modifies the bytearray in place."""
        buf = bytearray(b"secret")
        buf_id = id(buf)
        secure_wipe(buf)
        # Same object, modified in place
        self.assertEqual(id(buf), buf_id)
        self.assertEqual(buf, bytearray(b"\x00" * 6))

    def test_secure_wipe_all_bytes_zeroed(self):
        """Test that all bytes are zeroed."""
        buf = bytearray(b"\x01\x02\x03\xff\xaa")
        secure_wipe(buf)
        for byte in buf:
            self.assertEqual(byte, 0)


if __name__ == "__main__":
    unittest.main()
