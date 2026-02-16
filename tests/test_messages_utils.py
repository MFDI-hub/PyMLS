"""Comprehensive tests for rfc9420.protocol.messages utility functions."""

import unittest

from rfc9420.protocol.messages import (
    ContentType,
    compute_ciphertext_aad,
    add_zero_padding,
    apply_application_padding,
    remove_application_padding,
)


class TestMessagesUtils(unittest.TestCase):
    def test_compute_ciphertext_aad(self):
        """Test compute_ciphertext_aad function."""
        group_id = b"test_group"
        epoch = 5
        content_type = ContentType.APPLICATION
        authenticated_data = b"auth_data"

        aad = compute_ciphertext_aad(group_id, epoch, content_type, authenticated_data)

        self.assertIsInstance(aad, bytes)
        self.assertGreater(len(aad), 0)
        self.assertIn(group_id, aad)
        self.assertIn(authenticated_data, aad)

    def test_compute_ciphertext_aad_empty(self):
        """Test compute_ciphertext_aad with empty authenticated_data."""
        aad = compute_ciphertext_aad(b"group", 0, ContentType.APPLICATION, b"")
        self.assertIsInstance(aad, bytes)
        self.assertGreater(len(aad), 0)

    def test_compute_ciphertext_aad_different_types(self):
        """Test compute_ciphertext_aad with different content types."""
        group_id = b"group"
        epoch = 1

        aad1 = compute_ciphertext_aad(group_id, epoch, ContentType.APPLICATION, b"")
        aad2 = compute_ciphertext_aad(group_id, epoch, ContentType.COMMIT, b"")

        # Should be different due to content type
        self.assertNotEqual(aad1, aad2)

    def test_add_zero_padding_no_padding_needed(self):
        """Test add_zero_padding when no padding is needed."""
        data = b"test" * 4  # 16 bytes, divisible by 4
        padded = add_zero_padding(data, 4)
        self.assertEqual(padded, data)

    def test_add_zero_padding_needs_padding(self):
        """Test add_zero_padding when padding is needed."""
        data = b"test"  # 4 bytes
        padded = add_zero_padding(data, 8)
        self.assertEqual(len(padded), 8)
        self.assertEqual(padded[:4], data)
        self.assertEqual(padded[4:], b"\x00" * 4)

    def test_add_zero_padding_zero_pad_to(self):
        """Test add_zero_padding with pad_to <= 0."""
        data = b"test"
        padded = add_zero_padding(data, 0)
        self.assertEqual(padded, data)

        padded = add_zero_padding(data, -1)
        self.assertEqual(padded, data)

    def test_add_zero_padding_various_sizes(self):
        """Test add_zero_padding with various pad_to values."""
        data = b"x" * 5  # 5 bytes

        # Pad to 8
        padded = add_zero_padding(data, 8)
        self.assertEqual(len(padded), 8)
        self.assertEqual(padded[:5], data)
        self.assertEqual(padded[5:], b"\x00" * 3)

        # Pad to 16
        padded = add_zero_padding(data, 16)
        self.assertEqual(len(padded), 16)
        self.assertEqual(padded[:5], data)
        self.assertEqual(padded[5:], b"\x00" * 11)

    def test_apply_remove_application_padding_roundtrip(self):
        """Test apply_application_padding and remove_application_padding roundtrip."""
        data = b"test_data"

        padded = apply_application_padding(data, block=32)
        self.assertGreater(len(padded), len(data))

        unpadded = remove_application_padding(padded)
        self.assertEqual(unpadded, data)

    def test_apply_application_padding_block_size(self):
        """Test that apply_application_padding respects block size."""
        data = b"x" * 10
        padded = apply_application_padding(data, block=32)

        # Should be padded to multiple of 32
        self.assertEqual(len(padded) % 32, 0)

    def test_apply_application_padding_already_aligned(self):
        """Test apply_application_padding when data is already aligned."""
        # Data length + 1 (for pad_len byte) should be multiple of block
        data = b"x" * 31  # 31 + 1 = 32, already aligned
        padded = apply_application_padding(data, block=32)

        # Should still add padding byte
        self.assertGreaterEqual(len(padded), len(data) + 1)

    def test_remove_application_padding_empty(self):
        """Test remove_application_padding with empty bytes."""
        result = remove_application_padding(b"")
        self.assertEqual(result, b"")

    def test_remove_application_padding_malformed(self):
        """Test remove_application_padding with malformed padding."""
        # Pad length byte says 100 but only 10 bytes total
        malformed = b"test" + b"\x64"  # pad_len = 100
        result = remove_application_padding(malformed)
        # Should return as-is for malformed input
        self.assertEqual(result, malformed)

    def test_apply_remove_application_padding_various_sizes(self):
        """Test padding roundtrip with various data sizes."""
        for size in [0, 1, 10, 31, 32, 50, 100]:
            data = b"x" * size
            padded = apply_application_padding(data, block=32)
            unpadded = remove_application_padding(padded)
            self.assertEqual(unpadded, data, f"Failed for size {size}")

    def test_apply_application_padding_zero_block(self):
        """Test apply_application_padding with block <= 0."""
        data = b"test"
        padded = apply_application_padding(data, block=0)
        # Should add single zero byte
        self.assertEqual(len(padded), len(data) + 1)
        self.assertEqual(padded[-1], 0)

        padded = apply_application_padding(data, block=-1)
        self.assertEqual(len(padded), len(data) + 1)


if __name__ == "__main__":
    unittest.main()
