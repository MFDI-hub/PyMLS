"""Comprehensive tests for pymls.protocol.refs module."""
import unittest

from pymls.protocol.refs import (
    encode_ref_hash_input,
    make_key_package_ref,
    make_proposal_ref,
)
from pymls import DefaultCryptoProvider


class TestRefs(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()

    def test_encode_ref_hash_input_empty(self):
        """Test encoding RefHashInput with empty label and value."""
        result = encode_ref_hash_input(b"", b"")
        # Should have two 4-byte length prefixes
        self.assertEqual(len(result), 8)

    def test_encode_ref_hash_input_with_data(self):
        """Test encoding RefHashInput with label and value."""
        label = b"test_label"
        value = b"test_value"
        result = encode_ref_hash_input(label, value)
        
        # Should contain label and value with length prefixes
        self.assertGreater(len(result), len(label) + len(value))
        self.assertIn(label, result)
        self.assertIn(value, result)

    def test_encode_ref_hash_input_structure(self):
        """Test that encode_ref_hash_input produces correct structure."""
        label = b"MLS 1.0 KeyPackage Reference"
        value = b"key_package_data"
        result = encode_ref_hash_input(label, value)
        
        # Should start with 4-byte length prefix for label
        import struct
        label_len = struct.unpack("!L", result[:4])[0]
        self.assertEqual(label_len, len(label))
        
        # Next should be label
        self.assertEqual(result[4:4+label_len], label)
        
        # Then 4-byte length prefix for value
        value_len = struct.unpack("!L", result[4+label_len:4+label_len+4])[0]
        self.assertEqual(value_len, len(value))
        
        # Then value
        self.assertEqual(result[4+label_len+4:4+label_len+4+value_len], value)

    def test_make_key_package_ref(self):
        """Test make_key_package_ref function."""
        value = b"key_package_serialized_data"
        ref = make_key_package_ref(self.crypto, value)
        
        # Should produce hash of correct length
        self.assertEqual(len(ref), self.crypto.kdf_hash_len())
        self.assertIsInstance(ref, bytes)

    def test_make_key_package_ref_deterministic(self):
        """Test that make_key_package_ref is deterministic."""
        value = b"same_key_package_data"
        ref1 = make_key_package_ref(self.crypto, value)
        ref2 = make_key_package_ref(self.crypto, value)
        
        self.assertEqual(ref1, ref2)

    def test_make_key_package_ref_different_values(self):
        """Test that different values produce different refs."""
        value1 = b"key_package_1"
        value2 = b"key_package_2"
        
        ref1 = make_key_package_ref(self.crypto, value1)
        ref2 = make_key_package_ref(self.crypto, value2)
        
        self.assertNotEqual(ref1, ref2)

    def test_make_proposal_ref(self):
        """Test make_proposal_ref function."""
        value = b"proposal_serialized_data"
        ref = make_proposal_ref(self.crypto, value)
        
        # Should produce hash of correct length
        self.assertEqual(len(ref), self.crypto.kdf_hash_len())
        self.assertIsInstance(ref, bytes)

    def test_make_proposal_ref_deterministic(self):
        """Test that make_proposal_ref is deterministic."""
        value = b"same_proposal_data"
        ref1 = make_proposal_ref(self.crypto, value)
        ref2 = make_proposal_ref(self.crypto, value)
        
        self.assertEqual(ref1, ref2)

    def test_make_proposal_ref_different_values(self):
        """Test that different values produce different refs."""
        value1 = b"proposal_1"
        value2 = b"proposal_2"
        
        ref1 = make_proposal_ref(self.crypto, value1)
        ref2 = make_proposal_ref(self.crypto, value2)
        
        self.assertNotEqual(ref1, ref2)

    def test_key_package_ref_vs_proposal_ref_different(self):
        """Test that key package refs and proposal refs use different labels."""
        # Same value but different ref types should produce different hashes
        value = b"same_data"
        
        kp_ref = make_key_package_ref(self.crypto, value)
        prop_ref = make_proposal_ref(self.crypto, value)
        
        # Should be different because labels are different
        self.assertNotEqual(kp_ref, prop_ref)

    def test_refs_with_empty_value(self):
        """Test ref functions with empty value."""
        kp_ref = make_key_package_ref(self.crypto, b"")
        prop_ref = make_proposal_ref(self.crypto, b"")
        
        self.assertEqual(len(kp_ref), self.crypto.kdf_hash_len())
        self.assertEqual(len(prop_ref), self.crypto.kdf_hash_len())


if __name__ == "__main__":
    unittest.main()

