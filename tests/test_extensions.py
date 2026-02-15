"""Comprehensive tests for rfc9420.extensions.extensions module."""

import unittest

from rfc9420.extensions.extensions import (
    ExtensionType,
    Extension,
    serialize_extensions,
    deserialize_extensions,
    make_parent_hash_ext,
    make_capabilities_ext,
    make_key_id_ext,
    make_lifetime_ext,
    parse_lifetime_ext,
    make_external_pub_ext,
    parse_external_pub_ext,
    build_capabilities_data,
    parse_capabilities_data,
    build_required_capabilities,
    parse_required_capabilities,
)


class TestExtensions(unittest.TestCase):
    def test_extension_serialize_deserialize(self):
        """Test Extension serialize and deserialize."""
        ext = Extension(ExtensionType.PARENT_HASH, b"hash_data")
        serialized = ext.serialize()

        deserialized, bytes_used = Extension.deserialize(serialized)
        self.assertEqual(deserialized.ext_type, ExtensionType.PARENT_HASH)
        self.assertEqual(deserialized.data, b"hash_data")
        self.assertEqual(bytes_used, len(serialized))

    def test_serialize_deserialize_extensions_empty(self):
        """Test serializing and deserializing empty extensions list."""
        exts = []
        serialized = serialize_extensions(exts)
        deserialized = deserialize_extensions(serialized)

        self.assertEqual(len(deserialized), 0)

    def test_serialize_deserialize_extensions_multiple(self):
        """Test serializing and deserializing multiple extensions."""
        exts = [
            Extension(ExtensionType.PARENT_HASH, b"hash1"),
            Extension(ExtensionType.KEY_ID, b"key_id1"),
            Extension(ExtensionType.LIFETIME, b"lifetime_data"),
        ]

        serialized = serialize_extensions(exts)
        deserialized = deserialize_extensions(serialized)

        self.assertEqual(len(deserialized), 3)
        self.assertEqual(deserialized[0].ext_type, ExtensionType.PARENT_HASH)
        self.assertEqual(deserialized[0].data, b"hash1")
        self.assertEqual(deserialized[1].ext_type, ExtensionType.KEY_ID)
        self.assertEqual(deserialized[1].data, b"key_id1")

    def test_make_parent_hash_ext(self):
        """Test make_parent_hash_ext."""
        hash_data = b"\x00" * 32
        ext = make_parent_hash_ext(hash_data)

        self.assertEqual(ext.ext_type, ExtensionType.PARENT_HASH)
        self.assertEqual(ext.data, hash_data)

    def test_make_capabilities_ext(self):
        """Test make_capabilities_ext."""
        cap_data = b"capabilities_data"
        ext = make_capabilities_ext(cap_data)

        self.assertEqual(ext.ext_type, ExtensionType.CAPABILITIES)
        self.assertEqual(ext.data, cap_data)

    def test_make_key_id_ext(self):
        """Test make_key_id_ext."""
        key_id = b"key_identifier"
        ext = make_key_id_ext(key_id)

        self.assertEqual(ext.ext_type, ExtensionType.KEY_ID)
        self.assertEqual(ext.data, key_id)

    def test_make_parse_lifetime_ext(self):
        """Test make_lifetime_ext and parse_lifetime_ext."""
        not_before = 1000000000
        not_after = 2000000000

        ext = make_lifetime_ext(not_before, not_after)
        self.assertEqual(ext.ext_type, ExtensionType.LIFETIME)

        parsed_before, parsed_after = parse_lifetime_ext(ext.data)
        self.assertEqual(parsed_before, not_before)
        self.assertEqual(parsed_after, not_after)

    def test_make_parse_external_pub_ext(self):
        """Test make_external_pub_ext and parse_external_pub_ext."""
        pub_key = b"public_key_data"

        ext = make_external_pub_ext(pub_key)
        self.assertEqual(ext.ext_type, ExtensionType.EXTERNAL_PUB)

        parsed = parse_external_pub_ext(ext.data)
        self.assertEqual(parsed, pub_key)

    def test_build_parse_capabilities_data(self):
        """Test build_capabilities_data and parse_capabilities_data."""
        ciphersuite_ids = [0x0001, 0x0002, 0x0003]
        supported_exts = [ExtensionType.PARENT_HASH, ExtensionType.KEY_ID]

        data = build_capabilities_data(ciphersuite_ids, supported_exts)
        parsed_ids, parsed_exts = parse_capabilities_data(data)

        self.assertEqual(parsed_ids, ciphersuite_ids)
        self.assertEqual(parsed_exts, supported_exts)

    def test_build_parse_capabilities_data_empty(self):
        """Test build/parse capabilities with empty lists."""
        data = build_capabilities_data([], [])
        parsed_ids, parsed_exts = parse_capabilities_data(data)

        self.assertEqual(parsed_ids, [])
        self.assertEqual(parsed_exts, [])

    def test_build_parse_required_capabilities(self):
        """Test build_required_capabilities and parse_required_capabilities."""
        required = [ExtensionType.PARENT_HASH, ExtensionType.LIFETIME]

        data = build_required_capabilities(required)
        parsed = parse_required_capabilities(data)

        self.assertEqual(parsed, required)

    def test_build_parse_required_capabilities_empty(self):
        """Test build/parse required capabilities with empty list."""
        data = build_required_capabilities([])
        parsed = parse_required_capabilities(data)

        self.assertEqual(parsed, [])

    def test_extension_roundtrip_all_types(self):
        """Test roundtrip for all extension types."""
        test_cases = [
            (ExtensionType.PARENT_HASH, b"hash"),
            (ExtensionType.KEY_ID, b"key_id"),
            (ExtensionType.CAPABILITIES, b"caps"),
            (ExtensionType.LIFETIME, b"lifetime"),
            (ExtensionType.EXTERNAL_PUB, b"pub_key"),
        ]

        for ext_type, data in test_cases:
            ext = Extension(ext_type, data)
            serialized = ext.serialize()
            deserialized, _ = Extension.deserialize(serialized)

            self.assertEqual(deserialized.ext_type, ext_type)
            self.assertEqual(deserialized.data, data)


if __name__ == "__main__":
    unittest.main()
