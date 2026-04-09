"""
Unit tests for the IPv6 Prefix PDU module
"""

import struct
import unittest
from typing import Any

from pyrtr.rtr.pdu.errors import CorruptDataError, UnsupportedProtocolVersionError
from pyrtr.rtr.pdu.ipv6_prefix import LENGTH, TYPE, serialize, unserialize


class TestSerialize(unittest.TestCase):
    """Test the serialize function"""

    def test_min_values(self):
        """Test min values for serialization"""
        result = serialize(
            version=0, flags=0, prefix_length=0, max_length=0, prefix=b"\x00" * 16, asn=0
        )
        self.assertEqual(len(result), LENGTH)
        fields = struct.unpack("!BBHIBBBB8HI", result)
        self.assertEqual(fields[0], 0)
        self.assertEqual(fields[1], TYPE)
        self.assertEqual(fields[4], 0)
        self.assertEqual(fields[5], 0)
        self.assertEqual(fields[6], 0)

    def test_max_values(self):
        """Test max values for serialization"""
        result = serialize(
            version=1,
            flags=1,
            prefix_length=128,
            max_length=128,
            prefix=b"\xff" * 16,
            asn=4294967295,
        )
        self.assertEqual(len(result), LENGTH)
        fields = struct.unpack("!BBHIBBBB8HI", result)
        self.assertEqual(fields[0], 1)
        self.assertEqual(fields[4], 1)
        self.assertEqual(fields[5], 128)
        self.assertEqual(fields[6], 128)
        self.assertEqual(fields[16], 4294967295)

    def test_serialize_length(self):
        """Test that serialized output is correct length"""
        result = serialize(
            version=0, flags=0, prefix_length=64, max_length=64, prefix=b"\x00" * 16, asn=64512
        )
        self.assertEqual(len(result), LENGTH)

    def test_serialize_type(self):
        """Test that serialized output has correct type field"""
        result = serialize(
            version=0, flags=0, prefix_length=64, max_length=64, prefix=b"\x00" * 16, asn=64512
        )
        fields = struct.unpack("!BBHIBBBB8HI", result)
        self.assertEqual(fields[1], TYPE)

    def test_serialize_with_announcement_flag(self):
        """Test serialization with announcement flag (1)"""
        result = serialize(
            version=1,
            flags=1,
            prefix_length=48,
            max_length=64,
            prefix=b"\x20\x01\x0d\xb8" + b"\x00" * 12,
            asn=65001,
        )
        fields = struct.unpack("!BBHIBBBB8HI", result)
        self.assertEqual(fields[4], 1)

    def test_serialize_with_withdrawal_flag(self):
        """Test serialization with withdrawal flag (0)"""
        result = serialize(
            version=1,
            flags=0,
            prefix_length=48,
            max_length=64,
            prefix=b"\x20\x01\x0d\xb8" + b"\x00" * 12,
            asn=65001,
        )
        fields = struct.unpack("!BBHIBBBB8HI", result)
        self.assertEqual(fields[4], 0)


class TestUnserialize(unittest.TestCase):
    """Test the unserialize function"""

    def test_min_values(self):
        """Test min values for unserialization"""
        buffer = serialize(
            version=0, flags=0, prefix_length=0, max_length=0, prefix=b"\x00" * 16, asn=0
        )
        result = unserialize(version=0, buffer=buffer)

        self.assertEqual(result["version"], 0)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["flags"], 0)
        self.assertEqual(result["prefix_length"], 0)
        self.assertEqual(result["max_length"], 0)
        self.assertEqual(result["asn"], 0)

    def test_max_values(self):
        """Test max values for unserialization"""
        buffer = serialize(
            version=1,
            flags=1,
            prefix_length=128,
            max_length=128,
            prefix=b"\xff" * 16,
            asn=4294967295,
        )
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["version"], 1)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["flags"], 1)
        self.assertEqual(result["prefix_length"], 128)
        self.assertEqual(result["max_length"], 128)
        self.assertEqual(result["asn"], 4294967295)

    def test_unserialize_roundtrip(self):
        """Test serialize/unserialize roundtrip"""
        original: dict[str, Any] = {
            "version": 1,
            "flags": 1,
            "prefix_length": 64,
            "max_length": 128,
            "prefix": b"\x20\x01\x0d\xb8" + b"\x00" * 12,
            "asn": 65000,
        }
        serialized = serialize(**original)
        unserialized = unserialize(version=1, buffer=serialized)

        self.assertEqual(unserialized["version"], original["version"])
        self.assertEqual(unserialized["flags"], original["flags"])
        self.assertEqual(unserialized["prefix_length"], original["prefix_length"])
        self.assertEqual(unserialized["max_length"], original["max_length"])
        self.assertEqual(unserialized["asn"], original["asn"])

    def test_unserialize_returns_typeddict(self):
        """Test that unserialize returns proper IPv6Prefix structure"""
        buffer = serialize(
            version=1, flags=0, prefix_length=48, max_length=64, prefix=b"\x00" * 16, asn=65001
        )
        result = unserialize(version=1, buffer=buffer)

        # Check all required keys are present
        required_keys = {
            "version",
            "type",
            "length",
            "flags",
            "prefix_length",
            "max_length",
            "prefix",
            "asn",
        }
        self.assertEqual(set(result.keys()), required_keys)

    def test_unserialize_prefix_extraction(self):
        """Test that prefix is correctly extracted as integer"""
        prefix_bytes = b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        buffer = serialize(
            version=1, flags=0, prefix_length=64, max_length=128, prefix=prefix_bytes, asn=64512
        )
        result = unserialize(version=1, buffer=buffer)

        expected_prefix = int.from_bytes(prefix_bytes, "big")
        self.assertEqual(result["prefix"], expected_prefix)


class TestUnserializeValidation(unittest.TestCase):
    """Test validation logic in unserialize"""

    def test_unserialize_corrupt_data_short_buffer(self):
        """Test that short buffer raises CorruptDataError"""
        buffer = b"\x01\x06\x00\x00"  # Too short
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_corrupt_data_long_buffer(self):
        """Test that buffer longer than LENGTH raises CorruptDataError"""
        buffer = serialize(
            version=1, flags=0, prefix_length=64, max_length=128, prefix=b"\x00" * 16, asn=64512
        )
        buffer = buffer + b"\x00"
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_version(self):
        """Test that mismatched version raises UnsupportedProtocolVersionError"""
        buffer = serialize(
            version=1, flags=0, prefix_length=64, max_length=128, prefix=b"\x00" * 16, asn=64512
        )
        with self.assertRaises(UnsupportedProtocolVersionError):
            unserialize(version=0, buffer=buffer)

    def test_unserialize_invalid_type(self):
        """Test that invalid TYPE raises CorruptDataError"""
        buffer = serialize(
            version=1, flags=0, prefix_length=64, max_length=128, prefix=b"\x00" * 16, asn=64512
        )
        # Corrupt the type field (byte 1)
        buffer_list = bytearray(buffer)
        buffer_list[1] = 99
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=bytes(buffer_list))

    def test_unserialize_invalid_length_field(self):
        """Test that invalid LENGTH field raises CorruptDataError"""
        buffer = serialize(
            version=1, flags=0, prefix_length=64, max_length=128, prefix=b"\x00" * 16, asn=64512
        )
        # Corrupt the length field (bytes 4-5)
        buffer_list = bytearray(buffer)
        buffer_list[4:6] = struct.pack("!H", 999)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=bytes(buffer_list))

    def test_unserialize_invalid_flags(self):
        """Test that invalid flags raise CorruptDataError"""
        buffer = serialize(
            version=1, flags=0, prefix_length=64, max_length=128, prefix=b"\x00" * 16, asn=64512
        )
        # Corrupt the flags field (byte 6)
        buffer_list = bytearray(buffer)
        buffer_list[6] = 2  # Invalid: must be 0 or 1
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=bytes(buffer_list))

    def test_unserialize_invalid_prefix_length(self):
        """Test that prefix_length > 128 raises CorruptDataError"""
        buffer = serialize(
            version=1, flags=0, prefix_length=64, max_length=128, prefix=b"\x00" * 16, asn=64512
        )
        # Corrupt the prefix_length field (byte 7)
        buffer_list = bytearray(buffer)
        buffer_list[7] = 129  # Invalid: must be <= 128
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=bytes(buffer_list))

    def test_unserialize_invalid_max_length(self):
        """Test that max_length > 128 raises CorruptDataError"""
        buffer = serialize(
            version=1, flags=0, prefix_length=64, max_length=128, prefix=b"\x00" * 16, asn=64512
        )
        # Corrupt the max_length field (byte 8)
        buffer_list = bytearray(buffer)
        buffer_list[8] = 129  # Invalid: must be <= 128
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=bytes(buffer_list))

    def test_unserialize_no_validation(self):
        """Test that validation can be disabled"""
        buffer = serialize(
            version=0, flags=0, prefix_length=64, max_length=128, prefix=b"\x00" * 16, asn=64512
        )
        # Corrupt the version to test that it's not validated
        buffer_list = bytearray(buffer)
        buffer_list[0] = 2
        result = unserialize(version=1, buffer=bytes(buffer_list), validate=False)

        # Should return the corrupted version without raising
        self.assertEqual(result["version"], 2)

    def test_unserialize_no_validation_invalid_flags(self):
        """Test that invalid flags are accepted when validation disabled"""
        buffer = serialize(
            version=1, flags=0, prefix_length=64, max_length=128, prefix=b"\x00" * 16, asn=64512
        )
        # Corrupt the flags field
        buffer_list = bytearray(buffer)
        buffer_list[8] = 2
        result = unserialize(version=1, buffer=bytes(buffer_list), validate=False)

        self.assertEqual(result["flags"], 2)

    def test_unserialize_no_validation_invalid_prefix_length(self):
        """Test that invalid prefix_length is accepted when validation disabled"""
        buffer = serialize(
            version=1, flags=0, prefix_length=64, max_length=128, prefix=b"\x00" * 16, asn=64512
        )
        # Corrupt the prefix_length field
        buffer_list = bytearray(buffer)
        buffer_list[9] = 129
        result = unserialize(version=1, buffer=bytes(buffer_list), validate=False)

        self.assertEqual(result["prefix_length"], 129)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""

    def test_serialize_with_various_prefix_lengths(self):
        """Test serialization with various valid prefix lengths"""
        for prefix_length in [0, 1, 64, 127, 128]:
            result = serialize(
                version=1,
                flags=0,
                prefix_length=prefix_length,
                max_length=128,
                prefix=b"\x00" * 16,
                asn=64512,
            )
            unserialized = unserialize(version=1, buffer=result)
            self.assertEqual(unserialized["prefix_length"], prefix_length)

    def test_serialize_with_various_max_lengths(self):
        """Test serialization with various valid max lengths"""
        for max_length in [0, 1, 64, 127, 128]:
            result = serialize(
                version=1,
                flags=0,
                prefix_length=0,
                max_length=max_length,
                prefix=b"\x00" * 16,
                asn=64512,
            )
            unserialized = unserialize(version=1, buffer=result)
            self.assertEqual(unserialized["max_length"], max_length)

    def test_prefix_length_field_consistent(self):
        """Test that all fields are consistently preserved"""
        buffer = serialize(
            version=1, flags=1, prefix_length=96, max_length=110, prefix=b"\x00" * 16, asn=65432
        )
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["length"], LENGTH)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["flags"], 1)
        self.assertEqual(result["prefix_length"], 96)
        self.assertEqual(result["max_length"], 110)
        self.assertEqual(result["asn"], 65432)


if __name__ == "__main__":
    unittest.main()
