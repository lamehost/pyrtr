"""
Unit tests for the Reset Query PDU module
"""

import struct
import unittest

from pyrtr.rtr.pdu.errors import CorruptDataError, UnsupportedProtocolVersionError
from pyrtr.rtr.pdu.reset_query import LENGTH, TYPE, serialize, unserialize


class TestSerialize(unittest.TestCase):
    """Test the serialize function"""

    def test_version_zero(self):
        """Test serialization with version 0"""
        result = serialize(version=0)
        expected = struct.pack("!BBHI", 0, TYPE, 0, LENGTH)
        self.assertEqual(result, expected)

    def test_version_one(self):
        """Test serialization with version 1"""
        result = serialize(version=1)
        expected = struct.pack("!BBHI", 1, TYPE, 0, LENGTH)
        self.assertEqual(result, expected)

    def test_version_max(self):
        """Test serialization with max version value"""
        result = serialize(version=255)
        expected = struct.pack("!BBHI", 255, TYPE, 0, LENGTH)
        self.assertEqual(result, expected)

    def test_serialize_length(self):
        """Test that serialized output is correct length"""
        result = serialize(version=0)
        self.assertEqual(len(result), LENGTH)

    def test_serialize_type(self):
        """Test that serialized output has correct type field"""
        result = serialize(version=0)
        fields = struct.unpack("!BBHI", result)
        self.assertEqual(fields[1], TYPE)

    def test_serialize_reserved_field(self):
        """Test that reserved field is always 0"""
        result = serialize(version=0)
        fields = struct.unpack("!BBHI", result)
        self.assertEqual(fields[2], 0)

    def test_serialize_length_field(self):
        """Test that length field is set correctly"""
        result = serialize(version=0)
        fields = struct.unpack("!BBHI", result)
        self.assertEqual(fields[3], LENGTH)


class TestUnserialize(unittest.TestCase):
    """Test the unserialize function"""

    def test_unserialize_version_zero(self):
        """Test unserialization with version 0"""
        buffer = struct.pack("!BBHI", 0, TYPE, 0, LENGTH)
        result = unserialize(version=0, buffer=buffer)

        self.assertEqual(result["version"], 0)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["length"], LENGTH)

    def test_unserialize_version_one(self):
        """Test unserialization with version 1"""
        buffer = struct.pack("!BBHI", 1, TYPE, 0, LENGTH)
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["version"], 1)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["length"], LENGTH)

    def test_unserialize_version_max(self):
        """Test unserialization with max version value"""
        buffer = struct.pack("!BBHI", 255, TYPE, 0, LENGTH)
        result = unserialize(version=255, buffer=buffer)

        self.assertEqual(result["version"], 255)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["length"], LENGTH)

    def test_unserialize_roundtrip(self):
        """Test serialize/unserialize roundtrip"""
        original_version = 1
        serialized = serialize(version=original_version)
        unserialized = unserialize(version=original_version, buffer=serialized)

        self.assertEqual(unserialized["version"], original_version)
        self.assertEqual(unserialized["type"], TYPE)
        self.assertEqual(unserialized["length"], LENGTH)

    def test_unserialize_returns_typeddict(self):
        """Test that unserialize returns proper ResetQuery structure"""
        buffer = struct.pack("!BBHI", 1, TYPE, 0, LENGTH)
        result = unserialize(version=1, buffer=buffer)

        # Check all required keys are present
        required_keys = {"version", "type", "length"}
        self.assertEqual(set(result.keys()), required_keys)


class TestUnserializeValidation(unittest.TestCase):
    """Test validation logic in unserialize"""

    def test_unserialize_corrupt_data_short_buffer(self):
        """Test that short buffer raises CorruptDataError"""
        buffer = b"\x01\x01\x00"  # Too short
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_corrupt_data_long_buffer(self):
        """Test that buffer longer than LENGTH raises CorruptDataError"""
        buffer = struct.pack("!BBHI", 1, TYPE, 0, LENGTH) + b"\x00"
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_corrupt_data_empty_buffer(self):
        """Test that empty buffer raises CorruptDataError"""
        buffer = b""
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_version(self):
        """Test that mismatched version raises UnsupportedProtocolVersionError"""
        buffer = struct.pack("!BBHI", 2, TYPE, 0, LENGTH)
        with self.assertRaises(UnsupportedProtocolVersionError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_type(self):
        """Test that invalid TYPE raises CorruptDataError"""
        buffer = struct.pack("!BBHI", 1, 99, 0, LENGTH)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_length_field(self):
        """Test that invalid LENGTH field raises CorruptDataError"""
        buffer = struct.pack("!BBHI", 1, TYPE, 0, 999)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_validation_enabled_by_default(self):
        """Test that validation is enabled by default"""
        buffer = struct.pack("!BBHI", 2, TYPE, 0, LENGTH)
        with self.assertRaises(UnsupportedProtocolVersionError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_no_validation(self):
        """Test that validation can be disabled"""
        # Create a buffer with wrong version but validation disabled
        buffer = struct.pack("!BBHI", 2, TYPE, 0, LENGTH)
        result = unserialize(version=1, buffer=buffer, validate=False)

        # Should return the wrong version without raising
        self.assertEqual(result["version"], 2)

    def test_unserialize_no_validation_wrong_type(self):
        """Test that wrong TYPE is accepted when validation disabled"""
        buffer = struct.pack("!BBHI", 1, 99, 0, LENGTH)
        result = unserialize(version=1, buffer=buffer, validate=False)

        self.assertEqual(result["type"], 99)

    def test_unserialize_no_validation_wrong_length_field(self):
        """Test that wrong LENGTH field is accepted when validation disabled"""
        buffer = struct.pack("!BBHI", 1, TYPE, 0, 999)
        result = unserialize(version=1, buffer=buffer, validate=False)

        self.assertEqual(result["length"], 999)


if __name__ == "__main__":
    unittest.main()
