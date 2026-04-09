"""
Unit tests for the Cache Response PDU module
"""

import struct
import unittest

from pyrtr.rtr.pdu.cache_response import LENGTH, TYPE, serialize, unserialize
from pyrtr.rtr.pdu.errors import CorruptDataError, UnsupportedProtocolVersionError


class TestSerialize(unittest.TestCase):
    """Test the serialize function"""

    def test_min_values(self):
        """Test min values for serialization"""
        result = serialize(version=0, session=0)
        expected = struct.pack("!BBHI", 0, TYPE, 0, LENGTH)
        self.assertEqual(result, expected)

    def test_max_values(self):
        """Test max values for session ID"""
        result = serialize(version=1, session=65535)
        expected = struct.pack("!BBHI", 1, TYPE, 65535, LENGTH)
        self.assertEqual(result, expected)

    def test_serialize_length(self):
        """Test that serialized output is correct length"""
        result = serialize(version=0, session=1)
        self.assertEqual(len(result), LENGTH)

    def test_serialize_type(self):
        """Test that serialized output has correct type field"""
        result = serialize(version=0, session=1)
        fields = struct.unpack("!BBHI", result)
        self.assertEqual(fields[1], TYPE)


class TestUnserialize(unittest.TestCase):
    """Test the unserialize function"""

    def test_min_values(self):
        """Test min values for unserialization"""
        buffer = struct.pack("!BBHI", 0, TYPE, 0, LENGTH)
        result = unserialize(version=0, buffer=buffer)

        self.assertEqual(result["version"], 0)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["session"], 0)
        self.assertEqual(result["length"], LENGTH)

    def test_max_values(self):
        """Test max values for unserialization"""
        buffer = struct.pack("!BBHI", 1, TYPE, 65535, LENGTH)
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["version"], 1)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["session"], 65535)
        self.assertEqual(result["length"], LENGTH)

    def test_unserialize_roundtrip(self):
        """Test serialize/unserialize roundtrip"""
        original = {"version": 1, "session": 999}
        serialized = serialize(**original)
        unserialized = unserialize(version=1, buffer=serialized)

        self.assertEqual(unserialized["version"], original["version"])
        self.assertEqual(unserialized["session"], original["session"])

    def test_unserialize_returns_typeddict(self):
        """Test that unserialize returns proper CacheResponse structure"""
        buffer = struct.pack("!BBHI", 1, TYPE, 0, LENGTH)
        result = unserialize(version=1, buffer=buffer)

        # Check all required keys are present
        required_keys = {"version", "type", "session", "length"}
        self.assertEqual(set(result.keys()), required_keys)


class TestUnserializeValidation(unittest.TestCase):
    """Test validation logic in unserialize"""

    def test_unserialize_corrupt_data_short_buffer(self):
        """Test that short buffer raises CorruptDataError"""
        buffer = b"\x01\x01\x00\x00"  # Too short
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_corrupt_data_long_buffer(self):
        """Test that buffer longer than LENGTH raises CorruptDataError"""
        buffer = struct.pack("!BBHI", 1, TYPE, 0, LENGTH) + b"\x00"
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
