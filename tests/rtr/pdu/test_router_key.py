"""
Unit tests for the Router Key PDU module
"""

import struct
import unittest
from typing import Any

from pyrtr.rtr.pdu.errors import CorruptDataError, UnsupportedProtocolVersionError
from pyrtr.rtr.pdu.router_key import LENGTH, TYPE, serialize, unserialize


class TestSerialize(unittest.TestCase):
    """Test the serialize function"""

    def test_min_values(self):
        """Test min values for serialization"""
        result = serialize(version=0, flags=0, ski=b"\x00" * 20, asn=0, spki=b"\x00" * 91)
        self.assertEqual(len(result), LENGTH)
        fields = struct.unpack("!BBBBI", result[:8])
        self.assertEqual(fields[0], 0)
        self.assertEqual(fields[1], TYPE)
        self.assertEqual(fields[2], 0)
        self.assertEqual(fields[4], LENGTH)

    def test_max_values(self):
        """Test max values for serialization"""
        result = serialize(version=1, flags=1, ski=b"\xff" * 20, asn=4294967295, spki=b"\xff" * 91)
        self.assertEqual(len(result), LENGTH)
        fields = struct.unpack("!BBBBI", result[:8])
        self.assertEqual(fields[0], 1)
        self.assertEqual(fields[1], TYPE)
        self.assertEqual(fields[2], 1)
        self.assertEqual(fields[4], LENGTH)

    def test_serialize_length(self):
        """Test that serialized output is correct length"""
        result = serialize(version=0, flags=0, ski=b"\x00" * 20, asn=1, spki=b"\x00" * 91)
        self.assertEqual(len(result), LENGTH)

    def test_serialize_type(self):
        """Test that serialized output has correct type field"""
        result = serialize(version=0, flags=0, ski=b"\x00" * 20, asn=1, spki=b"\x00" * 91)
        fields = struct.unpack("!BBBBI", result[:8])
        self.assertEqual(fields[1], TYPE)

    def test_serialize_flags_announcement(self):
        """Test serialization with announcement flag"""
        result = serialize(version=0, flags=1, ski=b"\x00" * 20, asn=1, spki=b"\x00" * 91)
        fields = struct.unpack("!BBBBI", result[:8])
        self.assertEqual(fields[2], 1)

    def test_serialize_flags_withdrawal(self):
        """Test serialization with withdrawal flag"""
        result = serialize(version=0, flags=0, ski=b"\x00" * 20, asn=1, spki=b"\x00" * 91)
        fields = struct.unpack("!BBBBI", result[:8])
        self.assertEqual(fields[2], 0)

    def test_serialize_ski_placement(self):
        """Test that SKI is placed correctly in serialized output"""
        ski = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
        result = serialize(version=0, flags=0, ski=ski, asn=1, spki=b"\x00" * 91)
        self.assertEqual(result[8:28], ski)

    def test_serialize_asn_placement(self):
        """Test that ASN is placed correctly in serialized output"""
        result = serialize(version=0, flags=0, ski=b"\x00" * 20, asn=0x12345678, spki=b"\x00" * 91)
        asn_bytes = struct.unpack("!I", result[28:32])[0]
        self.assertEqual(asn_bytes, 0x12345678)

    def test_serialize_spki_placement(self):
        """Test that SPKI is placed correctly in serialized output"""
        spki = b"\xff" * 91
        result = serialize(version=0, flags=0, ski=b"\x00" * 20, asn=1, spki=spki)
        self.assertEqual(result[32:], spki)


class TestUnserialize(unittest.TestCase):
    """Test the unserialize function"""

    def test_min_values(self):
        """Test min values for unserialization"""
        buffer = (
            struct.pack("!BBBBI", 0, TYPE, 0, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
        )
        result = unserialize(version=0, buffer=buffer)

        self.assertEqual(result["version"], 0)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["flags"], 0)
        self.assertEqual(result["length"], LENGTH)
        self.assertEqual(result["ski"], b"\x00" * 20)
        self.assertEqual(result["asn"], 0)
        self.assertEqual(result["spki"], b"\x00" * 91)

    def test_max_values(self):
        """Test max values for unserialization"""
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 1, 0, LENGTH)
            + b"\xff" * 20
            + struct.pack("!I", 4294967295)
            + b"\xff" * 91
        )
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["version"], 1)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["flags"], 1)
        self.assertEqual(result["length"], LENGTH)
        self.assertEqual(result["ski"], b"\xff" * 20)
        self.assertEqual(result["asn"], 4294967295)
        self.assertEqual(result["spki"], b"\xff" * 91)

    def test_unserialize_roundtrip(self):
        """Test serialize/unserialize roundtrip"""
        ski = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x00" * 14
        spki = b"\x11\x22\x33\x44\x55\x66\x77\x88" + b"\x00" * 83
        original: dict[str, Any] = {
            "version": 1,
            "flags": 1,
            "ski": ski,
            "asn": 12345,
            "spki": spki,
        }

        serialized = serialize(**original)
        unserialized = unserialize(version=1, buffer=serialized)

        self.assertEqual(unserialized["version"], original["version"])
        self.assertEqual(unserialized["flags"], original["flags"])
        self.assertEqual(unserialized["ski"], original["ski"])
        self.assertEqual(unserialized["asn"], original["asn"])
        self.assertEqual(unserialized["spki"], original["spki"])

    def test_unserialize_returns_typeddict(self):
        """Test that unserialize returns proper RouterKey structure"""
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 0, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
        )
        result = unserialize(version=1, buffer=buffer)

        # Check all required keys are present
        required_keys = {"version", "type", "flags", "length", "ski", "asn", "spki"}
        self.assertEqual(set(result.keys()), required_keys)

    def test_unserialize_ski_extraction(self):
        """Test that SKI is correctly extracted"""
        ski = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x01\x02\x03\x04"
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 0, 0, LENGTH) + ski + struct.pack("!I", 0) + b"\x00" * 91
        )
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["ski"], ski)

    def test_unserialize_asn_extraction(self):
        """Test that ASN is correctly extracted"""
        asn = 65000
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 0, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", asn)
            + b"\x00" * 91
        )
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["asn"], asn)

    def test_unserialize_spki_extraction(self):
        """Test that SPKI is correctly extracted"""
        spki = b"\xaa" * 91
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 0, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + spki
        )
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["spki"], spki)


class TestUnserializeValidation(unittest.TestCase):
    """Test validation logic in unserialize"""

    def test_unserialize_corrupt_data_short_buffer(self):
        """Test that short buffer raises CorruptDataError"""
        buffer = b"\x01\x01\x00\x00"  # Too short
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_corrupt_data_long_buffer(self):
        """Test that buffer longer than LENGTH raises CorruptDataError"""
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 0, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
            + b"\x00"
        )
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_corrupt_data_short_exact_length(self):
        """Test that buffer shorter than LENGTH raises CorruptDataError"""
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 0, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 90
        )
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_version(self):
        """Test that mismatched version raises UnsupportedProtocolVersionError"""
        buffer = (
            struct.pack("!BBBBI", 2, TYPE, 0, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
        )
        with self.assertRaises(UnsupportedProtocolVersionError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_type(self):
        """Test that invalid TYPE raises CorruptDataError"""
        buffer = (
            struct.pack("!BBBBI", 1, 99, 0, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
        )
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_flags_high(self):
        """Test that invalid flags value raises CorruptDataError"""
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 2, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
        )
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_length_field(self):
        """Test that invalid LENGTH field raises CorruptDataError"""
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 0, 0, 999)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
        )
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_no_validation(self):
        """Test that validation can be disabled"""
        # Create a buffer with wrong version but validation disabled
        buffer = (
            struct.pack("!BBBBI", 2, TYPE, 0, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
        )
        result = unserialize(version=1, buffer=buffer, validate=False)

        # Should return the wrong version without raising
        self.assertEqual(result["version"], 2)

    def test_unserialize_no_validation_wrong_type(self):
        """Test that wrong TYPE is accepted when validation disabled"""
        buffer = (
            struct.pack("!BBBBI", 1, 99, 0, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
        )
        result = unserialize(version=1, buffer=buffer, validate=False)

        self.assertEqual(result["type"], 99)

    def test_unserialize_no_validation_wrong_flags(self):
        """Test that wrong flags are accepted when validation disabled"""
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 2, 0, LENGTH)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
        )
        result = unserialize(version=1, buffer=buffer, validate=False)

        self.assertEqual(result["flags"], 2)

    def test_unserialize_no_validation_wrong_length_field(self):
        """Test that wrong LENGTH field is accepted when validation disabled"""
        buffer = (
            struct.pack("!BBBBI", 1, TYPE, 0, 0, 999)
            + b"\x00" * 20
            + struct.pack("!I", 0)
            + b"\x00" * 91
        )
        result = unserialize(version=1, buffer=buffer, validate=False)

        self.assertEqual(result["length"], 999)


if __name__ == "__main__":
    unittest.main()
