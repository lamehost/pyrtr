"""
Unit tests for the End of Data PDU module
"""

import struct
import unittest

from pyrtr.rtr.pdu.end_of_data import (
    LENGTH_V0,
    LENGTH_V1,
    TYPE,
    EndOfDataV0,
    EndOfDataV1,
    serialize,
    serialize_v0,
    serialize_v1,
    unserialize,
    unserialize_v0,
    unserialize_v1,
)
from pyrtr.rtr.pdu.errors import CorruptDataError, UnsupportedProtocolVersionError


class TestSerializeV0(unittest.TestCase):
    """Test the serialize_v0 function"""

    def test_min_values(self):
        """Test min values for serialization"""
        result = serialize_v0(session=0, serial=0)
        expected = struct.pack("!BBHII", 0, TYPE, 0, LENGTH_V0, 0)
        self.assertEqual(result, expected)

    def test_max_values(self):
        """Test max values for session and serial"""
        result = serialize_v0(session=65535, serial=4294967295)
        expected = struct.pack("!BBHII", 0, TYPE, 65535, LENGTH_V0, 4294967295)
        self.assertEqual(result, expected)

    def test_serialize_length(self):
        """Test that serialized output is correct length"""
        result = serialize_v0(session=1, serial=1)
        self.assertEqual(len(result), LENGTH_V0)

    def test_serialize_type(self):
        """Test that serialized output has correct type field"""
        result = serialize_v0(session=1, serial=1)
        fields = struct.unpack("!BBHII", result)
        self.assertEqual(fields[1], TYPE)

    def test_serialize_version(self):
        """Test that serialized output has correct version"""
        result = serialize_v0(session=1, serial=1)
        fields = struct.unpack("!BBHII", result)
        self.assertEqual(fields[0], 0)


class TestSerializeV1(unittest.TestCase):
    """Test the serialize_v1 function"""

    def test_min_values(self):
        """Test min values for serialization"""
        result = serialize_v1(session=0, serial=0)
        expected = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 3600, 600, 7200)
        self.assertEqual(result, expected)

    def test_max_values(self):
        """Test max values for session and serial"""
        result = serialize_v1(
            session=65535, serial=4294967295, refresh=86400, retry=7200, expire=172800
        )
        expected = struct.pack(
            "!BBHIIIII", 1, TYPE, 65535, LENGTH_V1, 4294967295, 86400, 7200, 172800
        )
        self.assertEqual(result, expected)

    def test_serialize_length(self):
        """Test that serialized output is correct length"""
        result = serialize_v1(session=1, serial=1)
        self.assertEqual(len(result), LENGTH_V1)

    def test_serialize_type(self):
        """Test that serialized output has correct type field"""
        result = serialize_v1(session=1, serial=1)
        fields = struct.unpack("!BBHIIIII", result)
        self.assertEqual(fields[1], TYPE)

    def test_serialize_version(self):
        """Test that serialized output has correct version"""
        result = serialize_v1(session=1, serial=1)
        fields = struct.unpack("!BBHIIIII", result)
        self.assertEqual(fields[0], 1)

    def test_serialize_default_intervals(self):
        """Test that default intervals are used"""
        result = serialize_v1(session=1, serial=1)
        fields = struct.unpack("!BBHIIIII", result)
        self.assertEqual(fields[5], 3600)  # refresh
        self.assertEqual(fields[6], 600)  # retry
        self.assertEqual(fields[7], 7200)  # expire

    def test_serialize_custom_intervals(self):
        """Test custom refresh, retry, and expire values"""
        result = serialize_v1(session=1, serial=1, refresh=1800, retry=300, expire=3600)
        fields = struct.unpack("!BBHIIIII", result)
        self.assertEqual(fields[5], 1800)  # refresh
        self.assertEqual(fields[6], 300)  # retry
        self.assertEqual(fields[7], 3600)  # expire


class TestSerialize(unittest.TestCase):
    """Test the serialize dispatcher function"""

    def test_serialize_v0(self):
        """Test serialize dispatches to serialize_v0"""
        result = serialize(version=0, session=100, serial=200)
        expected = serialize_v0(session=100, serial=200)
        self.assertEqual(result, expected)

    def test_serialize_v1(self):
        """Test serialize dispatches to serialize_v1"""
        result = serialize(version=1, session=100, serial=200)
        expected = serialize_v1(session=100, serial=200)
        self.assertEqual(result, expected)

    def test_serialize_v1_with_intervals(self):
        """Test serialize with custom intervals"""
        result = serialize(
            version=1,
            session=100,
            serial=200,
            refresh=1800,
            retry=300,
            expire=3600,
        )
        expected = serialize_v1(session=100, serial=200, refresh=1800, retry=300, expire=3600)
        self.assertEqual(result, expected)

    def test_serialize_unsupported_version(self):
        """Test that unsupported version raises error"""
        with self.assertRaises(UnsupportedProtocolVersionError):
            serialize(version=2, session=0, serial=0)

    def test_serialize_negative_version(self):
        """Test that negative version raises error"""
        with self.assertRaises(UnsupportedProtocolVersionError):
            serialize(version=-1, session=0, serial=0)


class TestUnserializeV0(unittest.TestCase):
    """Test the unserialize_v0 function"""

    def test_min_values(self):
        """Test min values for unserialization"""
        buffer = struct.pack("!BBHII", 0, TYPE, 0, LENGTH_V0, 0)
        result: EndOfDataV0 = unserialize_v0(buffer)

        self.assertEqual(result["version"], 0)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["session"], 0)
        self.assertEqual(result["length"], LENGTH_V0)
        self.assertEqual(result["serial"], 0)

    def test_max_values(self):
        """Test max values for unserialization"""
        buffer = struct.pack("!BBHII", 0, TYPE, 65535, LENGTH_V0, 4294967295)
        result: EndOfDataV0 = unserialize_v0(buffer)

        self.assertEqual(result["version"], 0)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["session"], 65535)
        self.assertEqual(result["length"], LENGTH_V0)
        self.assertEqual(result["serial"], 4294967295)

    def test_unserialize_roundtrip(self):
        """Test serialize/unserialize roundtrip"""
        original_session = 999
        original_serial = 123456
        serialized = serialize_v0(session=original_session, serial=original_serial)
        unserialized: EndOfDataV0 = unserialize_v0(serialized)

        self.assertEqual(unserialized["session"], original_session)
        self.assertEqual(unserialized["serial"], original_serial)

    def test_unserialize_returns_typeddict(self):
        """Test that unserialize returns proper EndOfDataV0 structure"""
        buffer = struct.pack("!BBHII", 0, TYPE, 0, LENGTH_V0, 0)
        result: EndOfDataV0 = unserialize_v0(buffer)

        # Check all required keys are present
        required_keys = {"version", "type", "session", "length", "serial"}
        self.assertEqual(set(result.keys()), required_keys)


class TestUnserializeV1(unittest.TestCase):
    """Test the unserialize_v1 function"""

    def test_min_values(self):
        """Test min values for unserialization"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 3600, 600, 7200)
        result: EndOfDataV1 = unserialize_v1(buffer)

        self.assertEqual(result["version"], 1)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["session"], 0)
        self.assertEqual(result["length"], LENGTH_V1)
        self.assertEqual(result["serial"], 0)
        self.assertEqual(result["refresh"], 3600)
        self.assertEqual(result["retry"], 600)
        self.assertEqual(result["expire"], 7200)

    def test_max_values(self):
        """Test max values for unserialization"""
        buffer = struct.pack(
            "!BBHIIIII", 1, TYPE, 65535, LENGTH_V1, 4294967295, 86400, 7200, 172800
        )
        result: EndOfDataV1 = unserialize_v1(buffer)

        self.assertEqual(result["version"], 1)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["session"], 65535)
        self.assertEqual(result["length"], LENGTH_V1)
        self.assertEqual(result["serial"], 4294967295)
        self.assertEqual(result["refresh"], 86400)
        self.assertEqual(result["retry"], 7200)
        self.assertEqual(result["expire"], 172800)

    def test_unserialize_roundtrip(self):
        """Test serialize/unserialize roundtrip"""
        original_session = 999
        original_serial = 123456
        original_refresh = 1800
        original_retry = 300
        original_expire = 3600

        serialized = serialize_v1(
            session=original_session,
            serial=original_serial,
            refresh=original_refresh,
            retry=original_retry,
            expire=original_expire,
        )
        unserialized: EndOfDataV1 = unserialize_v1(serialized)

        self.assertEqual(unserialized["session"], original_session)
        self.assertEqual(unserialized["serial"], original_serial)
        self.assertEqual(unserialized["refresh"], original_refresh)
        self.assertEqual(unserialized["retry"], original_retry)
        self.assertEqual(unserialized["expire"], original_expire)

    def test_unserialize_returns_typeddict(self):
        """Test that unserialize returns proper EndOfDataV1 structure"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 3600, 600, 7200)
        result = unserialize_v1(buffer)

        # Check all required keys are present
        required_keys = {
            "version",
            "type",
            "session",
            "length",
            "serial",
            "refresh",
            "retry",
            "expire",
        }
        self.assertEqual(set(result.keys()), required_keys)


class TestUnserializeV0Validation(unittest.TestCase):
    """Test validation logic in unserialize_v0"""

    def test_unserialize_corrupt_data_short_buffer(self):
        """Test that short buffer raises CorruptDataError"""
        buffer = b"\x00\x07\x00\x00"  # Too short
        with self.assertRaises(CorruptDataError):
            unserialize(version=0, buffer=buffer)

    def test_unserialize_corrupt_data_long_buffer(self):
        """Test that buffer longer than LENGTH_V0 raises CorruptDataError"""
        buffer = struct.pack("!BBHII", 0, TYPE, 0, LENGTH_V0, 0) + b"\x00"
        with self.assertRaises(CorruptDataError):
            unserialize(version=0, buffer=buffer)

    def test_unserialize_invalid_version(self):
        """Test that mismatched version raises UnsupportedProtocolVersionError"""
        buffer = struct.pack("!BBHII", 1, TYPE, 0, LENGTH_V0, 0)
        with self.assertRaises(UnsupportedProtocolVersionError):
            unserialize(version=0, buffer=buffer)

    def test_unserialize_invalid_type(self):
        """Test that invalid TYPE raises CorruptDataError"""
        buffer = struct.pack("!BBHII", 0, 99, 0, LENGTH_V0, 0)
        with self.assertRaises(CorruptDataError):
            unserialize(version=0, buffer=buffer)

    def test_unserialize_invalid_length_field(self):
        """Test that invalid LENGTH field raises CorruptDataError"""
        buffer = struct.pack("!BBHII", 0, TYPE, 0, 999, 0)
        with self.assertRaises(CorruptDataError):
            unserialize(version=0, buffer=buffer)

    def test_unserialize_no_validation(self):
        """Test that validation can be disabled"""
        # Create a buffer with wrong version but validation disabled
        buffer = struct.pack("!BBHII", 1, TYPE, 0, LENGTH_V0, 0)
        result = unserialize_v0(buffer, validate=False)

        # Should return the wrong version without raising
        self.assertEqual(result["version"], 1)

    def test_unserialize_no_validation_wrong_type(self):
        """Test that wrong TYPE is accepted when validation disabled"""
        buffer = struct.pack("!BBHII", 0, 99, 0, LENGTH_V0, 0)
        result = unserialize_v0(buffer, validate=False)

        self.assertEqual(result["type"], 99)

    def test_unserialize_no_validation_wrong_length_field(self):
        """Test that wrong LENGTH field is accepted when validation disabled"""
        buffer = struct.pack("!BBHII", 0, TYPE, 0, 999, 0)
        result = unserialize_v0(buffer, validate=False)

        self.assertEqual(result["length"], 999)


class TestUnserializeV1Validation(unittest.TestCase):
    """Test validation logic in unserialize_v1"""

    def test_unserialize_corrupt_data_short_buffer(self):
        """Test that short buffer raises CorruptDataError"""
        buffer = b"\x01\x07\x00\x00"  # Too short
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_corrupt_data_long_buffer(self):
        """Test that buffer longer than LENGTH_V1 raises CorruptDataError"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 3600, 600, 7200) + b"\x00"
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_version(self):
        """Test that mismatched version raises UnsupportedProtocolVersionError"""
        buffer = struct.pack("!BBHIIIII", 0, TYPE, 0, LENGTH_V1, 0, 3600, 600, 7200)
        with self.assertRaises(UnsupportedProtocolVersionError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_type(self):
        """Test that invalid TYPE raises CorruptDataError"""
        buffer = struct.pack("!BBHIIIII", 1, 99, 0, LENGTH_V1, 0, 3600, 600, 7200)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_length_field(self):
        """Test that invalid LENGTH field raises CorruptDataError"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, 999, 0, 3600, 600, 7200)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_refresh_too_low(self):
        """Test that refresh < 1 raises CorruptDataError"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 0, 600, 7200)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_refresh_too_high(self):
        """Test that refresh > 86400 raises CorruptDataError"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 86401, 600, 7200)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_retry_too_low(self):
        """Test that retry < 1 raises CorruptDataError"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 3600, 0, 7200)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_retry_too_high(self):
        """Test that retry > 7200 raises CorruptDataError"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 3600, 7201, 7200)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_expire_too_low(self):
        """Test that expire < 1 raises CorruptDataError"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 3600, 600, 0)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_expire_too_high(self):
        """Test that expire > 172800 raises CorruptDataError"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 3600, 600, 172801)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_no_validation(self):
        """Test that validation can be disabled"""
        # Create a buffer with wrong intervals but validation disabled
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 0, LENGTH_V1, 0, 0, 0, 0)
        result = unserialize(version=1, buffer=buffer, validate=False)

        self.assertEqual(result["refresh"], 0)
        self.assertEqual(result["retry"], 0)
        self.assertEqual(result["expire"], 0)


class TestUnserializeDispatcher(unittest.TestCase):
    """Test the unserialize dispatcher function"""

    def test_unserialize_v0(self):
        """Test unserialize dispatches to unserialize_v0"""
        buffer = struct.pack("!BBHII", 0, TYPE, 100, LENGTH_V0, 200)
        result = unserialize(version=0, buffer=buffer)

        self.assertEqual(result["version"], 0)
        self.assertEqual(result["session"], 100)
        self.assertEqual(result["serial"], 200)

    def test_unserialize_v1(self):
        """Test unserialize dispatches to unserialize_v1"""
        buffer = struct.pack("!BBHIIIII", 1, TYPE, 100, LENGTH_V1, 200, 3600, 600, 7200)
        result: EndOfDataV1 = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["version"], 1)
        self.assertEqual(result["session"], 100)
        self.assertEqual(result["serial"], 200)
        self.assertEqual(result["refresh"], 3600)

    def test_unserialize_unsupported_version(self):
        """Test that unsupported version raises error"""
        buffer = b"\x00" * LENGTH_V0
        with self.assertRaises(UnsupportedProtocolVersionError):
            unserialize(version=2, buffer=buffer)  # type: ignore

    def test_unserialize_corrupt_data_wraps_struct_error_v0(self):
        """Test that struct.error is wrapped in CorruptDataError for V0"""
        buffer = b"\x00\x07"  # Too short to unpack
        with self.assertRaises(CorruptDataError) as context:
            unserialize(version=0, buffer=buffer)

        self.assertIn("Unable to unpack", str(context.exception))

    def test_unserialize_corrupt_data_wraps_struct_error_v1(self):
        """Test that struct.error is wrapped in CorruptDataError for V1"""
        buffer = b"\x01\x07"  # Too short to unpack
        with self.assertRaises(CorruptDataError) as context:
            unserialize(version=1, buffer=buffer)

        self.assertIn("Unable to unpack", str(context.exception))


class TestRoundtrip(unittest.TestCase):
    """Test full serialize/unserialize roundtrips"""

    def test_roundtrip_v0_min(self):
        """Test roundtrip with minimum values for V0"""
        serialized = serialize(version=0, session=0, serial=0)
        deserialized = unserialize(version=0, buffer=serialized)

        self.assertEqual(deserialized["session"], 0)
        self.assertEqual(deserialized["serial"], 0)

    def test_roundtrip_v0_max(self):
        """Test roundtrip with maximum values for V0"""
        serialized = serialize(version=0, session=65535, serial=4294967295)
        deserialized = unserialize(version=0, buffer=serialized)

        self.assertEqual(deserialized["session"], 65535)
        self.assertEqual(deserialized["serial"], 4294967295)

    def test_roundtrip_v1_min(self):
        """Test roundtrip with minimum values for V1"""
        serialized = serialize(version=1, session=0, serial=0)
        deserialized: EndOfDataV1 = unserialize(version=1, buffer=serialized)

        self.assertEqual(deserialized["session"], 0)
        self.assertEqual(deserialized["serial"], 0)
        self.assertEqual(deserialized["refresh"], 3600)
        self.assertEqual(deserialized["retry"], 600)
        self.assertEqual(deserialized["expire"], 7200)

    def test_roundtrip_v1_max(self):
        """Test roundtrip with maximum values for V1"""
        serialized = serialize(
            version=1,
            session=65535,
            serial=4294967295,
            refresh=86400,
            retry=7200,
            expire=172800,
        )
        deserialized: EndOfDataV1 = unserialize(version=1, buffer=serialized)

        self.assertEqual(deserialized["session"], 65535)
        self.assertEqual(deserialized["serial"], 4294967295)
        self.assertEqual(deserialized["refresh"], 86400)
        self.assertEqual(deserialized["retry"], 7200)
        self.assertEqual(deserialized["expire"], 172800)

    def test_roundtrip_v1_custom_intervals(self):
        """Test roundtrip with custom interval values for V1"""
        serialized = serialize(
            version=1,
            session=999,
            serial=123456,
            refresh=1800,
            retry=300,
            expire=3600,
        )
        deserialized: EndOfDataV1 = unserialize(version=1, buffer=serialized)

        self.assertEqual(deserialized["session"], 999)
        self.assertEqual(deserialized["serial"], 123456)
        self.assertEqual(deserialized["refresh"], 1800)
        self.assertEqual(deserialized["retry"], 300)
        self.assertEqual(deserialized["expire"], 3600)


if __name__ == "__main__":
    unittest.main()
