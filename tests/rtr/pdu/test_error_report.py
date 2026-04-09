"""
Unit tests for the Error Report PDU module
"""

import struct
import unittest
from typing import Any

from pyrtr.rtr.pdu.error_report import TYPE, serialize, unserialize
from pyrtr.rtr.pdu.errors import CorruptDataError, UnsupportedProtocolVersionError


class TestSerialize(unittest.TestCase):
    """Test the serialize function"""

    def test_min_values(self):
        """Test min values for serialization"""
        result = serialize(version=0, error=0, pdu=b"")
        expected = struct.pack("!BBHII", 0, TYPE, 0, 16, 0) + struct.pack("!I", 0)
        self.assertEqual(result, expected)

    def test_max_error_code(self):
        """Test max error code value"""
        result = serialize(version=1, error=8, pdu=b"")
        fields = struct.unpack("!BBHII", result[:12])
        self.assertEqual(fields[2], 8)

    def test_serialize_with_pdu(self):
        """Test serialization with erroneous PDU"""
        pdu_data = b"\x01\x02\x03\x04"
        result = serialize(version=1, error=1, pdu=pdu_data)

        # Extract length field and verify it includes pdu
        fields = struct.unpack("!BBHII", result[:12])
        expected_length = 16 + len(pdu_data)
        self.assertEqual(fields[3], expected_length)

        # Verify pdu is in the result
        self.assertIn(pdu_data, result)

    def test_serialize_with_text(self):
        """Test serialization with error diagnostic message"""
        text = b"Error message"
        result = serialize(version=1, error=1, pdu=b"", text=text)

        fields = struct.unpack("!BBHII", result[:12])
        expected_length = 16 + 0 + len(text)
        self.assertEqual(fields[3], expected_length)

        # Verify text is in the result
        self.assertIn(text, result)

    def test_serialize_with_pdu_and_text(self):
        """Test serialization with both PDU and text"""
        pdu_data = b"\x01\x02\x03\x04"
        text = b"Error message"
        result = serialize(version=1, error=2, pdu=pdu_data, text=text)

        fields = struct.unpack("!BBHII", result[:12])
        expected_length = 16 + len(pdu_data) + len(text)
        self.assertEqual(fields[3], expected_length)

    def test_serialize_type_field(self):
        """Test that serialized output has correct type field"""
        result = serialize(version=0, error=1, pdu=b"")
        fields = struct.unpack("!BBHII", result[:12])
        self.assertEqual(fields[1], TYPE)

    def test_serialize_text_as_string(self):
        """Test that text parameter accepts strings and converts to bytes"""
        text_str = "Error message".encode("utf-8")
        result = serialize(version=1, error=1, pdu=b"", text=text_str)

        # Should complete without error
        self.assertIsInstance(result, bytes)
        self.assertIn(text_str, result)

    def test_serialize_structure(self):
        """Test the structure of serialized output"""
        pdu_data = b"\x01\x02"
        text = b"msg"
        result = serialize(version=1, error=3, pdu=pdu_data, text=text)

        # Unpack and verify structure
        fields = struct.unpack("!BBHII", result[:12])
        pdu_length = fields[4]
        text_length = struct.unpack("!I", result[12 + pdu_length : 12 + pdu_length + 4])[0]

        self.assertEqual(pdu_length, len(pdu_data))
        self.assertEqual(text_length, len(text))


class TestUnserialize(unittest.TestCase):
    """Test the unserialize function"""

    def test_min_values(self):
        """Test min values for unserialization"""
        buffer = struct.pack("!BBHII", 0, TYPE, 0, 16, 0) + struct.pack("!I", 0)
        result = unserialize(version=0, buffer=buffer)

        self.assertEqual(result["version"], 0)
        self.assertEqual(result["type"], TYPE)
        self.assertEqual(result["error"], 0)
        self.assertEqual(result["length"], 16)
        self.assertEqual(result["pdu_length"], 0)
        self.assertEqual(result["pdu"], b"")
        self.assertEqual(result["text_length"], 0)
        self.assertIsNone(result["text"])

    def test_max_error_code(self):
        """Test max error code for unserialization"""
        buffer = struct.pack("!BBHII", 1, TYPE, 8, 16, 0) + struct.pack("!I", 0)
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["error"], 8)

    def test_unserialize_with_pdu(self):
        """Test unserialization with PDU"""
        pdu_data = b"\x01\x02\x03\x04"
        length = 16 + len(pdu_data)
        buffer = (
            struct.pack("!BBHII", 1, TYPE, 1, length, len(pdu_data))
            + pdu_data
            + struct.pack("!I", 0)
        )
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["pdu_length"], len(pdu_data))
        self.assertEqual(result["pdu"], pdu_data)

    def test_unserialize_with_text(self):
        """Test unserialization with error text"""
        text = b"Error message"
        length = 16 + len(text)
        buffer = struct.pack("!BBHII", 1, TYPE, 1, length, 0) + struct.pack("!I", len(text)) + text
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["text_length"], len(text))
        self.assertEqual(result["text"], text.decode("utf-8"))

    def test_unserialize_with_pdu_and_text(self):
        """Test unserialization with both PDU and text"""
        pdu_data = b"\x01\x02\x03\x04"
        text = b"Error message"
        length = 16 + len(pdu_data) + len(text)
        buffer = (
            struct.pack("!BBHII", 1, TYPE, 2, length, len(pdu_data))
            + pdu_data
            + struct.pack("!I", len(text))
            + text
        )
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["pdu_length"], len(pdu_data))
        self.assertEqual(result["pdu"], pdu_data)
        self.assertEqual(result["text_length"], len(text))
        self.assertEqual(result["text"], text.decode("utf-8"))

    def test_unserialize_roundtrip(self):
        """Test serialize/unserialize roundtrip"""
        pdu_data = b"\x01\x02\x03\x04"
        text = b"Error message"
        original: dict[str, Any] = {"version": 1, "error": 5, "pdu": pdu_data, "text": text}

        serialized = serialize(**original)
        unserialized = unserialize(version=1, buffer=serialized)

        self.assertEqual(unserialized["version"], original["version"])
        self.assertEqual(unserialized["error"], original["error"])
        self.assertEqual(unserialized["pdu"], original["pdu"])
        self.assertEqual(unserialized["text"], original["text"].decode("utf-8"))

    def test_unserialize_returns_typeddict(self):
        """Test that unserialize returns proper ErrorReport structure"""
        buffer = struct.pack("!BBHII", 1, TYPE, 0, 16, 0) + struct.pack("!I", 0)
        result = unserialize(version=1, buffer=buffer)

        # Check all required keys are present
        required_keys = {
            "version",
            "type",
            "error",
            "length",
            "pdu_length",
            "pdu",
            "text_length",
            "text",
        }
        self.assertEqual(set(result.keys()), required_keys)

    def test_unserialize_utf8_text(self):
        """Test that text is properly decoded from UTF-8"""
        text = "Error: Ñoño".encode("utf-8")
        length = 16 + len(text)
        buffer = struct.pack("!BBHII", 1, TYPE, 1, length, 0) + struct.pack("!I", len(text)) + text
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["text"], "Error: Ñoño")


class TestUnserializeValidation(unittest.TestCase):
    """Test validation logic in unserialize"""

    def test_unserialize_corrupt_data_short_buffer(self):
        """Test that short buffer raises CorruptDataError"""
        buffer = b"\x01\x01\x00\x00"  # Too short
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_corrupt_data_long_buffer(self):
        """Test that buffer longer than reported length raises CorruptDataError"""
        buffer = struct.pack("!BBHII", 1, TYPE, 0, 16, 0) + struct.pack("!I", 0) + b"\x00"
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_corrupt_data_short_buffer_for_declared_length(self):
        """Test that buffer shorter than declared length raises CorruptDataError"""
        buffer = struct.pack("!BBHII", 1, TYPE, 0, 100, 0)  # Claims 100 bytes but only 16
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_version(self):
        """Test that mismatched version raises UnsupportedProtocolVersionError"""
        buffer = struct.pack("!BBHII", 2, TYPE, 0, 16, 0) + struct.pack("!I", 0)
        with self.assertRaises(UnsupportedProtocolVersionError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_type(self):
        """Test that invalid TYPE raises CorruptDataError"""
        buffer = struct.pack("!BBHII", 1, 99, 0, 16, 0) + struct.pack("!I", 0)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_error_code(self):
        """Test that invalid error code raises CorruptDataError"""
        buffer = struct.pack("!BBHII", 1, TYPE, 9, 16, 0) + struct.pack("!I", 0)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_invalid_length_too_large(self):
        """Test that length > 65535 raises CorruptDataError"""
        buffer = struct.pack("!BBHII", 1, TYPE, 0, 65536, 0)
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer)

    def test_unserialize_no_validation(self):
        """Test that validation can be disabled"""
        # Create a buffer with wrong version but validation disabled
        buffer = struct.pack("!BBHII", 2, TYPE, 0, 16, 0) + struct.pack("!I", 0)
        result = unserialize(version=1, buffer=buffer, validate=False)

        # Should return the wrong version without raising
        self.assertEqual(result["version"], 2)

    def test_unserialize_no_validation_wrong_type(self):
        """Test that wrong TYPE is accepted when validation disabled"""
        buffer = struct.pack("!BBHII", 1, 99, 0, 16, 0) + struct.pack("!I", 0)
        result = unserialize(version=1, buffer=buffer, validate=False)

        self.assertEqual(result["type"], 99)

    def test_unserialize_no_validation_invalid_error_code(self):
        """Test that invalid error code is accepted when validation disabled"""
        buffer = struct.pack("!BBHII", 1, TYPE, 9, 16, 0) + struct.pack("!I", 0)
        result = unserialize(version=1, buffer=buffer, validate=False)

        self.assertEqual(result["error"], 9)

    def test_unserialize_no_validation_oversized_length(self):
        """Test that oversized length is accepted when validation disabled"""
        buffer = struct.pack("!BBHII", 1, TYPE, 0, 65536, 0) + struct.pack("!I", 0)
        result = unserialize(version=1, buffer=buffer, validate=False)

        self.assertEqual(result["length"], 65536)

    def test_unserialize_no_validation_corrupt_struct(self):
        """Test that struct error still raises even with validation disabled"""
        buffer = b"\x01\x01\x00\x00"  # Too short
        with self.assertRaises(CorruptDataError):
            unserialize(version=1, buffer=buffer, validate=False)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""

    def test_serialize_large_pdu(self):
        """Test serialization with large PDU"""
        large_pdu = b"\x00" * 10000
        result = serialize(version=1, error=1, pdu=large_pdu)

        fields = struct.unpack("!BBHII", result[:12])
        self.assertEqual(fields[4], len(large_pdu))

    def test_serialize_large_text(self):
        """Test serialization with large text"""
        large_text = "x".encode("utf-8") * 10000
        result = serialize(version=1, error=1, pdu=b"", text=large_text)

        self.assertIn(large_text, result)

    def test_unserialize_empty_pdu_with_text(self):
        """Test unserialization with empty PDU but with text"""
        text = b"Error"
        length = 16 + len(text)
        buffer = struct.pack("!BBHII", 1, TYPE, 1, length, 0) + struct.pack("!I", len(text)) + text
        result = unserialize(version=1, buffer=buffer)

        self.assertEqual(result["pdu"], b"")
        self.assertEqual(result["text"], "Error")

    def test_serialize_empty_bytes_vs_none(self):
        """Test that default empty bytes works correctly"""
        result1 = serialize(version=1, error=1, pdu=b"")
        result2 = serialize(version=1, error=1, pdu=b"", text=b"")

        self.assertEqual(result1, result2)

    def test_all_error_codes(self):
        """Test all valid error codes"""
        for error_code in range(9):
            buffer = struct.pack("!BBHII", 1, TYPE, error_code, 16, 0) + struct.pack("!I", 0)
            result = unserialize(version=1, buffer=buffer)
            self.assertEqual(result["error"], error_code)


if __name__ == "__main__":
    unittest.main()
