"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.7
"""

import struct
from typing import TypedDict

VERSION = 1
TYPE = 6
LENGTH = 32


class IPv6Prefix(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    zero: int
    length: int
    flags: int
    prefix_length: int
    max_length: int
    padding: int
    prefix: bytes
    asn: int


def serialize(flags: int, prefix_length: int, max_length: int, prefix: bytes, asn: int) -> bytes:
    """
    Serializes the PDU

    Returns:
    --------
    bytes: Serialized data
    """

    before_prefix = struct.pack(
        "!BBHIBBBB",
        VERSION,
        TYPE,
        0,
        LENGTH,
        flags,
        prefix_length,
        max_length,
        0,
    )
    after_prefix = struct.pack("!I", asn)

    return before_prefix + prefix + after_prefix


def unserialize(buffer: bytes) -> IPv6Prefix:
    """
    Unserializes the PDU

    Arguments:
    ----------
    buffer: bytes
        Binary PDU data

    Returns:
    --------
    IPv4Prefix: Dictionary representing the content
    """
    fields = struct.unpack("!BBHIBBBBDI", buffer)

    pdu: IPv6Prefix = {
        "version": fields[0],
        "type": fields[1],
        "zero": fields[2],
        "length": fields[3],
        "flags": fields[4],
        "prefix_length": fields[5],
        "max_length": fields[6],
        "padding": fields[7],
        "prefix": fields[8],
        "asn": fields[9],
    }

    return pdu


def validate(pdu: IPv6Prefix):
    """
    Raises AssertionError if the PDU is not valid

    Arguments:
    ----------
    pdu: IPv4Prefix
        The PDU to validate
    """
    assert pdu["version"] == VERSION, f"Invalid pdu version: {pdu['version']}"
    assert pdu["type"] == TYPE, f"Invalid pdu tyoe: {pdu['type']}"
    assert pdu["zero"] == 0, f"Invalid pdu zero: {pdu['zero']}"
    assert pdu["length"] == LENGTH, f"Invalid pdu length: {pdu['length']}"
    assert pdu["padding"] == 0, f"Invalid pdu padding: {pdu['zero']}"
