"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.4
"""

import struct
from typing import TypedDict

VERSION = 1
TYPE = 2
LENGTH = 8


class ResetQuery(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    zero: int
    length: int


def serialize() -> bytes:
    """
    Serializes the PDU

    Returns:
    --------
    bytes: Serialized data
    """
    return struct.pack("!", VERSION, TYPE, 0, LENGTH)


def unserialize(buffer: bytes) -> ResetQuery:
    """
    Unserializes the PDU

    Arguments:
    ----------
    buffer: bytes
        Binary PDU data

    Returns:
    --------
    ResetQuery: Dictionary representing the content
    """
    fields = struct.unpack("!BBHI", buffer)

    pdu: ResetQuery = {
        "version": fields[0],
        "type": fields[1],
        "zero": fields[2],
        "length": fields[3],
    }

    return pdu


def validate(pdu: ResetQuery):
    """
    Raises AssertionError if the PDU is not valid

    Arguments:
    ----------
    pdu: ResetQuery
        The PDU to validate
    """
    assert pdu["version"] == VERSION, f"Invalid pdu version: {pdu['version']}"
    assert pdu["type"] == TYPE, f"Invalid pdu version: {pdu['type']}"
    assert pdu["length"] == LENGTH, f"Invalid pdu version: {pdu['length']}"
