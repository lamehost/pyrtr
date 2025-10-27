"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.5
"""

import struct
from typing import TypedDict

VERSION = 1
TYPE = 3
LENGTH = 8


class CacheResponse(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    session: int
    length: int


def serialize(session: int) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    session: int
        The RTR session ID

    Returns:
    --------
    bytes: Serialized data
    """
    return struct.pack(
        "!BBHI",
        VERSION,
        TYPE,
        session,
        LENGTH,
    )


def unserialize(buffer: bytes) -> CacheResponse:
    """
    Unserializes the PDU

    Arguments:
    ----------
    buffer: bytes
        Binary PDU data

    Returns:
    --------
    CacheResponse: Dictionary representing the content
    """
    fields = struct.unpack("!BBHI", buffer)

    pdu: CacheResponse = {
        "version": fields[0],
        "type": fields[1],
        "session": fields[2],
        "length": fields[3],
    }

    return pdu


def validate(pdu: CacheResponse):
    """
    Raises AssertionError if the PDU is not valid

    Arguments:
    ----------
    pdu: CacheResponse
        The PDU to validate
    """
    assert pdu["version"] == VERSION, f"Invalid pdu version: {pdu['version']}"
    assert pdu["type"] == TYPE, f"Invalid pdu version: {pdu['type']}"
    assert pdu["length"] == LENGTH, f"Invalid pdu version: {pdu['length']}"
