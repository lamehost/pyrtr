"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.4
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

VERSION = 1
TYPE = 2
LENGTH = 8


class ResetQuery(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    length: int


def serialize() -> bytes:
    """
    Serializes the PDU

    Returns:
    --------
    bytes: Serialized data
    """
    return struct.pack("!BBHI", VERSION, TYPE, 0, LENGTH)


def unserialize(buffer: bytes, validate: bool = True) -> ResetQuery:
    """
    Unserializes the PDU

    Arguments:
    ----------
    buffer: bytes
        Binary PDU data
    validate: bool
        If True, then validates the values. Default: True

    Returns:
    --------
    ResetQuery: Dictionary representing the content
    """
    fields = struct.unpack("!BBHI", buffer)

    if validate:
        if fields[0] != VERSION:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[3] != LENGTH:
            raise CorruptDataError(f"Invalid PDU length field: {fields[3]}")

        if len(buffer) > LENGTH:
            raise CorruptDataError(f"The PDU is not {LENGTH} bytes long: {len(buffer)}")

        if fields[2] != 0:
            raise CorruptDataError(f"The zero field is not zero: {fields[2]}")

    pdu: ResetQuery = {
        "version": fields[0],
        "type": fields[1],
        "length": fields[3],
    }

    return pdu
