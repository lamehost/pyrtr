"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.9
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

TYPE = 8
LENGTH = 8


class CacheReset(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    length: int


def serialize(version: int) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    version: int
        The version identifier

    Returns:
    --------
    bytes: Serialized data
    """
    return struct.pack(
        "!BBHI",
        version,
        TYPE,
        0,
        LENGTH,
    )


def unserialize(version: int, buffer: bytes, validate: bool = True) -> CacheReset:
    """
    Unserializes the PDU

    Arguments:
    ----------
    version: int
        The version identifier
    buffer: bytes
        Binary PDU data
    validate: bool
        If True, then validates the values. Default: True
    version: int | None
        Negotiated version number

    Returns:
    --------
    CacheReset: Dictionary representing the content
    """
    try:
        fields = struct.unpack("!BBHI", buffer)
    except struct.error as error:
        raise CorruptDataError("Unable to unpack the Cache Reset PDU") from error

    if validate:
        if fields[0] != version:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[1] != TYPE:
            raise CorruptDataError("Not a valid Cache Reset PDU.")

        if fields[3] != LENGTH:
            raise CorruptDataError(f"Invalid PDU length field: {fields[3]}")

        if len(buffer) != LENGTH:
            raise CorruptDataError(f"The PDU is not {LENGTH} bytes long: {len(buffer)}")

    pdu: CacheReset = {
        "version": fields[0],
        "type": fields[1],
        "length": fields[3],
    }

    return pdu
