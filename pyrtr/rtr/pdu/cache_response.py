"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.5
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

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


def serialize(version: int, session: int) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    version: int
        The version identifier
    session: int
        The RTR session ID

    Returns:
    --------
    bytes: Serialized data
    """
    return struct.pack(
        "!BBHI",
        version,
        TYPE,
        session,
        LENGTH,
    )


def unserialize(
    buffer: bytes, validate: bool = True, *, version: int | None = None
) -> CacheResponse:
    """
    Unserializes the PDU

    Arguments:
    ----------
    buffer: bytes
        Binary PDU data
    validate: bool
        If True, then validates the values. Default: True
    version: int | None
        Negotiated version number

    Returns:
    --------
    CacheResponse: Dictionary representing the content
    """
    fields = struct.unpack("!BBHI", buffer)

    if validate:
        if version is None:
            raise ValueError("Specify a version to perform validation")

        if fields[0] != version:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[3] != LENGTH:
            raise CorruptDataError(f"Invalid PDU length field: {fields[3]}")

        if len(buffer) > LENGTH:
            raise CorruptDataError(f"The PDU is not {LENGTH} bytes long: {len(buffer)}")

    pdu: CacheResponse = {
        "version": fields[0],
        "type": fields[1],
        "session": fields[2],
        "length": fields[3],
    }

    return pdu
