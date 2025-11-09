"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.8
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

VERSION = 1
TYPE = 7
LENGTH = 24


class EndOfdata(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    session: int
    length: int
    serial: int
    refresh: int
    retry: int
    expire: int


def serialize(
    session: int, serial: int, *, refresh: int = 3600, retry: int = 600, expire: int = 7200
) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    session: int
        The RTR session ID
    serial: int
        The current serial number of the RPKI cache
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds: Expire: 7200

    Returns:
    --------
    bytes: Serialized data
    """
    return struct.pack(
        "!BBHIIIII",
        VERSION,
        TYPE,
        session,
        LENGTH,
        serial,
        refresh,
        retry,
        expire,
    )


def unserialize(buffer: bytes, validate: bool = True) -> EndOfdata:  # NOSONAR
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
    EndOfdata: Dictionary representing the content
    """
    fields = struct.unpack("!BBHIIIII", buffer)

    if validate:
        if fields[0] != VERSION:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[3] != LENGTH:
            raise CorruptDataError(f"Invalid PDU length field: {fields[3]}")

        if len(buffer) > LENGTH:
            raise CorruptDataError(f"The PDU is not {LENGTH} bytes long: {len(buffer)}")

        if fields[2] < 1 or fields[2] > 65535:
            raise CorruptDataError(f"Invalid session ID: {fields[2]}")

        if fields[4] < 1 or fields[4] > 4294967295:
            raise CorruptDataError(f"Invalid serial ID: {fields[4]}")

        if fields[5] < 1 or fields[5] > 86400:
            raise CorruptDataError(f"Invalid refresh period: {fields[5]}")

        if fields[6] < 1 or fields[6] > 7200:
            raise CorruptDataError(f"Invalid retry period: {fields[6]}")

        if fields[7] < 1 or fields[7] > 172800:
            raise CorruptDataError(f"Invalid expire period: {fields[7]}")

    pdu: EndOfdata = {
        "version": fields[0],
        "type": fields[1],
        "session": fields[2],
        "length": fields[3],
        "serial": fields[4],
        "refresh": fields[5],
        "retry": fields[6],
        "expire": fields[7],
    }

    return pdu
