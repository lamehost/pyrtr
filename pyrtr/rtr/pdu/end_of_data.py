"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.8
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

TYPE = 7
LENGTH = 24


class EndOfDataV0(TypedDict):
    """
    Unserialized PDU fields version 0
    """

    version: int
    type: int
    session: int
    length: int
    serial: int


class EndOfDataV1(EndOfDataV0):
    """
    Unserialized PDU fields version 1
    """

    refresh: int
    retry: int
    expire: int


def serialize(
    version: int,
    session: int,
    serial: int,
    *,
    refresh: int = 3600,
    retry: int = 600,
    expire: int = 7200,
) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    version: int
        The version identifier
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
    if version == 0:
        return struct.pack(
            "!BBHII",
            version,
            TYPE,
            session,
            LENGTH,
            serial,
        )

    return struct.pack(
        "!BBHIIIII",
        version,
        TYPE,
        session,
        LENGTH,
        serial,
        refresh,
        retry,
        expire,
    )


def unserialize(  # NOSONAR
    buffer: bytes, validate: bool = True, *, version: int | None = False
) -> EndOfDataV0 | EndOfDataV1:
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
    EndOfdata: Dictionary representing the content
    """
    fields = struct.unpack("!BBHIIIII", buffer)

    if validate:
        if version is None:
            raise ValueError("Specify a version to perform validation")

        if fields[0] != version:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[3] != LENGTH:
            raise CorruptDataError(f"Invalid PDU length field: {fields[3]}")

        if len(buffer) > LENGTH:
            raise CorruptDataError(f"The PDU is not {LENGTH} bytes long: {len(buffer)}")

        if fields[2] < 0 or fields[2] > 65535:
            raise CorruptDataError(f"Invalid session ID: {fields[2]}")

        if fields[4] < 0 or fields[4] > 4294967295:
            raise CorruptDataError(f"Invalid serial ID: {fields[4]}")

        if version > 0:
            if fields[5] < 1 or fields[5] > 86400:
                raise CorruptDataError(f"Invalid refresh period: {fields[5]}")

            if fields[6] < 1 or fields[6] > 7200:
                raise CorruptDataError(f"Invalid retry period: {fields[6]}")

            if fields[7] < 1 or fields[7] > 172800:
                raise CorruptDataError(f"Invalid expire period: {fields[7]}")

    if version == 0:
        return EndOfDataV0(
            version=fields[0],
            type=fields[1],
            session=fields[2],
            length=fields[3],
            serial=fields[4],
        )

    return EndOfDataV1(
        version=fields[0],
        type=fields[1],
        session=fields[2],
        length=fields[3],
        serial=fields[4],
        refresh=fields[5],
        retry=fields[6],
        expire=fields[7],
    )
