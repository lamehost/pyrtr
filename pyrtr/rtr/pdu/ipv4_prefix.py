"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.6
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

VERSION = 1
TYPE = 4
LENGTH = 20


class IPv4Prefix(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    length: int
    flags: int
    prefix_length: int
    max_length: int
    prefix: str
    asn: int


def serialize(flags: int, prefix_length: int, max_length: int, prefix: bytes, asn: int) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    flags: int
        1 for announcement and 0 for withdrawal
    prefix_length:
        The length of the prefix
    max_length:
        The MaxLength of the ROA
    prefxi: bytes
        The packed prefix broadcast address
    asn: int
        The AS number

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


def unserialize(buffer: bytes, validate: bool = True) -> IPv4Prefix:  # NOSONAR
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
    IPv4Prefix: Dictionary representing the content
    """
    fields = struct.unpack("!BBHIBBBBII", buffer)

    if validate:
        if fields[0] != VERSION:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[3] != LENGTH:
            raise CorruptDataError(f"Invalid PDU length field: {fields[3]}")

        if len(buffer) > LENGTH:
            raise CorruptDataError(f"The PDU is not {LENGTH} bytes long: {len(buffer)}")

        if fields[2] != 0:
            raise CorruptDataError(f"The zero field is not zero: {fields[2]}")

        if fields[2] != 0 or fields[7] != 0:
            raise CorruptDataError(f"Invalid pdu zero: {fields[2]}")

        if fields[4] not in [0, 1]:
            raise CorruptDataError(f"Invalid pdu flags: {fields[4]}")

        if fields[5] < 0 or fields[5] > 32:
            raise CorruptDataError(f"Invalid pdu prefix length: {fields[5]}")

        if fields[6] < 0 or fields[6] > 32:
            raise CorruptDataError(f"Invalid pdu max length: {fields[6]}")

    pdu: IPv4Prefix = {
        "version": fields[0],
        "type": fields[1],
        "length": fields[3],
        "flags": fields[4],
        "prefix_length": fields[5],
        "max_length": fields[6],
        "prefix": fields[8],
        "asn": fields[9],
    }

    return pdu
