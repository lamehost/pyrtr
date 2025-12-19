"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.7
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

TYPE = 6
LENGTH = 32


class IPv6Prefix(TypedDict):
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


def serialize(  # pylint:disable=too-many-arguments, too-many-positional-arguments
    version: int, flags: int, prefix_length: int, max_length: int, prefix: bytes, asn: int
) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    version: int
        The version identifier
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
        version,
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


def unserialize(version: int, buffer: bytes, validate: bool = True) -> IPv6Prefix:
    """
    Unserializes the PDU

    Arguments:
    ----------
    version: int
        Version number
    buffer: bytes
        Binary PDU data
    validate: bool
        If True, then validates the values. Default: True

    Returns:
    --------
    IPv4Prefix: Dictionary representing the content
    """
    fields = struct.unpack("!BBHIBBBBDI", buffer)

    if validate:
        if fields[0] != version:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[3] != LENGTH:
            raise CorruptDataError(f"Invalid PDU length field: {fields[3]}")

        if len(buffer) > LENGTH:
            raise CorruptDataError(f"The PDU is not {LENGTH} bytes long: {len(buffer)}")

        if fields[2] != 0 or fields[7] != 0:
            raise CorruptDataError(f"Invalid pdu zero: {fields[2]}")

        if fields[4] not in [0, 1]:
            raise CorruptDataError(f"Invalid pdu flags: {fields[4]}")

        if fields[5] < 0 or fields[5] > 128:
            raise CorruptDataError(f"Invalid pdu prefix length: {fields[5]}")

        if fields[6] < 0 or fields[6] > 128:
            raise CorruptDataError(f"Invalid pdu max length: {fields[6]}")

    pdu: IPv6Prefix = {
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
