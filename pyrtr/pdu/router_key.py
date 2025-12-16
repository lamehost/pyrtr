"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.10
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

VERSION = 1
TYPE = 9
# The drawing in the RFC does not relfect the true size of the PDU
LENGTH = 123


class RouterKey(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    flags: int
    length: int
    ski: bytes
    asn: int
    spki: bytes


def serialize(flags: int, ski: bytes, asn: int, spki: bytes) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    flags: int
        1 for announcement and 0 for withdrawal
    ski: bytes
        The Subject Key Identifier
    asn: int
        The AS number
    spki: bytes
        The Subject Public Key Info
    Returns:
    --------
    bytes: Serialized data
    """
    before_ski = struct.pack(
        "!BBBBI",
        VERSION,
        TYPE,
        flags,
        0,
        LENGTH,
    )
    after_ski = struct.pack("!I", asn)

    return before_ski + ski + after_ski + spki


def unserialize(buffer: bytes, validate: bool = True) -> RouterKey:  # NOSONAR
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
    RouterKey: Dictionary representing the content
    """
    fields = struct.unpack("!BBBBI", buffer[:8])
    fields = fields + struct.unpack("!I", buffer[28:32])

    if validate:
        if fields[0] != VERSION:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[2] not in [0, 1]:
            raise CorruptDataError(f"Invalid pdu flags: {fields[2]}")

        if fields[4] != LENGTH:
            raise CorruptDataError(f"Invalid PDU length field: {fields[3]}")

        if len(buffer) > LENGTH:
            raise CorruptDataError(f"The PDU is not {LENGTH} bytes long: {len(buffer)}")

    pdu: RouterKey = {
        "version": fields[0],
        "type": fields[1],
        "flags": fields[2],
        "length": fields[4],
        "ski": buffer[8:28],
        "asn": fields[6],
        "spki": buffer[32:],
    }

    return pdu
