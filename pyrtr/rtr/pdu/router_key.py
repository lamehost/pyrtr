"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.10
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

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


def serialize(version: int, flags: int, ski: bytes, asn: int, spki: bytes) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    version: int
        The version identifier
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
        version,
        TYPE,
        flags,
        0,
        LENGTH,
    )
    after_ski = struct.pack("!I", asn)

    return before_ski + ski + after_ski + spki


def unserialize(version: int, buffer: bytes, validate: bool = True) -> RouterKey:
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
    RouterKey: Dictionary representing the content
    """
    fields = struct.unpack("!BBBBI", buffer[:8])
    fields = fields + struct.unpack("!I", buffer[28:32])

    if validate:
        if fields[0] != version:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[1] != TYPE:
            raise TypeError("Not a valid Router Key PDU.")

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
        "ski": bytes(buffer[8:28]),
        "asn": fields[5],
        "spki": bytes(buffer[32:]),
    }

    return pdu
