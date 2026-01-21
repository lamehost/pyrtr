"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.2
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

TYPE = 0
LENGTH = 12


class SerialNotify(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    session: int
    length: int
    serial: int


def serialize(version: int, session: int, serial: int) -> bytes:
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

    Returns:
    --------
    bytes: Serialized data
    """
    return struct.pack("!BBHII", version, TYPE, session, LENGTH, serial)


def unserialize(version: int, buffer: bytes, validate: bool = True) -> SerialNotify:
    """
    Unserializes the PDU

    Arguments:
    ----------
    Version: int
        Version number
    buffer: bytes
        Binary PDU data
    validate: bool
        If True, then validates the values. Default: True

    Returns:
    --------
    ResetQuery: Dictionary representing the content
    """
    try:
        fields = struct.unpack("!BBHII", buffer)
    except struct.error as error:
        raise CorruptDataError("Unable to unpack the Serial Notify PDU") from error     

    if validate:
        if fields[0] != version:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[1] != TYPE:
            raise CorruptDataError("Not a valid Serial Notify PDU.")

        if fields[3] != LENGTH:
            raise CorruptDataError(f"Invalid PDU length field: {fields[3]}")

        if len(buffer) != LENGTH:
            raise CorruptDataError(f"The PDU is not {LENGTH} bytes long: {len(buffer)}")

    pdu: SerialNotify = {
        "version": fields[0],
        "type": fields[1],
        "session": fields[2],
        "length": fields[3],
        "serial": fields[4],
    }

    return pdu
