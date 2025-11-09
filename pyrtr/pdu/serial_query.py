"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.3
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

VERSION = 1
TYPE = 1
LENGTH = 12


class SerialQuery(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    session: int
    length: int
    serial: int


def serialize(session: int, serial: int) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    session: int
        The RTR session ID
    serial: int
        The current serial number of the RPKI cache

    Returns:
    --------
    bytes: Serialized data
    """
    return struct.pack("!BBHII", VERSION, TYPE, session, LENGTH, serial)


def unserialize(buffer: bytes, validate: bool = True) -> SerialQuery:
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
    SerialQuery: Dictionary representing the content
    """
    fields = struct.unpack("!BBHII", buffer)

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

    pdu: SerialQuery = {
        "version": fields[0],
        "type": fields[1],
        "session": fields[2],
        "length": fields[3],
        "serial": fields[4],
    }

    return pdu
