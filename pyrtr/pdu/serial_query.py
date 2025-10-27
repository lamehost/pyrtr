"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.3
"""

import struct
from typing import TypedDict

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


def unserialize(buffer: bytes) -> SerialQuery:
    """
    Unserializes the PDU

    Arguments:
    ----------
    buffer: bytes
        Binary PDU data

    Returns:
    --------
    SerialQuery: Dictionary representing the content
    """
    fields = struct.unpack("!BBHII", buffer)

    pdu: SerialQuery = {
        "version": fields[0],
        "type": fields[1],
        "session": fields[2],
        "length": fields[3],
        "serial": fields[4],
    }

    return pdu


def validate(pdu: SerialQuery):
    """
    Raises AssertionError if the PDU is not valid

    Arguments:
    ----------
    pdu: SerialQuery
        The PDU to validate
    """
    assert pdu["version"] == VERSION, f"Invalid pdu version: {pdu['version']}"
    assert pdu["type"] == TYPE, f"Invalid pdu version: {pdu['type']}"
    assert pdu["length"] == LENGTH, f"Invalid pdu version: {pdu['length']}"
