"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.8
"""

import struct
from typing import TypedDict

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


def unserialize(buffer: bytes) -> EndOfdata:
    """
    Unserializes the PDU

    Arguments:
    ----------
    buffer: bytes
        Binary PDU data

    Returns:
    --------
    EndOfdata: Dictionary representing the content
    """
    fields = struct.unpack("!BBHIIIII", buffer)

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


def validate(pdu: EndOfdata):
    """
    Raises AssertionError if the PDU is not valid

    Arguments:
    ----------
    pdu: EndOfdata
        The PDU to validate
    """
    assert pdu["version"] == VERSION, f"Invalid pdu version: {pdu['version']}"
    assert pdu["type"] == TYPE, f"Invalid pdu version: {pdu['type']}"
    assert pdu["length"] == LENGTH, f"Invalid pdu version: {pdu['length']}"

    assert pdu["refresh"] >= 1, f"Invalid refresh period: {pdu['refresh']}"
    assert pdu["refresh"] <= 86400, f"Invalid refresh period: {pdu['refresh']}"

    assert pdu["retry"] >= 1, f"Invalid retry period: {pdu['retry']}"
    assert pdu["retry"] <= 7200, f"Invalid retry period: {pdu['retry']}"

    assert pdu["expire"] >= 1, f"Invalid expire period: {pdu['expire']}"
    assert pdu["expire"] <= 172800, f"Invalid expire period: {pdu['expire']}"
