"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.11
"""

import struct
from typing import TypedDict

VERSION = 1
TYPE = 10


class ErrorReport(TypedDict):
    """
    Unserialized PDU fields
    """

    version: int
    type: int
    error: int
    length: int
    pdu_length: int
    pdu: bytes
    text_length: int
    text: str | None


def serialize(error: int, pdu: bytes, *, text: bytes | None = None) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    error: int
        RTR error code
    pdu: bytes
        Serialized erroneous PDU
    text: bytes
        Error diagnostic message. Default: None

    Returns:
    --------
    bytes: Serialized data
    """
    if text is not None:
        length = 12 + len(pdu) + len(text)

        return struct.pack(
            "!BBHIIIII",
            VERSION,
            TYPE,
            error,
            length,
            len(pdu),
            pdu,
            len(text),
            text,
        )

    length = 12 + len(pdu)

    return struct.pack(
        "!BBHIIII",
        VERSION,
        TYPE,
        error,
        length,
        len(pdu),
        pdu,
        0,
    )


def unserialize(buffer: bytes) -> ErrorReport:
    """
    Unserializes the PDU

    Arguments:
    ----------
    buffer: bytes
        Binary PDU data

    Returns:
    --------
    ErrorReport: Dictionary representing the content
    """
    fields = struct.unpack("!BBHII", buffer[:12])

    pdu: ErrorReport = {
        "version": fields[0],
        "type": fields[1],
        "error": fields[2],
        "length": fields[3],
        "pdu_length": fields[4],
        "pdu": bytes(),
        "text_length": 0,
        "text": None,
    }

    remaining_buffer = buffer[12:]

    if pdu["pdu_length"]:
        pdu["pdu"] = remaining_buffer[: pdu["pdu_length"]]
        remaining_buffer = remaining_buffer[pdu["pdu_length"] :]

    pdu["text_length"] = next(iter(struct.unpack("!I", remaining_buffer[:4])))
    remaining_buffer = remaining_buffer[4:]

    if pdu["text_length"]:
        pdu["text"] = remaining_buffer.decode("utf-8")

    return pdu


def validate(pdu: ErrorReport):
    """
    Raises AssertionError if the PDU is not valid

    Arguments:
    ----------
    pdu: ErrorReport
        The PDU to validate
    """
    assert pdu["version"] == VERSION, f"Invalid pdu version: {pdu['version']}"
    assert pdu["type"] == TYPE, f"Invalid pdu version: {pdu['type']}"
