"""
Implements https://datatracker.ietf.org/doc/html/rfc8210#section-5.11
"""

import struct
from typing import TypedDict

from .errors import CorruptDataError, UnsupportedProtocolVersionError

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


def serialize(version: int, error: int, pdu: bytes, text: bytes = bytes()) -> bytes:
    """
    Serializes the PDU

    Arguments:
    ----------
    version: int
        The version identifier
    error: int
        RTR error code
    pdu: bytes
        Serialized erroneous PDU
    text: bytes
        Error diagnostic message. Default: bytes()

    Returns:
    --------
    bytes: Serialized data
    """
    # Force text to by bytes
    text = bytes(text)
    length = 16 + len(pdu) + len(text)

    before_pdu = struct.pack(
        "!BBHII",
        version,
        TYPE,
        error,
        length,
        len(pdu),
    )

    after_pdu = struct.pack(
        "!I",
        len(text),
    )

    return before_pdu + pdu + after_pdu + text


def unserialize(version: int, buffer: bytes, validate: bool = True) -> ErrorReport:
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
    ErrorReport: Dictionary representing the content
    """
    fields = struct.unpack("!BBHII", buffer[:12])

    if validate:
        if fields[0] != version:
            raise UnsupportedProtocolVersionError(f"Unsupported protocol version: {fields[0]}")

        if fields[1] != TYPE:
            raise CorruptDataError("Not a valid Error Report PDU.")

        if fields[3] > 65535:
            raise CorruptDataError(f"PDU is too long: {fields[2]}")

        if len(buffer) != fields[3]:
            raise CorruptDataError(f"The PDU is not {fields[3]} bytes long: {len(buffer)}")

        if fields[2] > 8:
            raise CorruptDataError(f"Invalid error code: {fields[2]}")

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
    remaining_buffer = bytes(remaining_buffer[4:])

    if pdu["text_length"]:
        pdu["text"] = remaining_buffer.decode("utf-8")

    return pdu
