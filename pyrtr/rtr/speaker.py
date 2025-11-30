"""
Implements the Abstract Base Class for the RTR speaker
"""

import asyncio
import logging
import struct
from abc import ABC, abstractmethod
from typing import TypedDict

from pyrtr.pdu import (
    cache_reset,
    cache_response,
    end_of_data,
    error_report,
    serial_query,
)
from pyrtr.pdu.errors import (
    CorruptDataError,
    DuplicateAnnouncementReceivedError,
    InternalError,
    InvalidRequestError,
    NoDataAvailableError,
    PDUError,
    UnexpectedProtocolVersionError,
    UnsupportedPDUTypeError,
    UnsupportedProtocolVersionError,
    WithdrawalofUnknownRecordError,
)

logger = logging.getLogger(__name__)


class RTRHeader(TypedDict):
    """
    Fixed fields present in every RTR PDU that are required to identify the PDU type.
    """

    version: int
    type: int
    length: int


class FatalRTRError(Exception):
    """
    Raised when a fatal RTR error is received
    """


class Speaker(ABC):
    """
    Abstract Base Class that defines the RTR spekaer

    Arguments:
    ----------
    session: int
        The RTR session ID
    """

    version: int | None = None
    serial: int = 1
    session: int

    reader: asyncio.streams.StreamReader
    writer: asyncio.streams.StreamWriter
    client: str

    def __init__(self, session: int):
        self.session = session

    async def parse_header(self) -> tuple[bytes, RTRHeader]:
        """
        Reads and arses the RTR PDU header.

        Returns:
        --------
        bytes, RTRHeader: The binary RTR header data and the parsed RTR header
        """
        # Read buffer
        buffer = await self.read(8)
        if len(buffer) < 8:
            raise CorruptDataError("PDU is too short")

        # Parser header
        fields = struct.unpack("!BBHI", buffer)

        return (
            buffer,
            {
                "version": fields[0],
                "type": fields[1],
                "length": fields[3],
            },
        )

    async def drain(self) -> None:
        """
        Blocks until the asyncio stream writer buffer is transmitted
        """
        await self.writer.drain()

    async def read(self, length: int) -> bytes:
        """
        Reads from the asyncio stream reader

        Arguments:
        ----------
        lenght: int
            The amount of bytes to read

        Returns:
        --------
        bytes: Data read from the asyncio stream reader
        """
        return await self.reader.read(length)

    def write(self, buffer: bytes) -> None:
        """
        Writes to the asyncio stream writer

        Arguments:
        ----------
        buffer: bytes
            The serialized PDU to send
        """
        self.writer.write(buffer)

    def write_serial_query(self) -> None:
        """
        Writes a Serial Query PDU to the wire
        """
        pdu = serial_query.serialize(session=self.session, serial=self.serial)
        self.write(pdu)
        logger.debug("Serial query PDU sent to %s", self.client)

    def write_reset_query(self) -> None:
        """
        Writes a Reset Query PDU to the wire
        """
        pdu = serial_query.serialize(session=self.session, serial=self.serial)
        self.write(pdu)
        logger.debug("Reset query PDU sent to %s", self.client)

    def write_cache_response(self) -> None:
        """
        Writes a Cache Response PDU to the wire
        """
        pdu = cache_response.serialize(session=self.session)
        self.write(pdu)
        logger.debug("Cache response PDU sent to %s", self.client)

    def write_ip_prefixes(self, prefixes: list[bytes]) -> None:
        """
        Writes IP prefxies to the wire

        Arguments:
        ----------
        list[bytes]:
            List of serialized IP prefixes
        """
        self.writer.writelines(prefixes)
        logger.debug("IP prefix PDUs sent to %s", self.client)

    def write_end_of_data(self, refresh: int = 3600, retry: int = 600, expire: int = 7200) -> None:
        """
        Writes an End Of Data PDU to the wire

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
        """

        pdu = end_of_data.serialize(
            session=self.session, serial=self.serial, refresh=refresh, retry=retry, expire=expire
        )
        self.write(pdu)
        logger.debug("End of data PDU sent to %s", self.client)

    def write_cache_reset(self) -> None:
        """
        Writes a Cache Reset PDU to the wire
        """
        pdu = cache_reset.serialize()
        self.write(pdu)
        logger.debug("Cache reset PDU sent to %s", self.client)

    def write_error_report(self, error: int, pdu: bytes = bytes(), text: bytes = bytes()) -> None:
        """
        Writes an Error Report PDU  to the wire

        Arguments:
        ----------
        error: int
            RTR error code
        pdu: bytes
            Serialized erroneous PDU
        text: bytes
            Error diagnostic message. Default: bytes()
        """
        _pdu = error_report.serialize(error=error, pdu=pdu, text=text)
        self.write(_pdu)
        logger.debug("Error report PDU sent to %s", self.client)

    @abstractmethod
    async def handle_pdu(self, header: RTRHeader, buffer: bytes) -> None:
        """
        Handles the inbound PDU.

        header: RTRHeader
            The fixed header part of the PDU

        buffer: bytes
            The entire content of the PDU
        """
        raise NotImplementedError

    def handle_error_report(self, buffer: bytes):
        """
        Handles the Error Report PDU and raises a PDUError

        Arguments:
        ----------
        buffer: bytes
            The Error Report PDU binary data
        """
        # https://datatracker.ietf.org/doc/html/rfc8210#section-12
        pdu = error_report.unserialize(buffer)

        message = pdu["text"] or ""

        match pdu["error"]:
            case 0:
                raise CorruptDataError(message=message, buffer=pdu["pdu"])
            case 1:
                raise InternalError(message=message, buffer=pdu["pdu"])
            case 2:
                raise NoDataAvailableError(message=message, buffer=pdu["pdu"])
            case 3:
                raise InvalidRequestError(message=message, buffer=pdu["pdu"])
            case 4:
                raise UnsupportedProtocolVersionError(message=message, buffer=pdu["pdu"])
            case 5:
                raise UnsupportedPDUTypeError(message=message, buffer=pdu["pdu"])
            case 6:
                raise WithdrawalofUnknownRecordError(message=message, buffer=pdu["pdu"])
            case 7:
                raise DuplicateAnnouncementReceivedError(message=message, buffer=pdu["pdu"])
            case 8:
                raise UnexpectedProtocolVersionError(message=message, buffer=pdu["pdu"])
            case _:
                ...

    def handle_pdu_error_exception(self, header: RTRHeader | None, error: PDUError) -> bool:
        """
        Handles PDUErrors

        header: RTRHeader | None
            The fixed header part of the PDU

        error: PDUError
            The error thrown by the script

        Returns:
        --------
        bool: Whether is the error is fatal or not
        """
        if header is not None and header["type"] == error_report.TYPE:
            logger.info("Received a malformed Error Report from: %s", self.client)
        else:
            if error.fatal:
                logger.info("Fatal error while handling a PDU from %s: %s", self.client, str(error))
            else:
                logger.info(
                    "Non fatal error while handling a PDU from %s: %s",
                    self.client,
                    str(error),
                )
            self.write_error_report(
                error=error.code, pdu=error.buffer, text=bytes(str(error), "utf-8")
            )

        return error.fatal

    async def client_connected_cb(
        self, reader: asyncio.streams.StreamReader, writer: asyncio.streams.StreamWriter
    ):
        """
        Callback invoked by the asyncio TCP server when a new client is connected.
        Implemente the sequences of PDU transmissions for the Cache.

        Arguments:
        ----------
        reader: asyncio.streams.StreamReader
            The reader object as passed by the asyncio TCP server
        writer: asyncio.streams.StreamWriter
            The writer object as passed by the asyncio TCP server
        """

        # Set the reader and writer streams for this client
        self.reader = reader
        self.writer = writer

        # Find the remote socket data
        host, port = self.writer.get_extra_info("peername")
        self.client = f"{host}:{port}"
        logger.info("New client connected: %s", self.client)

        while not reader.at_eof():
            # Create empty `buffer` in case the PDU is too short and an error is raised
            header = None
            buffer = bytes()

            try:
                # Read and parse the header
                buffer, header = await self.parse_header()

                # Version negotiation
                if self.version is None:
                    self.version = header["version"]
                elif self.version != header["version"]:
                    raise UnexpectedProtocolVersionError(
                        f"Negotatited version is {self.version}, received {header["version"]}"
                    )

                # Find if there's more to read
                remaining_bytes = header["length"] - 8
                if remaining_bytes:
                    # Read the rest of the PDU
                    buffer = buffer + await self.read(remaining_bytes)

                # Handle the PDU
                await self.handle_pdu(header, buffer)
            except PDUError as error:
                exit_loop = self.handle_pdu_error_exception(header, error)
                if exit_loop:
                    break
            except BrokenPipeError:
                logger.info("Connection died unexpectedly: %s", self.client)
                break

        logger.info("Client disconnected: %s", self.client)

        # Close the writer stream
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except BrokenPipeError:
            pass
