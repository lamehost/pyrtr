"""
Defines the RTR protocol sequence for the RTR Cache
"""

import asyncio
import logging
import struct
from abc import ABC
from typing import TypedDict

from .pdu import (
    cache_reset,
    cache_response,
    end_of_data,
    error_report,
    reset_query,
    serial_query,
)

logger = logging.getLogger(__name__)


class FataErrorPDU(Exception):
    """
    Raised when an Error Report contains a fatal error
    """

    error: int

    def __init__(self, message: str, error: int):
        self.error = error

        super().__init__(message)


class InvalidPDUError(Exception):
    """
    Raised when an invalid PDU is received
    """

    pdu: bytes

    def __init__(self, message: str, pdu: bytes):
        self.pdu = pdu

        super().__init__(message)


class RTRHeader(TypedDict):
    """
    Fixed fields present in every RTR PDU that are required to identify the PDU type.
    """

    version: int
    type: int
    length: int


class Speaker(ABC):
    """
    Abstract Base Class that defines the RTR spekaer

    Arguments:
    ----------
    session: int
        The RTR session ID
    """

    serial: int = 1

    reader: asyncio.streams.StreamReader
    writer: asyncio.streams.StreamWriter

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
            raise InvalidPDUError("PDU is too short", buffer)

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

    async def drain(self):
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

    def write(self, buffer: bytes):
        """
        Writes to the asyncio stream writer

        Arguments:
        ----------
        buffer: bytes
            Data to be sent to the asyncio stream writer
        """
        self.writer.write(buffer)

    async def handle_pdu(self):
        """
        Handles inbound RTR PDUs by reading from the asyncio stream reader and writing to the
        asyncio stream writer.
        """
        raise NotImplementedError()


class Cache(Speaker):
    """
    Handles the the sequences of PDU transmissions on an RTR Cache

    """

    def __init__(self, session: int, *, refresh: int = 3600, expire: int = 600, retry: int = 7200):
        self.refresh = refresh
        self.expire = expire
        self.retry = retry

        super().__init__(session)

    def handle_error_report(self, buffer: bytes):
        """
        Implements the sequences of PDU transmissions to handle the Error Report PDU

        Arguments:
        ----------
        buffer: bytes
            The Error Report PDU binary data
        """
        pdu = error_report.unserialize(buffer)
        error_report.validate(pdu)
        logger.warning(pdu)

        if pdu["error"] in [0, 1, 3, 4, 5, 6, 7, 8]:
            raise FataErrorPDU(pdu["text"], pdu["error"])

    async def handle_serial_query(self, buffer: bytes):
        """
        Implements the sequences of PDU transmissions to handle the Serial Query PDU

        Arguments:
        ----------
        buffer: bytes
            The Serial Query PDU binary data
        """
        pdu = serial_query.unserialize(buffer)
        serial_query.validate(pdu)

        pdu = cache_response.serialize(self.session)
        self.write(pdu)

        pdu = end_of_data.serialize(
            self.session, self.serial, refresh=self.refresh, expire=self.expire, retry=self.retry
        )
        self.write(pdu)

        await self.drain()

    async def handle_reset_query(self, buffer: bytes):
        """
        Implements the sequences of PDU transmissions to handle the Reset Query PDU

        Arguments:
        ----------
        buffer: bytes
            The Reset Query PDU binary data
        """
        pdu = reset_query.unserialize(buffer)
        reset_query.validate(pdu)

        pdu = cache_response.serialize(self.session)
        self.write(pdu)

        # ROAs go here

        pdu = end_of_data.serialize(
            self.session, self.serial, refresh=self.refresh, expire=self.expire, retry=self.retry
        )
        self.write(pdu)

        await self.drain()

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
        client = f"{host}:{port}"
        logger.info("New client connected: %s", client)

        while not reader.at_eof():
            # Read and parse the header
            try:
                buffer, header = await self.parse_header()
            except InvalidPDUError as error:
                logger.warning("Discarding spurious dara from: %s", client)
                logger.debug("Excessively short PDU received from %s: %s", client, error.pdu)
                continue

            # Find if there's more to read
            remaining_bytes = header["length"] - 8
            if remaining_bytes:
                # Read the rest of the PDU
                buffer = buffer + await self.read(remaining_bytes)

            # Handle the PDU
            match header["type"]:
                case serial_query.TYPE:
                    logger.info("Serial query PDU received from %s", client)
                    await self.handle_serial_query(buffer)
                case reset_query.TYPE:
                    logger.info("Reset query PDU received from %s", client)
                    await self.handle_reset_query(buffer)
                case cache_response.TYPE:
                    logger.info("Cache response PDU received from %s", client)
                case end_of_data.TYPE:
                    logger.info("End of data PDU received from %s", client)
                case cache_reset.TYPE:
                    logger.info("Cache reset PDU received from %s", client)
                case error_report.TYPE:
                    logger.warning("Error report PDU received from %s", client)
                    try:
                        self.handle_error_report(buffer)
                    except FataErrorPDU as error:
                        logger.warning(
                            "Error report contains fatal error (%i): %s", error.error, error
                        )
                        break
                case _:
                    logger.warning("Unsupport PDU type %s received from %s", header["type"], client)

        logger.info("Client disconnected: %s", client)

        # Close the writer stream
        self.writer.close()
        await self.writer.wait_closed()
