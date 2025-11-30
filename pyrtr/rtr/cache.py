"""
Defines the RTR protocol sequence for the RTR Cache
"""

import logging
from typing import TypedDict

from pyrtr.pdu import (
    cache_reset,
    error_report,
    reset_query,
    serial_query,
)
from pyrtr.pdu.errors import (
    InternalError,
    UnsupportedPDUTypeError,
)
from pyrtr.rpki_client import RPKIClient
from pyrtr.rtr.speaker import Speaker

logger = logging.getLogger(__name__)


class RTRHeader(TypedDict):
    """
    Fixed fields present in every RTR PDU that are required to identify the PDU type.
    """

    version: int
    type: int
    length: int


class Cache(Speaker):
    """
    Handles the the sequences of PDU transmissions on an RTR Cache
    """

    rpki_client: RPKIClient

    def __init__(  # pylint: disable=too-many-arguments
        self,
        session: int,
        rpki_client: RPKIClient,
        *,
        refresh: int = 3600,
        expire: int = 600,
        retry: int = 7200,
    ):
        self.rpki_client = rpki_client

        self.refresh = refresh
        self.expire = expire
        self.retry = retry

        super().__init__(session)

    async def handle_serial_query(self, buffer: bytes):
        """
        Implements the sequences of PDU transmissions to handle the Serial Query PDU as described by
        https://datatracker.ietf.org/doc/html/rfc8210#section-8.2

        Arguments:
        ----------
        buffer: bytes
            The Serial Query PDU binary data
        """
        # Validates the PDU
        serial_query.unserialize(buffer)

        raise InternalError("Not implemented yet", buffer=buffer)

    async def handle_reset_query(self, buffer: bytes):
        """
        Implements the sequences of PDU transmissions to handle the Reset Query PDU as described by
        https://datatracker.ietf.org/doc/html/rfc8210#section-8.1

        Arguments:
        ----------
        buffer: bytes
            The Reset Query PDU binary data
        """
        # Validates the PDU
        reset_query.unserialize(buffer)

        self.write_cache_response()

        self.write_ip_prefixes(prefixes=self.rpki_client.prefixes)
        await self.drain()

        self.write_end_of_data(
            refresh=self.refresh,
            expire=self.expire,
            retry=self.retry,
        )

        await self.drain()

    async def handle_pdu(self, header: RTRHeader, buffer: bytes) -> None:
        """
        Handles the inbound PDU.

        header: RTRHeader
            The fixed header part of the PDU

        buffer: bytes
            The entire content of the PDU
        """
        match header["type"]:
            case serial_query.TYPE:
                logger.debug("Serial query PDU received from %s", self.client)
                await self.handle_serial_query(buffer)
            case reset_query.TYPE:
                logger.debug("Reset query PDU received from %s", self.client)
                await self.handle_reset_query(buffer)
            case cache_reset.TYPE:
                logger.debug("Cache reset PDU received from %s", self.client)
            case error_report.TYPE:
                logger.debug("Error report PDU received from %s", self.client)
                self.handle_error_report(buffer)
            case _:
                raise UnsupportedPDUTypeError(f"Unsupported PDU Type: {header["type"]}")
