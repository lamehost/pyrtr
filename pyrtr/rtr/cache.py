"""
Defines the RTR protocol sequence for the RTR Cache
"""

import asyncio
import logging
from typing import Callable, Literal, Self, TypedDict

from pyrtr.pdu import (
    cache_reset,
    error_report,
    reset_query,
    serial_query,
)
from pyrtr.pdu.errors import (
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

    Arguments:
    ----------
    session: str
        The session ID
    rpki_client: RPKIClient instance
        RPKIClient instance
    cache_registry: Cache
        The RTR Cache registry
    register_callback: Callable[[str, Self], None] | Literal[False]
        If not False, the function executed to register the Cache.
        Takes 2 argument the Cache ID and Cache instance
    unregister_callback: Callable[[str], None] | Literal[False]
        If not False, the function executed to register the Cache.
        Takes 1 argument the Cache ID
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds: Expire: 7200
    """

    rpki_client: RPKIClient
    register_callback: Callable[[str, Self], None] | Literal[False]
    unregister_callback: Callable[[str], None] | Literal[False]

    def __init__(  # pylint: disable=too-many-arguments
        self,
        session: int,
        rpki_client: RPKIClient,
        *,
        register_callback: Callable[[str, Self], None] | Literal[False] = False,
        unregister_callback: Callable[[str], None] | Literal[False] = False,
        refresh: int = 3600,
        expire: int = 600,
        retry: int = 7200,
    ):
        self.rpki_client = rpki_client
        self.register_callback = register_callback
        self.unregister_callback = unregister_callback

        self.refresh = refresh
        self.expire = expire
        self.retry = retry

        super().__init__(session)

    def connection_made(self, transport: asyncio.Transport):
        """
        Called when a connection is made.

        transport: asyncio.Transport
             Transport representing the connection.
        """
        super().connection_made(transport)

        if self.register_callback:
            self.register_callback(self.client, self)

    def connection_lost(self, exc: Exception | None) -> None:
        """
        Called when the connection is lost or closed.

        exc: Exception | None
            The exception that forced the connection to be closed
        """
        super().connection_lost(exc)  # pyright: ignore

        if self.unregister_callback:
            self.unregister_callback(self.client)

    def handle_serial_query(self, data: bytes):
        """
        Implements the sequences of PDU transmissions to handle the Serial Query PDU as described by
        https://datatracker.ietf.org/doc/html/rfc8210#section-8.2

        Arguments:
        ----------
        data: bytes
            The Serial Query PDU binary data
        """
        # Validates the PDU
        pdu = serial_query.unserialize(data)

        serial = int(pdu["serial"])
        try:
            prefixes = self.rpki_client.json[serial]["diffs"]
        except KeyError:
            # Send Cache Reset in case the serial doesn't exist anymore
            self.write_cache_reset()
            return

        self.write_cache_response()
        self.write_ip_prefixes(prefixes=prefixes)

        self.write_end_of_data(
            refresh=self.refresh,
            expire=self.expire,
            retry=self.retry,
        )

    def handle_reset_query(self, data: bytes):
        """
        Implements the sequences of PDU transmissions to handle the Reset Query PDU as described by
        https://datatracker.ietf.org/doc/html/rfc8210#section-8.1

        Arguments:
        ----------
        data: bytes
            The Reset Query PDU binary data
        """
        # Validates the PDU
        reset_query.unserialize(data)

        self.write_cache_response()

        self.write_ip_prefixes(prefixes=self.rpki_client.prefixes)

        self.write_end_of_data(
            refresh=self.refresh,
            expire=self.expire,
            retry=self.retry,
        )

    def handle_pdu(self, header: RTRHeader, data: bytes) -> None:
        """
        Handles the inbound PDU.

        header: RTRHeader
            The fixed header part of the PDU

        data: bytes
            The entire content of the PDU
        """
        match header["type"]:
            case serial_query.TYPE:
                logger.debug("Serial query PDU received from %s", self.client)
                self.handle_serial_query(data)
            case reset_query.TYPE:
                logger.debug("Reset query PDU received from %s", self.client)
                self.handle_reset_query(data)
            case cache_reset.TYPE:
                logger.debug("Cache reset PDU received from %s", self.client)
            case error_report.TYPE:
                logger.debug("Error report PDU received from %s", self.client)
                self.raise_on_error_report(data)
            case _:
                raise UnsupportedPDUTypeError(f"Unsupported PDU Type: {header["type"]}")
