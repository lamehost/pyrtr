"""
Defines the RTR protocol sequence for the RTR Cache
"""

import logging
from asyncio import Transport
from typing import Callable, Literal, Self, TypedDict

from pyrtr.rpki_client import RPKIClient
from pyrtr.rtr.speaker import Speaker

from .pdu import (
    error_report,
    reset_query,
    serial_query,
)
from .pdu.errors import (
    CorruptDataError,
    InternalError,
    NoDataAvailableError,
    UnsupportedPDUTypeError,
)

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
    sessions: dict[int, int]
        The session IDs (one per version)
    rpki_client: RPKIClient instance
        RPKIClient instances (one per version)
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

    register_callback: Callable[[str, Self], None] | Literal[False]
    unregister_callback: Callable[[str], None] | Literal[False]

    def __init__(  # pylint: disable=too-many-arguments
        self,
        sessions: dict[int, int],
        rpki_clients: dict[int, RPKIClient],
        *,
        connect_callback: Callable[[Self], None] | Literal[False] = False,
        disconnect_callback: Callable[[Self], None] | Literal[False] = False,
        refresh: int = 3600,
        expire: int = 600,
        retry: int = 7200,
    ):
        self.rpki_clients = rpki_clients

        self.refresh = refresh
        self.expire = expire
        self.retry = retry

        super().__init__(
            sessions, connect_callback=connect_callback, disconnect_callback=disconnect_callback
        )

    def connection_made(self, transport: Transport) -> None:
        super().connection_made(transport)

        logger.info("New client connected: %s", self.remote)

    def connection_lost(self, exc: Exception | None) -> None:
        super().connection_lost(exc)

        logger.info("Client disconnected: %s", self.remote)

    def handle_serial_query(self, data: bytes) -> None:
        """
        Implements the sequences of PDU transmissions to handle the Serial Query PDU as described by
        https://datatracker.ietf.org/doc/html/rfc8210#section-8.2

        Arguments:
        ----------
        data: bytes
            The Serial Query PDU binary data
        """
        if self.version is None:
            raise InternalError("Inconsistent version state.")

        # Validates the PDU
        pdu = serial_query.unserialize(self.version, data)

        # This is ambigous. parts of the RFC suggests to send Error Report PDU, others Cache Reset.
        if pdu["session"] != self.session:
            raise CorruptDataError(f"Unknown session ID: {pdu['session']}")

        # https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-8210bis#section-8.4
        if not self.current_serial:
            raise NoDataAvailableError("No data available yet")

        serial = int(pdu["serial"])
        try:
            vrps = self.rpki_client.json[serial]["diffs"]["vrps"]
            router_keys = self.rpki_client.json[serial]["diffs"]["router_keys"]
        except KeyError:
            # Send Cache Reset in case the serial doesn't exist anymore
            self.write_cache_reset()
            return

        self.write_cache_response()
        self.write_vrps(vrps=vrps)
        self.write_router_keys(router_keys=router_keys)

        self.write_end_of_data(
            refresh=self.refresh,
            expire=self.expire,
            retry=self.retry,
        )

    def handle_reset_query(self, data: bytes) -> None:
        """
        Implements the sequences of PDU transmissions to handle the Reset Query PDU as described by
        https://datatracker.ietf.org/doc/html/rfc8210#section-8.1

        Arguments:
        ----------
        data: bytes
            The Reset Query PDU binary data
        """
        if self.version is None:
            raise InternalError("Inconsistent version state.")

        # Validates the PDU
        reset_query.unserialize(self.version, data)

        # https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-8210bis#section-8.4
        if not self.current_serial:
            raise NoDataAvailableError("No data available yet")

        self.write_cache_response()

        self.write_vrps(vrps=self.rpki_client.vrps)
        if self.version >= 1:
            self.write_router_keys(router_keys=self.rpki_client.router_keys)

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
                logger.debug("Serial query PDU received from %s", self.remote)
                self.handle_serial_query(data)
            case reset_query.TYPE:
                logger.debug("Reset query PDU received from %s", self.remote)
                self.handle_reset_query(data)
            case error_report.TYPE:
                logger.debug("Error report PDU received from %s", self.remote)
                self.raise_on_error_report(data)
            case _:
                raise UnsupportedPDUTypeError(f"Unsupported PDU Type: {header["type"]}")
