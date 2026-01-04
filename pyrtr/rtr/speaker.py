"""
Implements the Abstract Base Class for the RTR speaker
"""

import asyncio
import logging
import struct
from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Callable, Self, TypedDict
from uuid import uuid4

from .pdu import (
    cache_reset,
    cache_response,
    end_of_data,
    error_report,
    reset_query,
    serial_notify,
    serial_query,
)
from .pdu.errors import (
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


class SupportedVersions(IntEnum):
    """
    Defines the supported RTR versions
    """

    VERSION_0 = 0
    VERSION_1 = 1


class RTRHeader(TypedDict):
    """
    Fixed fields present in every RTR PDU that are required to identify the PDU type.
    """

    version: int
    type: int
    length: int


class Speaker(asyncio.Protocol, ABC):
    """
    Abstract Base Class that defines the RTR speaker
    """

    version: int | None = None

    def __init__(
        self,
        sessions: dict[int, int],
        *,
        connect_callback: Callable[[Self], None] | None = None,
        disconnect_callback: Callable[[Self], None] | None = None,
    ):
        """
        Arguments:
        ----------
        session: int
            The RTR session ID
        connect_callback: Callable[[Self], None] | None = None
            The method executed after the connection is established
        disconnect_callback: Callable[[Self], None] | None = None
            The method executed after the connection is terminated
        """
        self.sessions: dict[int, int] = sessions
        self.connect_callback: Callable[[Self], None] | None = connect_callback
        self.disconnect_callback: Callable[[Self], None] | None = disconnect_callback

        self.current_serial: int = 0
        self.remote: str | None = None
        self.transport: asyncio.Transport | None = None
        self.session: int | None = None

    def parse_header(self, data: bytes) -> RTRHeader:
        """
        Reads and parses the RTR PDU header.

        Returns:
        --------
        RTRHeader: The parsed RTR header
        """
        # Read data
        if len(data) < 8:
            raise CorruptDataError("PDU is too short")

        # Parser header
        fields = struct.unpack("!BBHI", data[:8])

        return RTRHeader(
            version=fields[0],
            type=fields[1],
            length=fields[3],
        )

    def write(self, data: bytes) -> None:
        """
        Writes to the asyncio stream writer

        Arguments:
        ----------
        data: bytes
            The serialized PDU to send
        """
        self.transport.write(data)  # pyright: ignore

    def write_serial_notify(self) -> None:
        """
        Writes a Serial Notify PDU to the wire
        """
        if self.version is None or self.session is None:
            raise InternalError("Inconsistent version state.")  # NOSONAR

        pdu = serial_notify.serialize(
            version=self.version, session=self.session, serial=self.current_serial
        )
        self.write(pdu)
        logger.debug("Serial notify PDU sent to %s", self.remote)

    def write_serial_query(self) -> None:
        """
        Writes a Serial Query PDU to the wire
        """
        if self.version is None or self.session is None:
            raise InternalError("Inconsistent version state.")

        pdu = serial_query.serialize(
            version=self.version, session=self.session, serial=self.current_serial
        )
        self.write(pdu)
        logger.debug("Serial query PDU sent to %s", self.remote)

    def write_reset_query(self) -> None:
        """
        Writes a Reset Query PDU to the wire
        """
        if self.version is None:
            raise InternalError("Inconsistent version state.")

        pdu = reset_query.serialize(version=self.version)
        self.write(pdu)
        logger.debug("Reset query PDU sent to %s", self.remote)

    def write_cache_response(self) -> None:
        """
        Writes a Cache Response PDU to the wire
        """
        if self.version is None or self.session is None:
            raise InternalError("Inconsistent version state.")

        pdu = cache_response.serialize(
            version=self.version,
            session=self.session,
        )
        self.write(pdu)
        logger.debug("Cache response PDU sent to %s", self.remote)

    def write_vrps(self, vrps: list[bytes]) -> None:
        """
        Writes IP prefixes to the wire

        Arguments:
        ----------
        list[bytes]:
            List of serialized VRPs
        """
        self.transport.writelines(vrps)  # pyright: ignore
        logger.debug("IP prefix PDUs sent to %s", self.remote)

    def write_end_of_data(self, refresh: int = 3600, retry: int = 600, expire: int = 7200) -> None:
        """
        Writes an End Of Data PDU to the wire

        Arguments:
        ----------
        refresh: int
            Refresh Interval in seconds. Default: 3600
        retry: int
            Retry Interval in seconds. Default: 600
        expire: int
            Expire Interval in seconds: Expire: 7200
        """
        if self.version is None or self.session is None:
            raise InternalError("Inconsistent version state.")

        pdu = end_of_data.serialize(
            version=self.version,
            session=self.session,
            serial=self.current_serial,
            refresh=refresh,
            retry=retry,
            expire=expire,
        )
        self.write(pdu)
        logger.debug("End of data PDU sent to %s", self.remote)

    def write_cache_reset(self) -> None:
        """
        Writes a Cache Reset PDU to the wire
        """
        if self.version is None:
            raise InternalError("Inconsistent version state.")

        pdu = cache_reset.serialize(version=self.version)
        self.write(pdu)
        logger.debug("Cache reset PDU sent to %s", self.remote)

    def write_router_keys(self, router_keys: list[bytes]) -> None:
        """
        Writes Router Keys to the wire

        Arguments:
        ----------
        list[bytes]:
            List of serialized Router Keys
        """
        if self.version is None:
            raise InternalError("Inconsistent version state.")

        self.transport.writelines(router_keys)  # pyright: ignore
        logger.debug("Router keys PDUs sent to %s", self.remote)

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
        if self.version is None:
            raise InternalError("Inconsistent version state.")

        _pdu = error_report.serialize(version=self.version, error=error, pdu=pdu, text=text)
        self.write(_pdu)
        logger.debug("Error report PDU sent to %s", self.remote)

    @abstractmethod
    def handle_pdu(self, header: RTRHeader, data: bytes) -> None:
        """
        Handles the inbound PDU.

        header: RTRHeader
            The fixed header part of the PDU

        data: bytes
            The entire content of the PDU
        """
        raise NotImplementedError

    def raise_on_error_report(self, data: bytes) -> None:
        """
        Handles the Error Report PDU and raises a PDUError

        Arguments:
        ----------
        data: bytes
            The Error Report PDU binary data
        """
        # https://datatracker.ietf.org/doc/html/rfc8210#section-12
        if self.version is None:
            raise InternalError("Inconsistent version state.")

        pdu = error_report.unserialize(self.version, data)

        message = pdu["text"] or ""

        match pdu["error"]:
            case 0:
                raise CorruptDataError(message=message, data=pdu["pdu"])
            case 1:
                raise InternalError(message=message, data=pdu["pdu"])
            case 2:
                raise NoDataAvailableError(message=message, data=pdu["pdu"])
            case 3:
                raise InvalidRequestError(message=message, data=pdu["pdu"])
            case 4:
                raise UnsupportedProtocolVersionError(message=message, data=pdu["pdu"])
            case 5:
                raise UnsupportedPDUTypeError(message=message, data=pdu["pdu"])
            case 6:
                raise WithdrawalofUnknownRecordError(message=message, data=pdu["pdu"])
            case 7:
                raise DuplicateAnnouncementReceivedError(message=message, data=pdu["pdu"])
            case 8:
                raise UnexpectedProtocolVersionError(message=message, data=pdu["pdu"])
            case _:
                logger.warning("Received an unsupported error report type: %d", pdu["error"])

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
        if error.fatal:
            logger.info("Fatal error while handling a PDU from %s: %s", self.remote, str(error))
        else:
            logger.info(
                "Non fatal error while handling a PDU from %s: %s",
                self.remote,
                str(error),
            )

        if header is None or header["type"] != error_report.TYPE:
            self.write_error_report(
                error=error.code, pdu=error.data, text=bytes(str(error), "utf-8")
            )

        return error.fatal

    def connection_made(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, transport: asyncio.Transport
    ) -> None:
        """
        Called when a connection is made.

        transport: asyncio.Transport
             Transport representing the connection.
        """
        # Find the remote socket data
        try:
            host, port = transport.get_extra_info("peername")
            self.remote = f"{host}:{port}"
        except TypeError:
            # Raised using neither TCP nor UDP
            self.remote = str(uuid4())

        # Set the transport for this host
        self.transport = transport

        if self.connect_callback:
            self.connect_callback(self)

    def connection_lost(self, exc: Exception | None) -> None:
        """
        Called when the connection is lost or closed.

        exc: Exception | None
            The exception that forced the connection to be closed
        """
        if isinstance(exc, ConnectionResetError):
            logger.info("Connection reset by the remote host: %s", self.remote)

        if isinstance(exc, BrokenPipeError):
            logger.info("Connection died unexpectedly: %s", self.remote)

        if self.disconnect_callback:
            self.disconnect_callback(self)

        # Close the writer stream
        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    def data_received(self, data: bytes) -> None:
        """
        Called when some data is received.

        Arguments:
        ----------
        data: bytes
            The received data
        """
        # Create empty `data` in case the PDU is too short and an error is raised
        header = None

        try:
            # Read and parse the header
            header = self.parse_header(data)

            # Version negotiation
            if self.version is None:
                try:
                    self.version = SupportedVersions(header["version"]).value
                    self.session = self.sessions[self.version]
                except ValueError as error:
                    if self.transport is not None:
                        self.transport.close()
                        return
                except KeyError as error:
                    raise UnexpectedProtocolVersionError(
                        f"Unsupported protocol version: {header['version']}"
                    ) from error
            else:
                # Version changed
                if self.version != header["version"]:
                    raise UnexpectedProtocolVersionError(
                        f"Negotiated protocol version is {self.version},"
                        f" received version is {header['version']}"
                    )

            # Handle the PDU
            self.handle_pdu(header, data)
        except PDUError as error:
            if self.version:
                # If the version happned AFTER version was negotaited
                exit_loop = self.handle_pdu_error_exception(header, error)
                if exit_loop and self.transport is not None:
                    self.transport.close()
            elif self.transport:
                # If the error happened BEFORE version was negotiated
                self.transport.close()
