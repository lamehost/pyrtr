"""
Implements the Abstract Base Class for the RTR speaker
"""

import asyncio
import logging
import socket
import struct
from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Callable, Self, TypedDict
from uuid import uuid4

from typing_extensions import override

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


class SliceSizeError(Exception):
    """
    Raised when Speaker attempts to read from a portion of the buffer that exceeds data_length
    """


class Speaker(asyncio.BufferedProtocol, ABC):
    """
    Abstract Base Class that defines a TCP speaker
    """

    def __init__(
        self,
        *,
        connect_callback: Callable[[Self], None] | None = None,
        disconnect_callback: Callable[[Self], None] | None = None,
    ):
        """
        Arguments:
        ----------
        connect_callback: Callable[[Self], None] | None = None
            The method executed after the connection is established
        disconnect_callback: Callable[[Self], None] | None = None
            The method executed after the connection is terminated
        """
        self.connect_callback: Callable[[Self], None] | None = connect_callback
        self.disconnect_callback: Callable[[Self], None] | None = disconnect_callback

        self._data_length: int = 0
        self._buffer: memoryview = memoryview(bytearray(524_288))

        self.remote: str | None = None
        self.transport: asyncio.Transport | None = None
        self.transport_socket: socket.socket | None = None

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

        # Enable Nagle's algorithm (set TCP_NODELAY=False) to coalesce small writes into larger TCP
        # segments, improving throughput at the cost of increased latency for small messages.
        self.transport_socket = self.transport.get_extra_info("socket")
        if self.transport_socket:
            self.transport_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, False)

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

    def get_buffer(self, sizehint: int) -> memoryview:
        """
        Returns the buffer object at the first "writable" position

        Arguments:
        ----------
        sizehint: int
            Ignored

        Returns:
        --------
        memoryview: The buffer object at the first "writable" position
        """
        return self._buffer[self._data_length :]

    def read_buffer(self, offset: int, nbytes: int) -> memoryview:
        """
        Reads slice of data from the buffer

        Arguments:
        ----------
        offset: int
            Where within the buffer to read data from
        nbytes: int
            How many bytes to read

        Returns:
        --------
        memoryview: The slice of data
        """
        if offset + nbytes > self._data_length:
            raise SliceSizeError("The requested buffer slice exceeds data length")

        return self._buffer[offset : offset + nbytes]

    @abstractmethod
    def read_pdu(self, offset: int) -> int:
        """
        Reads PDU from the buffer

        Arguments:
        ----------
        offset: int
            Where to read the PDU from within the buffer

        Returns:
        --------
        int: The amount of buffer read
        """
        raise NotImplementedError

    def rebase_buffer(self, offset: int) -> None:
        """
        Shifts data at offset at the start of the buffer and resets data_length

        Arguments:
        ----------
        offset: imt
            Where within buffer you want to shift data from
        """
        remaining_data = self._buffer[offset : self._data_length]
        # Set data_length to the current remaining data
        self._data_length = len(remaining_data)
        # Move remaining data to the beginning of the buffer
        self._buffer[: self._data_length] = remaining_data

    def buffer_updated(self, nbytes: int) -> None:
        """
        Called when some data is received.

        Arguments:
        ----------
        nbytes: int
            The amount of bytes added to the buffer
        """
        self._data_length = self._data_length + nbytes
        buffer_percent = round(self._data_length * 100 / len(self._buffer))
        logger.debug(
            "Recevied %d bytes from remote host: %s. Buffer utilization: %d%%",
            nbytes,
            self.remote,
            buffer_percent,
        )

        # Read data
        if self._data_length < 8:
            raise CorruptDataError("PDU is too short")

        offset: int = 0
        while offset < self._data_length:
            try:
                read_data: int = self.read_pdu(offset)
                # Update offset
                offset = offset + read_data
            except SliceSizeError:
                self.rebase_buffer(offset)
                return

        self._data_length = self._data_length - offset


class RTRSpeaker(Speaker):
    """
    Abstract Base Class that defines a RTR speaker
    """

    def __init__(
        self,
        *,
        connect_callback: Callable[[Self], None] | None = None,
        disconnect_callback: Callable[[Self], None] | None = None,
    ):
        """
        Arguments:
        ----------
        connect_callback: Callable[[Self], None] | None = None
            The method executed after the connection is established
        disconnect_callback: Callable[[Self], None] | None = None
            The method executed after the connection is terminated
        """
        super().__init__(connect_callback=connect_callback, disconnect_callback=disconnect_callback)

        self.current_serial: int = 0
        self.session: int | None = None
        self.version: int | None = None

    def parse_header(self, data: bytes) -> RTRHeader:
        """
        Reads and parses the RTR PDU header.

        Returns:
        --------
        RTRHeader: The parsed RTR header
        """
        # Parser header
        fields = struct.unpack("!BBHI", data[:8])

        return RTRHeader(
            version=fields[0],
            type=fields[1],
            length=fields[3],
        )

    def negotiate_version(self, header: RTRHeader, data: bytes) -> None:
        """
        Negotiate the version with the remote host. Raises error if version changes

        Arguments:
        ----------
        header: RTRHeader
            The parsed RTR header data
        data: bytes
            The PDU
        """
        # Version negotiation
        if self.version is None:
            try:
                self.version = SupportedVersions(header["version"]).value
            except ValueError:
                if self.transport is not None:
                    # Silently close transport if version negotiation fails.
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
                    f" received version is {header['version']}",
                    data=data,
                )

    def write(self, data: bytes) -> None:
        """
        Writes to the asyncio stream writer

        Arguments:
        ----------
        data: bytes
            The serialized PDU to send
        """
        if self.transport is None:
            raise BrokenPipeError("Transport is not ready")

        self.transport.write(data)

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
        vrps: list[bytes]
            List of serialized VRPs
        """
        if self.transport is None:
            raise BrokenPipeError("Transport is not ready")

        self.transport.writelines(vrps)

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

        if self.transport is None:
            raise BrokenPipeError("Transport is not ready")

        self.transport.writelines(router_keys)

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

    @override
    def read_pdu(self, offset: int) -> int:
        """
        Reads PDU from the buffer

        Arguments:
        ----------
        offset: int
            Where to read the PDU from within the buffer

        Returns:
        --------
        int: The amount of buffer read
        """
        # Create empty `header` in case the PDU is too short and an error is raised
        header = None
        pdu_data = bytes()

        try:
            # Read the header
            header_data = self.read_buffer(offset, 8)

            # Parse the header
            header = self.parse_header(header_data)

            # Read the PDU
            pdu_data = self.read_buffer(offset, header["length"])

            # Negotiation version
            self.negotiate_version(header, pdu_data)

            # Handle the PDU
            self.handle_pdu(header, pdu_data)
        except PDUError as error:
            if self.version is not None:
                # If the version happend AFTER version was negotaited
                exit_loop = self.handle_pdu_error_exception(header, error)
                if exit_loop and self.transport is not None:
                    self.transport.close()
            elif self.transport:
                # If the error happened BEFORE version was negotiated
                self.transport.close()

        return len(pdu_data)
