"""
Implements the Abstract Base Class for the Datasource
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from ipaddress import ip_network
from typing import Any, TypedDict

import msgpack  # pyright: ignore[reportMissingTypeStubs]

from pyrtr import prometheus
from pyrtr.rtr.pdu import ipv4_prefix, ipv6_prefix, router_key

logger = logging.getLogger(__name__)


class Serialized(TypedDict):
    """
    Diffs object

    Keys:
    -----
    vrps: The serialized VRPs
    """

    vrps: list[bytes]
    router_keys: list[bytes]


class Data(TypedDict):
    """
    Datasource Data instance

    Keys:
    -----
    timestamp: float
        The unix timestamp the file has been created
    hash: str
        The hash of the datasource content
    diffs: Serialized
        The VRP and Router Keys difference between this and the last instance
    serialized: Serialized
        The VRPs and Router Keys for this instance
    content:
        The content provided by the data source
    """

    timestamp: float
    hash: str
    diffs: Serialized
    serialized: Serialized
    content: Any


class VRP(TypedDict):
    """RPKI ROA"""

    asn: int
    prefix: str
    maxLength: int
    ta: str
    expires: int


class RouterKey(TypedDict):
    """BGPSec key"""

    asn: int
    ski: str
    pubkey: str
    ta: str
    expires: int


class Datasource(ABC):
    """
    Abstract Base Class that defines a data sources that can be passed to Cache and data_reloader().
    """

    def __init__(self, version: int, location: Any, expire: int = 7200):
        """
        Arguments:
        ----------
        version: int
            The version identifier
        location: Any
            The location of the data. The actual type is implementation specific
        expire: int
            When the data expires
        """
        self.version: int = version
        self.location: Any = location
        self.expire: int = expire

        # Serial equals 0 means no data is available
        self.serial: int = 0

        self.copies: dict[int, Data] = {}
        self.vrps: list[bytes] = []
        self.router_keys: list[bytes] = []
        self.last_update: str | None = None

    async def purge(self) -> None:  # NOSONAR
        """
        Deletes expired data copies
        """
        self.copies = {
            serial: data
            for serial, data in self.copies.items()
            if data["timestamp"] > datetime.now(timezone.utc).timestamp() - self.expire
        }

    async def dump(self) -> bytes:  # NOSONAR
        """
        Dumps the content of self.copies to Msgpack

        Returns:
        --------
        bytes: The packed representation of self.copies
        """
        return msgpack.dumps(self.copies)  # pyright: ignore

    @abstractmethod
    async def reload(self) -> bool:  # NOSONAR
        """
        Reloads data and recalculates diffs

        Returns:
        --------
        bool: True if the reload was succesfull, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def parse(self) -> Data:  # NOSONAR
        """
        Parses data at `self.location` and returns Data

        Returns:
        --------
        Data: The parsed Data
        """
        raise NotImplementedError

    async def update_prometheus(self, increment_serial: bool = True) -> None:  # NOSONAR
        """
        Updates the RPKI prometheus endpoints

        Arguments:
        ----------
        increment_serial: bool
            Whether to increment the metric for the serial counter of not. Defatul: True
        """
        match self.version:
            case 0:
                if increment_serial:
                    prometheus.rpki_v0_serial.inc()
                prometheus.rpki_v0_vrps.set(len(self.vrps))
                prometheus.rpki_v0_bgpsec_keys.set(len(self.router_keys))
            case 1:
                if increment_serial:
                    prometheus.rpki_v1_serial.inc()
                prometheus.rpki_v1_vrps.set(len(self.vrps))
                prometheus.rpki_v1_bgpsec_keys.set(len(self.router_keys))
            case _:
                logger.warning(
                    "Not exporting the RPKI serial counter for version: %d", self.version
                )

    def serialize_router_key(self, asn: int, ski: bytes, pubkey: bytes, flags: int) -> bytes:
        """
        Serialize router keys to bytes

        Arguments:
        ----------
        asn: int
            Router Key ASN
        ski: bytes
            Subject Key Identifier
        pubkey: bytes
            Subject Public Key Info
        flags: int
            RTR announcements flags
        """
        return router_key.serialize(
            version=self.version,
            flags=flags,
            ski=ski,
            spki=pubkey,
            asn=asn,
        )

    def serialize_prefix(self, prefix: str, asn: int, maxlength: int, flags: int) -> bytes:
        """
        Serialize router keys to bytes

        Arguments:
        ----------
        prefix: str
            Prefix with prefixlen
        asn: int
            Autonomous System Number
        maxlength: int
            The longest prefix lenght allowed
        flags: int
            RTR announcements flags
        """
        parsed_prefix = ip_network(prefix)
        if parsed_prefix.version == 4:
            return ipv4_prefix.serialize(
                version=self.version,
                prefix=parsed_prefix.network_address.packed,
                prefix_length=parsed_prefix.prefixlen,
                flags=flags,
                max_length=maxlength,
                asn=asn,
            )

        return ipv6_prefix.serialize(
            version=self.version,
            prefix=parsed_prefix.network_address.packed,
            prefix_length=parsed_prefix.prefixlen,
            flags=flags,
            max_length=maxlength,
            asn=asn,
        )
