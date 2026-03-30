"""
Implements the Abstract Base Class for the Datasource
"""

import logging
from abc import ABC, abstractmethod
from base64 import b64encode
from collections.abc import Collection
from ipaddress import ip_network
from typing import Any, AsyncGenerator, TypedDict

# from pyrtr import prometheus
from pyrtr.rtr.pdu import ipv4_prefix, ipv6_prefix, router_key

logger = logging.getLogger(__name__)


class Serialized(TypedDict):
    """
    Diffs object

    Keys:
    -----
    vrps: Iterable[bytes]
        The serialized VRPs
    router_keys: Iterable[bytes]
        The Router Keys
    """

    vrps: Collection[bytes]
    router_keys: Collection[bytes]


class Data(TypedDict):
    """
    Datasource Data instance

    Keys:
    -----
    timestamp: float
        The unix timestamp the file has been created
    diffs: Serialized
        The VRP and Router Keys difference between this and the last instance
    serialized: Serialized
        The VRPs and Router Keys for this instance
    content:
        The content provided by the data source
    """

    hash: str
    timestamp: float
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


class SnapshotDump(TypedDict):
    """Data dump for a snapshot"""

    type: str
    version: int
    serial: int
    hash: str
    timestamp: str

class DumpMetadata(TypedDict):
    """Data dump metadata (usually yielded as the first item of a dump)"""
    type: str
    version: int
    serial: int
    snapshots: list[int]
    last_update: str | None


class SerializedDump(TypedDict):
    """Data dump for serialized VRPs and Router Keys"""
    type: str
    version: int
    serial: int
    serialized: str


class Datasource(ABC):
    """
    Abstract Base Class that defines a data sources that can be passed to Cache and data_reloader().
    """

    def __init__(self, version: int, data_location: Any, cache_location: Any, expire: int = 7200):
        """
        Arguments:
        ----------
        version: int
            The version identifier
        data_location: Any
            The location of the data. The actual type is implementation specific
        cache_location: Any
            The location of the cache directory. The actual type is implementation specific
        expire: int
            When the data expires
        """
        self.version: int = version
        self.data_location: Any = data_location
        self.cache_location: Any = cache_location
        self.expire: int = expire

        self.snapshots: dict[int, Data] = {}
        self.last_update: str | None = None

    @property
    def serial(self) -> int:
        """
        Property that returns the current serial number

        Returns
        -------
        int: The current serial number
        """
        try:
            return max(self.snapshots.keys())
        except ValueError:
            # Zero means no data
            return 0

    @property
    def vrps(self) -> Collection[bytes]:
        """
        Property that returns the current VRPs

        Returns
        -------
        Collection[bytes]: The data bytes for each VRP
        """
        try:
            return self.snapshots[self.serial]["serialized"]["vrps"]
        except KeyError:
            return []

    @property
    def router_keys(self) -> Collection[bytes]:
        """
        Property that returns the current Router Keys

        Returns
        -------
        Collection[bytes]: The data bytes for each Router Key
        """
        try:
            return self.snapshots[self.serial]["serialized"]["router_keys"]
        except KeyError:
            return []

    @abstractmethod
    async def parse(self) -> Data:
        """
        Parses data at `self.location` and returns Data

        Returns:
        --------
        Data: The parsed Data
        """
        raise NotImplementedError

    @abstractmethod
    async def reload(self) -> bool:
        """
        Reloads data and recalculates diffs

        Returns:
        --------
        bool: True if the reload was succesfull, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def purge(self) -> None:
        """
        Deletes expired data copies
        """
        raise NotImplementedError

    # async def update_prometheus(self, increment_serial: bool = True) -> None:
    #     """
    #     Updates the RPKI prometheus endpoints

    #     Arguments:
    #     ----------
    #     increment_serial: bool
    #         Whether to increment the metric for the serial counter of not. Defatul: True
    #     """
    #     match self.version:
    #         case 0:
    #             if increment_serial:
    #                 prometheus.rpki_v0_serial.inc()
    #             prometheus.rpki_v0_vrps.set(len(self.vrps))
    #             prometheus.rpki_v0_bgpsec_keys.set(len(self.router_keys))
    #         case 1:
    #             if increment_serial:
    #                 prometheus.rpki_v1_serial.inc()
    #             prometheus.rpki_v1_vrps.set(len(self.vrps))
    #             prometheus.rpki_v1_bgpsec_keys.set(len(self.router_keys))
    #         case _:
    #             logger.warning(
    #                 "Not exporting the RPKI serial counter for version: %d", self.version
    #             )

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

    async def dump(self) -> AsyncGenerator[DumpMetadata | SnapshotDump | SerializedDump, None]:
        """
        Dumps the current data to JSON serializable format.
        The first yielded dict contains the metadata of the dump, then snapshots follows, and the 
        remaining dicts contain the serialized data encoded in base64.

        Yields:
        -------
        AsyncGeneratr[DumpMetadata | SnapshotDump | SerializedDump, None]: The metadata and data of
        the data dumps
        """

        # Metadata dump
        yield DumpMetadata(
            type="metadata",
            version=self.version,
            serial=self.serial,
            snapshots=list(self.snapshots.keys()),
            last_update=str(self.last_update) if self.last_update else None,
        )

        # Snapshots dump
        for snapshot_serial, snapshot in self.snapshots.items():
            yield SnapshotDump(
                type="snapshot",
                version=self.version,
                serial=snapshot_serial,
                hash=snapshot["hash"],
                timestamp=str(snapshot["timestamp"]),
            )

        # Serialized data dump
        for vrp in self.vrps:
            yield SerializedDump(
                type="vrp",
                version=self.version,
                serial=self.serial,
                serialized=b64encode(vrp).decode(),
            )

        for _router_key in self.router_keys:
            yield SerializedDump(
                type="router_key",
                version=self.version,
                serial=self.serial,
                serialized=b64encode(_router_key).decode(),
            )

        for serial, snapshot in self.snapshots.items():
            for vrp in snapshot["diffs"]["vrps"]:
                yield SerializedDump(
                    type="vrp_diff",
                    version=self.version,
                    serial=serial,
                    serialized=b64encode(vrp).decode(),
                )

            for _router_key in snapshot["diffs"]["router_keys"]:
                yield SerializedDump(
                    type="router_key_diff",
                    version=self.version,
                    serial=serial,
                    serialized=b64encode(_router_key).decode(),
                )
