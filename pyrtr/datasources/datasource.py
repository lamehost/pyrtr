"""
Implements the Abstract Base Class for the Datasource

Two further ABC of `Datasource` class are provided:
    - `RPKIDatasource`: For RPKI data (primarily used by data_reloader() and Cache)
    - `SLURMDatasource`: For SLURM data (primarily used by data_reloader() and RPKIDatasource)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from base64 import b64encode
from collections.abc import Collection, Generator
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import (
    Any,
    AsyncGenerator,
    Generic,
    Optional,
    TypedDict,
    TypeVar,
    override,
)
from urllib.parse import urlparse

import aiofiles
import aiohttp

from pyrtr.rtr.pdu import ipv4_prefix, ipv6_prefix, router_key

logger = logging.getLogger(__name__)


class PrefixFilter(TypedDict):
    """
    Internal contstruct used by SLURMDataSource to represent SLURM Prefix filters.

    Keys:
    -----
    asn: Optional[int]
        If not null, matches all ROAs with the same ASN
    prefix: Optional[IPv4Network | IPv6Network]
        If not null, matches all ROAs with a prefix that is a subnet of this prefix
    """

    asn: Optional[int]
    prefix: Optional[IPv4Network | IPv6Network]


class BGPSecFilter(TypedDict):
    """
    Internal contstruct used by SLURMDataSource to represent SLURM BGPSec Key filters.

    Keys:
    -----
    asn: Optional[int]
        If not null, matches all ROAs with the same ASN
    ski: Optional[bytes]
        If not null, matches all ROAs with the same SKI
    """

    asn: Optional[int]
    ski: Optional[bytes]


class ROA(TypedDict):
    """
    Internal contstruct that represents RPKI ROAs and SLURM Prefix Assertions.

    Keys:
    -----
    asn: int
        The ASN of the ROA
    prefix: IPv4Network | IPv6Network
        The prefix of the ROA
    maxLength: int
        The maximum prefix length of the ROA
    ta: Optional[str]
        The Trust Anchor of the ROA. This field is not present in SLURM Prefix Assertions, so it is
        optional.
    expires: float
        The unix timestamp of when the ROA expires.
    """

    asn: int
    prefix: IPv4Network | IPv6Network
    maxLength: int
    ta: Optional[str]
    expires: float


class BGPSecKey(TypedDict):
    """
    Internal construct that represents RPKI BGPSec keys and SLURM BGPSec Key Assertions.

    Keys:
    -----
    asn: int
        The ASN of the BGPSec Key
    ski: str
        The Subject Key Identifier of the BGPSec Key
    pubkey: str
        The Subject Public Key Info of the BGPSec Key, encoded in base64
    ta: Optional[str]
        The Trust Anchor of the BGPSec Key. This field is not present in SLURM BGPSec Key
        Assertions, so it is optional.
    expires: Optional[int]
        The unix timestamp of when the BGPSec Key expires. This field is not present in SLURM Prefix
        Assertions, so it is optional.
    """

    asn: int
    ski: bytes
    pubkey: bytes
    ta: Optional[str]
    expires: int


class ASPA(TypedDict):
    """RPKI ASPA object"""

    customer_asid: int
    expires: int
    providers: list[int]


class Serialized(TypedDict):
    """
    RPKI VRPs and Router Keys serialized to bytes according to the RTR format.
    These are the bytes that will be sent to the RTR clients by the cache.

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
    RPKI Data instance

    Keys:
    -----
    hash: str
        The hash representing the data
    timestamp: float
        The unix timestamp the file has been created
    diffs: Serialized
        The VRP and Router Keys difference between this and the last instance
    serialized: Serialized
        The VRPs and Router Keys for this instance
    content:
        The content provided by the data source, which is a JSONContent in this case.
    """

    hash: str
    timestamp: float
    content: Any


class RPKIData(Data):
    """
    RPKI Data instance

    Keys:
    -----
    hash: str
        The hash representing the data,
    timestamp: float
        The unix timestamp the file has been created
    diffs: Serialized
        The VRP and Router Keys difference between this and the last instance
    serialized: Serialized
        The VRPs and Router Keys for this instance
    content:
        The content provided by the data source, which is a JSONContent in this case.
    """

    diffs: Serialized
    serialized: Serialized


# Type variable for the Datasource class.
# It is bound to the Data type, so it can be used to specify the type of the data in the snapshots
# dict of the Datasource class.
DATATYPE = TypeVar("DATATYPE", bound=Data)


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


class Datasource(ABC, Generic[DATATYPE]):
    """
    Abstract Base Class that defines a data source that can be passed to Cache and
    `data_reloader()`.

    Provides 2 properties and 3 abstract methods:
        - serial: Returns the current serial number
        - content: Returns the current content provided by the data source
        - parse: Parses data at `self.location()` and returns Data
        - purge: Deletes expired snapshots
        - reload: Adds a new snapshot and recalculates diffs

    `snapshots` is a dict whose keys are the serial number and values are the `Data` for that serial
    number. This construct comes handy with RPKIDatasource (a subclass of this ABC) that requires
    multiple (incremental) snapshots of the same dataset.
    """

    def __init__(
        self,
        version: int,
        data_location: Any,
        cache_location: Any,
        expire: int = 7200,
    ):
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
            When the data expires. Default: 7200 seconds (2 hours)
        """
        self.version: int = version
        self.data_location: Any = data_location
        self.cache_location: Any = cache_location
        self.expire: int = expire

        self.snapshots: dict[int, DATATYPE] = {}
        self.last_update: str | None = None

    async def read_json_file(self) -> bytes:
        """
        Reads the JSON file either locally or remotely if `self.data_location` is an URL

        Returns:
        --------
        bytes: The content of the JSON file
        """
        if not isinstance(self.data_location, (str, bytes)):
            raise ValueError("Data_location must be a string or bytes")

        # Test if the `data_location` is a URL
        if urlparse(str(self.data_location)).scheme in ("http", "https"):
            async with aiohttp.ClientSession() as session:
                async with session.get(str(self.data_location)) as response:
                    return (await response.text()).encode("utf-8")
        else:
            async with aiofiles.open(self.data_location, mode="rb") as file:
                return await file.read()

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
    def content(self) -> Any:
        """
        Returns the current content provided by the data source

        Returns:
        -------
        Any: The content provided by the data source
        """
        try:
            return self.snapshots[self.serial]["content"]
        except KeyError:
            return None

    @abstractmethod
    async def parse(self) -> Data:
        """
        Parses data at `self.data_location` and returns Data

        This method is *usually* invoked by `reload()`

        Returns:
        --------
        Data: The parsed Data
        """
        raise NotImplementedError

    @abstractmethod
    async def purge(self) -> None:
        """
        Deletes the items in `self.snapshots` whose `timestamp` is older than `expire`.

        This method is usually invoked by `reload` and should:
            1) Delete expired `snapshots`
            2) Delete the data in `self.cache_location` that is not referenced by `self.snapshots`
        """
        raise NotImplementedError

    @abstractmethod
    async def reload(self) -> bool:
        """
        Reloads the data at self.data_location, creates a new snapshot, and recalculates diffs
        (if necessary).

        This method should:
            1) Run `self.parse()`
            3) Update the diffs in each of the items in `self.snapshots`
            2) Add the output of parse() to `self.snapshots`

        Returns:
        --------
        bool: True if the reload was succesfull, False otherwise
        """
        raise NotImplementedError


class SLURMDatasource(Datasource[Data]):
    """
    Abstract Base Class that defines a SLURM data source. This is used by RPKIDatasource to filter
    the ROAs and BGPSec Keys according to the SLURM.

    Differently to RPKIDatasource, this data source does not need multiple snapshots. However it
    still uses it for simplicity. As a result, the `self.purge()` method implemented in the concrete
    classes should drop all the snapshots but the very last.
    """

    def __init__(
        self,
        version: int,
        data_location: Any,
        cache_location: Any,
        expire: int = 7200,
    ):
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
            When the data expires. Default: 7200 seconds (2 hours)
        """
        super().__init__(
            version=version,
            data_location=data_location,
            cache_location=cache_location,
            expire=expire,
        )

    @property
    def prefix_filters(self) -> Generator[PrefixFilter, None, None]:
        """
        Generator that yields prefix filters from the most recent snapshot.

        Yields:
        -------
        Generator[PrefixFilter, None, None]: PrefixFilter objects
        """
        raise NotImplementedError

    @property
    def bgpsec_filters(self) -> Generator[BGPSecFilter, None, None]:
        """
        Generator that yields BGPSec Key filters from the most recent snapshot.

        Yields:
        -------
        Generator[BGPSecFilter, None, None]: BGPSecFilter objects
        """
        raise NotImplementedError

    @property
    def roas(self) -> Generator[ROA, None, None]:
        """
        Generator that yields ROAs from the most recent snapshot.

        Yields:
        -------
        Generator[ROA, None, None]: ROA objects
        """
        raise NotImplementedError

    @property
    def bgpsec_keys(self) -> Generator[BGPSecKey, None, None]:
        """
        Generator that yields BGPSec Keys from the most recent snapshot.

        Yields:
        -------
        Generator[BGPSecKey, None, None]: BGPSecKey objects
        """
        raise NotImplementedError


class RPKIDatasource(Datasource[RPKIData]):
    """
    Abstract Base Class that defines a data sources that can be passed to Cache and data_reloader().
    """

    def __init__(
        self,
        *,
        version: int,
        data_location: Any,
        cache_location: Any,
        expire: int = 7200,
        slurm: Optional[SLURMDatasource] = None,
    ):
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
            When the data expires. Default: 7200 seconds (2 hours)
        slurm: Optional[SLURMDatasource] = None
            The slurm data source. The actual type is implementation specific. Default: None
        """
        super().__init__(
            version=version,
            data_location=data_location,
            cache_location=cache_location,
            expire=expire,
        )

        self.snapshots: dict[int, RPKIData] = {}
        self.slurm: Optional[SLURMDatasource] = slurm

    @override
    @abstractmethod
    async def parse(self) -> RPKIData:
        """
        Parses data at `self.data_location` and returns RPKIData

        This method is *usually* invoked by `self.reload()`

        Returns:
        --------
        RPKIData: The parsed RPKI Data
        """
        raise NotImplementedError

    @property
    def vrps(self) -> Collection[bytes]:
        """
        Property that returns the current set of VRPs

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
        Property that returns the current set of Router Keys

        Returns
        -------
        Collection[bytes]: The data bytes for each Router Key
        """
        try:
            return self.snapshots[self.serial]["serialized"]["router_keys"]
        except KeyError:
            return []

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

        Returns:
        -------
        bytes: The serialized Router Key
        """
        return router_key.serialize(
            version=self.version,
            flags=flags,
            ski=ski,
            spki=pubkey,
            asn=asn,
        )

    def serialize_prefix(
        self, prefix: str | IPv4Network | IPv6Network, asn: int, maxlength: int, flags: int
    ) -> bytes:
        """
        Serialize router keys to bytes

        Arguments:
        ----------
        prefix: str | IPv4Network | IPv6Network
            Prefix with prefixlen
        asn: int
            Autonomous System Number
        maxlength: int
            The longest prefix lenght allowed
        flags: int
            RTR announcements flags

        Returns:
        -------
        bytes: The serialized Prefix
        """
        if isinstance(prefix, str):
            prefix = ip_network(prefix)

        if prefix.version == 4:
            return ipv4_prefix.serialize(
                version=self.version,
                prefix=prefix.network_address.packed,
                prefix_length=prefix.prefixlen,
                flags=flags,
                max_length=maxlength,
                asn=asn,
            )

        return ipv6_prefix.serialize(
            version=self.version,
            prefix=prefix.network_address.packed,
            prefix_length=prefix.prefixlen,
            flags=flags,
            max_length=maxlength,
            asn=asn,
        )

    async def dump(self) -> AsyncGenerator[DumpMetadata | SnapshotDump | SerializedDump, None]:
        """
        Dumps the current data to JSON serializable format.
        It yelds a dict with the metadata for the dump first, than the snapshots, and than again the
        remaining dicts that contain the serialized data encoded in base64.

        Yields:
        -------
        AsyncGeneratr[DumpMetadata | SnapshotDump | SerializedDump, None]: The metadata, the dump of
        the snapshots and the dump of the data.
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
