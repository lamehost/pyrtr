"""
SLURM datasource implementation

This module is different compared to the other datasources because it is not designed to be used as
a standalone datasource, but rather as a helper for other datasources that want to support SLURM.
It is responsible for parsing the SLURM file and storing the data in a local
database.

The other datasources can use the SLURM oobject to get the relevant information.
"""

import asyncio
import logging
import os
from base64 import b64decode
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network
from typing import Generator, NotRequired, Optional, TypedDict, override

import orjson
import xxhash

from pyrtr.datasources.datasource import (
    ROA,
    BGPSecFilter,
    BGPSecKey,
    Data,
    PrefixFilter,
    SLURMDatasource,
)
from pyrtr.kvdb import KVDB, KVDBView

logger = logging.getLogger(__name__)


class JSONPrefixFilter(TypedDict):
    """
    SLURM Prefix filter found in the JSON file as defined in
    https://www.rfc-editor.org/rfc/rfc8416.html#section-3.3.1 .

    Keys:
    -----
    prefix: NotRequired[str]
        The prefix to filter. It can be missing. In that case is set to None during parsing
    asn: NotRequired[int]
        The ASN to filter. It can be missing. In that case is set to None during parsing
    comment: NotRequired[str]
        An optional comment for the filter
    """

    prefix: NotRequired[str]
    asn: NotRequired[int]
    comment: NotRequired[str]


class JSONBGPSecFilter(TypedDict):
    """
    SLURM BGPSec Key filter found in the JSON file as defined in
    https://www.rfc-editor.org/rfc/rfc8416.html#section-3.3.2 .

    Keys:
    -----
    SKI: NotRequired[str]
        The SKI to filter. It can be missing. In that case is set to None during parsing
    asn: NotRequired[int]
        The ASN to filter. It can be missing. In that case is set to None during parsing
    comment: NotRequired[str]
        An optional comment for the filter
    """

    asn: NotRequired[int]
    SKI: NotRequired[str]
    comment: NotRequired[str]


class JSONPrefixAssertion(TypedDict):
    """
    SLURM BGP Prefix Assertion found in the JSON file as defined in
    https://www.rfc-editor.org/rfc/rfc8416.html#section-3.4.1 .

    Keys:
    -----
    prefix: str
        The prefix in the assertion
    asn: str
        The ASN in the assertion
    maxPrefixLength: NotRequired[int]
        The maximum prefix length of the assertion. It can be missing. In that case is set to
        the lentgh of the prefix during parsing
    comment: NotRequired[str]
        An optional comment for the filter
    """

    prefix: str
    asn: int
    maxPrefixLength: NotRequired[int]
    comment: NotRequired[str]


class JSONBGPSecAssertion(TypedDict):
    """BGPSec Key assertion"""

    asn: int
    SKI: str
    routerPublicKey: str
    comment: NotRequired[str]


class JSONValidationOutputFilters(TypedDict):
    """Validation output filters"""

    prefixFilters: list[JSONPrefixFilter]
    bgpsecFilters: list[JSONBGPSecFilter]


class JSONLocallyAddedAssertions(TypedDict):
    """Locally added assertions"""

    prefixAssertions: list[JSONPrefixAssertion]
    bgpsecAssertions: list[JSONBGPSecAssertion]


class JSONFile(TypedDict):
    """Content of a  file"""

    slurmVersion: int
    validationOutputFilters: JSONValidationOutputFilters
    locallyAddedAssertions: JSONLocallyAddedAssertions


class JSONContent(TypedDict):
    """Defines the keys and values in for the content field"""

    db_path: os.PathLike[str] | str


class JSON(Data):
    """Defines the keys and values in the JSON snapshot"""

    content: JSONContent


class SLURM(SLURMDatasource):
    """SLURM datasource"""

    @override
    def __init__(
        self,
        *,
        version: int,
        data_location: str | os.PathLike[str],
        cache_location: str | os.PathLike[str],
        expire: int = 7200,
        encryption_key: Optional[bytes] | None = None,
    ):
        """
        Initialize the SLURM datasource

        Arguments:
        ----------
        version: int
            Version of the datasource
        data_location: str
            Location of the data. It can be either a local path or an URL
        cache_location: str
            Location of the cache. In can be either a local path or an URL
        expire: int
            Expiration time for the snapshots in seconds (default: 7200)
        encryption_key: Optional[bytes]
            The encryption key for the database (default: None)
        """
        super().__init__(
            version=version,
            data_location=data_location,
            cache_location=cache_location,
            expire=expire,
        )

        self.snapshots: dict[int, Data]
        if encryption_key is None:
            encryption_key = b""
            logger.warning("No encryption key provided for SLURM. Using empty key.")
        self.encryption_key = encryption_key

    @property
    def prefix_filters(self) -> Generator[PrefixFilter, None, None]:
        """
        Generator that yields prefix filters from the most recent snapshot.
        """
        try:
            for prefix_filter in KVDBView(
                self.snapshots[self.serial]["content"]["db_path"],
                "prefix_fiters_",
                self.encryption_key,
            ):
                if prefix_filter["prefix"] is not None:
                    prefix_filter["prefix"] = ip_network(prefix_filter["prefix"])
                    yield prefix_filter
        except KeyError:
            logger.info(
                "No prefix filters found in the SLURM snapshot %d for V%d",
                self.serial,
                self.version,
            )

    @property
    def bgpsec_filters(self) -> Generator[BGPSecFilter, None, None]:
        """
        Generator that yields BGPSec Key filters from the most recent snapshot.
        """
        try:
            for bgpsec_filter in KVDBView(
                self.snapshots[self.serial]["content"]["db_path"],
                "bgpsec_filters_",
                self.encryption_key,
            ):
                if bgpsec_filter["ski"] is not None:
                    bgpsec_filter["ski"] = b64decode(bgpsec_filter["ski"])
                yield bgpsec_filter
        except KeyError:
            logger.info(
                "No BGPSec Key filters found in the SLURM snapshot %d for V%d",
                self.serial,
                self.version,
            )

    @property
    def roas(self) -> Generator[ROA, None, None]:
        """
        Generator that yields ROAs from the most recent snapshot.
        """
        try:
            yield from KVDBView(
                self.snapshots[self.serial]["content"]["db_path"], "roas_", self.encryption_key
            )
        except KeyError:
            logger.info("No ROAs found in the SLURM snapshot %d for V%d", self.serial, self.version)

    @property
    def bgpsec_keys(self) -> Generator[BGPSecKey, None, None]:
        """
        Generator that yields BGPSec Keys from the most recent snapshot.
        """
        try:
            yield from KVDBView(
                self.snapshots[self.serial]["content"]["db_path"],
                "bgpsec_keys_",
                self.encryption_key,
            )
        except KeyError:
            logger.info(
                "No BGPSec Keys found in the SLURM snapshot %d for V%d", self.serial, self.version
            )

    async def _parse_prefix_filters(
        self, prefix_filters: list[JSONPrefixFilter]
    ) -> dict[bytes, PrefixFilter]:
        """
        Parses the list of JSONPrefixFilter objects into a dictionary of PrefixFilter objects.

        Arguments:
        ----------
        prefix_filters: list[JSONPrefixFilter]
            List of JSON prefix filters

        Returns:
        --------
        dict[bytes, PrefixFilter]: Dictionary of PrefixFilter objects, where the key is a string in
        the format "network|broadcast|asn"
        """
        reduced_prefix_filters: dict[bytes, PrefixFilter] = {}
        for prefix_filter in prefix_filters:
            # Set baseline object
            reduced_prefix_filter: PrefixFilter = {"asn": None, "prefix": None}

            # Normalize values
            try:
                prefix = ip_network(prefix_filter["prefix"])  # type: ignore
                reduced_prefix_filter["prefix"] = prefix
            except KeyError:
                pass

            try:
                reduced_prefix_filter["asn"] = prefix_filter["asn"]  # type: ignore
            except KeyError:
                pass

            # This mean "if either `asn` or `prefix` is not None"
            if any(reduced_prefix_filter.values()):
                key = (f"{reduced_prefix_filter['prefix']}|{reduced_prefix_filter['asn']}").encode(
                    "utf-8"
                )

                reduced_prefix_filters[key] = reduced_prefix_filter

            await asyncio.sleep(0)

        return reduced_prefix_filters

    async def _parse_bgpsec_filters(
        self, json_bgpsec_filters: list[JSONBGPSecFilter]
    ) -> dict[bytes, BGPSecFilter]:
        """
        Parses the list of JSONBGPSec filters into a dictionary of BGPSecFilter objects.

        Arguments:
        ----------
        json_bgpsec_filters: list[JSONBGPSecFilter]
            List of JSON BGPSec filters

        Returns:
        --------
        dict[bytes, BGPSecFilter]: Dictionary of BGPSecFilter objects, where the key is a string in
        the format "ski|asn"
        """
        bgpsec_filters: dict[bytes, BGPSecFilter] = {}
        for json_bgpsec_filter in json_bgpsec_filters:
            # Set baseline object
            bgpsec_filter: BGPSecFilter = {"ski": None, "asn": None}

            # Normalize values
            try:
                bgpsec_filter["ski"] = json_bgpsec_filter["SKI"].encode("utf-8")  # type: ignore
            except KeyError:
                pass

            try:
                bgpsec_filter["asn"] = json_bgpsec_filter["asn"]  # type: ignore
            except KeyError:
                pass

            # This mean "if either `asn` or `prefix` is not None"
            if any(bgpsec_filter.values()):
                bgpsec_filter_ski = b"" if bgpsec_filter["ski"] is None else bgpsec_filter["ski"]
                key = b"|".join([bgpsec_filter_ski, str(bgpsec_filter["asn"]).encode("utf-8")])

                bgpsec_filters[key] = bgpsec_filter

            await asyncio.sleep(0)

        return bgpsec_filters

    async def _parse_prefix_assertions(
        self, json_prefix_assertions: list[JSONPrefixAssertion]
    ) -> dict[bytes, ROA]:
        """
        Parses the list of JSON PrefixAssertion objects into a dictionary of ROA objects.

        Arguments:
        ----------
        json_prefix_assertions: list[JSONPrefixAssertion]
            List of JSON prefix assertions

        Returns:
        --------
        dict[bytes, ROA]: Dictionary of ROA objects, where the key is a string in the
            format"asn|prefix|maxLength"
        """
        expires_datetime = timedelta(seconds=self.expire) + datetime.now(timezone.utc)
        expires = int(expires_datetime.timestamp())

        roas: dict[bytes, ROA] = {}
        for json_prefix_assertion in json_prefix_assertions:
            try:
                max_length = json_prefix_assertion["maxPrefixLength"]  # type: ignore
            except KeyError:
                max_length = ip_network(json_prefix_assertion["prefix"]).prefixlen

            roa: ROA = {
                "asn": json_prefix_assertion["asn"],
                "prefix": ip_network(json_prefix_assertion["prefix"]),
                "maxLength": max_length,
                "ta": "SLURM",
                "expires": expires,
            }

            key = (f'{roa["asn"]}|{roa["prefix"]}|{roa["maxLength"]}').encode("utf-8")
            roas[key] = roa
            await asyncio.sleep(0)

        return roas

    async def _parse_bgpsec_assertions(
        self, json_bgpsec_keys: list[JSONBGPSecAssertion]
    ) -> dict[bytes, BGPSecKey]:
        """
        Parses the list of JSON BGPSecAssertion objects into a dictionary of BGPSecKey objects.

        Arguments:
        ----------
        json_bgpsec_keys: list[JSONBGPSecAssertion]
            List of JSON BGPSec assertions

        Returns:
        --------
        dict[bytes, BGPSecKey]: Dictionary of BGPSecKey objects, where the key is a string in the
        format "asn|ski|pubkey"
        """
        expires_datetime = timedelta(seconds=self.expire) + datetime.now(timezone.utc)
        expires = int(expires_datetime.timestamp())

        bgpsec_keys: dict[bytes, BGPSecKey] = {}
        for json_bgpsec_key in json_bgpsec_keys:
            reduced_bgpsec_key: BGPSecKey = {
                "asn": json_bgpsec_key["asn"],
                "pubkey": b64decode(json_bgpsec_key["routerPublicKey"]),
                "ski": b64decode(json_bgpsec_key["SKI"]),
                "expires": expires,
                "ta": "SLURM",
            }

            key = (
                f"{json_bgpsec_key['asn']}|"
                f"{json_bgpsec_key['SKI'].upper()}|"
                f"{json_bgpsec_key['routerPublicKey'].upper()}"
            ).encode("utf-8")
            bgpsec_keys[key] = reduced_bgpsec_key
            await asyncio.sleep(0)

        return bgpsec_keys

    @override
    async def parse(self) -> JSON:
        """
        Loads the content of the file.

        Returns:
        --------
        JSON: The JSON file
        """
        logger.debug("Parsing the JSON file")

        # Read the JSON file
        data: bytes = await self.read_json_file()
        json_file: JSONFile = orjson.loads(data)  # pylint: disable=no-member

        # Generate the database path string
        db_name: str = f'{json_file["slurmVersion"]}'
        db_path: str = os.path.join(self.cache_location, f"slurm_{db_name}_v{self.version}.sqlite")

        if os.path.exists(db_path):
            raise FileExistsError("The SLURM database file already exists")

        # Set values baseline
        prefix_filters: dict[bytes, PrefixFilter] = {}
        roas: dict[bytes, ROA] = {}
        bgpsec_filters: dict[bytes, BGPSecFilter] = {}
        bgpsec_keys: dict[bytes, BGPSecKey] = {}

        match self.version:
            case 0:
                # Parse prefixes and ignore BGPSec Keys
                prefix_filters = await self._parse_prefix_filters(
                    json_file["validationOutputFilters"]["prefixFilters"]
                )
                roas = await self._parse_prefix_assertions(
                    json_file["locallyAddedAssertions"]["prefixAssertions"]
                )
            case 1:
                # Parse prefixes
                prefix_filters = await self._parse_prefix_filters(
                    json_file["validationOutputFilters"]["prefixFilters"]
                )
                roas = await self._parse_prefix_assertions(
                    json_file["locallyAddedAssertions"]["prefixAssertions"]
                )
                # PArse BGPSec Keys
                bgpsec_filters = await self._parse_bgpsec_filters(
                    json_file["validationOutputFilters"]["bgpsecFilters"]
                )
                bgpsec_keys = await self._parse_bgpsec_assertions(
                    json_file["locallyAddedAssertions"]["bgpsecAssertions"]
                )
            case _:
                raise ValueError(f"Unsupported version number: {self.version}")

        # Calculate hash
        json_hash: str = xxhash.xxh64(
            bytes().join(prefix_filters.keys())
            + bytes().join(roas.keys())
            + bytes().join(bgpsec_filters.keys())
            + bytes().join(bgpsec_keys.keys())
        ).hexdigest()

        # Write full dumps
        with KVDB(
            db_path=db_path, table="prefix_fiters_", encryption_key=self.encryption_key
        ) as prefix_fiters_db:
            prefix_fiters_db.create_table()
            try:
                prefix_fiters_db.begin()
                for key, prefix_filter in prefix_filters.items():
                    prefix_fiters_db[key] = prefix_filter
                    await asyncio.sleep(0)
            finally:
                prefix_fiters_db.commit()

        with KVDB(db_path=db_path, table="roas_", encryption_key=self.encryption_key) as roas_db:
            roas_db.create_table()
            try:
                roas_db.begin()
                for key, roa in roas.items():
                    roas_db[key] = roa
                    await asyncio.sleep(0)
            finally:
                roas_db.commit()

        with KVDB(
            db_path=db_path, table="bgpsec_filters_", encryption_key=self.encryption_key
        ) as bgpsec_filters_db:
            bgpsec_filters_db.create_table()
            try:
                bgpsec_filters_db.begin()
                for key, bgpsec_filter in bgpsec_filters.items():
                    bgpsec_filters_db[key] = bgpsec_filter
                    await asyncio.sleep(0)
            finally:
                bgpsec_filters_db.commit()

        with KVDB(
            db_path=db_path, table="bgpsec_keys_", encryption_key=self.encryption_key
        ) as bgpsec_keys_db:
            bgpsec_keys_db.create_table()
            try:
                bgpsec_keys_db.begin()
                for key, bgpsec_key in bgpsec_keys.items():
                    bgpsec_keys_db[key] = bgpsec_key
                    await asyncio.sleep(0)
            finally:
                bgpsec_keys_db.commit()

        return {
            "content": {"db_path": db_path},
            "hash": json_hash,
            "timestamp": datetime.now(timezone.utc).timestamp(),
        }

    @override
    async def reload(self) -> bool:
        """
        Purge old JSON files, load the new one, calculate diffs, and increment serial.

        Return:
        -------
        bool: True if the process completed successfully.
        """
        logger.debug("Reloading the SLURM for V%d", self.version)

        # Delete stale snapshots
        await self.purge()

        # Read the JSON file
        try:
            new_snapshot: JSON = await self.parse()
        except FileExistsError:
            return False
        except (orjson.JSONDecodeError, KeyError) as error:  # pylint: disable=no-member
            raise ValueError(f"Unable to load the SLURM file: {error}") from error

        # Check if the new and the current most recent JSON are the same
        try:
            if new_snapshot["hash"] == self.snapshots[self.serial]["hash"]:
                # Delete new database
                try:
                    KVDB(
                        db_path=new_snapshot["content"]["db_path"],
                        table="",
                        encryption_key=self.encryption_key,
                    ).purge()
                except (FileExistsError, FileNotFoundError):
                    pass

                return False
        except KeyError:
            pass

        # self.serial is a property that only returns the max() key in self.snapthosts,
        # so adding a new key to snapshots, also increases serial.
        self.snapshots[self.serial + 1] = new_snapshot
        self.last_update = str(datetime.now(tz=timezone.utc))

        logger.info("Serial for the SLURM for V%d changed to: %d", self.version, self.serial)

        return True

    @override
    async def purge(self) -> None:
        """
        Purges all the databases but he last.
        """
        try:
            current_snapshot_file_name = os.path.basename(
                self.snapshots[self.serial]["content"]["db_path"]
            )
        except KeyError:
            current_snapshot_file_name = None

        # Remove stale databases
        for file in os.scandir(self.cache_location):
            if (
                current_snapshot_file_name != file.name
                and os.path.isfile(file)
                and file.name.startswith("slurm_")
                and file.name.endswith(f"_v{self.version}.sqlite")
            ):
                db_path = os.path.join(self.cache_location, file.name)
                for filename in KVDB(
                    db_path=db_path, table="", encryption_key=self.encryption_key
                ).purge():
                    logger.debug("Purging SLURM file from cache: %s", filename)

            await asyncio.sleep(0)
