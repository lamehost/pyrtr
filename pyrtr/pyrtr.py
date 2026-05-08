"""Implements the pyrtr application"""

import asyncio
import functools
import logging
import os
import random
import secrets

from pyrtr import prometheus
from pyrtr.datasources import SLURM, RPKIClient, RPKIDatasource, SLURMDatasource
from pyrtr.http import http_server
from pyrtr.rtr.cache import Cache

logger = logging.getLogger(__name__)


async def datasource_reloader(
    rpki_instances: dict[int, RPKIDatasource],
    slurm_instances: dict[int, SLURMDatasource | None],
    cache_registry: dict[str, Cache],
    sleep: int = 900,
) -> None:
    """
    Reloads the content of the datasources and notify clients of changes.
    Holds `sleeps` seconds between every attempt

    Arguments:
    ----------
    rpki_instances: dict[int, RPKIDatasource]
        Datasource instances (one per version)
    slurm_instances: dict[int, SLURMDatasource | None]
        SLURM instances (one per version)
    cache_registry: dict[str, Cache]
        The Cache registry
    sleep: int
        Sleep interval in seconds. Default: 900
    """
    while True:
        # There is one datasource per version
        for rpki_instance in rpki_instances.values():
            # Reload SLURM
            slurm = slurm_instances.get(rpki_instance.version)
            if slurm is not None:
                try:
                    # Load a new snapshot of the SLURM datasource
                    await slurm.reload()
                except Exception as error:  # pylint: disable=broad-exception-caught
                    logger.exception(
                        "Unable to reload the SLURM data source: %s", error, exc_info=True
                    )
                    continue

            try:
                # Load a new snapshot of the RPKI datasource
                await rpki_instance.reload()
            except Exception as error:  # pylint: disable=broad-exception-caught
                logger.exception("Unable to reload the RPKI data source: %s", error, exc_info=True)
                continue

            logger.info(
                "Data sources reloaded for v%d: %d VRPs, %d BGPsec Keys",
                rpki_instance.version,
                len(rpki_instance.vrps),
                len(rpki_instance.router_keys),
            )

            # Notify clients of changes
            cache_ids = list(cache_registry)
            for cache_id in cache_ids:
                try:
                    cache = cache_registry[cache_id]
                except KeyError:
                    # cache_registry might change outside the function while we iterate through it
                    continue

                if rpki_instance.version != cache.version:
                    # Do not send notifications if the session is different.
                    # This should never happen, since the session ID is negotiated during the
                    # connection phase, but we check it just in case.
                    continue

                if not cache.current_serial or not cache.datasource:
                    # Cache isntances are registered immediately after the connection is
                    # established, but before the version is determined.
                    # In some cases, the datasource might not be set yet.
                    continue

                if cache.current_serial != cache.datasource.serial:
                    # Notify clients that the current serial has changed to send the Serial Query
                    # PDU
                    try:
                        cache.write_serial_notify()
                        cache.current_serial = cache.datasource.serial
                    except ConnectionResetError:
                        logger.warning("Unable to notify serial to: %s", cache.remote)

            await asyncio.sleep(0)

        logger.debug("Datasources will be reloaded in: %d seconds", sleep)
        await asyncio.sleep(sleep)


def register_cache(cache: Cache, *, cache_registry: dict[str, Cache]) -> None:
    """
    Registers a Cache instance to the Cache registry. Usually triggered when a client connects to
    the RTR server.

    Arguments:
    ----------
    cache: Cache
        Cache instance
    cache_registry: dict[str, Cache]
        Cache registry
    """
    if cache.remote is None:
        raise RuntimeError("Attempting to register an uninitialized cache")

    cache_registry[cache.remote] = cache
    prometheus.clients.inc()
    logger.info("Registered cache instance: %s", cache.remote)


def unregister_cache(cache: Cache, *, cache_registry: dict[str, Cache]) -> None:
    """
    Unregisters a Cache instance from the Cache registry. Usually triggered whena a client
    disconnects from the RTR server.

    Arguments:
    ----------
    cache: Cache
        Cache instance
    cache_registry: dict[str, Cache]
        Cache registry
    """
    if cache.remote is None:
        raise RuntimeError("Attempting to unregister an uninitialized cache")

    try:
        del cache_registry[cache.remote]
        prometheus.clients.dec()
        logger.info("Unregistered cache instance: %s", cache.remote)
    except KeyError:
        logger.error("Attempted to unregister a non existing cache client: %s", cache.remote)


async def rtr_server(  # pylint: disable=too-many-arguments
    host: str,
    port: int,
    sessions: dict[int, int],
    datasources: dict[int, RPKIDatasource],
    cache_registry: dict[str, Cache],
    *,
    refresh: int = 3600,
    retry: int = 600,
    expire: int = 7200,
) -> None:
    """
    Starts a local async RTR server and binds it to the specified host and port

    Arguments:
    ----------
    host: str
        The host to bind to
    port: int
        The TCP port to bind to
    sessions: dict[int, int]
        The session IDs (one per version)
    datasources: dict[int, RPKIDatasource]
        RPKI Datasources instances (one per version)
    cache_registry: Cache
        The RTR Cache registry
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
         Expire Interval in seconds. Default: 7200
    """
    # Initialize the server
    loop = asyncio.get_running_loop()

    # Define callbacks in a manner the linters can understand
    connect_callback: functools.partial[None] = functools.partial[None](
        register_cache, cache_registry=cache_registry
    )
    disconnect_callback: functools.partial[None] = functools.partial[None](
        unregister_cache, cache_registry=cache_registry
    )

    # Run up the cache instance
    server = await loop.create_server(
        lambda: Cache(
            connect_callback=connect_callback,
            disconnect_callback=disconnect_callback,
            sessions=sessions,
            datasources=datasources,
            refresh=refresh,
            retry=retry,
            expire=expire,
        ),
        host,
        port,
        keep_alive=True,
    )

    # Start the server
    async with server:
        logger.info(
            "RTR Cache listening at %s:%d. v0 Session: %d. v1 Session: %d",
            host,
            port,
            sessions.get(0),
            sessions.get(1),
        )
        # Start the server
        await server.serve_forever()


async def run_cache(  # pylint: disable=too-many-arguments
    host: str,
    rtr_port: int,
    http_port: int,
    reload: int,
    datasource: str,
    *,
    data_location: str | os.PathLike[str] | None = None,
    cache_location: str | os.PathLike[str] | None = None,
    slurm_location: str | os.PathLike[str] | None = None,
    disable_cache_encryption: bool = False,
    refresh: int = 3600,
    retry: int = 600,
    expire: int = 7200,
) -> None:
    """
    Reloads the content of the RPKI datasource output every half `refresh`, and starts the RTR
    server.

    Arguments:
    ----------
    host: str
        The host to bind to
    rtr_port: int
        The TCP port to bind the RTR Cache to
    http_port: int
        The TCP port to bind the HTTP server to
    reload: int
        The Interval after which the Datasources are reloaded
    datasource: str
        The chosen datasource
    data_location: str | os.PathLike[str] | None
        The path pointing to the datasource file. Default: None
    cache_location: str | os.PathLike[str] | None
        The path pointing to the cache directory. Default: None
    slurm_location: str | os.PathLike[str] | None
        The path pointing to the SLURM file. Default: None
    disable_cache_encryption: bool
        Whether to disable cache encryption. Default: False
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds. Default: 7200
    """

    # Set encryption key
    encryption_key: bytes | None = None
    if disable_cache_encryption:
        logger.warning(
            "Cache encryption disabled. "
            "This is dangerous and should only be used for testing purposes."
        )
    else:
        encryption_key = secrets.token_bytes(32)
        logger.debug("Cache encryption enabled. Encryption key: %s", encryption_key.hex())

    # Initialize the SLURM datasources
    slurm_instances: dict[int, SLURMDatasource | None]
    if slurm_location is not None:
        if cache_location is None:
            raise ValueError("cache_location is required for the SLURM datasource")

        slurm_instances = {
            0: SLURM(
                version=0,
                data_location=slurm_location,
                cache_location=cache_location,
                encryption_key=encryption_key,
            ),
            1: SLURM(
                version=1,
                data_location=slurm_location,
                cache_location=cache_location,
                encryption_key=encryption_key,
            ),
        }
    else:
        slurm_instances = {0: None, 1: None}

    # Initialize the RPKI datasources
    rpki_instances: dict[int, RPKIDatasource]
    match datasource:
        case "RPKICLIENT":
            if data_location is None:
                raise ValueError("data_location is required for the RPKICLIENT datasource")
            if cache_location is None:
                raise ValueError("cache_location is required for the RPKICLIENT datasource")
            rpki_instances = {
                0: RPKIClient(
                    version=0,
                    data_location=data_location,
                    cache_location=cache_location,
                    slurm=slurm_instances[0],
                    expire=expire,
                    encryption_key=encryption_key,
                ),
                1: RPKIClient(
                    version=1,
                    data_location=data_location,
                    cache_location=cache_location,
                    slurm=slurm_instances[1],
                    expire=expire,
                    encryption_key=encryption_key,
                ),
            }
        case _:
            raise ValueError(f"Unsupported datasource: {datasource}")

    # Initialize the session IDs and the Cache registry
    sessions: dict[int, int] = {0: random.randint(0, 65535), 1: random.randint(0, 65535)}
    cache_registry: dict[str, Cache] = {}

    # The datasource_reloader coroutine is always executed, while for the others it depends on the
    # config.
    coroutines = [datasource_reloader(rpki_instances, slurm_instances, cache_registry, reload)]

    if rtr_port > 0:
        # Execute the rtr_server if rtr_port is bigger than 0
        coroutines.append(
            rtr_server(
                host,
                rtr_port,
                sessions,
                rpki_instances,
                cache_registry,
                refresh=refresh,
                retry=retry,
                expire=expire,
            )
        )

    if http_port > 0:
        # Execute the http_server if http_port is bigger than 0
        coroutines.append(http_server(host, http_port, sessions, rpki_instances, cache_registry))

    await asyncio.gather(*coroutines)
