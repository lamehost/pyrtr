"""Implements the pyrtr application"""

import asyncio
import functools
import logging
import os
import random

from pyrtr.rpki_client import RPKIClient
from pyrtr.rtr.cache import Cache

logger = logging.getLogger(__name__)


async def json_reloader(
    path: str | os.PathLike[str],
    rpki_client: RPKIClient,
    cache_registry: dict[str, Cache],
    expire: int = 7200,
    sleep: int = 1800,
) -> None:
    """
    Reloads the content of the RPKI JSON output. Holds `sleeps` seconds between every attempt

    Arguments:
    ----------
    path: str | os.PathLike[str]
        The path pointing to the JSON file
    rpki_client: RPKIClient instance
        RPKIClient instance
    cache_registry: dict[str, Cache]
        The Cache registry
    expire: int
        Expire Interval in seconds: Expire: 7200
    sleep: int
        Sleep interval in seconds. Default: 1800
    """
    while True:
        # Remove stale entries
        rpki_client.purge(expire)

        try:
            # Load new entries
            await rpki_client.load(path)
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.error("Unable to load the RPKI client JSON file: %s", error)
            await asyncio.sleep(sleep)
            continue

        logger.info(
            "JSON file reloaded: %d prefixes, %d BGPsec Keys",
            len(rpki_client.prefixes),
            len(rpki_client.router_keys),
        )

        for cache in cache_registry.values():
            # Notify clients if needed
            if cache.current_serial != cache.rpki_client.serial:
                try:
                    cache.write_serial_notify()
                    cache.current_serial = cache.rpki_client.serial
                except ConnectionResetError:
                    logger.warning("Unable to notify serial to: %s", cache.remote)

        logger.debug("JSON file will be reloaded in: %d seconds", sleep)
        await asyncio.sleep(sleep)


def register_cache(cache: Cache, *, cache_registry: dict[str, Cache]) -> None:
    """
    Registers the Cache instance to the Cache registry.

    Arguments:
    ----------
    cache: Cache
        Cache instance
    cache_registry: dict[str, Cache]
        Cache registry
    """
    cache_registry[cache.remote] = cache
    logger.info("Registered cache: %s", cache.remote)


def unregister_cache(cache: Cache, *, cache_registry: dict[str, Cache]) -> None:
    """
    Unregisters the Cache instance from the Cache registry.

    Arguments:
    ----------
    cache: Cache
        Cache instance
    cache_registry: dict[str, Cache]
        Cache registry
    """
    try:
        del cache_registry[cache.remote]
        logger.info("Unregisterd cache: %s", cache.remote)
    except KeyError:
        logger.error("Attempted to unregister a non existing cache client: %s", cache.remote)


def create_cache_instance(  # pylint: disable=too-many-arguments
    session: int,
    rpki_client: RPKIClient,
    cache_registry: dict[str, Cache],
    *,
    refresh: int = 3600,
    retry: int = 600,
    expire: int = 7200,
) -> Cache:
    """
    Creates a Cache instance that registers itself to the registry

    Arguments:
    ----------
    session: str
        The session ID
    rpki_client: RPKIClient instance
        RPKIClient instance
    cache_registry: dict[str, Cache]
        The Cache registry
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds: Expire: 7200

    Returns:
    --------
    Cache: The cache instance
    """

    cache = Cache(
        session,
        rpki_client,
        connect_callback=functools.partial(register_cache, cache_registry=cache_registry),
        disconnect_callback=functools.partial(unregister_cache, cache_registry=cache_registry),
        refresh=refresh,
        retry=retry,
        expire=expire,
    )

    return cache


async def rtr_server(  # pylint: disable=too-many-arguments
    host: str,
    port: int,
    session: int,
    rpki_client: RPKIClient,
    cache_registry: dict[str, Cache],
    *,
    refresh: int = 3600,
    retry: int = 600,
    expire: int = 7200,
):
    """
    Starts a local async RTR server and binds it to the specified host and port

    Arguments:
    ----------
    host: str
        The host to bind to
    port: int
        The TCP port to bind to
    rpki_client: RPKIClient instance
        RPKIClient instance
    cache_registry: Cache
        The RTR Cache registry
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds: Expire: 7200
    """
    # Initialize server
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: create_cache_instance(
            session,
            rpki_client,
            cache_registry,
            refresh=refresh,
            retry=retry,
            expire=expire,
        ),
        host,
        port,
    )

    # Find the sockets the server will bind to
    listening_sockets = ", ".join(
        [
            f"{listening_host}:{listening_port}"
            for _socket in server.sockets
            if (listening_host := _socket.getsockname()[0])
            if (listening_port := _socket.getsockname()[1])
        ]
    )

    async with server:
        logger.info("Listening on %s. Session: %i", listening_sockets, session)
        # Start the server
        await server.serve_forever()


async def pyrtr(  # pylint: disable=too-many-arguments
    host: str,
    port: int,
    path: str | os.PathLike[str],
    *,
    refresh: int = 3600,
    expire: int = 600,
    retry: int = 7200,
) -> None:
    """
    Reloads the content of the RPKI JSON output every half `refresh`, and starts the RTR server.

    Arguments:
    ----------
    host: str
        The host to bind to
    port: int
        The TCP port to bind t
    path: str | os.PathLike[str]
        The path pointing to the JSON file
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds: Expire: 7200
    """

    rpki_client = RPKIClient()
    session: int = random.randrange(0, 65535)
    cache_registry: dict[str, Cache] = {}

    await asyncio.gather(
        json_reloader(path, rpki_client, cache_registry, expire, int(refresh / 2)),
        rtr_server(
            host,
            port,
            session,
            rpki_client,
            cache_registry,
            refresh=refresh,
            expire=expire,
            retry=retry,
        ),
    )
