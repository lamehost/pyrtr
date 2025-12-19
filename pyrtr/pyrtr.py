"""Implements the pyrtr application"""

import asyncio
import functools
import json
import logging
import os
import random
from typing import TypedDict

from aiohttp import web

from pyrtr.rpki_client import RPKIClient
from pyrtr.rtr.cache import Cache

logger = logging.getLogger(__name__)


class RPKIClientStatus(TypedDict):
    """
    Defines the set of metadata describing the status of the RPKIClient JSON file
    """

    serial: int
    vrps: int
    router_keys: int
    last_update: str | None


class Status(TypedDict):
    """
    Defines the set of metadata describing the application status
    """

    rpki_client: dict[str, RPKIClientStatus]
    clients: list[str]
    sessions: dict[str, int]
    pid: int


async def https_server(
    host: str,
    port: int,
    sessions: dict[int, int],
    rpki_clients: dict[int, RPKIClient],
    cache_registry: dict[str, Cache],
) -> web.TCPSite:
    """
    Runs the HTTP server for the /status endpoint.

    Arguments:
    ----------
    host: str
        The host to bind to
    port: int
        The TCP port to bind to
    sessions: dict[int, int]
        The session IDs
    rpki_client: RPKIClient instance
        RPKIClient instance
    cache_registry: Cache
        The RTR Cache registry

    Returns:
    --------
    web.TCPSite: The TCP server coroutine
    """

    async def handle_get_status(_: web.Request) -> web.Response:  # NOSONAR
        status = Status(
            rpki_client={
                "v0": RPKIClientStatus(
                    serial=rpki_clients[0].serial,
                    vrps=len(rpki_clients[0].vrps),
                    router_keys=len(rpki_clients[0].router_keys),
                    last_update=rpki_clients[0].last_update,
                ),
                "v1": RPKIClientStatus(
                    serial=rpki_clients[1].serial,
                    vrps=len(rpki_clients[1].vrps),
                    router_keys=len(rpki_clients[1].router_keys),
                    last_update=rpki_clients[1].last_update,
                ),
            },
            clients=list(cache_registry.keys()),
            sessions={"v0": sessions[0], "v1": sessions[1]},
            pid=os.getpid(),
        )

        return web.json_response(status, dumps=lambda data: json.dumps(data, indent=2))

    webapp = web.Application()
    webapp.router.add_get(
        "/healthz",
        handle_get_status,
        allow_head=True,
    )

    runner = web.AppRunner(webapp)
    await runner.setup()
    site = web.TCPSite(runner, host, port)

    logger.info("Status endpoint available at http://%s:%d/healthz", host, port)
    await site.start()

    while True:
        await asyncio.sleep(60)


async def json_reloader(
    path: str | os.PathLike[str],
    rpki_clients: dict[int, RPKIClient],
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
    rpki_client: RPKIClient
        RPKIClient instances (one per version)
    cache_registry: dict[str, Cache]
        The Cache registry
    expire: int
        Expire Interval in seconds: Expire: 7200
    sleep: int
        Sleep interval in seconds. Default: 1800
    """
    while True:
        # Remove stale entries
        for rpki_client in rpki_clients.values():
            rpki_client.purge(expire)

            try:
                # Load new entries
                await rpki_client.load(path)
            except Exception as error:  # pylint: disable=broad-exception-caught
                logger.error("Unable to load the RPKI client JSON file: %s", error)
                await asyncio.sleep(sleep)
                continue

            logger.info(
                "JSON file reloaded (version %d): %d VRPs, %d BGPsec Keys",
                rpki_client.version,
                len(rpki_client.vrps),
                len(rpki_client.router_keys),
            )

            for cache in cache_registry.values():
                if rpki_client.version != cache.version:
                    continue

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
    sessions: dict[int, int],
    rpki_clients: dict[int, RPKIClient],
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
    sessions: dict[int, int]
        The session IDs (one per version)
    rpki_clients: dict[int, RPKIClient]
        RPKIClient instances (one per version)
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
        sessions,
        rpki_clients,
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
    sessions: dict[int, int],
    rpki_clients: dict[int, RPKIClient],
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
    sessions: dict[int, int]
        The session IDs (one per version)
    rpki_clients: RPKIClient
        RPKIClient instances (one per version)
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
            sessions,
            rpki_clients,
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
        logger.info(
            "Listening on %s. V0 Session: %d. V1 Session: %d",
            listening_sockets,
            sessions[0],
            sessions[1],
        )
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
        The TCP port to bind to
    path: str | os.PathLike[str]
        The path pointing to the JSON file
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds: Expire: 7200
    """

    rpki_clients: dict[int, RPKIClient] = {0: RPKIClient(version=0), 1: RPKIClient(version=1)}
    sessions: dict[int, int] = {0: random.randrange(0, 65535), 1: random.randrange(0, 65535)}
    cache_registry: dict[str, Cache] = {}

    await asyncio.gather(
        json_reloader(path, rpki_clients, cache_registry, expire, int(refresh / 2)),
        rtr_server(
            host,
            port,
            sessions,
            rpki_clients,
            cache_registry,
            refresh=refresh,
            expire=expire,
            retry=retry,
        ),
        https_server(host, 8080, sessions, rpki_clients, cache_registry),
    )
