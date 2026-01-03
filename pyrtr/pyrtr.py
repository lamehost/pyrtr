"""Implements the pyrtr application"""

import asyncio
import functools
import logging
import os
import random
from typing import TypedDict

from aiohttp import web
from prometheus_client.aiohttp import make_aiohttp_handler as prometheus_aiohttp_handler

from pyrtr import prometheus
from pyrtr.rpki_client import RPKIClient
from pyrtr.rtr.cache import Cache

logger = logging.getLogger(__name__)


class RPKIClientStats(TypedDict):
    """
    Defines the set of metadata describing the status of the RPKIClient JSON file
    """

    last_update: str | None


class Status(TypedDict):
    """
    Defines the set of metadata describing the application status
    """

    rpki_clients: dict[str, RPKIClientStats]
    sessions: dict[str, int | None]
    pid: int


async def http_server(
    host: str,
    port: int,
    sessions: dict[int, int],
    rpki_clients: dict[int, RPKIClient],
    cache_registry: dict[str, Cache],
) -> None:
    """
    Runs the HTTP server providing three endpoints:
     - /clients: List of connected clients
     - /healthz: Application status
     - /metrics: Prometheus metrics

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
    cache_registry: dict[str, Cache]
        The Cache registry
    """

    async def get_clients(_: web.Request) -> web.Response:  # NOSONAR
        clients = [
            {"client": client_id, "version": f"V{cache.version}"}
            for client_id, cache in cache_registry.items()
        ]
        return web.json_response(clients)

    async def get_health(_: web.Request) -> web.Response:  # NOSONAR
        try:
            v0_last_update = rpki_clients[0].last_update
            v0_session = sessions[0]
        except KeyError:
            v0_last_update = None
            v0_session = None

        try:
            v1_last_update = rpki_clients[1].last_update
            v1_session = sessions[1]
        except KeyError:
            v1_last_update = None
            v1_session = None

        status: Status = {
            "rpki_clients": {
                "V0": {"last_update": v0_last_update},
                "V1": {"last_update": v1_last_update},
            },
            "sessions": {"V0": v0_session, "V1": v1_session},
            "pid": os.getpid(),
        }

        return web.json_response(status)

    webapp = web.Application()
    webapp.router.add_get(
        "/clients",
        get_clients,
        allow_head=True,
    )
    webapp.router.add_get(
        "/healthz",
        get_health,
        allow_head=True,
    )
    webapp.router.add_get(
        "/metrics",
        prometheus_aiohttp_handler(),
        allow_head=True,
    )

    runner = web.AppRunner(webapp)
    await runner.setup()
    site = web.TCPSite(runner, host, port)

    logger.info("Web server available at http://%s:%d/", host, port)
    await site.start()

    while True:
        await asyncio.sleep(60)


async def json_reloader(
    rpki_clients: dict[int, RPKIClient],
    cache_registry: dict[str, Cache],
    sleep: int = 900,
) -> None:
    """
    Reloads the content of the RPKI JSON output. Holds `sleeps` seconds between every attempt

    Arguments:
    ----------
    rpki_clients: dict[int, RPKIClient]
        RPKIClient instances (one per version)
    cache_registry: dict[str, Cache]
        The Cache registry
    sleep: int
        Sleep interval in seconds. Default: 900
    """
    while True:
        # Remove stale entries
        for rpki_client in rpki_clients.values():
            rpki_client.purge()

            try:
                # Load new entries
                rpki_client.reload()
            except Exception as error:  # pylint: disable=broad-exception-caught
                logger.error("Unable to load the RPKI client JSON file: %s", error)
                continue

            logger.info(
                "JSON file reloaded (V%d): %d VRPs, %d BGPsec Keys",
                rpki_client.version,
                len(rpki_client.vrps),
                len(rpki_client.router_keys),
            )

            for cache in cache_registry.values():
                if rpki_client.version != cache.version:
                    continue

                if not cache.current_serial or not cache.rpki_client:
                    # Version is still unknown
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
    prometheus.clients.inc()
    logger.info("Registered cache instance: %s", cache.remote)


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
        prometheus.clients.dec()
        logger.info("Unregistered cache instance: %s", cache.remote)
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
        connect_callback=functools.partial(register_cache, cache_registry=cache_registry),
        disconnect_callback=functools.partial(unregister_cache, cache_registry=cache_registry),
        rpki_clients=rpki_clients,
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


async def run_cache(  # pylint: disable=too-many-arguments
    host: str,
    port: int,
    json_file: str | os.PathLike[str],
    reload: int,
    *,
    refresh: int = 3600,
    retry: int = 600,
    expire: int = 7200,
) -> None:
    """
    Reloads the content of the RPKI JSON output every half `refresh`, and starts the RTR server.

    Arguments:
    ----------
    host: str
        The host to bind to
    port: int
        The TCP port to bind to
    json_file: str | os.PathLike[str]
        The path pointing to the JSON file
    reload: int
        The Interval after which RPKIClient is reloaded
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds: Expire: 7200
    """

    rpki_clients: dict[int, RPKIClient] = {
        0: RPKIClient(version=0, json_file=json_file, expire=expire),
        1: RPKIClient(version=1, json_file=json_file, expire=expire),
    }
    sessions: dict[int, int] = {0: random.randint(0, 65535), 1: random.randint(0, 65535)}
    cache_registry: dict[str, Cache] = {}

    await asyncio.gather(
        json_reloader(rpki_clients, cache_registry, reload),
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
        http_server(host, 8080, sessions, rpki_clients, cache_registry),
    )
