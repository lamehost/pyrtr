"""Implements the pyrtr application"""

import asyncio
import logging
import os
import random

from pyrtr.rpki_client import RPKIClient
from pyrtr.rtr.cache import Cache

logger = logging.getLogger(__name__)


async def json_reloader(path: str | os.PathLike[str], cache: Cache, sleep: int = 1800) -> None:
    """
    Reloads the content of the RPKI JSON output. Holds `sleeps` seconds between every attempt

    Arguments:
    ----------
    path: str | os.PathLike[str]
        The path pointing to the JSON file
    cache: Cache
        The RTR Cache instance to update
    refresh: int
        Refresh Interval in seconds. Default: 3600
    """
    serial: int = 0

    while True:
        # Remove stale entries
        cache.rpki_client.purge(cache.expire)
        # Load new entris
        await cache.rpki_client.load(path)
        logger.info("JSON file reloaded: %d prefixes", len(cache.rpki_client.prefixes))

        # Notify clients if needed
        if serial != cache.rpki_client.serial:
            for client in cache.streams:
                try:
                    cache.write_serial_notify(client=client)
                    await cache.drain(client)
                except ConnectionResetError:
                    pass
            serial = cache.rpki_client.serial

        await asyncio.sleep(sleep)


async def rtr_server(host: str, port: int, cache: Cache):  # pylint: disable=too-many-arguments
    """
    Starts a local async RTR server and binds it to the specified host and port

    Arguments:
    ----------
    host: str
        The host to bind to
    port: int
        The TCP port to bind to
    cache: Cache
        The RTR Cache instance to send data to
    """
    # Initialize server
    server = await asyncio.start_server(cache.client_connected_cb, host, port)

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
        logger.info("Listening on %s. Session: %i", listening_sockets, cache.session)
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
    rpki_client: RPKIClient instance
        RPKIClient instance
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds: Expire: 7200
    """

    rpki_client = RPKIClient()
    session: int = random.randrange(0, 65535)
    cache = Cache(session, rpki_client, refresh=refresh, retry=retry, expire=expire)

    await asyncio.gather(
        json_reloader(path, cache, int(refresh / 2)),
        rtr_server(host, port, cache),
    )
