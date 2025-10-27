"""
Local async RTR server
"""

import asyncio
import logging

from .rtr import Cache

logger = logging.getLogger(__name__)


async def rtr_server(
    host: str, port: int, session: int, *, refresh: int = 3600, expire: int = 600, retry: int = 7200
):
    """
    Starts a local async RTR server and binds it to the specified host and port

    Arguments:
    ----------
    host: str
        The host to bind to
    port: int
        The TCP port to bind to
    session: int
        The RTR session ID
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds: Expire: 7200
    """
    cache = Cache(session, refresh=refresh, retry=retry, expire=expire)

    # Initialize server
    server = await asyncio.start_server(cache.client_connected_cb, host, port)

    # Find the sockets the server will bind to
    sockets = ", ".join(
        [f"{_socket.getsockname()[0]}:{_socket.getsockname()[1]}" for _socket in server.sockets]
    )

    async with server:
        logger.info("Listening on %s. Session: %i", sockets, session)
        # Start the server
        await server.serve_forever()
