"""
Local async RTR server
"""

import asyncio
import logging
import random

from pyrtr.rpki_client import RPKIClient
from pyrtr.rtr.cache import Cache

logger = logging.getLogger(__name__)


async def rtr_server(  # pylint: disable=too-many-arguments
    host: str,
    port: int,
    rpki_client: RPKIClient,
    *,
    refresh: int = 3600,
    expire: int = 600,
    retry: int = 7200,
):
    """
    Starts a local async RTR server and binds it to the specified host and port

    Arguments:
    ----------
    host: str
        The host to bind to
    port: int
        The TCP port to bind to
    rpki_client: RPKIClient
        RPKIClient instance
    refresh: int
        Refresh Interval in seconds. Default: 3600
    retry: int
        Retry Interval in seconds. Default: 600
    expire: int
        Expire Interval in seconds: Expire: 7200
    """
    session = random.randrange(0, 65535)

    cache = Cache(session, rpki_client, refresh=refresh, retry=retry, expire=expire)

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
        logger.info("Listening on %s. Session: %i", listening_sockets, session)
        # Start the server
        await server.serve_forever()
