"""Implements the pyrtr application"""

import asyncio
import logging
import os

from .rpki_client import RPKIClient
from .server import rtr_server

logger = logging.getLogger(__name__)


async def json_loader(
    path: str | os.PathLike[str], rpki_client: RPKIClient, refresh: int = 3600
) -> None:
    """
    Reloads the content of the RPKI JSON output

    Arguments:
    ----------
    path: str | os.PathLike[str]
        The path pointing to the JSON file
    rpki_client: RPKIClient
        RPKIClient instance
    refresh: int
        Refresh Interval in seconds. Default: 3600
    """
    while True:
        await rpki_client.load(path)
        logger.info("JSON file reloaded: %d prefixes", len(rpki_client.prefixes))
        await asyncio.sleep(refresh)


async def pyrtr(  # pylint: disable=too-many-arguments
    host: str,
    port: int,
    path: str | os.PathLike[str],
    rpki_client: RPKIClient,
    *,
    refresh: int = 3600,
    expire: int = 600,
    retry: int = 7200,
) -> None:
    """
    Reloads the content of the RPKI JSON output

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
    await asyncio.gather(
        json_loader(path, rpki_client, refresh),
        rtr_server(host, port, rpki_client, refresh=refresh, retry=retry, expire=expire),
    )
