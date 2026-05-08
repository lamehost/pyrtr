"""
Internal HTTP server
"""

import asyncio
import logging
import os
from typing import TypedDict

import orjson
from aiohttp import web
from prometheus_client.aiohttp import make_aiohttp_handler as prometheus_aiohttp_handler

from pyrtr.datasources import RPKIDatasource
from pyrtr.rtr.cache import Cache

logger = logging.getLogger(__name__)


class DatasourceStats(TypedDict):
    """
    Defines the set of metadata describing the status of the Datasource

    Keys:
    -----
    last_update: The moment the datasource was updated last
    """

    last_update: str | None


class Status(TypedDict):
    """
    Defines the set of metadata describing the application status

    Keys:
    -----
    rpki_datasource: Object with version numbers as keys and DatasourceStats as values
    sessions: Object with version numbers as keys and session IDs as values
    pid: the process ID
    """

    rpki_datasources: dict[str, DatasourceStats]
    sessions: dict[str, int | None]
    pid: int


async def http_server(
    host: str,
    port: int,
    sessions: dict[int, int],
    rpki_instances: dict[int, RPKIDatasource],
    cache_registry: dict[str, Cache],
) -> None:
    """
    Runs the HTTP server providing four endpoints:
     - /clients: List of connected clients
     - /healthz: Application status
     - /metrics: Prometheus metrics
     - /dumps: Dumps of the current data in the datasources

    Arguments:
    ----------
    host: str
        The host to bind to
    port: int
        The TCP port to bind to
    sessions: dict[int, int]
        The session IDs
    rpki_instances: dict[int, RPKIDatasource]
        RPKI Datasource instances (one per version)
    cache_registry: dict[str, Cache]
        The Cache registry
    """

    async def get_clients(_: web.Request) -> web.Response:  # NOSONAR
        """
        Returns the ist of RTR clients sarialized as a JSON text

        Arguments:
        ----------
        _: web.Request
            Ignored
        
        Returns:
        --------
        web.Response: The aiohttp Response with the JSON text
        """
        clients = [
            {"client": client_id, "version": f"V{cache.version}"}
            for client_id, cache in cache_registry.items()
        ]
        return web.json_response(clients)

    async def get_health(_: web.Request) -> web.Response:  # NOSONAR
        """
        Returns info describing the health of the application sarialized as a JSON text

        Arguments:
        ----------
        _: web.Request
            Ignored

        Returns:
        --------
        web.Response: The aiohttp Response with the JSON text
        -------------

        """
        try:
            v0_last_update = rpki_instances[0].last_update
            v0_session = sessions[0]
        except KeyError:
            v0_last_update = None
            v0_session = None

        try:
            v1_last_update = rpki_instances[1].last_update
            v1_session = sessions[1]
        except KeyError:
            v1_last_update = None
            v1_session = None

        status: Status = {
            "rpki_datasources": {
                "V0": {"last_update": v0_last_update},
                "V1": {"last_update": v1_last_update},
            },
            "sessions": {"V0": v0_session, "V1": v1_session},
            "pid": os.getpid(),
        }

        return web.json_response(status)

    async def get_dumps(request: web.Request) -> web.StreamResponse:  # NOSONAR
        """
        Returns the list of items in the RPKI instance serialized as JSONL

        Arguments:
        ----------
        request: web.Request
            The aiohttp web request

        Returns:
        --------
        web.StreamResponse: The aiohttp Streamresponse with the JSONL lines
        """
        response = web.StreamResponse()
        response.headers["Content-Type"] = "application/jsonl"
        await response.prepare(request)

        for rpki_instance in rpki_instances.values():
            async for line in rpki_instance.dump():
                try:
                    await response.write(orjson.dumps(line) + b"\n")  # pylint: disable=no-member
                    await asyncio.sleep(0)
                except ConnectionResetError:
                    break

        return response

    # Add `routes` to the http server
    webapp = web.Application()
    webapp.router.add_get("/clients", get_clients, allow_head=True)
    webapp.router.add_get("/healthz", get_health, allow_head=True)
    webapp.router.add_get("/metrics", prometheus_aiohttp_handler(), allow_head=True)
    webapp.router.add_get("/dumps", get_dumps, allow_head=True)

    # Run the server
    runner = web.AppRunner(webapp)
    await runner.setup()
    site = web.TCPSite(runner, host, port)

    logger.info("Web server listening at http://%s:%d/", host, port)
    await site.start()

    while True:
        await asyncio.sleep(60)
