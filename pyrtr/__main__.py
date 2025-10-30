"""
Main entrypoint for the package
"""

import asyncio
import logging
import os

from .server import rtr_server

logger = logging.getLogger(__name__)


def main():
    """
    Initializes logging and starts the server
    """
    # Initialize logging
    loglevel_str = os.environ.get("PYRTR_LOGLEVEL", "INFO")
    loglevel = getattr(logging, loglevel_str)

    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        level=loglevel,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("Loglevel set to: %s", loglevel_str)

    # Start the server
    host = os.environ.get("PYRTR_HOST", "127.0.0.1")
    port = int(os.environ.get("PYRTR_PORT", 8323))

    refresh = int(os.environ.get("PYRTR_REFRESH", 3600))
    retry = int(os.environ.get("PYRTR_RETRY", 3600))
    expire = int(os.environ.get("PYRTR_EXPIRE", 3600))

    asyncio.run(rtr_server(host, port, refresh=refresh, retry=retry, expire=expire))


if __name__ == "__main__":
    main()
