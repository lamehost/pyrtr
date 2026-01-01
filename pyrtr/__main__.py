"""
Main entrypoint for the package
"""

import asyncio
import logging
import sys

from pyrtr.pyrtr import run_cache
from pyrtr.settings import Settings

logger = logging.getLogger(__name__)


def main() -> None:
    """
    Initializes logging and starts the server
    """
    settings = Settings()

    # Initialize logging
    # The settings module validate that LOGLEVEL is a valid logging attibute.
    loglevel = getattr(logging, settings.LOGLEVEL)
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        level=loglevel,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger.info("Loglevel set to: %s", settings.LOGLEVEL)

    # Start the server
    asyncio.run(
        run_cache(
            str(settings.HOST),
            settings.PORT,
            settings.JSONFILE,
            settings.RELOAD,
            refresh=settings.REFRESH,
            retry=settings.RETRY,
            expire=settings.EXPIRE,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user (KeyboardInterrupt)")
    except Exception as error:  # pylint: disable=broad-exception-caught
        logger.exception("Unhandled exception while running the server: %s", error)
        sys.exit(1)
