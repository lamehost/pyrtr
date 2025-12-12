"""
Main entrypoint for the package
"""

import asyncio
import logging
import sys

from pyrtr.pyrtr import pyrtr
from pyrtr.settings import Settings

logger = logging.getLogger(__name__)


def main():
    """
    Initializes logging and starts the server
    """
    settings = Settings()

    # Initialize logging
    loglevel = getattr(logging, settings.LOGLEVEL)

    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        level=loglevel,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("Loglevel set to: %s", settings.LOGLEVEL)

    # Start the server
    try:
        asyncio.run(
            pyrtr(
                str(settings.HOST),
                settings.PORT,
                settings.PATH,
                refresh=settings.REFRESH,
                retry=settings.RETRY,
                expire=settings.EXPIRE,
            )
        )
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user (KeyboardInterrupt)")
    except Exception as error:
        logger.exception("Unhandled exception while running the server: %s", error)
        sys.exit(1)


if __name__ == "__main__":
    main()
