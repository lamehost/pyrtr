"""
Main entrypoint for the package
"""

import asyncio
import logging

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


if __name__ == "__main__":
    main()
