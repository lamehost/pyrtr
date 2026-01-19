"""
Defines the RTR protocol sequence for the RTR Client
"""

import argparse
import asyncio
import functools
import ipaddress
import logging
from typing import Any, Callable, Self

import orjson

from pyrtr.rtr.pdu import (
    cache_response,
    end_of_data,
    error_report,
    ipv4_prefix,
    ipv6_prefix,
    router_key,
    serial_notify,
)
from pyrtr.rtr.pdu.errors import InternalError
from pyrtr.rtr.speaker import RTRHeader, RTRSpeaker

logger = logging.getLogger(__name__)


class Client(RTRSpeaker):
    """
    Handles the the sequences of PDU transmissions of an RTR Client
    """

    def __init__(
        self,
        *,
        connect_callback: Callable[[Self], None] | None = None,
        disconnect_callback: Callable[[Self], None] | None = None,
        version: int = 1,
    ):
        """
        Arguments:
        ----------
        session: int
            The RTR session ID
        connect_callback: Callable[[Self], None] | None = None
            The method executed after the connection is established
        disconnect_callback: Callable[[Self], None] | None = None
            The method executed after the connection is terminated
        version: int
            The RTR version number. Default: 1
        """
        super().__init__()
        self.connect_callback = connect_callback
        self.disconnect_callback = disconnect_callback
        self.version = version

    def handle_pdu(self, header: RTRHeader, data: bytes) -> None:
        """
        Handles the inbound PDU.

        header: RTRHeader
            The fixed header part of the PDU

        data: bytes
            The entire content of the PDU
        """
        match header["type"]:
            case cache_response.TYPE:
                logger.info("Received Cache Response")
            case end_of_data.TYPE:
                self.handle_end_of_data(data)
            case ipv4_prefix.TYPE:
                self.handle_ipv4_prefix(data)
            case ipv6_prefix.TYPE:
                self.handle_ipv6_prefix(data)
            case router_key.TYPE:
                self.handle_router_key(data)
            case error_report.TYPE:
                logger.info("Error report PDU received from %s", self.remote)
                self.raise_on_error_report(data)
            case serial_notify.TYPE:
                logger.info("Ignoring Serial Notify")
            case _:
                logger.warning("Unsupported message received. Type: %d", header["type"])

    def handle_end_of_data(self, _: bytes) -> None:
        """
        Handles End of Data PDU by disconnecting the client.

        Arguments:
        ----------
        _: bytes
            Ignored
        """
        logger.debug("Reveived End Of Data")

        if self.transport is not None:
            self.transport.close()

    def handle_ipv4_prefix(self, data: bytes) -> None:
        """
        Prints the content of an IPv4 Prefix PDU

        Arguments:
        ----------
        data: bytes
            The IPv4 Prefix PDU binary data
        """
        if self.version is None:
            raise InternalError("Inconsistent version state.")  # NOSONAR

        prefix = ipv4_prefix.unserialize(self.version, data)
        prefix_str = str(ipaddress.IPv4Address(prefix["prefix"]))

        print(
            orjson.dumps(  # pylint: disable=no-member
                {
                    "type": "ipv4_prefix",
                    "prefix": f"{prefix_str}/{prefix['prefix_length']}",
                    "max_length": prefix["max_length"],
                    "asn": f"AS{prefix["asn"]}",
                }
            ).decode("utf-8")
        )

    def handle_ipv6_prefix(self, data: bytes) -> None:
        """
        Prints the content of an IPv6 Prefix PDU

        Arguments:
        ----------
        data: bytes
            The IPv6 Prefix PDU binary data
        """
        if self.version is None:
            raise InternalError("Inconsistent version state.")

        prefix = ipv6_prefix.unserialize(self.version, data)
        prefix_str = str(ipaddress.IPv6Address(prefix["prefix"]))

        print(
            orjson.dumps(  # pylint: disable=no-member
                {
                    "type": "ipv6_prefix",
                    "prefix": f"{prefix_str}/{prefix['prefix_length']}",
                    "max_length": prefix["max_length"],
                    "asn": f"AS{prefix["asn"]}",
                }
            ).decode("utf-8")
        )

    def handle_router_key(self, data: bytes) -> None:
        """
        Prints the content of a Router Key PDU

        Arguments:
        ----------
        data: bytes
            The Router Key PDU binary data
        """
        if self.version is None:
            raise InternalError("Inconsistent version state.")

        key = router_key.unserialize(self.version, data)
        print(
            orjson.dumps(  # pylint: disable=no-member
                {
                    "type": "router_key",
                    "ski": key["ski"].hex(),
                    "asn": f"AS{key['asn']}",
                    "spki": key["spki"].hex(),
                }
            ).decode("utf-8")
        )


def client_connected_callback(client: RTRSpeaker):
    """
    Triggered when client connects to the Cache. Sends Reset Query.

    Argument:
    ---------
    client: RTRSpeaker
        The Cache the client is connected to
    """
    logger.info("Client connected")
    client.write_reset_query()


def client_disconnected_callback(_: RTRSpeaker, awaitable: asyncio.Future[Any]):
    """
    Triggered when client disconnects from the Cache. Sends Reset Query.

    Argument:
    ---------
    awaitable: asyncio.Future[Any]
        The awaitable to mark as done
    """
    logger.info("Client disconnected")
    awaitable.set_result(True)


async def run_client(host: str, port: int, version: int = 1):
    """
    Connects to `host` and `port` and prints IPv4 Prefixes, IPv6 Prefixes and Router Keys

    Arguments:
    ----------
    host: str
        The host to connect to
    port: int
        The port to connect to
    version: int
        The RTR version
    """
    loop = asyncio.get_running_loop()

    client_disconnected = loop.create_future()

    transport, _ = await loop.create_connection(
        lambda: Client(
            connect_callback=client_connected_callback,
            disconnect_callback=functools.partial(
                client_disconnected_callback, awaitable=client_disconnected
            ),
            version=version,
        ),
        host,
        port,
    )

    try:
        await client_disconnected
    finally:
        transport.close()


def main():
    """
    Main entrypoint for the script
    """
    parser = argparse.ArgumentParser(
        description=(
            "Connects to an RTR Cache and prints IPv4 Prefixes, IPv6 Prefixes and Router Keys"
        ),
        prog="rtr_client",
    )
    parser.add_argument("host", metavar="HOST", type=str, help="Host to connect to")
    parser.add_argument("port", metavar="PORT", type=int, help="Port to connect to")
    parser.add_argument(
        "-l", "--loglevel", type=str, default="INFO", help="Loglevel. Default: INFO"
    )
    parser.add_argument("--version", type=int, default=1, help="RTR version to use. Default: 1")

    args = parser.parse_args()

    loglevel = getattr(logging, args.loglevel)
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        level=loglevel,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger.info("Loglevel set to: %s", args.loglevel)

    asyncio.run(run_client(args.host, args.port, args.version))


if __name__ == "__main__":
    main()
