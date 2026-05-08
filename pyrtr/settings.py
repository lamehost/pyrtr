"""Implements the application settings parser"""

from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings


class LogLevelEnums(str, Enum):
    """
    Supported logging levels
    """

    FATAL = "FATAL"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"  # NOSONAR


class DatasourceEnums(str, Enum):
    """
    Supported Datasources
    """

    RPKICLIENT = "RPKICLIENT"


class Settings(BaseSettings, cli_parse_args=True, cli_prog_name="pyrtr"):
    """
    Resource Public Key Infrastructure (RPKI) to Router Protocol Version 1 cache written in Python.

    Arguments can be set either through the CLI arguments below or through enviroment variables.
    The variables use the same naming scheme and use the screaming snake case format (CLI: rtr-port
    / env: RTR_PORT).
    """

    LOGLEVEL: Annotated[
        LogLevelEnums, Field(default=LogLevelEnums.INFO, description="The log level")
    ] = LogLevelEnums.INFO
    HOST: Annotated[
        IPv4Address | IPv6Address,
        Field(
            default=IPv4Address("127.0.0.1"),
            description="The host to bind the HTTP and RTR sockets to",
        ),
    ] = IPv4Address("127.0.0.1")
    RTR_PORT: Annotated[
        int, Field(gt=-1, lt=65536, default=8323, description="The TCP to bind the RTR server to")
    ] = 8323
    HTTP_PORT: Annotated[
        int, Field(gt=-1, lt=65536, default=8080, description="The TCP to bind the HTTP server to")
    ] = 8080
    DATASOURCE: Annotated[
        DatasourceEnums,
        Field(default=DatasourceEnums.RPKICLIENT, description="The RPKI datasource type"),
    ] = DatasourceEnums.RPKICLIENT
    DATA_LOCATION: Annotated[
        str | None,
        Field(
            default="rpki_client.json",
            description="The path or the URL towards the data provided by the RPKI datasource",
        ),
    ] = "rpki_client.json"
    SLURM_LOCATION: Annotated[
        str | None,
        Field(
            default="slurm.json",
            description="The path or the URL towards the data provided by the SLURM datasource",
        ),
    ] = "slurm.json"
    CACHE_LOCATION: Annotated[
        str | None,
        Field(
            default="cache",
            description="The path or the URL towards the cache for the datasource type",
        ),
    ] = "cache"
    DISABLE_CACHE_ENCRYPTION: Annotated[
        bool,
        Field(
            default=False,
            description="If the datasource support it, whether or not to disable cache encryption",
        ),
    ] = False
    RELOAD: Annotated[
        int,
        Field(
            gt=29,
            lt=3601,
            default=900,
            description="The amount of seconds after which a datasource is reloaded",
        ),
    ] = 900

    # https://datatracker.ietf.org/doc/html/rfc8210#section-6
    REFRESH: Annotated[
        int, Field(gt=59, lt=86401, default=3600, description="The RTR refresh value for the cache")
    ] = 3600
    RETRY: Annotated[
        int, Field(gt=59, lt=7201, default=600, description="The RTR retry value for the cache")
    ] = 600
    EXPIRE: Annotated[
        int,
        Field(gt=599, lt=172801, default=7200, description="The RTR expire value for the cache"),
    ] = 7200

    @model_validator(mode="after")
    def validate_timers(self) -> Self:
        """
        Checks that EXPIRE is larger than REFRESH and RETRY:
        """
        if self.EXPIRE <= self.REFRESH or self.EXPIRE <= self.RETRY:
            raise ValueError("EXPIRE interval must be larger than either REFRESH or RETRY")
        return self
