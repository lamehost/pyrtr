"""Implements the application settings parser"""

from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, CliApp


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
    """

    LOGLEVEL: LogLevelEnums = LogLevelEnums.INFO

    HOST: IPv4Address | IPv6Address = IPv4Address("127.0.0.1")
    RTR_PORT: Annotated[int, Field(gt=-1, lt=65536)] = 8323
    HTTP_PORT: Annotated[int, Field(gt=-1, lt=65536)] = 8080
    DATASOURCE: DatasourceEnums = DatasourceEnums.RPKICLIENT
    DATA_LOCATION: str | None = "rpki_client.json"
    SLURM_LOCATION: str | None = "slurm.json"
    CACHE_LOCATION: str | None = "cache"
    DISABLE_CACHE_ENCRYPTION: bool = False
    RELOAD: Annotated[int, Field(gt=29, lt=3601)] = 900

    # https://datatracker.ietf.org/doc/html/rfc8210#section-6
    REFRESH: Annotated[int, Field(gt=59, lt=86401)] = 3600
    RETRY: Annotated[int, Field(gt=59, lt=7201)] = 600
    EXPIRE: Annotated[int, Field(gt=599, lt=172801)] = 7200

    @model_validator(mode="after")
    def validate_timers(self) -> Self:
        """
        Checks that EXPIRE is larger than REFRESH and RETRY:
        """
        if self.EXPIRE <= self.REFRESH or self.EXPIRE <= self.RETRY:
            raise ValueError("EXPIRE interval must be larger than either REFRESH or RETRY")
        return self

    def cli_cmd(self) -> None:
        """
        Defines the CLI command for the application
        """
        # Will print help for the current command or subcommand instance.
        CliApp.print_help(self)
        # Will return formatted help for the current command or subcommand instance.
        CliApp.format_help(self)
