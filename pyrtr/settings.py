"""Implements the application settings parser"""

import os
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing_extensions import Self


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


class Settings(BaseSettings):
    """Application settings parser"""

    LOGLEVEL: LogLevelEnums = LogLevelEnums.INFO

    HOST: IPv4Address | IPv6Address = IPv4Address("127.0.0.1")
    PORT: Annotated[int, Field(gt=0, lt=65536)] = 8323
    JSONFILE: str | os.PathLike[str] = "json"
    RELOAD: Annotated[int, Field(gt=0, lt=3600)] = 900

    # https://datatracker.ietf.org/doc/html/rfc8210#section-6
    REFRESH: Annotated[int, Field(gt=0, lt=86401)] = 3600
    RETRY: Annotated[int, Field(gt=0, lt=7201)] = 600
    EXPIRE: Annotated[int, Field(gt=599, lt=172801)] = 7200

    model_config = SettingsConfigDict(env_prefix="PYRTR_")

    @model_validator(mode="after")
    def validate_timers(self) -> Self:
        """
        Checks that EXPIRE is larger than REFRESH and RETRY:
        """
        if self.EXPIRE < self.REFRESH or self.EXPIRE < self.RETRY:
            raise ValueError("EXPIRE interval must be larger than either REFRESH or RETRY")
        return self
