"""Implements the application settings parser"""

import os
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings parser"""

    LOGLEVEL: str = "INFO"

    HOST: IPv4Address | IPv6Address = IPv4Address("127.0.0.1")
    PORT: Annotated[int, Field(gt=0, lt=65536)] = 8323  # pyright: ignore[reportCallIssue]
    PATH: str | os.PathLike[str] = "json"

    # https://datatracker.ietf.org/doc/html/rfc8210#section-6
    REFRESH: Annotated[int, Field(gt=0, ls=86401)] = 3600  # pyright: ignore[reportCallIssue]
    RETRY: Annotated[int, Field(gt=0, ls=7201)] = 600  # pyright: ignore[reportCallIssue]
    EXPIRE: Annotated[int, Field(gt=599, ls=172801)] = 7200  # pyright: ignore[reportCallIssue]

    model_config = SettingsConfigDict(env_prefix="PYRTR_")
