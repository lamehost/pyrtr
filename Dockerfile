# Prepare the OS
FROM python:3.14.2-slim-trixie AS base

## Install deps
RUN apt-get update \
  && apt-get install --no-install-recommends --yes curl \
  && apt-get clean

# Install the app
FROM base AS application

## Copy script
COPY pyrtr /pyrtr
COPY README.md /

## Install PyRTR
COPY pyproject.toml /pyproject.toml
RUN pip install --no-cache-dir poetry \
  && poetry config virtualenvs.create false \
  && poetry install --no-interaction --no-ansi

# Setup the environment
FROM application

## Meta
EXPOSE 8080/tcp
EXPOSE 8323/tcp

## Run script
USER nobody
ENTRYPOINT [ "python3", "-m", "pyrtr" ]

## Healtchecks
HEALTHCHECK CMD [ "/usr/bin/curl", "-fsSLo", "/dev/null", "http://localhost:8080/healthz" ]
