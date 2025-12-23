# PyRTR

[Resource Public Key Infrastructure (RPKI) to Router Protocol Version 1 Cache written in Python](https://datatracker.ietf.org/doc/html/rfc6810)

## Tested with
 - FRR
 - JunOS

## Configuration
PyRTR is configured through the following ENV variables:
```
    PYRTR_LOGLEVEL: Sets the log level. Default: INFO

    PYRTR_HOST: Host to bind the RTR and HTTP servers to. Default: localhost
    PYRTR_PORT: Port to bind the RTR server to (HTTP port is _always_ 8080). Default: 8323
    PYRTR_JSONFILE: Path to the RPKI-client JSON file. Default: `json`

    # https://datatracker.ietf.org/doc/html/rfc8210#section-6
    PYRTR_REFRESH: RTR Refresh Interval. Default: 3600s
    PYRTR_RETRY: RTR Retry Interval. Default: 600s
    PYRTR_EXPIRE: RTR Expire Interval. Default: 7200s
```