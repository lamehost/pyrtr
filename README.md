# pyRTR
[Resource Public Key Infrastructure (RPKI) to Router Protocol Version 1](https://www.rfc-editor.org/rfc/rfc8210) cache written in Python.

![pyRTR logo](pyRTR.png "pyRTR logo")

## Features
 - RPKI-client backend
 - HTTP health and connected clients endpoints
 - Prometheus metrics

## Tested with
 - FRR
 - JunOS

## Run with Python
```
git clone https://github.com/lamehost/pyrtr.git
poetry install
env PYRTR_LOGLEVEL=DEBUG poetry run pyrtr
```

## Run with Docker
```
docker run -v $(pwd)/json:/json -e PYRTR_JSONFILE=/json -p 8323:8323 lamehost/pyrtr
```

## Configuration
pyRTR has no configuration files and takes no CLI arguments. Parameters can be set through the following ENV variables:

| Variable | Description | Default |
| -------- | ------------| ----- |
| PYRTR_LOGLEVEL |  Sets the log level | INFO |
| PYRTR_HOST |  Host to bind the RTR and HTTP servers to | localhost |
| PYRTR_RTR_PORT |  Port to bind the RTR server to. Use False to disable the Cache | 8323 |
| PYRTR_HTTP_PORT | Port to bind the HTTP server to. Use False to disable the HTTP server | 8080 |
| PYRTR_DATASOURCE | Datasource type to use | RPKICLIENT |
| PYRTR_LOCATION |  Path to the RPKI-client JSON file | json |
| PYRTR_RELOAD | The amount of seconds after which the RPKIclient JSON file is realoaded | 900 |
| PYRTR_REFRESH |  RTR Refresh Interval in seconds * | 3600 |
| PYRTR_RETRY |  RTR Retry Interval in seconds * | 600 |
| PYRTR_EXPIRE |  RTR Expire Interval in seconds * | 7200 |

\* See https://datatracker.ietf.org/doc/html/rfc8210#section-6

## HTTP endpoints
The following HTTP endpoints are available at HTTP port 8080:
 - **/clients**: List of connected clients
 - **/copies**: Msgpack packed representation of the Datasource copies in memory
 - **/healthz**: Application status
 - **/metrics**: Prometheus metrics
