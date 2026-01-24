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
env LOGLEVEL=DEBUG poetry run pyrtr
```

## Run with Docker
```
docker run -v $(pwd)/json:/json -e JSONFILE=/json -p 8323:8323 lamehost/pyrtr
```

## Configuration
pyRTR has no configuration files and takes no CLI arguments. Parameters can be set through the following ENV variables:

| Variable | Description | Default |
| -------- | ------------| ----- |
|  LOGLEVEL |  Sets the log level | INFO |
|  HOST |  Host to bind the RTR and HTTP servers to | localhost |
|  RTR_PORT |  Port to bind the RTR server to. Use False to disable the Cache | 8323 |
|  HTTP_PORT | Port to bind the HTTP server to. Use False to disable the HTTP server | 8080 |
|  DATASOURCE | Datasource type to use (see below) | RPKICLIENT |
|  LOCATION |  Path to the RPKI-client JSON file | json |
|  RELOAD | The amount of seconds after which the RPKIclient JSON file is realoaded | 900 |
|  REFRESH |  RTR Refresh Interval in seconds * | 3600 |
|  RETRY |  RTR Retry Interval in seconds * | 600 |
|  EXPIRE |  RTR Expire Interval in seconds * | 7200 |

\* See https://datatracker.ietf.org/doc/html/rfc8210#section-6

## Datasources
pyRTR is designed to support multiple Datasources. The following is a list of those that are currently supported

### RPKI Client
Loads the RPKI Client JSON file.  
**Name**: RPKICLIENT  
**Location**: Can be either local path or HTTP URL

## HTTP endpoints
The following HTTP endpoints are available at HTTP port 8080:
 - **/clients**: List of connected clients
 - **/copies**: Msgpack packed representation of the Datasource copies in memory
 - **/healthz**: Application status
 - **/metrics**: Prometheus metrics
