# pyRTR
[Resource Public Key Infrastructure (RPKI) to Router Protocol Version 1](https://www.rfc-editor.org/rfc/rfc8210) cache written in Python.

![pyRTR logo](pyRTR.png "pyRTR logo")

## Features
 - RPKI-client backend
 - HTTP health and connected clients endpoints (some endpoints might be broken)
 - SLURM
 - Prometheus metrics (largely TODO)

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
pyRTR has no configuration files. Parameters can be set through CLI arguments or enviroment variables:
```
usage: pyrtr [-h] [--loglevel {FATAL,CRITICAL,ERROR,WARNING,INFO,DEBUG}]
             [--host {IPv4Address,IPv6Address}] [--rtr_port int] [--http_port int]
             [--datasource RPKICLIENT] [--data_location {str,null}] [--slurm_location {str,null}]
             [--cache_location {str,null}] [--disable_cache_encryption bool] [--reload int]
             [--refresh int] [--retry int] [--expire int]

Resource Public Key Infrastructure (RPKI) to Router Protocol Version 1 cache written in Python.

Arguments can be set either through the CLI arguments below or through enviroment variables.
The variables use the same naming scheme and use the screaming snake case format (CLI: rtr-port
/ env: RTR_PORT).

options:
  -h, --help            show this help message and exit
  --loglevel {FATAL,CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        The log level (default: INFO)
  --host {IPv4Address,IPv6Address}
                        The host to bind the HTTP and RTR sockets to (default: 127.0.0.1)
  --rtr_port int        The TCP to bind the RTR server to (default: 8323)
  --http_port int       The TCP to bind the HTTP server to (default: 8080)
  --datasource RPKICLIENT
                        The RPKI datasource type (default: RPKICLIENT)
  --data_location {str,null}
                        The path or the URL towards the data provided by the RPKI datasource
                        (default: rpki_client.json)
  --slurm_location {str,null}
                        The path or the URL towards the data provided by the SLURM datasource
                        (default: slurm.json)
  --cache_location {str,null}
                        The path or the URL towards the cache for the datasource type (default:
                        cache)
  --disable_cache_encryption bool
                        If the datasource support it, whether or not to disable cache encryption
                        (default: False)
  --reload int          The amount of seconds after which a datasource is reloaded (default: 900)
  --refresh int         The RTR refresh value for the cache (default: 3600)
  --retry int           The RTR retry value for the cache (default: 600)
  --expire int          The RTR expire value for the cache (default: 7200)
```

See https://datatracker.ietf.org/doc/html/rfc8210#section-6 for more details about the RTR values.
  
## Datasources
pyRTR is designed to support multiple Datasources. The following is a list of those that are currently supported

### SLURM
SLURM is a special datasource that loads a SLURM file [formatted as defined by RFC8416](https://datatracker.ietf.org/doc/html/rfc8416.html#section-3.5).  
**Location**: Can be either local path or HTTP URL

### RPKI Client
Loads the RPKI Client JSON file.  
**Name**: RPKICLIENT  
**Location**: Can be either local path or HTTP URL

## HTTP endpoints
The following HTTP endpoints are available at HTTP port 8080:
 - **/clients**: List of connected clients
 - **/dumps**: JSONL stream representing the RPKI data structures
 - **/healthz**: Application status
 - **/metrics**: Prometheus metrics
