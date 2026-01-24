# Tools/Router

Starts a FRF bgpd isntance to test the PyRTR Cache.  

# Run it
Run the command below to start the FRF bgpd instance. All logs are sent to STDOUT.
```
$ env HOST=172.17.0.1 PORT=8383 docker-compose up; docker-compose down
```
  
To login into the instance, use (**password**: zebra):
```
$ telnet localhost 8023
```

## Environmental variables
 - **HOST**: The host the PyRTR Cache is bound to
 - **PORT**: The TCP port the PyRTR Cache is bound to
