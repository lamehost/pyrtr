#!/bin/bash

sed 's@__PYRTR_HOST__@'"$PYRTR_HOST"'@; s@__PYRTR_PORT__@'"$PYRTR_PORT"'@;' /bgpd.conf.template > /bgpd.conf

/usr/lib/frr/bgpd \
  --no_zebra \
  --no_kernel \
  --skip_runas \
  --listenon=0.0.0.0 \
  --bgp_port=0 \
  --vty_port=8023 \
  --config_file=/bgpd.conf \
  --log-level=error \
  --log=stdout \
  -M \
  rpki
