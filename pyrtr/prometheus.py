"""Implements the Prometheus metric endpoints"""

from prometheus_client import Counter, Gauge

clients = Gauge("clients", "Connected clients")

rpki_v0_bgpsec_keys = Gauge("rpki_v0_bgpsec_keys", "Amount of RPKI BGPSec Keys for V0")
rpki_v0_serial = Counter("rpki_v0_serial", "Serial number for RPKI data for V0")
rpki_v0_vrps = Gauge("rpki_v0_vrps", "Amount of RPKI VRPs for V0")

rpki_v1_bgpsec_keys = Gauge("rpki_v1_bgpsec_keys", "Amount of RPKI BGPSec Keys for V1")
rpki_v1_serial = Counter("rpki_v1_serial", "Serial number for RPKI data for V1")
rpki_v1_vrps = Gauge("rpki_v1_vrps", "Amount of RPKI VRPs for V1")
