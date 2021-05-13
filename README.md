# iptables-exporter

Prometheus exporter for `iptables` that collects number of packets and bytes that matched marked rules.

## Installation

Download binary from the latest release on Github, or pull container image `maximbaz/iptables-exporter` from Docker Hub.

Release artifacts are signed with the following PGP key: `8053EB88879A68CB4873D32B011FDC52DA839335`

## Usage

First mark rules that you are interested to monitor with `iptables-exporter` comment:

```sh
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "iptables-exporter related,established" -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -m comment --comment "iptables-exporter invalid" -j DROP
iptables -A INPUT -i lo -m comment --comment "iptables-exporter loopback" -j ACCEPT
```

Then run the binary:

```sh
$ iptables-exporter
```

Or in Docker:

```sh
$ docker run --net=host --cap-add=NET_ADMIN maximbaz/iptables-exporter
```

Or in `docker-compose`:

```yaml
iptables-exporter:
image: maximbaz/iptables-exporter
restart: always
network_mode: host
cap_add:
  - NET_ADMIN
```

Finally navigate to `http://127.0.0.1:9119/metrics` to explore your metrics, or point Prometheus to this endpoint.

```sh
$ curl 127.0.0.1:9119/metrics

# HELP iptables_packets Number of matched packets
# TYPE iptables_packets counter
iptables_packets{ip_version="4",table="filter",chain="INPUT",rule="related,established"} 277108
iptables_packets{ip_version="4",table="filter",chain="INPUT",rule="invalid"} 732
iptables_packets{ip_version="4",table="filter",chain="INPUT",rule="loopback"} 1198

# HELP iptables_bytes Number of matched bytes
# TYPE iptables_bytes counter
iptables_bytes{ip_version="4",table="filter",chain="INPUT",rule="related,established"} 103651838
iptables_bytes{ip_version="4",table="filter",chain="INPUT",rule="invalid"} 7669
iptables_bytes{ip_version="4",table="filter",chain="INPUT",rule="loopback"} 104737
```

## Configuration

Bind address and port are configurable with CLI arguments, e.g.:

```sh
$ iptables-exporter --address 192.168.0.1 --port 12345
```

## Related projects

- [madron/iptables-exporter](https://github.com/madron/iptables-exporter) - heavily inspired this project, but (at the time of writing) used a quite buggy iptables parsing library.
