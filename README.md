### General information
This is IFi the interactive firewall. The main purpose is to build
a firewal profile based on user decision while network is active.

<p align="center">
  <img src="https://raw.githubusercontent.com/mike01/ifi/master/screenshot.png" alt="ifi"/>
</p>

This comes in handy when hardening a system via firewall rules
but the actual needed/allowed addresses and ports are unknown.

This is NOT an application firewall. Rules are based
on source/destination IP address and (if present) upper
layer protocol informations. The reason for this is to achieve
a reasonable performance. Nevertheless IFi gives a hint
which process is initiating a connection to allow an
educated white/blacklisting of connections.

### Prerequisites
- Un*x based operating system
- python 3.x
- pypacker
- psutil
- pyyaml
- iptables, NFQUEUE target support in kernel for packet intercepting, CPython

### Installation
Just download/unpack

### Usage examples
Just call `python ifi.py` or see options via `python ifi.py -h`
