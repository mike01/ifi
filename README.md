# <span style="color:red">Please note: This respository has become staled due to relocation to GitLab. Visit https://gitlab.com/mike01/ for up-to-date versions.</span>


### General information
This is IFi the interactive firewall. The main purpose is to build
a firewall profile based on user decision while network is active.
All rules are stored to human readable files (fw_rules_xxx.txt) for
inspection/customizing.

<p align="center">
  <img src="https://raw.githubusercontent.com/mike01/ifi/master/screenshot.png" alt="ifi"/>
</p>

This comes in handy when hardening a system via firewall rules
but the actual needed/allowed addresses and ports for incoming
or outgoing connections are unknown.

This is NOT an application firewall. Rules are based
on source/destination IP address and (if present) upper
layer protocol information. The reason for this is to achieve
a reasonable performance. Nevertheless IFi gives a hint
which process is initiating an outgoing connection to allow an
educated white/blacklisting of connections.

Note: Packets with UDP target or source port 53 are always allowed outgoing/incoming.
These two rules would have to be added manually if applied on a different machine.
### Prerequisites
- Un*x based operating system
- python 3.x
- pypacker
- psutil
- pyyaml
- iptables, NFQUEUE target support in kernel for packet intercepting, CPython

### Installation
Just download/unpack

### Usage
- Start in learning mode: black/whitelist addresses, stop via Ctrl+C. Customize fw_rules_xxx files and restart if needed.

  `python ifi.py -l True`

- Start firewall in active mode

  `python ifi.py`
