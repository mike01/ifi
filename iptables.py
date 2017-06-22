"""
IFi - the interactive Firewall.

Copyright (C) 2017 Michael Stahn <michael.stahn.42@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import logging
import subprocess

logger = logging.getLogger("ifi")


class IPTablesHandler(object):
	IPTABLES_RULES_ACTIVE = [
		["iptables -I OUTPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT"],
		["iptables -I OUTPUT 2 --protocol udp --dport 53 -j ACCEPT"],
		["iptables -I OUTPUT 3 -j NFQUEUE --queue-balance 0:3"],

		["iptables -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT"],
		["iptables -I INPUT 2 --protocol udp --sport 53 -j ACCEPT"],
		["iptables -I INPUT 3 -j NFQUEUE --queue-balance 4:7"]
	]

	IPTABLES_RULES_INACTIVE = [
		["iptables -D OUTPUT 1"],
		["iptables -D OUTPUT 1"],
		["iptables -D OUTPUT 1"],
		["iptables -D INPUT 1"],
		["iptables -D INPUT 1"],
		["iptables -D INPUT 1"],
	]

	def __init__(self):
		self._state_active = False

	def set_nfqueue_config(self, state_active=True):
		if self._state_active == state_active:
			logger.warning("state didn't change (state=%r): won't set config", state_active)
			return

		self._state_active = state_active
		rules = IPTablesHandler.IPTABLES_RULES_ACTIVE if state_active else IPTablesHandler.IPTABLES_RULES_INACTIVE

		for rule in rules:
			output = subprocess.getoutput(rule)
			# logger.debug("output for %r: %r", rule, output)
