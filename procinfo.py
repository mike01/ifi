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
import hashlib


try:
	from psutil import net_connections, Process
	psutil_found = True
except ImportError:
	psutil_found = True


logger = logging.getLogger("ifi")


def get_procinfo_by_address(ip_src, ip_dst, port_src=None, port_dst=None):
	"""
	Gets Infos about the Prozess associated with the given address information
	Both port_src and port_dst must be not None or None at the same time.

	return -- [pid, "/path/to/command", "user", "hash"] or []
	"""
	result = []

	if port_src is not None:
		pids = [c.pid for c in net_connections()
			if len(c.raddr) != 0 and c.pid is not None and
				(c.laddr[0], c.raddr[0], c.laddr[1], c.raddr[1]) == (ip_src, ip_dst, port_src, port_dst)]
	else:
		pids = [c.pid for c in net_connections()
			if len(c.raddr) != 0 and c.pid is not None and (c.laddr[0], c.raddr[0]) == (ip_src, ip_dst)]

	try:
		if len(pids[0]) > 0:
			logger.warning("more than 1 process: %r", pids)
		proc = Process(pids[0])
		cmd = [pids[0], proc.cmdline(), proc.username()]
		procinfo_hash = hashlib.sha256("%d%s%s" % (cmd[0], cmd[1], cmd[2]))
		cmd.append(procinfo_hash)
		logger.debug("process info: %r", cmd)
		return cmd
	except IndexError:
		pass
	return []

if not psutil_found:
	# dummy implementation if psutil is missing
	def get_procinfo_by_address_dummy(ip_src, ip_dst, port_src=None, port_dst=None):
		return []
	get_procinfo_by_address = get_procinfo_by_address_dummy
