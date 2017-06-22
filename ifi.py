"""
IFi - the interactive Firewall.

This is NOT an application firewall. Packets are filtered
based on source/destination IP address and (if present) upper
layer protocol informations. The reason for this is to achieve
a reasonable performance. Nevertheless IFi gives you a hint
which process is initiating a connection to allow an
educated white/blacklisting of connections.

Requirements:
- python 3.x
- pypacker
- psutil
- pyyaml
- Conntract support in Linux Kernel and userspace
- Iptables

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
import os
import argparse
import time

from fw_logic import Firewall

logger = logging.getLogger("ifi")
logger.setLevel(logging.DEBUG)
# logger.setLevel(logging.WARNING)

logger_streamhandler = logging.StreamHandler()
logger_formatter = logging.Formatter("%(message)s")
logger_streamhandler.setFormatter(logger_formatter)

logger.addHandler(logger_streamhandler)

uid = os.getuid()

if uid != 0:
	logger.warning("you need to be root to use this program")

if __name__ == "__main__":
	#VERBOSITY_DEFAULT = 1
	VERBOSITY_DEFAULT = 1
	verbosity_val = {
		0: logging.WARNING,
		1: logging.INFO,
		2: logging.DEBUG,
	}

	parser = argparse.ArgumentParser(
		description="IFi - The interactive Firewall",
		formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("-v", "--verbosity", type=int,
						help="Verbosity 0,1 or 2, higher = more verbosity",
						required=False,
						default=VERBOSITY_DEFAULT)
	parser.add_argument("-l", "--learninmode", type=bool,
						help="Learn allowed connections based on user decision",
						required=False,
						default=False)
	parser.add_argument("-c", "--convert", type=bool,
						help="Convert stored rules to readable format",
						required=False,
						default=False)

	args = parser.parse_args()
	logger.setLevel(verbosity_val.get(args.verbosity, VERBOSITY_DEFAULT))
	logger.debug("learning mode active: %r", args.learninmode)

	fw = Firewall(learningmode=args.learninmode)

	if args.convert:
		fw.store_wl_rules_readable()

	logger.info("Starting firewall")
	fw.set_state(state_active=True)

	try:
		time.sleep(999)
	except KeyboardInterrupt:
		logger.info("user intterupt, stopping...")
	fw.set_state(state_active=False)
