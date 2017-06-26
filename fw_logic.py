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

import socket
import struct
import threading
import logging
import hashlib
import copy
from collections import defaultdict, namedtuple
import re

import yaml

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip, ip6
from pypacker.layer4 import tcp, udp
from pypacker import pypacker, ppcap, interceptor

from iptables import IPTablesHandler
from procinfo import get_procinfo_by_address

pack_B = struct.Struct("B").pack
pack_H = struct.Struct("H").pack
unpack_I = struct.Struct(">I").unpack
PATTERN_IP = re.compile("\d+\.\d+\.\d+\.\d+")

logger = logging.getLogger("ifi")


class recdefaultdict(defaultdict):
	"""
	Recursive defaultdict. I heard you like defaultdicts, so I put a ...
	"""
	def __init__(self, dict_init=None):
		super().__init__(recdefaultdict)
		#TypeError: descriptor 'keys' of 'dict' object needs an argument
		logger.debug("init using dict_init: %r type: %r",
			dict_init,
			type(dict_init)
		)
		if dict_init is not None:
			self.update(dict_init)


# config yaml to use defaultdict
def _dict_constructor(loader, node):
	return recdefaultdict(loader.construct_pairs(node))

_mapping_tag = yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG
#yaml.add_constructor(_mapping_tag, _dict_constructor)


def _dict_representer(dumper, data):
	return dumper.represent_dict(data.items())

#yaml.add_representer(recdefaultdict, _dict_representer)


class Firewall(object):
	EXRACT_CB_OUT = {
		ip.IP_PROTO_TCP: lambda pkt: " %d" % pkt.dport,
		ip.IP_PROTO_UDP: lambda pkt: " %d" % pkt.dport
	}

	def __init__(self, learningmode=True):
		self._ipt_handler = IPTablesHandler()
		self._ictor_out = interceptor.Interceptor()
		self._ictor_in = interceptor.Interceptor()
		self._state_active = False
		# Rule format: b"1234A" b"1234ABB"
		self._rules_ip_proto_wl_out = set()
		self._rules_ip_proto_bl_out = set()
		self._rules_ip_proto_wl_in = set()
		self._rules_ip_proto_bl_in = set()
		# hashes of known apps, stored non volatile (PID is dynamic)
		self._app_wl = set()
		self._app_bl = set()
		self._rulefile_wl_out = "fw_rules_wl_out.txt"
		self._rulefile_bl_out = "fw_rules_bl_out.txt"
		self._rulefile_wl_in = "fw_rules_wl_in.txt"
		self._rulefile_bl_in = "fw_rules_bl_in.txt"
		self._inputlock = threading.Lock()
		self._learningmode = learningmode

	def _load_all_rules(self):
		Firewall._load_rules(self._rulefile_wl_out, self._rules_ip_proto_wl_out)
		Firewall._load_rules(self._rulefile_bl_out, self._rules_ip_proto_bl_out)
		Firewall._load_rules(self._rulefile_wl_in, self._rules_ip_proto_wl_in)
		Firewall._load_rules(self._rulefile_bl_in, self._rules_ip_proto_bl_in)

	def _save_all_rules(self):
		Firewall._save_rules(self._rulefile_wl_out, self._rules_ip_proto_wl_out)
		Firewall._save_rules(self._rulefile_bl_out, self._rules_ip_proto_bl_out)
		Firewall._save_rules(self._rulefile_wl_in, self._rules_ip_proto_wl_in)
		Firewall._save_rules(self._rulefile_bl_in, self._rules_ip_proto_bl_in)

	@staticmethod
	def _create_rule_entry(ipl):
		proto_id = ipl.p
		# extract layer 4 data (ports etc)
		ldata = Firewall.EXRACT_CB_OUT.get(proto_id, lambda pkt: "")(ipl.upper_layer)
		return ipl.dst_s + " %d" % proto_id + ldata

	def _user_decision(self, pkt, rules_wl, rules_bl):
		"""
		Get user decision about connection acceptance
		return -- True if connection gets accepted, else False
		"""
		sport, dport = None, None
		sport_str, dport_str = "", ""

		if pkt.upper_layer.__class__ in [tcp.TCP, udp.UDP]:
			sport, dport = pkt.upper_layer.sport, pkt.upper_layer.dport
			sport_str, dport_str = ":%d" % sport, ":%d" % dport

		# logger.debug("trying to get process info")
		cmd = get_procinfo_by_address(pkt.src_s, pkt.dst_s, port_src=sport, port_dst=dport)

		procinfo_question = ""
		procinfo = ""
		dns_src_dst = ["", ""]

		for idx, addr in enumerate([pkt.src_s, pkt.dst_s]):
			try:
				#logger.debug("getting host for %r", addr)
				dns_src_dst[idx] = socket.gethostbyaddr(addr)[0]
			except:
				# dns resolve error
				#logger.debug("unable to resolve %r", addr)
				pass

		if len(cmd) == 4:
			# check if app is known
			if cmd[3] in self._app_wl:
				rules_wl.add(Firewall._create_rule_entry(pkt))
				return True
			elif cmd[3] in self._app_bl:
				rules_bl.add(Firewall._create_rule_entry(pkt))
				return False

			procinfo_question = ", [a]ll conn. from this process, [n]o conn. from this process"
			procinfo = "Process: '%s'\n(PID: % d, User: % s)\ng" % (cmd[1], cmd[0], cmd[2])

		# TODO: show if IN or OUT direction
		pstack = " + ".join([l.__class__.__name__ for l in pkt])
		msg = """Allow this connection? [w]hitelist [b]lacklist, [i]gnore%s (empty = ignore)
%sConnection: %s%s %s -> %s%s %s
Protocol stack: %s
Answer: """ % (
			procinfo_question,
			procinfo,
			pkt.src_s, sport_str, dns_src_dst[0],
			pkt.dst_s, dport_str, dns_src_dst[1],
			pstack
		)

		decision_str = input(msg).lower()
		logger.debug("decision was: %r", decision_str)
		accept = False

		if decision_str.startswith("w"):
			rules_wl.add(Firewall._create_rule_entry(pkt))
			accept = True
		elif decision_str.startswith("b"):
			rules_bl.add(Firewall._create_rule_entry(pkt))

		if len(cmd) == 4:
			if decision_str.startswith("a"):
				self._app_wl.add(cmd[3])
				accept = True
			elif decision_str.startswith("n"):
				self._app_bl.add(cmd[3])

		return accept

	# assume IPv4 or IPv6
	LL_PROTO_CB = {
		ethernet.ETH_TYPE_IP: ip.IP,
		ethernet.ETH_TYPE_IP6: ip6.IP6,
	}

	@staticmethod
	def verdict_cb(data, ll_proto_id, ctx):
		ipl = Firewall.LL_PROTO_CB[ll_proto_id](data)
		# logger.debug("verdict_cb, packet: %r", ipl)
		decision_accept = False

		rule = Firewall._create_rule_entry(ipl)

		if rule in ctx.rules_wl:
			decision_accept = True
		elif rule in ctx.rules_bl:
			pass
		else:
			logger.debug("no wl or bl rule found, asking user")

			# no bl rule found -> ask user
			if ctx.obj._learningmode:
				ctx.obj._inputlock.acquire()
				decision_accept = ctx.obj._user_decision(
					ipl,
					ctx.rules_wl,
					ctx.rules_bl
				)
				ctx.obj._inputlock.release()
				logger.debug("got user input, accept packet: %r", decision_accept)
			else:
				# no rule and not asking user -> drop
				decision_accept = False

		if decision_accept:
			logger.debug("accepting packet: %s -> %s", ipl.src_s, ipl.dst_s)
			return data, interceptor.NF_ACCEPT
		else:
			logger.debug("NOT accepting packet: %s -> %s", ipl.src_s, ipl.dst_s)
			return data, interceptor.NF_DROP

	@staticmethod
	def _save_rules(filename_rules, rules):
		"""
		Saves firewall rules to file.
		"""
		# logger.debug("saving rules to: %r", filename_rules)
		with open(filename_rules, "w") as fd_out:
			for rule in rules:
				rule = rule.strip()

				if len(rule) == 0:
					continue
				fd_out.write(rule + "\n")

	@staticmethod
	def _load_rules(filename_rules, rules):
		"""
		Loads Firewall rules from file.
		"""
		logger.debug("loading rules from: %r", filename_rules)
		rules.clear()

		try:
			with open(filename_rules, "r") as fd_in:
				for line in fd_in:
					line = line.strip()

					if len(line) == 0:
						continue
					rules.add(line)
		except FileNotFoundError:
			# no rules saved yet, nothing to load
			return

		logger.debug("loaded rules:")

		for rule in rules:
			logger.debug(rule)

	def set_state(self, state_active=True):
		if self._state_active == state_active:
			return
		self._state_active = state_active

		if state_active:
			logger.debug("loading firewall rules")
			self._load_all_rules()
			logger.debug("setting iptables rules")
			self._ipt_handler.set_nfqueue_config(state_active=True)
			logger.debug("starting interceptor handlers")

			Ctx = namedtuple("Ctx", ["rules_wl", "rules_bl", "obj"])
			ctx_out = Ctx(rules_wl=self._rules_ip_proto_wl_out,
				rules_bl=self._rules_ip_proto_bl_out,
				obj=self)
			self._ictor_out.start(Firewall.verdict_cb,
				queue_ids=[0, 1, 2, 3],
				ctx=ctx_out
			)
			ctx_in = Ctx(rules_wl=self._rules_ip_proto_wl_in,
						rules_bl=self._rules_ip_proto_bl_in,
						obj=self)
			self._ictor_in.start(Firewall.verdict_cb,
				queue_ids=[4, 5, 6, 7],
				ctx=ctx_in
			)
		else:
			logger.debug("stopping interceptor handlers")
			self._ictor_out.stop()
			self._ictor_in.stop()
			logger.debug("removing iptables rules")
			self._ipt_handler.set_nfqueue_config(state_active=False)
			logger.debug("saving firewall fules")
			self._save_all_rules()