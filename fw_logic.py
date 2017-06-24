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

unpack_I = struct.Struct(">I").unpack
pack_B = struct.Struct("B").pack
PATTERN_IP = re.compile("\d+\.\d+\.\d+\.\d+")

logger = logging.getLogger("ifi")


class recdefaultdict(defaultdict):
	"""
	Recursive defaultdict. I heard you like defaultdicts, so I put a ...
	"""
	def __init__(self, dict_init=None):
		super().__init__(recdefaultdict)
		#TypeError: descriptor 'keys' of 'dict' object needs an argument
		logger.debug("init using dict_init: %r type: %r", dict_init, type(dict_init))
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
	"""
	OUT:
		src:dst -> allow established/related
		dst -> allow known
	IN:
		src:dst -> allow established/related
		dst -> check known
	"""
	DECISION_CB = {
		ip.IP_PROTO_TCP: lambda pkt, ainfo: pkt.dport in ainfo,
		ip.IP_PROTO_UDP: lambda pkt, ainfo: pkt.dport in ainfo
	}

	DECISION_CB_DFLT = lambda pkt, ainfo: True
	EXRACT_CB_OUT = {
		ip.IP_PROTO_TCP: lambda pkt: pkt.dport,
		ip.IP_PROTO_UDP: lambda pkt: pkt.dport,
	}

	def __init__(self, learningmode=True):
		self._ipt_handler = IPTablesHandler()
		self._ictor_out = interceptor.Interceptor()
		self._ictor_in = interceptor.Interceptor()
		self._state_active = False
		# {b"ip" : {"proto" : {data, ...}, ...}}
		# data needs to be non-empty or rules will be ignored
		# TODO: avoid saving non-empty rules (autodict-behaviour)
		self._rules_ip_proto_wl_out = defaultdict(lambda: defaultdict(set))
		self._rules_ip_proto_bl_out = defaultdict(lambda: defaultdict(set))
		self._rules_ip_proto_wl_in = defaultdict(lambda: defaultdict(set))
		self._rules_ip_proto_bl_in = defaultdict(lambda: defaultdict(set))
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

	def _add_rule(self, ipl, dnsname, target):
		proto = ipl.p
		# extract layer 4 data (ports etc)
		ldata = Firewall.EXRACT_CB_OUT.get(
			proto, lambda pkt: "<data>")(ipl.upper_layer)

		if dnsname is not None and len(dnsname) > 0:
			# logger.debug("adding rule for DNS %r", dnsname)
			target[dnsname][proto].add(ldata)
			target[ipl.dst][proto].add(ldata)
			target[ipl.dst]["RESOLVED"] = True
		else:
			# error while resolving DNS, just add IP address
			target[ipl.dst][proto].add(ldata)

	def _user_decision(self, pkt, rules_wl, rules_bl):
		"""
		Get user decision about connection acceptance
		return -- True if connection gets accepted, else False
		"""
		# self._inputlock.lock()
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
				# TODO: set (lower) timeout, this can take many seconds...
				dns_src_dst[idx] = socket.gethostbyaddr(addr)[0]
			except:
				# dns resolve error
				#logger.debug("unable to resolve %r", addr)
				pass

		if len(cmd) == 4:
			# check if app is known
			if cmd[3] in self._app_wl:
				self._add_rule(ip1, dns_src_dst[1], rules_wl)
				return True
			elif cmd[3] in self._app_bl:
				self._add_rule(ip1, dns_src_dst[1], rules_bl)
				return False

			procinfo_question = ", [a]ll conn. from this process, [n]o conn. from this process"
			procinfo = "Process: '%s'\n(PID: % d, User: % s)\ng" % (cmd[1], cmd[0], cmd[2])

		# TODO: show if IN or OUT direction
		pstack = " + ".join([l.__class__.__name__ for l in pkt])
		msg = """Allow this connection? [w]hitelist [b]lacklist, [i]gnore %s (empty = ignore)
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
			self._add_rule(pkt, dns_src_dst[1], rules_wl)
			accept = True
		elif decision_str.startswith("b"):
			self._add_rule(pkt, dns_src_dst[1], rules_bl)

		if len(cmd) == 4:
			if decision_str.startswith("a"):
				self._app_wl.add(cmd[3])
				accept = True
			elif decision_str.startswith("n"):
				self._app_bl.add(cmd[3])

		return accept

	def _add_dns_to_wl(self, dns_ip_str):
		"""
		Add DNS server to whitelist

		"""
		logger.debug("adding DNS server to wl: %r", dns_ip_str)
		dns_ip_bytes = pypacker.ip4_str_to_bytes(dns_ip_str)
		# assume UDP target port 53
		self._rules_ip_proto_wl_out[dns_ip_bytes][ip.IP_PROTO_UDP].add(53)

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
		ainfo = ctx.rules_wl[ipl.dst][ipl.p]

		# TODO: this makes trouble if proto id does not match protocol
		if len(ainfo) != 0:
			decision_accept = Firewall.DECISION_CB.get(
				ipl.p, Firewall.DECISION_CB_DFLT)(ipl.upper_layer, ainfo)
		else:
			logger.debug("no wl rule found, trying bl")
			ainfo = ctx.rules_bl[ipl.dst][ipl.p]

			if len(ainfo) != 0:
				decision_accept = Firewall.DECISION_CB.get(
					ipl.p, Firewall.DECISION_CB_DFLT)(ipl.upper_layer, ainfo)
			else:
				logger.debug("no bl rule found")

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
			logger.debug("accepting packet: %s -> %s",
				ipl.src_s, ipl.dst_s)
			return data, interceptor.NF_ACCEPT
		else:
			logger.debug("NOT accepting packet: %s -> %s",
				ipl.src_s, ipl.dst_s)
			return data, interceptor.NF_DROP

	@staticmethod
	def _save_rules(filename_rules, target_dct):
		"""
		Saves firewall rules to file.
		"""
		# logger.debug("saving rules to: %r", filename_rules)
		filtered_rules = {}

		# only store non-resolved addresses
		for ip_dns, proto in target_dct.items():
			# don't store resolved addresses
			if "RESOLVED" in target_dct[ip_dns]:
				# TODO: check for correct rule saving
				continue

			# b"ip" -> "1.2.3.4"
			if type(ip_dns) is bytes:
				ip_dns = pypacker.ip4_bytes_to_str(ip_dns)

			filtered_rules[ip_dns] = proto

		# logger.debug("saving rules: %r", filtered_rules)

		with open(filename_rules, "w") as fd_out:
			yaml.dump(filtered_rules, fd_out)

	@staticmethod
	def _load_rules(filename_rules, target_dct):
		"""
		Loads Firewall rules from file.
		"""
		# logger.debug("loading rules from: %r", filename_rules)
		# {"ip|dns" : { "upper_proto" : {data, ...}}}
		try:
			with open(filename_rules, "r") as fd_in:
				config_rules = yaml.load(fd_in)
		except FileNotFoundError:
			# no rules saved yet, nothing to load
			return

		Firewall._update_dynamic_addresses(config_rules)
		target_dct.clear()

		# "1.2.3.4" -> b"ip"
		for ip_dns, proto in config_rules.items():
			if PATTERN_IP.match(ip_dns):
				ip_dns = pypacker.ip4_str_to_bytes(ip_dns)
			target_dct[ip_dns] = proto

		logger.debug("loaded rules:")

		for key, val in target_dct.items():
			logger.debug("%r -> %r", key, val)

	@staticmethod
	def _update_dynamic_addresses(target):
		"""
		Resolve DNS names to IP addresses
		"""
		# logger.debug("resolving DNS names")
		# remove old dynamic resolved addresses
		for addr in target.keys():
			if "RESOLVED" in target[addr]:
				del target[addr]

		# update dictionary when iterating -> copy keys
		for ip_dns in [key for key in target.keys()]:
			proto = target[ip_dns]
			# logger.debug("converting: %r %r", ip_dns, proto)

			if PATTERN_IP.match(ip_dns):
				continue
			try:
				# logger.debug("resolving: %r", ip_dns)
				ips = socket.gethostbyname_ex(ip_dns)[-1]
			except Exception:
				logger.debug("could not resolve: %r", ip_dns)
				continue

			for ip_resolved in ips:
				# don't overwrite non resolved addresses
				if ip_resolved in target:
					continue
				# avoid updating original
				target[ip_resolved] = copy.deepcopy(proto)
				target[ip_resolved]["RESOLVED"] = True
		# logger.debug("after resolving: %r", target)

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
			# logger.debug("self._ictor_out.stop()")
			self._ictor_out.stop()
			# logger.debug("self._ictor_in.stop()")
			self._ictor_in.stop()
			logger.debug("removing iptables rules")
			self._ipt_handler.set_nfqueue_config(state_active=False)
			logger.debug("saving firewall fules")
			self._save_all_rules()

	def store_wl_rules_readable(self, filename="fw_rules_readable.txt"):
		"""
		Stores the whitelist rules in readable format. Can be used
		to create iptables rules with default DROP policy.

		filename -- Name of the file to store wl rules to
		"""
		self._load_all_rules()
		fd_out = open(filename, "w")
		type_str_dct = {
			ip.IP_PROTO_TCP: "TCP",
			ip.IP_PROTO_UDP: "UDP",
			ip.IP_PROTO_ICMP: "ICMP"
		}

		for ruletype, rules in zip(["Whitelist OUT", "Whitelist IN"],
			[self._rules_ip_proto_wl_out, self._rules_ip_proto_wl_in]):
			fd_out.write(">>> %r\n" % ruletype)

			for ip_dns, protoid_data in rules.items():
				# don't store DNS names
				if type(ip_dns) is not bytes:
					continue

				fd_out.write("%s" % pypacker.ip4_bytes_to_str(ip_dns))

				for protoid, data in protoid_data.items():
					# store both resolved and non resolved IPs
					if type(protoid) is not int:
						continue

					#logger.debug("%r -> %r", protoid, data)
					protoid_str = type_str_dct.get(protoid, "%r" % protoid)
					fd_out.write(" (proto: %s" % protoid_str)

					for dataitem in data:
						if protoid in [ip.IP_PROTO_TCP, ip.IP_PROTO_UDP]:
							fd_out.write(", port %r" % dataitem)
					fd_out.write(")\n")
		fd_out.close()
