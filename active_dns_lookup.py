#!/usr/bin/env python3
"""Accepts IP addresses on stdin, looks up their hostnames with PTR
lookups, and looks up the IP addresses of those hostnames with A
lookups.  It then prints the final
hostname<tab>ip_address_list
pairs on stdout, or prints them in Zeek dns log format if requested."""

#Copyright 2023 William Stearns <bill@activecountermeasures.com>
#Released under the GPL


__version__ = '0.0.15'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2023, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'bill@activecountermeasures.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Development'										#Prototype, Development or Production


#Sample uses:
#To only look up _non-rfc1918_ ("external") addresses
#zcutter id.orig_h id.resp_h -r conn.*.log.gz | sed -e 's/\t/\n/' | egrep -v '(^10\.|^192\.168\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[01]\.|^127\.|^[Ff][Ee]80:)' | justone.py | active_dns_lookup.py -s 127.0.0.1 -z >dns.sample.log
#To only look up _rfc1918_ ("internal") addresses.  The DNS server you poll needs to have both A/AAAA and PTR records for these IPs.
#zcutter id.orig_h id.resp_h -r conn.*.log.gz | sed -e 's/\t/\n/' | egrep '(^10\.|^192\.168\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[01]\.|^127\.|^[Ff][Ee]80:)' | justone.py | active_dns_lookup.py -s 127.0.0.1 -z >dns.sample.log


#======== External libraries
import os
import sys												#Used for reading from stdin/writing to stdout
import signal
import errno
import random
import ipaddress											#For address manipulation
from typing import Dict, List, Tuple
sys.path.insert(0, os.getcwd())										#So we can locate db_lib in the current directory
from db_lib import buffer_merges, select_key								# pylint: disable=wrong-import-position

use_dns_resolver: bool = True
try:
	import dns.resolver
	import dns.query
	import dns.zone
except (ModuleNotFoundError, ImportError):
	print("Missing dns module; perhaps 'sudo -H pip install dnspython' or 'sudo port install py311-dnspython' ?  Exiting.")
	use_dns_resolver = False
	raise


#======== Functions
def Debug(DebugStr: str) -> None:
	"""Prints a note to stderr."""

	if Devel:
		sys.stderr.write(DebugStr + '\n')


def signal_handler(one_signal, frame) -> None:								# pylint: disable=unused-argument
	"""Register the fact that we received a shutdown signal, though we won't actually exit until we finish processing one IP address and are about to start on the next."""
	global sig_recvd										# pylint: disable=global-statement

	sig_recvd = True


def fail(fail_message: str) -> None:
	"""Prints a failure note to stderr and exits."""

	sys.stderr.write(fail_message + ', exiting.\n')
	sys.stderr.flush()
	sys.exit(1)


def mkdir_p(path: str) -> None:
	"""Create an entire directory branch.  Will not complain if the directory already exists."""

	if not os.path.isdir(path):
		try:
			os.makedirs(path)
		except OSError as exc:
			if exc.errno == errno.EEXIST and os.path.isdir(path):
				pass
			else:
				raise


def zone_transfer_addresses(zone_name: str, dns_server_ip: str) -> Tuple[Dict, Dict]:
	"""Perform a zone transfer for the requested domain to dns_server_ip.  This returns 2 address dictionaries (hostname->IPv4_list and hostname->IPv6_list)."""

	host_ip4s: Dict = {}			#Values are a list of IPv4 addresses
	host_ip6s: Dict = {}			#Values are a list of IPv6 addresses
	host_cnames: Dict = {}			#Values are a single dns destination object (you cannot have more than one CNAME record for a single object)

	try:
		zone_list = dns.zone.from_xfr(dns.query.xfr(dns_server_ip, zone_name))
		names = zone_list.nodes.keys()
		for n in names:
			if str(n) != '@':
				#print("==== " + str(n))
				zone_record_block = zone_list[n].to_text(n)
				zone_lines = zone_record_block.split("\n")
				for one_line in zone_lines:
					#The atoms for an A or AAAA record are dns_object, TTL, 'IN', 'A'/'AAAA', IP_address
					#The atoms for an CNAME record are dns_object, TTL, 'IN', 'CNAME', destination_dns_object
					#The atoms for an MX record are dns_object, TTL, 'IN', 'MX', mx_priority_integer, dns_object_receiving_the_mail
					line_atoms = one_line.split(" ")
					if line_atoms[2] == "IN":
						dns_obj = line_atoms[0]
						dest = line_atoms[4]
						if line_atoms[3] == 'A':
							if dns_obj not in host_ip4s:
								host_ip4s[dns_obj] = []
							host_ip4s[dns_obj].append(dest)
						elif line_atoms[3] == 'AAAA':
							if dns_obj not in host_ip6s:
								host_ip6s[dns_obj] = []
							host_ip6s[dns_obj].append(dest)
						elif line_atoms[3] == 'CNAME':
							host_cnames[dns_obj] = dest			#Remember, there can only be a single CNAME record for a DNS object.
	except dns.xfr.TransferError:
		print('Unable to transfer zone.  Is ' + dns_server_ip + ' a dns server?  Do you need to tell it to allow this host to do zone transfers?')

	#Now we look up all cnames and place the target IP in host_ip4s.  Ex: if bart is a CNAME to lisa and lisa has ips 1.1.1.1 and 2.2.2.2, we add bart -> 1.1.1.1 and bart -> 2.2.2.2 .  Same with ipv6 addresses.
	#Note: this function assumes that the destination of the CNAME _is part of this DNS zone_!  If you have "bart 38400 IN CNAME www.goober.org", we will not go out to retrieve www.goober.org's A or AAAA records.
	for one_obj, one_dest in host_cnames.items():
		if one_dest in host_ip4s:								#Our CNAME destination has IPv4 addresses, so we assign those to the dns object too.
			for one_final_ip in host_ip4s[one_dest]:
				if one_obj not in host_ip4s:
					host_ip4s[one_obj] = []
				host_ip4s[one_obj].append(one_final_ip)

		if one_dest in host_ip6s:								#Our CNAME destination has IPv6 addresses, so we assign those to the dns object too.
			for one_final_ip in host_ip6s[one_dest]:
				if one_obj not in host_ip6s:
					host_ip6s[one_obj] = []
				host_ip6s[one_obj].append(one_final_ip)

	return host_ip4s, host_ip6s


def dns_lookup(queries: List[str], dns_type: str, dns_servers: List[str]) -> List[str]:
	"""Returns a (possibly empty) list of responses associated with the supplied query."""

	response_list = []

	if not use_dns_resolver:
		fail('No dnspython library to load, exiting.')

	if 'dns_h' not in dns_lookup.__dict__:
		dns_lookup.dns_h: dns.resolver.Resolver = dns.resolver.Resolver()			# type: ignore
		dns_lookup.dns_h.timeout = dns_max_lookup_lifetime * 2 / 3				# type: ignore
		dns_lookup.dns_h.lifetime = dns_max_lookup_lifetime					# type: ignore
		if dns_servers:
			dns_lookup.dns_h.nameservers = dns_servers					# type: ignore
		else:
			dns_lookup.dns_h.nameservers = default_nameserver_list				# type: ignore


	if dns_type != '':
		for one_query in queries:
			if one_query:
				try:
					if dns_type == 'PTR' and not one_query.endswith(('.ip6.arpa', '.in-addr.arpa','.ip6.arpa.', '.in-addr.arpa.')):
						#Handles both IPv4 and IPv6 addresses, constructing ...ip6.arpa and ...in-addr.arpa forms
						rev_query = ipaddress.ip_address(one_query).reverse_pointer
						dns_answer_obj = dns_lookup.dns_h.resolve(rev_query, dns_type)	# type: ignore
					else:
						dns_answer_obj = dns_lookup.dns_h.resolve(one_query, dns_type)	# type: ignore
					for one_rec in dns_answer_obj:
						#Only append if not already there to avoid duplicate responses in the list.
						if one_rec.to_text() not in response_list:
							response_list.append(one_rec.to_text())
				except dns.resolver.NoAnswer:
					pass
					#Debug('No answer received')
				except dns.resolver.NXDOMAIN:
					pass
					#Debug('No answer exists.')
				except dns.resolver.NoNameservers:
					pass
					#Debug('No nameserver answered')
				except dns.resolver.LifetimeTimeout:
					pass
				except KeyboardInterrupt:
					pass

	return response_list


def print_address_record(out_hostname: str, out_ip_list: List[str], zeek_format: bool) -> None:
	"""Display the output line for a hostname->ip_list pair."""

	if 'h2i_already_printed' not in print_address_record.__dict__:
		print_address_record.h2i_already_printed: List[tuple[str]] = []				# type: ignore #A list of tuples (hostname, string of IP addresses list) that have already been printed.  Reduces redundant output.
													#Note: we _will_ print a (hostname, IP address list) set more than once if the IP address list changes.

	h2i_sig: tuple[str, ...] = ()									#Static tuple (hostname, string of IP addresses list) used to remember what we've already printed.

	if out_hostname and out_ip_list:
		h2i_sig = (out_hostname, str(out_ip_list))
		if h2i_sig not in print_address_record.h2i_already_printed:				# type: ignore
			#Debug('final ips: ' + str(out_ip_list))
			if zeek_format:
				print('aaaaaaaaaaaaaaaaaa\t10.0.0.1\t65535\t0.0.0.1\t53\tudp\t' + out_hostname + '\t1\tC_INTERNET\t1\tA\t0\tNOERROR\t' + ','.join(out_ip_list))
													#Rita/AC-Hunter require source internal, dest external, and neither in NeverInclude (so no 127.0.0.1)
			else:
				for one_ip in out_ip_list:
					print(one_ip + '\t' + out_hostname)
			print_address_record.h2i_already_printed.append(h2i_sig)			# type: ignore


def process_an_address(incoming_ip: str, dns_list: List, zeek_format: bool) -> None:
	"""Process a single IP address (turn it into a hostname, then
	turn that hostname back into one ore more IPs."""

	hostnames: List[str] = []									#List of hostnames (retrieved from cache or DNS) for the IP we're currently processing.
	final_ips: List[str] = []									#List of IPs (retrieved from cache or DNS) for the hostname we're currently processing.

	hostnames = select_key(ip_hostnames, incoming_ip)						#Check to see if we have cached hostnames for this IP first
	if (not hostnames) or (hostnames and relearn_percent <= random.random() * 100):			#We look up with DNS if we have no cached answers, OR if we do have cached answers randomly 3% of the time
		hostnames = dns_lookup([incoming_ip], 'PTR', dns_list)					#Look them up with DNS
		if hostnames:										#If we found some in DNS...
			buffer_merges(ip_hostnames, incoming_ip, hostnames, max_to_buffer)		#...cache those for later use
	#	else:
	#		Debug('Lookup fail: ' + incoming_ip)
	#Debug('intermediate hostnames: ' + str(hostnames))

	#Lookup up and print IPv4 ("A") records
	for one_hostname in hostnames:
		final_ips = sorted(select_key(hostname_ipv4s, one_hostname))				#Like above, look in cache first, then dns (and save these in cache if we found some in dns)
		if (not final_ips) or (final_ips and relearn_percent <= random.random() * 100):
			final_ips = sorted(dns_lookup([one_hostname], 'A', dns_list))
			if final_ips:
				buffer_merges(hostname_ipv4s, one_hostname, final_ips, max_to_buffer)
		#	else:
		#		Debug('A lookup fail: ' + one_hostname)
		print_address_record(one_hostname, final_ips, zeek_format)

	#Lookup and print IPv6 ("AAAA") records
	for one_hostname in hostnames:
		final_ips = sorted(select_key(hostname_ipv6s, one_hostname))				#Like above, look in cache first, then dns (and save these in cache if we found some in dns)
		if (not final_ips) or (final_ips and relearn_percent <= random.random() * 100):
			final_ips = sorted(dns_lookup([one_hostname], 'AAAA', dns_list))
			if final_ips:
				buffer_merges(hostname_ipv6s, one_hostname, final_ips, max_to_buffer)
		#	else:
		#		Debug('AAAA lookup fail: ' + one_hostname)
		print_address_record(one_hostname, final_ips, zeek_format)


#======== Global variables
Devel: bool = True

dns_max_lookup_lifetime: float = 8.0									#Combined maximum time spent looking up any dns object.  Max time for lookups to a single DNS server is 2/3 this.

#The following is the _complete_ Zeek DNS log header.  We don't print all of these fields, so see "dns_header" below instead.
#full_dns_header = r"""#separator \x09
##set_separator	,
##empty_field	(empty)
##unset_field	-
##path	dns
##open	0000-00-00-00-00-00
##fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
##types	time	string	addr	port	addr	port	enum	count	interval	string	count	string	count	string	count	string	bool	bool	bool	bool	count	vector[string]	vector[interval]	bool
##close	9999-12-31-23-59-59"""

dns_header = r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	0000-00-00-00-00-00
#fields	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	answers
#types	string	addr	port	addr	port	enum	string	count	string	count	string	count	string	vector[string]"""

dns_footer = r"""#close	9999-12-31-23-59-59"""

#ip_cache_dir_default = os.environ["HOME"] + '/.cache/'							#Default directory for the sqlite cache dbs (replace HOME with USERPROFILE (or %USERPROFILE% ?) on Windows)
ip_cache_dir_default = os.path.expanduser('~') + '/.cache/'						#Default directory for the sqlite cache dbs (portable, works on Linux and windows)
ip_cache_dir = ip_cache_dir_default
mkdir_p(ip_cache_dir)

ip_hostnames = [ ip_cache_dir + 'ip_hostnames.sqlite3' ]						#This sqlite db caches ip->[list of hostnames] mappings
hostname_ipv4s = [ ip_cache_dir + 'hostname_ipv4s.sqlite3' ]						#This sqlite db caches hostname->[list of ipv4s] mappings
hostname_ipv6s = [ ip_cache_dir + 'hostname_ipv6s.sqlite3' ]						#This sqlite db caches hostname->[list of ipv6s] mappings

max_to_buffer = 50											#We minimize writes to the sqlite db - this buffers up 50 writes before actually committing them.
relearn_percent = 1.0											#When we do have data in cache, we _still_ look it up 1% of the time (randomly-picked 1% of the requests)

sig_recvd = False											#Remembers if we've received a HUP signal so we can cleanly write out buffered writes and exit when we finish this lookup.
default_nameserver_list = ['8.8.8.8']									#If no nameserver(s) is/are specified on the command line, we use google's 8.8.8.8 public dns server

a_recs: Dict = {}
aaaa_recs: Dict = {}


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description='active_dns_lookup.py version ' + str(__version__) + ': Looks up the hostname for an IP by using PTR and A records.')
	parser.add_argument('-s', '--servers', help='DNS server(s) to query (default is ' + str(default_nameserver_list[0]) + ' )', default=default_nameserver_list, nargs='*')
	parser.add_argument('-z', '--zeekdns', help='present output in Zeek DNS log file format (default is "hosts" file format)', required=False, default=False, action='store_true')
	parser.add_argument('-x', '--xfer', help='perform a single dns zone transfer for this domain', required=False, default='')
	args = vars(parser.parse_args())
	dns_option: List = args['servers']
	zeek_option: bool = args['zeekdns']

	try:
		signal.signal(signal.SIGHUP, signal_handler)						#If we get a HUP signal this function notes it so we can cleanly write buffered writes before shutdown
	except AttributeError:
		pass											#We're likely on Windows, which doesn't have signals, so we can't catch one.


	if zeek_option:
		print(dns_header)

	if args['xfer']:
		(a_recs, aaaa_recs) = zone_transfer_addresses(args['xfer'], dns_option[0])		#We only perform the zone transfer against the first DNS server.
		for one_host, ip_list in a_recs.items():
			print_address_record(one_host, ip_list, zeek_option)
		for one_host, ip_list in aaaa_recs.items():
			print_address_record(one_host, ip_list, zeek_option)
	else:
		try:
			#Read input lines; lookup the hostnames for it, and then the IP addresses for those.
			for InLine in sys.stdin:
				IPAddress = InLine.rstrip('\n')
				process_an_address(IPAddress, dns_option, zeek_option)
				if sig_recvd:
					#print("Wait, flushing remaining writes.")			#SIGHUP can be from a closed terminal - we don't want to write to the terminal if it's closed.
					buffer_merges("", "", [], 0)
					#print("Flushing complete.")
					sys.exit(0)

		except KeyboardInterrupt:
			print("Wait, flushing remaining writes.")
			buffer_merges("", "", [], 0)
			print("Flushing complete.")
			sys.exit(0)

		#Flush out any remaining writes
		buffer_merges("", "", [], 0)

	if zeek_option:
		print(dns_footer)
