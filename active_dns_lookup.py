#!/usr/bin/env python3
"""Accepts IP addresses on stdin, looks up their hostnames with PTR
lookups, and looks up the IP addresses of those hostnames with A
lookups.  It then prints the final
hostname<tab>ip_address_list
pairs on stdout, or prints them in Zeek dns log format if requested."""

#Copyright 2023 William Stearns <bill@activecountermeasures.com>
#Released under the GPL


__version__ = '0.0.12'

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
from typing import List
sys.path.insert(0, os.getcwd())										#So we can locate db_lib in the current directory
from db_lib import buffer_merges, select_key	# pylint: disable=wrong-import-position

use_dns_resolver: bool = True
try:
	import dns.resolver
except (ModuleNotFoundError, ImportError):
	print("Missing dns module; perhaps 'sudo -H pip install dnspython' or 'sudo port install py39-dnspython' ?  Exiting.")
	use_dns_resolver = False
	raise


#======== Functions
def Debug(DebugStr: str) -> None:
	"""Prints a note to stderr"""

	if Devel:
		sys.stderr.write(DebugStr + '\n')


def signal_handler(one_signal, frame):						# pylint: disable=unused-argument
	"""Register the fact that we received a shutdown signal, though we won't actually exit until we finish processing one IP address and are about to start on the next."""
	global sig_recvd							# pylint: disable=global-statement

	sig_recvd = True


def fail(fail_message: str) -> None:
	"""Prints a note to stderr"""

	sys.stderr.write(fail_message + ', exiting.\n')
	sys.stderr.flush()
	sys.exit(1)


def mkdir_p(path: str):
	"""Create an entire directory branch.  Will not complain if the directory already exists."""

	if not os.path.isdir(path):
		try:
			os.makedirs(path)
		except OSError as exc:
			if exc.errno == errno.EEXIST and os.path.isdir(path):
				pass
			else:
				raise



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
			dns_lookup.dns_h.nameservers = ['8.8.8.8']					# type: ignore


	if dns_type != '':
		for one_query in queries:
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


def process_an_address(incoming_ip: str, dns_list: List, zeek_format: bool):
	"""Process a single IP address (turn it into a hostname, then
	turn that hostname back into one ore more IPs."""

	if 'h2i_already_printed' not in process_an_address.__dict__:
		process_an_address.h2i_already_printed: List[tuple[str]] = []				# type: ignore #A list of tuples (hostname, string of IP addresses list) that have already been printed.  Reduces redundant output.
													#Note: we _will_ print a (hostname, IP address list) set more than once if the IP address list changes.

	hostnames: List[str] = []									#List of hostnames (retrieved from cache or DNS) for the IP we're currently processing.
	final_ips: List[str] = []									#List of IPs (retrieved from cache or DNS) for the hostname we're currently processing.
	h2i_sig: tuple[str, ...] = ()									#Static tuple (hostname, string of IP addresses list) used to remember what we've already printed.

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
		if final_ips:
			h2i_sig = (one_hostname, str(final_ips))
			if h2i_sig not in process_an_address.h2i_already_printed:			# type: ignore
				#Debug('final ips: ' + str(final_ips))
				if zeek_format:
					print('aaaaaaaaaaaaaaaaaa\t10.0.0.1\t65535\t0.0.0.1\t53\tudp\t' + one_hostname + '\t1\tC_INTERNET\t1\tA\t0\tNOERROR\t' + ','.join(final_ips))
													#Rita/AC-Hunter require source internal, dest external, and neither in NeverInclude (so no 127.0.0.1)
				else:
					for one_ip in final_ips:
						print(one_ip + '\t' + one_hostname)
				process_an_address.h2i_already_printed.append(h2i_sig)			# type: ignore

	#Lookup and print IPv6 ("AAAA") records
	for one_hostname in hostnames:
		final_ips = sorted(select_key(hostname_ipv6s, one_hostname))				#Like above, look in cache first, then dns (and save these in cache if we found some in dns)
		if (not final_ips) or (final_ips and relearn_percent <= random.random() * 100):
			final_ips = sorted(dns_lookup([one_hostname], 'AAAA', dns_list))
			if final_ips:
				buffer_merges(hostname_ipv6s, one_hostname, final_ips, max_to_buffer)
		#	else:
		#		Debug('AAAA lookup fail: ' + one_hostname)
		if final_ips:
			h2i_sig = (one_hostname, str(final_ips))
			if h2i_sig not in process_an_address.h2i_already_printed:			# type: ignore
				#Debug('final ips: ' + str(final_ips))
				if zeek_format:
					print('aaaaaaaaaaaaaaaaaa\t10.0.0.1\t65535\t0.0.0.1\t53\tudp\t' + one_hostname + '\t1\tC_INTERNET\t1\tAAAA\t0\tNOERROR\t' + ','.join(final_ips))
				else:
					for one_ip in final_ips:
						print(one_ip + '\t' + one_hostname)
				process_an_address.h2i_already_printed.append(h2i_sig)			# type: ignore


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

ip_cache_dir_default = os.environ["HOME"] + '/.cache/'							#Default directory for the sqlite cache dbs
ip_cache_dir = ip_cache_dir_default
mkdir_p(ip_cache_dir)

ip_hostnames = [ ip_cache_dir + 'ip_hostnames.sqlite3' ]						#This sqlite db caches ip->[list of hostnames] mappings
hostname_ipv4s = [ ip_cache_dir + 'hostname_ipv4s.sqlite3' ]						#This sqlite db caches hostname->[list of ipv4s] mappings
hostname_ipv6s = [ ip_cache_dir + 'hostname_ipv6s.sqlite3' ]						#This sqlite db caches hostname->[list of ipv6s] mappings

max_to_buffer = 50											#We minimize writes to the sqlite db - this buffers up 50 writes before actually committing them.
relearn_percent = 1.0											#When we do have data in cache, we _still_ look it up 2% of the time (randomly-picked 2% of the requests)

sig_recvd = False											#Remembers if we've received a HUP signal so we can cleanly write out buffered writes and exit when we finish this lookup.



if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description='active_dns_lookup.py version ' + str(__version__) + ': Looks up the hostname for an IP by using PTR and A records.')
	parser.add_argument('-s', '--servers', help='DNS server(s) to query (default is just 8.8.8.8)', default=['8.8.8.8'], nargs='*')
	parser.add_argument('-z', '--zeekdns', help='present output in Zeek DNS log file format (default is "hosts" file format)', required=False, default=False, action='store_true')
	args = vars(parser.parse_args())
	dns_option: List = args['servers']
	zeek_option: bool = args['zeekdns']

	signal.signal(signal.SIGHUP, signal_handler)							#If we get a HUP signal this function notes it so we can cleanly write buffered writes before shutdown

	try:
		if zeek_option:
			print(dns_header)

		#Read input lines; lookup the hostnames for it, and then the IP addresses for those.
		for InLine in sys.stdin:
			IPAddress = InLine.rstrip('\n')
			process_an_address(IPAddress, dns_option, zeek_option)
			if sig_recvd:
				#print("Wait, flushing remaining writes.")				#SIGHUP can be from a closed terminal - we don't want to write to the terminal if it's closed.
				buffer_merges("", "", [], 0)
				#print("Flushing complete.")
				sys.exit(0)

		if zeek_option:
			print(dns_footer)
	except KeyboardInterrupt:
		print("Wait, flushing remaining writes.")
		buffer_merges("", "", [], 0)
		print("Flushing complete.")
		sys.exit(0)

	#Flush out any remaining writes
	buffer_merges("", "", [], 0)
