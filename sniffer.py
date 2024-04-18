import socket
import struct
import textwrap
import ipaddress
import sys, getopt
from signal import signal, SIGINT
from sys import exit
# Run this program as sudo !!!
# Packet Sniffer based on python3 sockets - JKirn - 4/17/24
#
# Based on:
# Python Network Packet Sniffer Tutorials
# https://www.youtube.com/playlist?list=PL6gx4Cwl9DGDdduy0IPDDHYnUx66Vc4ed

TAB_1 = '\t  '
TAB_2 = '\t\t  '
TAB_3 = '\t\t\t  '
TAB_4 = '\t\t\t\t  '

DATA_TAB_1 = '\t  '
DATA_TAB_2 = '\t\t  '
DATA_TAB_3 = '\t\t\t  '
DATA_TAB_4 = '\t\t\t\t  '

# Collect ethernet frames and process them through python based sockets	
def collect(show_data, show_segment):
	print('Collect: [show_data: {}, show_segment: {}]'.format(show_data, show_segment))
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	frame_cnt = 0
	while True:
		frame_cnt += 1
		raw_data, addr = conn.recvfrom(65536)
		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
		print('\n[>] Ethernet Frame #{}: .....{} -> {}'.format(frame_cnt, src_mac, dest_mac))
		# print(TAB_1 +'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

		print(TAB_1 + 'Ethernet Protocol: {} - ({})'.format(big2little(eth_proto), eth_proto))
		
		# print('*** eth_proto: {}'.format(eth_proto))
		
		# Check for IPv6 (0x86dd)
		if eth_proto == 56710:
			(version, length, nexthdr, hoplim, src, dst, ipv6data) = ipv6_packet(data)
			#print(TAB_1 + '[+] IPv6')
			print(TAB_1 + '[+] IPv6 Packet: ...............{} -> {}'.format(ipaddress.IPv6Address(src), ipaddress.IPv6Address(dst)))
			if not show_segment:
				continue
			print(TAB_2 + 'Version: {}'.format(hex(version)))
			print(TAB_2 + 'Length: {}'.format(hex(length)))
			print(TAB_2 + 'Next Header: {}'.format(hex(nexthdr)))
			print(TAB_2 + 'Hop Limit: {}'.format(hex(hoplim)))
			if show_data:
				print(TAB_2 + 'Data:')
				print(format_multi_line(DATA_TAB_2, ipv6data))
			
		# Check for Aruba IAP (OK)
		elif eth_proto == 64911:
			print(TAB_1 + '[+] IAP - Aruba Access Point')
			# print(TAB_2 + 'Data:')
			# print(format_multi_line(DATA_TAB_3, data))if !show_segment:
			if not show_segment:
				continue
			(magic, ver, iaptype, length, iapid, status, uptime, vcip, unknown, pvid) = iap_segment(data)
			print(TAB_2 + 'Magic: {}'.format(hex(magic)))
			print(TAB_2 + 'Version: {}'.format(ver))
			print(TAB_2 + 'Type: {}'.format(iaptype))
			print(TAB_2 + 'Length: {}'.format(hex(length)))
			print(TAB_2 + 'ID: {}'.format(iapid))
			print(TAB_2 + 'Status: {}'.format(status))
			print(TAB_2 + 'Uptime: {}'.format(hex(uptime)))
			print(TAB_2 + 'VC-IP: {}'.format(vcip))
			print(TAB_2 + 'Unknown: {}'.format(hex(unknown)))
			print(TAB_2 + 'PVID: {}'.format(hex(pvid)))
					
		# Check for ARP (OK)
		elif eth_proto == 1544:		
			(htype, ptype, hlen, plen, oper, sha, spa, tha, tpa) = arp_segment(data)
			# (src_port, dest_port, length, data) = udp_segment(data)
			print(TAB_1 + '[+] ARP Who has .....{} ? -> Tell {}'.format(tpa, spa))
			if not show_segment:
				continue
			print(TAB_2 + 'Hardware Type: {}'.format(htype))
			print(TAB_2 + 'Protocol Type: {}'.format(ptype))
			print(TAB_2 + 'Hardware Length: {}'.format(hlen))
			print(TAB_2 + 'Protocol Length: {}'.format(plen))
			print(TAB_2 + 'Operation: {}'.format(oper))
			print(TAB_2 + 'Sender Hardware Address: {}'.format(sha))
			print(TAB_2 + 'Sender Protocol Address: {}'.format(spa))
			print(TAB_2 + 'Target Hardware Address: {}'.format(tha))
			print(TAB_2 + 'Target Protocol Address: {}'.format(tpa))
#			print(TAB_2 + 'Data:')
#			print(format_multi_line(DATA_TAB_3, data))
		
		# Check for IPv4  -> 8 - (OK)
		elif eth_proto == 8:
			(version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
			print(TAB_1 + '[+] IPv4 Packet: ...............{} -> {}'.format(src, target))
			if not show_segment:
				continue
			print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
			# print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
			# Process the full IPv3 packet
			ipv4(version, header_length, ttl, proto, src, target, data, show_data)

		else:
			print('[+] Unknown Ethernet Frame Type:'.format(eth_proto))
			print(TAB_2 + 'Data:')
			print(format_multi_line(DATA_TAB_3, data))

# Unpack ethernet frame (OK)
def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]
	
# Returns properly formatted MAC address (OK)
def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytes_str).upper()

# Process the full IPv4 packet	
def ipv4(version, header_length, ttl, proto, src, target, data, show_data):
	
	# ICMP (OK)	
	if proto == 1: 
		icmp_type, code, checksum, data = icmp_packet(data)
		print(TAB_1 + '[+] ICMP Packet:')
		print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
		if show_data:
			print(TAB_2 + 'Data:')
			print(format_multi_line(DATA_TAB_3, data))
			
	# TCP (OK)
	elif proto == 6:
		(src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
		print(TAB_1 + '[+] TCP Segment: .......................{} -> {}'.format(src_port, dest_port))
		print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
		print(TAB_2 + 'Flags:')
		print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
		if show_data:
			print(TAB_2 + 'Data:')
			print(format_multi_line(DATA_TAB_3, data))
			
	# UDP (OK)
	elif proto == 17:
		(src_port, dest_port, length, chksum, data) = udp_segment(data)
		print(TAB_1 + '[+] UDP Segment:')
		print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
		print(TAB_2 + 'Length: {}, Checksum: {}'.format(length, chksum))
		if show_data:
			print(TAB_2 + 'Data:')
			print(format_multi_line(DATA_TAB_3, data))
				
	# Other IP packet
	else:
		print(TAB_1 + 'Unknown IPv4 Packet:')
		print(format_multi_line(DATA_TAB_2, data))
		
	return(True)

# Unpack the IPv4 packet details (OK)
def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 15) * 4
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	# return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]
	return version, header_length, ttl, proto, ipaddress.IPv4Address(src), ipaddress.IPv4Address(target), data[header_length:]
	
# Unpack the IPv6 packet details (OK)
def ipv6_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	(length, nexthdr, hoplim, src, dst) = struct.unpack('! 4x H B B 16s 16s', data[:40])
	return version, length, nexthdr, hoplim, src, dst, data[40:]

# Unpack ICMP packet details (OK)
def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]
	
# Unpack TCP segment details (OK) -> type 6
def tcp_segment(data):
	(src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1
	return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
	
# Unpack UDP segment details (OK)
def udp_segment(data):
	src_port, dest_port, length, chksum = struct.unpack('! H H H H', data[:8])
	#return src_port, dest_port, size, chksum, data[8:]
	return src_port, dest_port, length, chksum, data[8:]
	
# Unpack ARP segment details
def arp_segment(data):
	htype, ptype, hlen, plen, oper, sha, spa, tha, tpa = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])
	return htype, ptype, hlen, plen, oper, get_mac_addr(sha), ipaddress.IPv4Address(spa), get_mac_addr(tha), ipaddress.IPv4Address(tpa)

# Unpack IAP segment details
def iap_segment(data):
	magic, ver, iaptype, length, iapid, status, uptime, vcip, unknown, pvid = struct.unpack('! H B B B B B L 4s B H ', data[:18])
	return magic, ver, iaptype, length, iapid, status, uptime, ipaddress.IPv4Address(vcip), unknown, pvid

def big2little(n):
	bytes_val = n.to_bytes(2, 'little')
	int_val = int.from_bytes(bytes_val, 'big')
	# return (bytes_val.hex())
	hex_val = hex(int_val)
	return hex_val

# Formats multi-line data (OK)	
def format_multi_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ' '.join(r'{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Handle CTRL-C to exit gracefully
def handler(signal_recieved, frame):
	# Handle any cleanup here
	print(" SIGINT or CTRL-C detected. Exiting gracefully")
	exit(0)
	
# Print the logo
def logo():	
	# text from: https://fsymbols.com/generators/carty/
	print('░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░')
	print('█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗░░')
	print('╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝░░')
	print('░░░░░░░░░░░░                                                        ░░░░░░░░░░░░')
	print('░░░░░░░░░░░░  ░██████╗███╗░░██╗██╗███████╗███████╗███████╗██████╗░  ░░░░░░░░░░░░')
	print('░░░░░░░░░░░░  ██╔════╝████╗░██║██║██╔════╝██╔════╝██╔════╝██╔══██╗  ░░░░░░░░░░░░')
	print('█████╗█████╗  ╚█████╗░██╔██╗██║██║█████╗░░█████╗░░█████╗░░██████╔╝  █████╗█████╗')
	print('╚════╝╚════╝  ░╚═══██╗██║╚████║██║██╔══╝░░██╔══╝░░██╔══╝░░██╔══██╗  ╚════╝╚════╝')
	print('░░░░░░░░░░░░  ██████╔╝██║░╚███║██║██║░░░░░██║░░░░░███████╗██║░░██║  ░░░░░░░░░░░░')
	print('░░░░░░░░░░░░  ╚═════╝░╚═╝░░╚══╝╚═╝╚═╝░░░░░╚═╝░░░░░╚══════╝╚═╝░░╚═╝  ░░░░░░░░░░░░')
	print('░░░░░░░░░░░░                                                        ░░░░░░░░░░░░')
	print('█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗░░')
	print('╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝░░')
	print('░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░')
	print(' by J.Kirn 4.17.24')
	print()

# Process command line arguments
def main(argv):
	# Default values
	show_data = True
	show_segment = True
	show_logo = True

	try:
		opts, args = getopt.getopt(sys.argv[1:], "lhds",["help"])	
	except getopt.GetoptError as err:
		print(err)
		print('sniffer.py -h -d -l -s')
		sys.exit(2)

	for opt, arg in opts:
		if opt == '-l':
			show_logo = False
			
		elif opt == '-h':
			print('sniffer.py -h -d -s')
			print('\t -h shows this help messages')
			print('\t -l disables showing the sniffer logo')
			print('\t -d disables showing extended data')
			print('\t -s disables showing ethernet details')
			sys.exit()

		elif opt == '-d':		
			show_data = False

		elif opt == '-s':	
			show_segment = False
	
	if show_logo:
		logo()
	if show_data:
		print('show_data now enabled')
	if show_segment:
		print('show_segment data now enabled')
	# Start Processing frames/packets
	collect(show_data, show_segment)

# Start of Program	
if __name__ == '__main__':
	# Tell Python to run the handler() function when SIGINT is recieved
	signal(SIGINT, handler)
	main(sys.argv[1:])
		
