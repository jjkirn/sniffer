import socket
import struct
import textwrap
import ipaddress
import sys, getopt
from signal import signal, SIGINT
from sys import exit
import netifaces

# Run this program as sudo !!!
# Packet Sniffer based on python3 sockets - JKirn - 4/17/24
#
# loosely based on:
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
def collect(show_data, show_segment, show_arp, show_interfaces):
	print('Collect: [show_data: {}, show_segment: {}], show_arp: {}'.format(show_data, show_segment, show_arp))
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

	print('show_interfaces: {}'.format(show_interfaces))

	# Try to bind to a specific interface, defaulted off as it is not compatible with redirection (>)
	if show_interfaces:
		# Prompt for interface
		interface_selected = select_interface()
		# Enable the selected interface
		try:
			conn.setsockopt(socket.SOL_SOCKET, 25, str(interface_selected+'\0').encode('utf-8'))

		except socket.error as err:
			print('Exception', err)
			sys.exit()		

	# Start main loop
	frame_cnt = 0  # initialize frame count
	while True:
		frame_cnt += 1
		raw_data, addr = conn.recvfrom(65536)
		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
		print('\n[+] Ethernet II #{}: Src: {} -> Dst: {}'.format(frame_cnt, src_mac, dest_mac))
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
				continue  # exit loop

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
			if not show_arp:  # Exit of you dont want arp detais
				continue   # exit loop

#			if not show_segment:
#				continue  #exit loop
				
			print(TAB_2 + 'Hardware Type: 0x{:04x} - ({})'.format(htype, htype))
			print(TAB_2 + 'Protocol Type: 0x{:04x} - ({})'.format(ptype, ptype))
			print(TAB_2 + 'Hardware Length: {}'.format(hlen))
			print(TAB_2 + 'Protocol Length: {}'.format(plen))
			if oper == 1:
				print(TAB_2 + 'Operation - Request: 0x{:04x} - ({})'.format(oper, oper))
			else:
				print(TAB_2 + 'Operation - Reply: 0x{:04x} - ({})'.format(oper, oper))
			print(TAB_2 + 'Sender Hardware Address: {}'.format(sha))
			print(TAB_2 + 'Sender Protocol Address: {}'.format(spa))
			print(TAB_2 + 'Target Hardware Address: {}'.format(tha))
			print(TAB_2 + 'Target Protocol Address: {}'.format(tpa))
#			if show_data:
#				print(TAB_2 + 'Data:')
#				print(format_multi_line(DATA_TAB_3, data))

		
		# Check for IPv4  -> 8 - (OK)
		elif eth_proto == 8:
#			(version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
			(version, header_length, tos, length, packet_id, ttl, proto, chksum, src, dst, data) = ipv4_packet(data)

			print(TAB_1 + '[+] IPv4 Packet: ...............{} -> {}'.format(src, dst))
			if not show_segment:
				continue

			print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(hex(proto), src, dst))
#			print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
			
			# Process the full IPv4 packet
			ipv4(version, header_length, tos, length, packet_id, ttl, proto, chksum, src, dst, data, show_data)

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
def ipv4(version, header_length, tos, length, packet_id, ttl, proto, chksum, src, dst, data, show_data):

	print(TAB_2 + 'Version: {}, Header Length: {}, Type of Service: {}, Total Length: {}'.format(version, header_length, tos, length))
	print(TAB_2 + 'Packet ID: {}'.format(packet_id))
	print(TAB_2 + 'TTL: {}, IP Protocol: {}, Header Checksum: {}'.format(ttl, hex(proto), chksum))
	print(TAB_2 + 'Source IP: {}, Destination IP: {}'.format(src, dst))
#	print('*** proto: {} - ({})'.format(hex(proto), proto))

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
#		(src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
		(src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size, checksum, urgent_ptr, data) = tcp_segment(data)
		print(TAB_1 + '[+] TCP Segment: .......................{} -> {}'.format(src_port, dest_port))
		print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
		print(TAB_2 + 'Flags:')
		print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
		print(TAB_3 + 'Window Size: {}'.format(window_size))
		print(TAB_3 + 'Checksum: {}'.format(hex(checksum)))
		print(TAB_3 + 'Urgent Pointer: {}'.format(urgent_ptr))
		if show_data:
			print(TAB_2 + 'Data:')
			print(format_multi_line(DATA_TAB_3, data))
			
	# UDP (OK)
	elif proto == 17:
		(src_port, dest_port, length, chksum, data) = udp_segment(data)
		print(TAB_1 + '[+] UDP Segment:')
		print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
		print(TAB_2 + 'Length: {}, Checksum: {}'.format(length, chksum))
		
		# Test for BJNP - 0x4D2D5345 (1294816069) - (Canon) BubbleJet Network Protocol -> for printers
#		print('### data: {}'.format(data))		# For debug
		bjnp, bjnp_code, bjnp_id, payload, length, seq_num, sess_id, bjnp_type = struct.unpack('! 4s B B B L L H B', data[:18])
#		print('### BJNP: {}'.format(bjnp))		# For debug
		mybjnp = bytes('BJNP', 'utf-8')
#		print('### myBJNP: {}'.format(mybjnp))	# For debug
		if bjnp == mybjnp:
			bjnp_process(bjnp, bjnp_code, bjnp_id, payload, length, seq_num, sess_id, bjnp_type)

		elif show_data:
			print(TAB_2 + 'Data:')
			print(format_multi_line(DATA_TAB_3, data))
				
	# Other IP packet
	else:
		print(TAB_1 + 'Unknown IPv4 Packet:')
		print(format_multi_line(DATA_TAB_2, data))
		
	return(True)

# Process the full BJNP data	
def bjnp_process(bjnp, bjnp_code, bjnp_id, payload, length, seq_num, sess_id, bjnp_type):
	print(TAB_2 + '[+] BJNP - Cannon Printer Protocol: {}'.format(bjnp))
	print(TAB_3 + 'ID : {}'.format(bjnp_id))
	print(TAB_3 + 'Type: {}'.format(bjnp_type))
	print(TAB_3 + 'Code: {}'.format(bjnp_code))

#	print(TAB_3 + 'Payload: {}'.format(payload))
#	print(TAB_3 + 'Sequence Number: {}'.format(seq_num))
#	print(TAB_3 + 'Session ID: {}'.format(sess_id))

	return(True)

# Unpack the IPv4 packet details (OK)
def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 15) * 4
	
	tos, length, packet_id, ttl, proto, chksum, src, dst = struct.unpack('! 1x B H H 2x B B H 4s 4s', data[:20])
	return version, header_length, tos, length, packet_id, ttl, proto, chksum, ipaddress.IPv4Address(src), ipaddress.IPv4Address(dst), data[header_length:]
	
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
	(src_port, dest_port, sequence, acknowledgement, offset_reserved_flags, window_size, checksum, urgent_ptr) = struct.unpack('! H H L L H H H H', data[:20])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1
	return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size, checksum, urgent_ptr, data[offset:]
	
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

# Formats multi-line ascii (OK)	
def format_multi_ascii(prefix, bytes, size=80):
	string = str(bytes, 'ascii')
	for i in range(0, len(string), 80):
		print('{}'.format(string[i:i+80]))
		
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

def select_interface():
	# Getting interfaces 
	interfaces = netifaces.interfaces() 

	interface_list = []
	my_dict = {}

	cnt = 1	
	# Showing interfaces 
	for interface in interfaces: 
		my_dict[cnt] = interface
		cnt += 1

	i = 1	
	for key in my_dict:
		print('[{}] - {}'.format( i, my_dict.get(i)))
		i += 1
 
	print("Enter the number that corresponds to the interface you want to select:")
	# get input from user and check for bad input
	try:
		num1 = int(input())
	except:
		print('You did not enter a valid integer selection')
		exit()

	print('You selected: {}'.format(num1))
	if num1 in my_dict.keys():
		print('Valid key {} - value {}'.format(num1, my_dict.get(num1)))
	else:
		print('InValid key {}'.format(num1))
		exit()
	return my_dict.get(num1)

# Process command line arguments
def main(argv):
	# Default values
	show_data = True
	show_segment = True
	show_logo = True
	show_arp = False
	show_interfaces = False

	try:
		opts, args = getopt.getopt(sys.argv[1:], "adhils",["help"])	
	except getopt.GetoptError as err:
		print(err)
		print('sniffer.py -a -d -h -i -l -s')
		sys.exit(2)

	for opt, arg in opts:
		if opt == '-a':
			show_arp = True

		if opt == '-d':		
			show_data = False

		if opt == '-i':
			show_interfaces = True
			
		if opt == '-l':
			show_logo = False

		if opt == '-s':	
			show_segment = False
			
		elif opt == '-h':
			print('sniffer.py -a -h -l -d -s')
			print('\t -a enable arp details')
			print('\t -d disables showing extended data')
			print('\t -h shows this help messages')
			print('\t -i enables interface selection')
			print('\t -l disables showing the sniffer logo')
			print('\t -s disables showing ethernet details')
			sys.exit()
	if show_logo:
		logo()
#	if show_data:
#		print('show_data now enabled')
#	if show_segment:
#		print('show_segment data now enabled')
#	if not show_arp:
#		print('show_arp data not enabled')
#	if show_interfaces:
#		print('show_interfaces now enabled')
		
	# Start Processing frames/packets
	collect(show_data, show_segment, show_arp, show_interfaces)

# Start of Program	
if __name__ == '__main__':
	# Tell Python to run the handler() function when SIGINT is received
	signal(SIGINT, handler)
	main(sys.argv[1:])
		
