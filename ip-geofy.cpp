#pragma comment(lib, "Ws2_32.lib") // For MSVC, links Winsock library

#define _CRT_SECURE_NO_WARNINGS
#include <pcap.h>
#include <winsock2.h> // For Windows socket functions, INET6_ADDRSTRLEN, sockaddr_in etc.
#include <ws2tcpip.h> // For inet_ntop, IPPROTO_TCP, etc.

#include <chrono> // For time (though not directly used for formatting here, good for C++ time ops)
#include <ctime>  // For localtime_s, strftime (std::put_time alternative)
#include <iomanip> // For std::setw, std::setfill, std::put_time
#include <iostream>
#include <limits>  // For std::numeric_limits
#include <sstream> // For std::ostringstream
#include <string>
#include <vector>


// Custom header files (ensure these are C++ compatible or wrapped in extern "C"
// if they are C headers)
#include "ether_type.h"
#include "geoip_resolver.h"
#include "info_struct.h"
#include "protocol_headers.h"

// --- Constants ---
constexpr int DEFAULT_SNAPLEN = 65535;
constexpr int DEFAULT_READ_TIMEOUT = 1000; // milliseconds
const std::string DEFAULT_FILTER = "tcp or udp";
constexpr int MAX_TIMESTR_LEN =
32; // Increased buffer for timestamp string with usec
GeoIPResolver geo_resolver("GeoLite2-Country.mmdb");
GeoIPResolver geo_city_resolver("GeoLite2-City.mmdb");
// --- Function Prototypes ---
void packet_handler(unsigned char* param, const struct pcap_pkthdr* header,
	const unsigned char* pkt_data);
void log_error(const std::string& prefix, const std::string& message);
pcap_if_t* list_and_select_device(pcap_if_t*& alldevs_output_ref,
	int& device_count);
pcap_t* open_selected_device(pcap_if_t* selected_dev, char* errbuf);
int setup_packet_filter(pcap_t* handle, pcap_if_t* dev,
	const std::string& filter_expr, char* errbuf);

// Layer parsing functions (return true on success, false on failure)
bool parse_ethernet(const unsigned char* pkt_data,
	const struct pcap_pkthdr* header, uint16_t& ether_type,
	unsigned int& l3_offset);
bool parse_ipv4(const unsigned char* pkt_data, unsigned int offset,
	const struct pcap_pkthdr* header, PacketInfo& info);
bool parse_ipv6(const unsigned char* pkt_data, unsigned int offset,
	const struct pcap_pkthdr* header, PacketInfo& info);
bool parse_tcp(const unsigned char* transport_data,
	unsigned int transport_len_available, PacketInfo& info);
bool parse_udp(const unsigned char* transport_data,
	unsigned int transport_len_available, PacketInfo& info);
void print_packet_info(const std::string& timestamp_str, int len,
	const PacketInfo& info);
void parse_location_ipv4(char ip_str_buffer[INET6_ADDRSTRLEN],
	LocationInfo& loc_info);
void parse_location_ipv6(char ip_str_buffer[INET6_ADDRSTRLEN],
	LocationInfo& loc_info);
// process funtion
int main_logic(pcap_t*& adhandle, pcap_if_t*& alldevs_list);
// --- Main Application Logic ---
int main() {
	SetConsoleOutputCP(CP_UTF8);
	pcap_if_t* alldevs_list = nullptr; // Will hold the list of all devices
	pcap_t* adhandle = nullptr;
	int exit_code = 0;

	// test lookup v4
	// sockaddr_in ipv4_addr;
	// std::memset(&ipv4_addr, 0, sizeof(ipv4_addr)); // 清空结构体
	// ipv4_addr.sin_family = AF_INET;              // IPv4
	// inet_pton(AF_INET, "223.5.5.5", &(ipv4_addr.sin_addr)); // 设置 IP 地址
	// auto ret =
	// geo_city_resolver.lookup(reinterpret_cast<sockaddr*>(&ipv4_addr));

	// test lookup v6
	// sockaddr_in6 ipv6_addr;
	// std::memset(&ipv6_addr, 0, sizeof(ipv6_addr)); // 清空结构体
	// ipv6_addr.sin6_family = AF_INET6;             // IPv6
	// const char* ipv6_str = "2001:da8::1";
	// inet_pton(AF_INET6, ipv6_str, &(ipv6_addr.sin6_addr));
	// auto ret_v6 =
	// geo_city_resolver.lookup(reinterpret_cast<sockaddr*>(&ipv6_addr));

	main_logic(adhandle, alldevs_list);

	// Cleanup
	std::cout << "Releasing resources..." << std::endl;
	if (adhandle) {
		pcap_close(adhandle);
		adhandle = nullptr; // Prevent reuse
		std::cout << "Capture handle closed." << std::endl;
	}
	if (alldevs_list) { // If not freed before loop or if loop was skipped due to
		// an earlier error
		pcap_freealldevs(alldevs_list);
		alldevs_list = nullptr;
		std::cout << "Device list freed." << std::endl;
	}

	std::cout << "Exiting (code " << exit_code << ")." << std::endl;
	// std::cout << "Press Enter to continue...";
	// std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	// std::cin.get(); // Keep console open in some environments

	return exit_code;
}

int main_logic(pcap_t*& adhandle, pcap_if_t*& alldevs_list) {
	int device_count = 0;
	pcap_if_t* selected_dev = list_and_select_device(alldevs_list, device_count);
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 }; // Initialize error buffer

	if (!selected_dev) {
		// Error message already printed by list_and_select_device
		// alldevs_list should have been freed by list_and_select_device on error,
		// or it's nullptr if pcap_findalldevs_ex failed initially.
		return 1;
	}
	std::cout << "\nOpening device: "
		<< (selected_dev->description ? selected_dev->description
			: selected_dev->name)
		<< "..." << std::endl;

	adhandle = open_selected_device(selected_dev, errbuf);
	if (!adhandle) {
		// Error message printed by open_selected_device
		return 1;
	}
	if (setup_packet_filter(adhandle, selected_dev, DEFAULT_FILTER, errbuf) !=
		0) {
		// Error message printed by setup_packet_filter
		return 1;
	}
	std::cout << "\nFilter rule '" << DEFAULT_FILTER
		<< "' set successfully. Listening on "
		<< (selected_dev->description ? selected_dev->description
			: selected_dev->name)
		<< "..." << std::endl;

	// Device list is no longer needed after setup.
	if (alldevs_list) {
		pcap_freealldevs(alldevs_list);
		alldevs_list = nullptr; // Avoid double free in cleanup section
	}

	std::cout << "Starting capture loop (press Ctrl+C to stop)..." << std::endl;
	// pcap_loop blocks. 0 means capture indefinitely (or until
	// error/pcap_breakloop).
	pcap_loop(adhandle, 0, packet_handler, nullptr);

	// This line is reached when pcap_loop returns (e.g., error, or pcap_breakloop
	// call if implemented)
	std::cout << "\nCapture loop finished." << std::endl;

	return 0;
}

// --- Function Implementations ---

void log_error(const std::string& prefix, const std::string& message) {
	if (!prefix.empty()) {
		std::cerr << "ERROR [" << prefix << "]: " << message << std::endl;
	}
	else {
		std::cerr << "ERROR: " << message << std::endl;
	}
}

pcap_if_t* list_and_select_device(pcap_if_t*& alldevs_output_ref,
	int& device_count) {
	pcap_if_t* d = nullptr;
	int i = 0;
	int inum = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	// pcap_findalldevs_ex populates alldevs_output_ref (which is a reference to
	// main's alldevs_list)
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs_output_ref,
		errbuf) == -1) {
		log_error("pcap_findalldevs_ex", errbuf);
		alldevs_output_ref = nullptr; // Ensure caller's pointer is null
		return nullptr;
	}

	std::cout << "Available network interfaces:" << std::endl;
	for (d = alldevs_output_ref; d; d = d->next) {
		std::cout << std::setw(2) << ++i << ". " << d->name;
		if (d->description) {
			std::cout << " (" << d->description << ")" << std::endl;
		}
		else {
			std::cout << " (No description available)" << std::endl;
		}
	}
	device_count = i;

	if (i == 0) {
		log_error("", "No network interfaces found. Ensure Npcap (or WinPcap) is "
			"installed and drivers are working.");
		if (alldevs_output_ref) {
			pcap_freealldevs(alldevs_output_ref);
			alldevs_output_ref = nullptr;
		}
		return nullptr;
	}

	std::cout << "Enter the interface number (1-" << i << "): ";
	if (!(std::cin >> inum)) {
		log_error("", "Invalid input. Please enter a number.");
		std::cin.clear();  // Clear error flags
		std::cin.ignore(); // Discard invalid input
		if (alldevs_output_ref) {
			pcap_freealldevs(alldevs_output_ref);
			alldevs_output_ref = nullptr;
		}
		return nullptr;
	}
	// Consume the rest of the line, checking for extraneous characters
	std::string remaining_input;
	std::getline(std::cin, remaining_input); // Consume newline after number
	if (!remaining_input.empty() &&
		remaining_input.find_first_not_of(" \t\n\v\f\r") != std::string::npos) {
		log_error("", "Invalid trailing characters in input after the number.");
		if (alldevs_output_ref) {
			pcap_freealldevs(alldevs_output_ref);
			alldevs_output_ref = nullptr;
		}
		return nullptr;
	}

	if (inum < 1 || inum > i) {
		log_error("", "Interface number out of range.");
		if (alldevs_output_ref) {
			pcap_freealldevs(alldevs_output_ref);
			alldevs_output_ref = nullptr;
		}
		return nullptr;
	}

	// Traverse to the selected adapter
	for (d = alldevs_output_ref, i = 0; d != nullptr && i < inum - 1;
		d = d->next, i++)
		;

	// On success, d is the selected device. alldevs_output_ref is the full list.
	// The caller (main) is responsible for freeing alldevs_output_ref later.
	return d;
}

pcap_t* open_selected_device(pcap_if_t* selected_dev, char* errbuf) {
	pcap_t* handle = nullptr;

	if (!selected_dev) { // Should have been caught by caller, but good practice
		log_error("open_selected_device", "Invalid device pointer (null).");
		if (errbuf)
			snprintf(errbuf, PCAP_ERRBUF_SIZE, "Selected device was null.");
		return nullptr;
	}

	handle = pcap_open(selected_dev->name, DEFAULT_SNAPLEN,
		PCAP_OPENFLAG_PROMISCUOUS, DEFAULT_READ_TIMEOUT,
		nullptr, // No remote authentication
		errbuf); // pcap_open fills errbuf on error

	if (handle == nullptr) {
		// errbuf is already populated by pcap_open. Log it.
		log_error("pcap_open failed for '" +
			(selected_dev->name ? std::string(selected_dev->name)
				: "unknown device") +
			"'",
			errbuf);
		return nullptr;
	}

	// Check data link type - Ensure it's Ethernet
	if (pcap_datalink(handle) != DLT_EN10MB) {
		std::ostringstream error_stream;
		error_stream << "Device " << selected_dev->name
			<< " does not provide Ethernet headers (link type "
			<< pcap_datalink(handle)
			<< ") - not supported by this program.";
		log_error("pcap_datalink", error_stream.str());
		// Populate errbuf for consistency, though not strictly used by main from
		// this point
		strncpy(errbuf, error_stream.str().c_str(), PCAP_ERRBUF_SIZE - 1);
		errbuf[PCAP_ERRBUF_SIZE - 1] = '\0'; // Ensure null termination
		pcap_close(handle);
		return nullptr;
	}
	return handle;
}

int setup_packet_filter(pcap_t* handle, pcap_if_t* dev,
	const std::string& filter_expr, char* errbuf) {
	struct bpf_program fcode;
	bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN; // Default if no address found

	if (dev && dev->addresses != nullptr) {
		for (struct pcap_addr* addr = dev->addresses; addr != nullptr;
			addr = addr->next) {
			if (addr->addr && addr->addr->sa_family == AF_INET && addr->netmask) {
				// Ensure sockaddr_in structure for IPv4
				netmask = reinterpret_cast<struct sockaddr_in*>(addr->netmask)
					->sin_addr.S_un.S_addr;
				break;
			}
		}
	}
	// If no suitable IPv4 address/netmask found, netmask remains
	// PCAP_NETMASK_UNKNOWN, which is acceptable for pcap_compile.

	if (pcap_compile(handle, &fcode, filter_expr.c_str(), 1, netmask) < 0) {
		// pcap_compile fills errbuf of the handle, retrieve with pcap_geterr
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Error compiling filter '%s': %s",
			filter_expr.c_str(), pcap_geterr(handle));
		log_error("pcap_compile", errbuf);
		return -1;
	}

	if (pcap_setfilter(handle, &fcode) < 0) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Error setting filter: %s",
			pcap_geterr(handle));
		log_error("pcap_setfilter", errbuf);
		pcap_freecode(&fcode); // Free compiled code if setfilter fails
		return -1;
	}

	pcap_freecode(&fcode); // Filter is set, free the compiled code
	return 0;
}

void packet_handler(unsigned char* param, const struct pcap_pkthdr* header,
	const unsigned char* pkt_data) {
	(void)param;
	struct tm ltime = { 0 }; // Initialize
	time_t local_tv_sec;
	std::string timestamp_str;

	unsigned int l3_offset = 0;
	uint16_t ether_type = 0;
	PacketInfo info; // Parsed packet information

	local_tv_sec = header->ts.tv_sec;

	// Convert timestamp to readable format
	// Use localtime_s on Windows for safety, or localtime (with caveats) on POSIX
	if (localtime_s(&ltime, &local_tv_sec) != 0) {
		// Handle error, e.g., use a default string or log
		timestamp_str = "[time_error]";
	}

	if (timestamp_str.empty()) { // If no time error
		std::ostringstream oss_ts;
		oss_ts << std::put_time(&ltime, "%H:%M:%S"); // HH:MM:SS
		oss_ts << "." << std::setfill('0') << std::setw(6)
			<< header->ts.tv_usec; // .microseconds
		timestamp_str = oss_ts.str();
	}

	std::cout << timestamp_str
		<< " "; // Print timestamp prefix for all messages for this packet.

	// 1. Parse Ethernet Header
	if (!parse_ethernet(pkt_data, header, ether_type, l3_offset)) {
		std::cout << "[Invalid Ethernet Frame or too short]" << std::endl;
		return;
	}

	// 2. Parse Layer 3 Protocol (and subsequently Layer 4)
	// info.valid will be set by parse_ipv4/parse_ipv6 if successful
	bool l3_processed = false;
	switch (ether_type) {
	case ETHERTYPE_IP: // IPv4
		if (!parse_ipv4(pkt_data, l3_offset, header, info)) {
			// Error messages are printed within parse_ipv4 for specific failures.
			// If info.transport_protocol is empty, it means very early failure.
			if (info.transport_protocol.empty()) {
				std::cout << "[IPv4 Header invalid or too short for basic processing]"
					<< std::endl;
			} // else, L4 parsing might have failed, message already printed.
		}
		l3_processed = true;
		break;

	case ETHERTYPE_IPV6: // IPv6
		if (!parse_ipv6(pkt_data, l3_offset, header, info)) {
			if (info.transport_protocol.empty()) {
				std::cout << "[IPv6 Header invalid or too short for basic processing]"
					<< std::endl;
			}
		}
		l3_processed = true;
		break;

		// case ETHERTYPE_ARP:
		//     std::cout << "[ARP] len:" << header->len << std::endl;
		//     l3_processed = true;
		//     // No call to print_packet_info for ARP in this structure
		//     break;

	default:
		std::cout << "[Other L3: 0x" << std::hex << std::setw(4)
			<< std::setfill('0') << ether_type << std::dec
			<< "] len:" << header->len
			<< std::endl; // Reset to decimal for length
		l3_processed = true;
		// No call to print_packet_info for unknown L3
		break;
	}

	if (info.valid) { // info.valid is true if parse_ipvX and its L4 handling
		// succeeded
		print_packet_info(timestamp_str, header->len, info);
	}
	else if (l3_processed &&
		(ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6)) {
		// This means an IP packet was encountered, but parsing failed to set
		// info.valid. Ensure a newline if specific error messages didn't provide
		// one or if no specific message was relevant. Most messages from parsers
		// should already include std::endl. If all failure paths inside parsers
		// print a complete message (including newline), this might not be needed.
		// For instance, if parse_ipv4 returns false and printed its error, this
		// path is for "no valid info to print".
	}
}

bool parse_ethernet(const unsigned char* pkt_data,
	const struct pcap_pkthdr* header, uint16_t& ether_type,
	unsigned int& l3_offset) {
	if (header->caplen < sizeof(ethernet_header)) {
		return false; // Packet too short for basic Ethernet header
	}

	const auto* eth_hdr = reinterpret_cast<const ethernet_header*>(pkt_data);
	ether_type = ntohs(eth_hdr->ether_type);
	unsigned int current_offset = sizeof(ethernet_header); // Typically 14 bytes

	// Handle 802.1Q VLAN tag if present
	if (ether_type == ETHERTYPE_VLAN) {
		if (header->caplen <
			current_offset + 4) { // Need 4 more bytes for VLAN tag + real EtherType
			std::cout << "[VLAN tag truncated] ";
			return false;
		}
		// The real EtherType is after the 4-byte VLAN tag (TPID + TCI)
		ether_type = ntohs(
			*(reinterpret_cast<const uint16_t*>(pkt_data + current_offset + 2)));
		current_offset += 4; // Add VLAN tag size
		// std::cout << "[VLAN] "; // Optionally indicate VLAN presence
	}
	// QinQ (double VLAN tagging) could be handled with another similar check
	// here.

	l3_offset = current_offset;
	return true;
}

bool parse_ipv4(const unsigned char* pkt_data, unsigned int offset,
	const struct pcap_pkthdr* header, PacketInfo& info) {
	const ip_header* ih;
	unsigned int ip_hdr_len;
	unsigned char ip_version;

	// Check if captured length is sufficient for MINIMUM IP header (20 bytes)
	if (header->caplen < offset + 20) { // Use 20 as minimum sizeof(ip_header)
		return false; // Not enough data for even a minimal IP header
	}

	ih = reinterpret_cast<const ip_header*>(pkt_data + offset);

	ip_version = (ih->ver_ihl >> 4);
	if (ip_version != 4) {
		std::cout << "[Not IPv4 (Version: " << static_cast<unsigned int>(ip_version)
			<< ")] ";
		return false;
	}

	ip_hdr_len = (ih->ver_ihl & 0x0F) * 4;
	if (ip_hdr_len < 20) { // Minimum valid IPv4 header length
		std::cout << "[Invalid IPv4 header length: " << ip_hdr_len << "] ";
		return false;
	}

	// Temporary buffer for inet_ntop
	char ip_str_buffer[INET6_ADDRSTRLEN];

	// Check if the full IP header was captured
	if (header->caplen < offset + ip_hdr_len) {
		std::cout << "[IPv4 Header truncated (expected " << ip_hdr_len << ", got "
			<< (header->caplen - offset) << ")] ";
		// Attempt to extract partial info if possible
		if (inet_ntop(AF_INET, &(ih->saddr), ip_str_buffer, INET6_ADDRSTRLEN) !=
			nullptr) {
			info.src_ip = ip_str_buffer;
			parse_location_ipv4(ip_str_buffer, info.src_loc);
		}
		else
			info.src_ip = "[invalid_src]";
		if (inet_ntop(AF_INET, &(ih->daddr), ip_str_buffer, INET6_ADDRSTRLEN) !=
			nullptr) {
			info.dst_ip = ip_str_buffer;
			parse_location_ipv4(ip_str_buffer, info.dst_loc);
		}
		else
			info.dst_ip = "[invalid_dst]";
		info.transport_protocol = "v4_Truncated";
		// info.valid remains false because transport layer cannot be reliably
		// parsed
		return false;
	}

	// Successfully parsed IP header basics
	if (inet_ntop(AF_INET, &(ih->saddr), ip_str_buffer, INET6_ADDRSTRLEN) !=
		nullptr) {
		info.src_ip = ip_str_buffer;
		parse_location_ipv4(ip_str_buffer, info.src_loc);
	}
	else
		info.src_ip = "[invalid_src]";
	if (inet_ntop(AF_INET, &(ih->daddr), ip_str_buffer, INET6_ADDRSTRLEN) !=
		nullptr) {
		info.dst_ip = ip_str_buffer;
		parse_location_ipv4(ip_str_buffer, info.dst_loc);
	}
	else
		info.dst_ip = "[invalid_dst]";

	const unsigned char* transport_data = pkt_data + offset + ip_hdr_len;
	unsigned int transport_len_available = header->caplen - (offset + ip_hdr_len);
	bool transport_parsed_successfully = false;

	switch (ih->proto) {
	case IPPROTO_TCP:
		info.transport_protocol = "v4_TCP";
		if (parse_tcp(transport_data, transport_len_available, info)) {
			transport_parsed_successfully = true;
		}
		break;
	case IPPROTO_UDP:
		info.transport_protocol = "v4_UDP";
		if (parse_udp(transport_data, transport_len_available, info)) {
			transport_parsed_successfully = true;
		}
		break;
	default:
		info.transport_protocol = "v4_Other_" + std::to_string(ih->proto);
		info.sport = 0;
		info.dport = 0;
		transport_parsed_successfully =
			true; // IP part is okay, transport is "Other"
		break;
	}

	if (transport_parsed_successfully) {
		info.valid = true; // Ready for printing
		return true;       // Overall success for IPv4 layer processing
	}
	// If transport parsing failed (e.g., TCP/UDP header too short), info.valid
	// remains false.
	return false;
}

void parse_location_ipv4(char ip_str_buffer[INET6_ADDRSTRLEN],
	LocationInfo& loc_info) {
	//std::cerr << std::endl << "[DEBUG]" << "parse_location_ipv4 get ip " << ip_str_buffer << std::endl;
	sockaddr_in ipv4_addr;
	std::memset(&ipv4_addr, 0, sizeof(ipv4_addr));            // 清空结构体
	ipv4_addr.sin_family = AF_INET;                           // IPv4
	inet_pton(AF_INET, ip_str_buffer, &(ipv4_addr.sin_addr)); // 设置 IP 地址
	std::tie(loc_info.country, loc_info.province, loc_info.city)
		= geo_city_resolver.lookup(reinterpret_cast<sockaddr*>(&ipv4_addr));
}

bool parse_ipv6(const unsigned char* pkt_data, unsigned int offset,
	const struct pcap_pkthdr* header, PacketInfo& info) {
	const ipv6_header* ip6h;
	uint8_t ip_version;

	// Check if captured length is sufficient for the fixed IPv6 header (40 bytes)
	if (header->caplen < offset + sizeof(ipv6_header)) {
		return false;
	}

	ip6h = reinterpret_cast<const ipv6_header*>(pkt_data + offset);

	// Check IPv6 version (first 4 bits of vtc_flow)
	// vtc_flow is in network byte order.
	uint32_t vtc_flow_net =
		ip6h->ip6_ctlun.vtc_flow; // Keep as is, or ntohl then shift.
	ip_version = (ntohl(vtc_flow_net) >> 28) &
		0x0F; // Correctly get version from host byte order

	if (ip_version != 6) {
		std::cout << "[Not IPv6 (Version: " << static_cast<unsigned int>(ip_version)
			<< ")] ";
		return false;
	}

	char ip_str_buffer[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET6, &(ip6h->saddr), ip_str_buffer, INET6_ADDRSTRLEN) !=
		nullptr)
	{
		info.src_ip = ip_str_buffer;
		parse_location_ipv6(ip_str_buffer, info.src_loc);
	}
	else
		info.src_ip = "[invalid_src6]";
	if (inet_ntop(AF_INET6, &(ip6h->daddr), ip_str_buffer, INET6_ADDRSTRLEN) !=
		nullptr)
	{
		info.dst_ip = ip_str_buffer;
		parse_location_ipv6(ip_str_buffer, info.dst_loc);
	}
	else
		info.dst_ip = "[invalid_dst6]";

	// WARNING: This simplification ignores IPv6 Extension Headers.
	// A production parser would loop through extension headers.
	uint8_t next_hdr = ip6h->next_hdr;
	const unsigned char* transport_data = pkt_data + offset + sizeof(ipv6_header);
	unsigned int transport_len_available =
		header->caplen - (offset + sizeof(ipv6_header));
	bool transport_parsed_successfully = false;

	switch (next_hdr) {
	case IPPROTO_TCP:
		info.transport_protocol = "v6_TCP";
		if (parse_tcp(transport_data, transport_len_available, info)) {
			transport_parsed_successfully = true;
		}
		break;
	case IPPROTO_UDP:
		info.transport_protocol = "v6_UDP";
		if (parse_udp(transport_data, transport_len_available, info)) {
			transport_parsed_successfully = true;
		}
		break;
	default:
		// Could be an extension header type we don't parse, or an unhandled L4.
		info.transport_protocol = "v6_Other_" + std::to_string(next_hdr);
		info.sport = 0;
		info.dport = 0;
		transport_parsed_successfully = true;
		break;
	}

	if (transport_parsed_successfully) {
		info.valid = true;
		return true;
	}
	return false;
}

void parse_location_ipv6(char ip_str_buffer[INET6_ADDRSTRLEN],
	LocationInfo& loc_info) {
	//std::cerr << std::endl << "[DEBUG]" << "parse_location_ipv6 get ip " << ip_str_buffer << std::endl;
	sockaddr_in6 ipv6_addr;
	std::memset(&ipv6_addr, 0, sizeof(ipv6_addr));            // 清空结构体
	ipv6_addr.sin6_family = AF_INET6;                           // IPv6
	inet_pton(AF_INET6, ip_str_buffer, &(ipv6_addr.sin6_addr));
	std::tie(loc_info.country, loc_info.province, loc_info.city)
		= geo_city_resolver.lookup(reinterpret_cast<sockaddr*>(&ipv6_addr));
}

bool parse_tcp(const unsigned char* transport_data,
	unsigned int transport_len_available, PacketInfo& info) {
	// TCP header needs at least 20 bytes for full header, but ports are in the
	// first 4. For this basic parser, we only extract ports.
	if (transport_len_available < 4) { // Minimum for source and destination ports
		std::cout << "[TCP Header too short for ports (" << transport_len_available
			<< " bytes)] ";
		info.sport = 0;
		info.dport = 0;
		return false;
	}

	const auto* th = reinterpret_cast<const tcp_header*>(transport_data);
	info.sport = ntohs(th->sport);
	info.dport = ntohs(th->dport);
	return true;
}

bool parse_udp(const unsigned char* transport_data,
	unsigned int transport_len_available, PacketInfo& info) {
	// UDP header is fixed 8 bytes.
	if (transport_len_available < sizeof(udp_header)) {
		std::cout << "[UDP Header too short (" << transport_len_available
			<< " bytes)] ";
		info.sport = 0;
		info.dport = 0;
		return false;
	}

	const auto* uh = reinterpret_cast<const udp_header*>(transport_data);
	info.sport = ntohs(uh->sport);
	info.dport = ntohs(uh->dport);
	return true;
}

void print_packet_info(const std::string& timestamp_str, int len,
	const PacketInfo& info) {
	// Assumes timestamp_str already has a trailing space if printed by
	// packet_handler. Here we reconstruct the line starting from protocol.
	std::cout << "["
		<< (info.transport_protocol.empty() ? "UnknownProto"
			: info.transport_protocol)
		<< "][" << std::setw(4) << len << "] " << info.src_ip;

	if (info.sport != 0) { // Only print port if it's non-zero (parsed)
		std::cout << ":" << info.sport;
	}
	std::cout << " -> " << info.dst_ip;
	if (info.dport != 0) {
		std::cout << ":" << info.dport;
	}

	std::cout << " [" << info.src_loc.country << " " << info.src_loc.province
		<< " " << info.src_loc.city << " "

		<< " -> " << info.dst_loc.country << " " << info.dst_loc.province
		<< " " << info.dst_loc.city << " "
		<< "]";
	std::cout << std::endl;
	system("PAUSE");
}