#pragma comment(lib,"ws2_32.lib")
#include <pcap.h>
#include <time.h>
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
// 自定义头文件
#include "ether_type.h"
#include "protocol_headers.h"

#define DEFAULT_SNAPLEN 65535       // Max snapshot length
#define DEFAULT_READ_TIMEOUT 1000   // Read timeout in milliseconds
#define DEFAULT_FILTER "tcp or udp" // Default packet filter expression
#define MAX_TIMESTR_LEN 16          // Buffer size for timestamp string
typedef struct packet_info_t {
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
	u_short sport;
	u_short dport;
	const char* transport_protocol;
	int valid; // Flag to indicate if parsing was successful
} packet_info_t;

///* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
// --- Function Prototypes ---
void log_error(const char* prefix, const char* message);
pcap_if_t* list_and_select_device(int* device_count);
pcap_t* open_selected_device(pcap_if_t* selected_dev, char* errbuf);
int setup_packet_filter(pcap_t* handle, pcap_if_t* dev, const char* filter_expr, char* errbuf);;
//
//// Layer parsing functions
int parse_ethernet(const u_char* pkt_data, const struct pcap_pkthdr* header, u_short* ether_type, u_int* l3_offset);
int parse_ipv4(const u_char* pkt_data, u_int offset, const struct pcap_pkthdr* header, packet_info_t* info);
int parse_ipv6(const u_char* pkt_data, u_int offset, const struct pcap_pkthdr* header, packet_info_t* info);
int parse_tcp(const u_char* transport_data, u_int transport_len, packet_info_t* info);
int parse_udp(const u_char* transport_data, u_int transport_len, packet_info_t* info);
void print_packet_info(const char* timestamp, int len, const packet_info_t* info);

int main()
{
	pcap_if_t* alldevs = NULL; // 指向接口链表头的指针
	pcap_if_t* selected_dev = NULL;
	int inum;	// 用户选择的网络接口编号
	int i = 0;
	pcap_t* adhandle = NULL; // 打开的网络适配器（网卡）句柄
	char errbuf[PCAP_ERRBUF_SIZE]; // 存放错误信息的缓冲区
	u_int netmask; // 选中接口的子网掩码
	char packet_filter[] = "tcp or udp"; // 抓包过滤表达式
	struct bpf_program fcode; // 编译后的过滤规则结构体
	int device_count = 0;
	int exit_code = 0;


	selected_dev = list_and_select_device(&device_count);
	if (!selected_dev) {
		// Error message 在函数内部打印
		// alldevs 在函数内部释放
		exit_code = 1;
		goto cleanup; // Use goto for centralized cleanup
	}
	printf("\nOpening device: %s...\n", selected_dev->description ? selected_dev->description : selected_dev->name);

	// 2. Open the selected device, 检查是否是 Ethernet 设备，程序只支持 Ethernet 链路层协议
	adhandle = open_selected_device(selected_dev, errbuf);
	if (!adhandle) {
		// Error message printed inside open_selected_device
		exit_code = 1;
		goto cleanup;
	}

	if (setup_packet_filter(adhandle, selected_dev, DEFAULT_FILTER, errbuf) != 0) {
		// Error message printed inside setup_packet_filter
		exit_code = 1;
		goto cleanup;
	}

	if (setup_packet_filter(adhandle, selected_dev, DEFAULT_FILTER, errbuf) != 0) {
		// Error message printed inside setup_packet_filter
		exit_code = 1;
		goto cleanup;
	}

	printf("\n过滤规则 %s 设置成功，正在监听 %s...\n", DEFAULT_FILTER, selected_dev->description);

	/* 设备已经选定，不再需要设备列表；设置为 NULL 避免二次释放 */
	pcap_freealldevs(alldevs);
	alldevs = NULL;

	/* 开始抓包 */
	pcap_loop(adhandle, 0, packet_handler, NULL);

cleanup:
	printf("释放资源...\n");
	if (adhandle) {
		pcap_close(adhandle);
		adhandle = NULL;
		printf("Capture handle closed.\n");
	}
	if (alldevs) {
		pcap_freealldevs(alldevs); // Ensure list is freed if cleanup is reached before step 4
		alldevs = NULL;
		printf("Device list freed.\n");
	}

	printf("Exiting (code %d).\n", exit_code);
	return exit_code;
}

/**
 * @brief Callback function invoked by pcap_loop for each captured packet.
 * @param param User data passed to pcap_loop (NULL in this case).
 * @param header Metadata about the packet (timestamp, lengths).
 * @param pkt_data Raw packet data.
 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm ltime;
	time_t local_tv_sec;
	char timestr[MAX_TIMESTR_LEN];
	ethernet_header* eth_hdr;
	u_int l3_offset = sizeof(ethernet_header); // Initial offset for L3 header (usually 14)
	const char* protocol_str = "Other"; // Default
	u_short ether_type = 0;
	packet_info_t info = { 0 };

	ip_header* ih;
	ipv6_header* ip6h;
	udp_header* uh;
	tcp_header* th;
	u_int ip_len;
	u_short sport = 0, dport = 0;

	// 未使用的变量
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
	printf("%s.%.6d ", timestr, header->ts.tv_usec);

	// 1. 解析 Ethernet Header
	if (!parse_ethernet(pkt_data, header, &ether_type, &l3_offset)) {
		printf("%s [Invalid Ethernet Frame or too short]\n", timestr);
		return;
	}

	// 2. 解析 Layer 3 Protocol
	info.valid = 0; // Assume parsing fails unless proven otherwise
	switch (ether_type) {
	case ETHERTYPE_IP: // IPv4
		if (parse_ipv4(pkt_data, l3_offset, header, &info)) {
			// Further parsing (TCP/UDP) happens inside parse_ipv4
			info.valid = 1;
		}
		else {
			printf("%s [IPv4 Header invalid or too short]\n", timestr);
			// Optionally print partial info if available
		}
		break;

	case ETHERTYPE_IPV6: // IPv6
		if (parse_ipv6(pkt_data, l3_offset, header, &info)) {
			// Further parsing (TCP/UDP) happens inside parse_ipv6
			info.valid = 1;
		}
		else {
			printf("%s [IPv6 Header invalid or too short]\n", timestr);
			// Optionally print partial info if available
		}
		break;

		// case ETHERTYPE_ARP:
		//     printf("%s [ARP] len:%d\n", timestr, header->len);
		//     // Implement ARP parsing if needed
		//     return; // Don't print standard IP info

	default:
		printf("%s [Other L3: 0x%04x] len:%d\n", timestr, ether_type, header->len);
		return; // Unknown L3 protocol
	}
	if (info.valid) {
		print_packet_info(timestr, header->len, &info);
	}
}
/**
 * @brief Logs an error message to stderr.
 * @param prefix Optional prefix (e.g., function name).
 * @param message The error message.
 */
void log_error(const char* prefix, const char* message) {
	if (prefix) {
		fprintf(stderr, "ERROR [%s]: %s\n", prefix, message);
	}
	else {
		fprintf(stderr, "ERROR: %s\n", message);
	}
}
/**
 * @brief Finds all network devices, lists them, prompts the user for selection.
 * @param device_count Pointer to an integer to store the number of devices found.
 * @return Pointer to the selected pcap_if_t structure within the list, or NULL on error/no selection.
 * @note The caller is responsible for eventually calling pcap_freealldevs on the list returned indirectly if needed (although this function handles freeing on error internally). The returned pointer is invalidated once pcap_freealldevs is called.
 */
pcap_if_t* list_and_select_device(int* device_count) {
	pcap_if_t* alldevs = NULL;
	pcap_if_t* d = NULL;
	int i = 0;
	int inum = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		log_error("pcap_findalldevs_ex", errbuf);
		return NULL;
	}

	printf("Available network interfaces:\n");
	for (d = alldevs; d; d = d->next) {
		printf("%2d. %s", ++i, d->name);
		if (d->description) {
			printf(" (%s)\n", d->description);
		}
		else {
			printf(" (No description available)\n");
		}
	}
	*device_count = i;

	if (i == 0) {
		log_error(NULL, "No network interfaces found. Ensure Npcap is installed.");
		pcap_freealldevs(alldevs); // Free the list before returning
		return NULL;
	}

	printf("Enter the interface number (1-%d): ", i);
	// Use scanf_s for safety on Windows, check return value
	if (scanf_s("%d", &inum) != 1) {
		log_error(NULL, "Invalid input.");
		pcap_freealldevs(alldevs);
		return NULL;
	}


	if (inum < 1 || inum > i) {
		log_error(NULL, "Interface number out of range.");
		pcap_freealldevs(alldevs);
		return NULL;
	}

	// Jump to the selected adapter
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	// NOTE: We don't free alldevs here. The caller (main) needs the list
	// potentially for netmask info and must free it later. We return
	// a pointer *within* the alldevs list.
	return d;
}
/**
 * @brief Opens the specified network device for capture.
 * @param selected_dev Pointer to the device structure returned by list_and_select_device.
 * @param errbuf Buffer for error messages.
 * @return A handle to the opened device (pcap_t*), or NULL on failure.
 */
pcap_t* open_selected_device(pcap_if_t* selected_dev, char* errbuf) {
	pcap_t* handle = NULL;

	if (!selected_dev) {
		log_error("open_selected_device", "Invalid device pointer.");
		return NULL;
	}

	handle = pcap_open(selected_dev->name,
		DEFAULT_SNAPLEN,
		PCAP_OPENFLAG_PROMISCUOUS, // Capture all packets
		DEFAULT_READ_TIMEOUT,
		NULL, // No remote authentication
		errbuf);

	if (handle == NULL) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unable to open the adapter '%s'. %s is not supported by Npcap or permission denied.", selected_dev->name, selected_dev->name);
		log_error("pcap_open", errbuf);
		return NULL;
	}

	// Check data link type - Ensure it's Ethernet
	if (pcap_datalink(handle) != DLT_EN10MB) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Device %s does not provide Ethernet headers - not supported.", selected_dev->name);
		log_error("pcap_datalink", errbuf);
		pcap_close(handle); // Close the handle before returning
		return NULL;
	}

	return handle;
}
/**
 * @brief Compiles and applies a packet filter to the capture handle.
 * @param handle The pcap handle.
 * @param dev The device structure (needed for netmask).
 * @param filter_expr The filter expression string.
 * @param errbuf Buffer for error messages.
 * @return 0 on success, -1 on failure.
 */
int setup_packet_filter(pcap_t* handle, pcap_if_t* dev, const char* filter_expr, char* errbuf) {
	struct bpf_program fcode;
	bpf_u_int32 netmask = 0; // Default to 0 if no address found

	// Get the netmask of the first IPv4 address found for the device
	// Important: Check dev->addresses first!
	if (dev && dev->addresses != NULL) {
		struct pcap_addr* addr;
		for (addr = dev->addresses; addr != NULL; addr = addr->next) {
			if (addr->addr && addr->addr->sa_family == AF_INET && addr->netmask) {
				netmask = ((struct sockaddr_in*)(addr->netmask))->sin_addr.S_un.S_addr;
				break; // Found an IPv4 netmask
			}
		}
	}
	// If no suitable IPv4 address/netmask found, netmask remains 0, which is acceptable for pcap_compile.

	// Compile the filter expression
	if (pcap_compile(handle, &fcode, filter_expr, 1, netmask) < 0) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Error compiling filter '%s': %s", filter_expr, pcap_geterr(handle));
		log_error("pcap_compile", errbuf);
		// No need to free fcode if pcap_compile fails
		return -1;
	}

	// Set the compiled filter
	if (pcap_setfilter(handle, &fcode) < 0) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Error setting filter: %s", pcap_geterr(handle));
		log_error("pcap_setfilter", errbuf);
		pcap_freecode(&fcode); // Free the compiled code before returning
		return -1;
	}

	// Filter set successfully, free the compiled code (no longer needed by pcap)
	pcap_freecode(&fcode);
	return 0;
}

int parse_ethernet(const u_char* pkt_data, const struct pcap_pkthdr* header, u_short* ether_type, u_int* l3_offset) {
	ethernet_header* eth_hdr;
	u_int current_offset = 0;

	if (header->caplen < sizeof(ethernet_header)) {
		return 0; // Packet too short for basic Ethernet header
	}

	eth_hdr = (ethernet_header*)pkt_data;
	*ether_type = ntohs(eth_hdr->ether_type);
	current_offset = sizeof(ethernet_header); // 14 bytes

	// Handle 802.1Q VLAN tag if present
	if (*ether_type == ETHERTYPE_VLAN) {
		// Need 4 more bytes for VLAN tag (TPID + TCI) + 2 bytes for real EtherType
		if (header->caplen < current_offset + 4) {
			printf("[VLAN tag truncated] ");
			return 0; // Not enough data for VLAN tag info + next EtherType
		}
		// The real EtherType is after the 4-byte VLAN tag
		*ether_type = ntohs(*(u_short*)(pkt_data + current_offset + 2));
		current_offset += 4; // Add VLAN tag size to offset
		// printf("[VLAN] "); // Indicate VLAN presence if desired
	}
	// Could add support for QinQ (double VLAN tagging) here if needed

	*l3_offset = current_offset;
	return 1;
}

/**
 * @brief Parses the IPv4 header and calls transport layer parsing.
 * @param pkt_data Raw packet data starting from Ethernet header.
 * @param offset Offset to the start of the IP header.
 * @param header Packet metadata (for length checks).
 * @param info Output: Populated packet information struct.
 * @return 1 on success, 0 on failure.
 */
int parse_ipv4(const u_char* pkt_data, u_int offset, const struct pcap_pkthdr* header, packet_info_t* info) {
	ip_header* ih;
	u_int ip_hdr_len;
	u_char ip_version;
	const u_char* transport_data;
	u_int transport_len_available;

	// Check if captured length is sufficient for minimum IP header
	if (header->caplen < offset + sizeof(ip_header)) { // sizeof(ip_header) is usually 20
		return 0;
	}

	ih = (ip_header*)(pkt_data + offset);

	// Validate IP version
	ip_version = (ih->ver_ihl >> 4);
	if (ip_version != 4) {
		printf("[Not IPv4 (Version: %u)] ", ip_version);
		return 0;
	}

	// Calculate and validate IP header length
	ip_hdr_len = (ih->ver_ihl & 0x0F) * 4;
	if (ip_hdr_len < 20) { // Minimum valid IPv4 header length
		printf("[Invalid IPv4 header length: %u] ", ip_hdr_len);
		return 0;
	}

	// Check if the full IP header was captured
	if (header->caplen < offset + ip_hdr_len) {
		printf("[IPv4 Header truncated (expected %u)] ", ip_hdr_len);
		// Optionally extract partial info before returning
		inet_ntop(AF_INET, &(ih->saddr), info->src_ip, INET6_ADDRSTRLEN); // Use INET6_ADDRSTRLEN for safety, works for IPv4 mapped addrs too
		inet_ntop(AF_INET, &(ih->daddr), info->dst_ip, INET6_ADDRSTRLEN);
		info->transport_protocol = "v4_Truncated";
		return 0; // Indicate failure as full header isn't available
	}

	// --- Successfully parsed IP header basics ---
	if (inet_ntop(AF_INET, &(ih->saddr), info->src_ip, INET6_ADDRSTRLEN) == NULL) {
		strncpy_s(info->src_ip, INET6_ADDRSTRLEN, "[invalid_src]", _TRUNCATE);
	}
	if (inet_ntop(AF_INET, &(ih->daddr), info->dst_ip, INET6_ADDRSTRLEN) == NULL) {
		strncpy_s(info->dst_ip, INET6_ADDRSTRLEN, "[invalid_dst]", _TRUNCATE);
	}

	// Prepare for transport layer parsing
	transport_data = pkt_data + offset + ip_hdr_len;
	// Calculate available length for transport layer
	// Note: ih->tlen is the *total length* (IP header + data). Need captured length.
	transport_len_available = header->caplen - (offset + ip_hdr_len);

	// Parse transport layer based on protocol field
	switch (ih->proto) {
	case IPPROTO_TCP: // Defined in ws2tcpip.h or equivalent
		info->transport_protocol = "v4_TCP";
		return parse_tcp(transport_data, transport_len_available, info);
		break; // Keep break for clarity

	case IPPROTO_UDP:
		info->transport_protocol = "v4_UDP";
		return parse_udp(transport_data, transport_len_available, info);
		break;

		// case IPPROTO_ICMP:
		//     info->transport_protocol = "v4_ICMP";
		//     // Parse ICMP if needed, set info->valid = 1;
		//     return 1; // Return success if basic IP info is enough

	default:
		info->transport_protocol = "v4_Other";
		// Unknown/unhandled transport protocol, ports are irrelevant
		info->sport = 0;
		info->dport = 0;
		return 1; // Successfully parsed IP, even if transport is unknown
	}
}

/**
 * @brief Parses the IPv6 header and calls transport layer parsing.
 * @param pkt_data Raw packet data starting from Ethernet header.
 * @param offset Offset to the start of the IPv6 header.
 * @param header Packet metadata (for length checks).
 * @param info Output: Populated packet information struct.
 * @return 1 on success, 0 on failure.
 * @note This version does NOT handle IPv6 extension headers properly. It assumes
 * the next header field directly indicates the transport protocol.
 */
int parse_ipv6(const u_char* pkt_data, u_int offset, const struct pcap_pkthdr* header, packet_info_t* info) {
	ipv6_header* ip6h;
	uint32_t vtc_flow_host;
	uint8_t ip_version;
	uint8_t next_hdr;
	const u_char* transport_data;
	u_int transport_len_available;

	// Check if captured length is sufficient for the fixed IPv6 header
	if (header->caplen < offset + sizeof(ipv6_header)) { // sizeof(ipv6_header) is 40
		return 0;
	}

	ip6h = (ipv6_header*)(pkt_data + offset);

	// Check IPv6 version (first 4 bits of vtc_flow)
	vtc_flow_host = ntohl(ip6h->ip6_ctlun.vtc_flow); // Convert to host order first
	ip_version = (vtc_flow_host >> 28) & 0x0F;
	if (ip_version != 6) {
		printf("[Not IPv6 (Version: %u)] ", ip_version);
		return 0;
	}

	// --- Successfully parsed IPv6 header basics ---
	if (inet_ntop(AF_INET6, &(ip6h->saddr), info->src_ip, INET6_ADDRSTRLEN) == NULL) {
		strncpy_s(info->src_ip, INET6_ADDRSTRLEN, "[invalid_src6]", _TRUNCATE);
	}
	if (inet_ntop(AF_INET6, &(ip6h->daddr), info->dst_ip, INET6_ADDRSTRLEN) == NULL) {
		strncpy_s(info->dst_ip, INET6_ADDRSTRLEN, "[invalid_dst6]", _TRUNCATE);
	}

	// --- Transport Layer ---
	// WARNING: This simplification ignores IPv6 Extension Headers.
	// A production parser would loop through extension headers until it finds
	// a known transport protocol or the No Next Header indicator.
	next_hdr = ip6h->next_hdr;
	transport_data = pkt_data + offset + sizeof(ipv6_header);
	transport_len_available = header->caplen - (offset + sizeof(ipv6_header));


	switch (next_hdr) {
	case IPPROTO_TCP:
		info->transport_protocol = "v6_TCP";
		return parse_tcp(transport_data, transport_len_available, info);

	case IPPROTO_UDP:
		info->transport_protocol = "v6_UDP";
		return parse_udp(transport_data, transport_len_available, info);

		// case IPPROTO_ICMPV6:
		//     info->transport_protocol = "v6_ICMP";
		//     return 1;

	default:
		info->transport_protocol = "v6_Other";
		// Unknown/unhandled transport protocol (or extension header we didn't parse)
		info->sport = 0;
		info->dport = 0;
		return 1; // Successfully parsed IPv6 header itself
	}
}


/**
 * @brief Parses TCP source and destination ports.
 * @param transport_data Pointer to the start of the TCP header.
 * @param transport_len_available Available length for the transport header/payload.
 * @param info Output: packet_info_t struct to store ports.
 * @return 1 if ports parsed successfully, 0 if packet too short.
 */
int parse_tcp(const u_char* transport_data, u_int transport_len_available, packet_info_t* info) {
	tcp_header* th;
	// Need at least 4 bytes for source and destination ports
	if (transport_len_available < 4) { // Check against minimum needed part (ports)
		printf("[TCP Header too short for ports] ");
		info->sport = 0; // Indicate missing ports
		info->dport = 0;
		return 0; // Parsing failed
	}

	// Check for full header if using tcp_header struct size (usually 20)
	// if (transport_len_available < sizeof(tcp_header)) { ... }

	th = (tcp_header*)transport_data;
	info->sport = ntohs(th->sport);
	info->dport = ntohs(th->dport);
	return 1; // Successfully parsed ports
}

/**
 * @brief Parses UDP source and destination ports.
 * @param transport_data Pointer to the start of the UDP header.
 * @param transport_len_available Available length for the transport header/payload.
 * @param info Output: packet_info_t struct to store ports.
 * @return 1 if ports parsed successfully, 0 if packet too short.
 */
int parse_udp(const u_char* transport_data, u_int transport_len_available, packet_info_t* info) {
	udp_header* uh;
	if (transport_len_available < sizeof(udp_header)) { // UDP header is fixed size (8 bytes)
		printf("[UDP Header too short] ");
		info->sport = 0;
		info->dport = 0;
		return 0; // Parsing failed
	}

	uh = (udp_header*)transport_data;
	info->sport = ntohs(uh->sport);
	info->dport = ntohs(uh->dport);
	return 1; // Successfully parsed ports
}


/**
 * @brief Prints the formatted packet information.
 * @param timestamp Formatted timestamp string.
 * @param len Original packet length.
 * @param info Parsed packet information.
 */
void print_packet_info(const char* timestamp, int len, const packet_info_t* info) {
	// Basic format: timestamp [protocol][len] src_ip:sport -> dst_ip:dport
	printf("%s [%s][%4d] ",
		timestamp,
		info->transport_protocol ? info->transport_protocol : "Unknown", // Safety check
		len);

	// Print source IP (already formatted)
	printf("%s", info->src_ip);

	// Print source port if available (non-zero)
	if (info->sport != 0) {
		printf(":%d", info->sport);
	}

	printf(" -> ");

	// Print destination IP
	printf("%s", info->dst_ip);

	// Print destination port if available (non-zero)
	if (info->dport != 0) {
		printf(":%d", info->dport);
	}

	printf("\n");
}
