#pragma comment(lib,"ws2_32.lib")
#include <pcap.h>
#include <time.h>
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
// 自定义头文件
#include "ether_type.h"
#include "protocol_headers.h"
typedef struct {
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
//pcap_if_t* list_and_select_device(int* device_count);
//pcap_t* open_selected_device(pcap_if_t* selected_dev, char* errbuf);
//int setup_packet_filter(pcap_t* handle, pcap_if_t* dev, const char* filter_expr, char* errbuf);
//void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* pkt_data);
//
//// Layer parsing functions
//int parse_ethernet(const u_char* pkt_data, const struct pcap_pkthdr* header, u_short* ether_type, u_int* l3_offset);
//int parse_ipv4(const u_char* pkt_data, u_int offset, const struct pcap_pkthdr* header, packet_info_t* info);
//int parse_ipv6(const u_char* pkt_data, u_int offset, const struct pcap_pkthdr* header, packet_info_t* info);
//int parse_tcp(const u_char* transport_data, u_int transport_len, packet_info_t* info);
//int parse_udp(const u_char* transport_data, u_int transport_len, packet_info_t* info);
//void print_packet_info(const char* timestamp, int len, const packet_info_t* info);

int main()
{
	pcap_if_t* alldevs = NULL; // 指向接口链表头的指针
	pcap_if_t* d = NULL;
	int inum;	// 用户选择的网络接口编号
	int i = 0;
	pcap_t* adhandle = NULL; // 打开的网络适配器（网卡）句柄
	char errbuf[PCAP_ERRBUF_SIZE]; // 存放错误信息的缓冲区
	u_int netmask; // 选中接口的子网掩码
	char packet_filter[] = "tcp or udp"; // 抓包过滤表达式
	struct bpf_program fcode; // 编译后的过滤规则结构体

	/* 获取本机所有可用的网络接口（网卡）列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "pcap_findalldevs 发生错误: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%2d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (无描述)\n");
	}

	if (i == 0)
	{
		printf("\n未找到网络接口！请确保已安装Npcap。\n");
		return -1;
	}

	printf("请输入接口编号(1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\n接口编号超出范围。\n");
		/* 释放 device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1;d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open(d->name,	// 设备名称
		65536,		// 捕获的数据包长度（字节），65536保证能捕获到所有数据
		PCAP_OPENFLAG_PROMISCUOUS,			// promiscuous mode 混杂模式
		1000,		// read timeout 读取超时时间（毫秒）
		NULL,		// remote authentication 远程认证（本地不需要，填NULL）
		errbuf		// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\n无法打开适配器。%s 不被 Npcap 支持\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 本程序只支持 Ethernet 链路层协议 */
	// Ethernet 是链路层协议，程序需要利用头部 14 字节解析信息，因此指定了只能使用 Ethernet。
	// EN10MB 只是历史命名，代表“以太网帧格式”，不管实际速率是多少。
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\n本程序仅支持以太网 Ethernet 网络。\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* 取第一个地址的子网掩码 */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else // 该网卡没有分配 IP 地址
		/* 如果接口没有地址，假设是C类网络，掩码为255.255.255.0 */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\n无法编译数据包过滤器，请检查语法。\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	// 设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\n设置过滤器时发生错误。\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\n正在监听 %s...\n", d->description);

	/* 设备已经选定，不再需要设备列表 */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm ltime;
	char timestr[16];
	ethernet_header* eth_hdr;
	ip_header* ih;
	ipv6_header* ip6h;
	udp_header* uh;
	tcp_header* th;
	u_int ip_len;
	u_int l3_offset = sizeof(ethernet_header); // Initial offset for L3 header (usually 14)
	u_short ether_type;
	u_short sport = 0, dport = 0;
	time_t local_tv_sec;
	const char* protocol_str = "Other"; // Default

	/*
	 * Unused variable
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* print timestamp and length of the packet */
	//printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
	printf("%s.%.6d ", timestr, header->ts.tv_usec);

	if (header->caplen < sizeof(ethernet_header)) {
		printf("[Packet too short for Ethernet Header]\n");
		return;
	}
	eth_hdr = (ethernet_header*)pkt_data;
	ether_type = ntohs(eth_hdr->ether_type); // 网络大端序 -> 主机小端序

	if (ether_type == ETHERTYPE_VLAN) {
		printf("[VLAN] ");
		// Check if packet is long enough for VLAN tag + actual EtherType
		if (header->caplen < sizeof(ethernet_header) + 4) {
			printf("[Packet too short for VLAN Tag info]\n");
			return;
		}
		// The real EtherType is 4 bytes after the nominal Ethernet header end
		ether_type = ntohs(*(u_short*)(pkt_data + sizeof(ethernet_header) + 2));
		l3_offset += 4; // Adjust the offset for Layer 3 header
	}


	// --- Check EtherType to determine Layer 3 Protocol ---
	if (ether_type == ETHERTYPE_IP) {
		// Check if packet is long enough for minimum IP header at the calculated offset
		if (header->caplen < l3_offset + 20) { // Check for minimum IP header size (20 bytes)
			printf("[Packet too short for minimum IPv4 Header at offset %u]\n", l3_offset);
			return;
		}

		ih = (ip_header*)(pkt_data + l3_offset); // Point to the IP header

		// --- Validate IP Version and Header Length ---
		u_char ip_version = (ih->ver_ihl >> 4);
		if (ip_version != 4) {
			printf("[Not an IPv4 packet (Version: %u)]\n", ip_version);
			return; // Don't process if not IPv4
		}

		ip_len = (ih->ver_ihl & 0xf) * 4; // Calculate IP header length in bytes
		if (ip_len < 20) { // Basic sanity check (redundant with above caplen check, but good practice)
			// This is where your original error was triggered
			printf("[Invalid IPv4 header length: %u bytes]\n", ip_len);
			return;
		}

		// Check if the *entire* IP header was captured
		if (header->caplen < l3_offset + ip_len) {
			printf("[Packet too short for full IPv4 Header (expected %u bytes at offset %u)]\n", ip_len, l3_offset);
			// Optionally print partial info or just return
			 // Still print base IP info if possible
			printf("[Partial IP] %d.%d.%d.%d -> %d.%d.%d.%d ",
				ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4,
				ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
			return; // Return after printing partial info
		}

		// --- Now process TCP or UDP based on ih->proto ---
		u_int transport_header_offset = l3_offset + ip_len;
		switch (ih->proto) {
		case IPPROTO_TCP: {
			protocol_str = "v4_TCP";
			// Check if captured data is long enough for basic TCP header (ports)
			if (header->caplen < transport_header_offset + sizeof(tcp_header)) { // Using our simplified struct size
				printf("[Packet too short for TCP ports]\n");
			}
			else {
				th = (tcp_header*)((u_char*)ih + ip_len); // Pointer arithmetic relative to ih start
				sport = ntohs(th->sport);
				dport = ntohs(th->dport);
			}
			break;
		}
		case IPPROTO_UDP: {
			protocol_str = "v4_UDP";
			// Check if captured data is long enough for UDP header
			if (header->caplen < transport_header_offset + sizeof(udp_header)) {
				printf("[Packet too short for UDP header]\n");
			}
			else {
				uh = (udp_header*)((u_char*)ih + ip_len); // Pointer arithmetic relative to ih start
				sport = ntohs(uh->sport);
				dport = ntohs(uh->dport);
			}
			break;
		}
		default:
			protocol_str = "Other L4"; // Protocol number inside IP
			// sport and dport remain 0
			break;
		}
		printf("[%s][%4d] %d.%d.%d.%d",
			protocol_str,
			header->len,
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4);

		// 目标 IP；检查是否有端口信息
		if (sport != 0 || dport != 0) {
			printf(":%d -> %d.%d.%d.%d:%d\n",
				sport,
				ih->daddr.byte1,
				ih->daddr.byte2,
				ih->daddr.byte3,
				ih->daddr.byte4,
				dport);
		}
		else {
			// Print only destination IP if no ports are relevant/available/parsed
			printf(" -> %d.%d.%d.%d\n",
				ih->daddr.byte1,
				ih->daddr.byte2,
				ih->daddr.byte3,
				ih->daddr.byte4);
		}
	}
	else if (ether_type == ETHERTYPE_IPV6) {
		protocol_str = "IPv6";
		// 检查捕获长度是否足够包含 IPv6 头部
		if (header->caplen < l3_offset + sizeof(ipv6_header)) {
			printf("[%s] [Packet too short for full IPv6 Header at offset %u]\n", protocol_str, l3_offset);
			return;
		}
		ip6h = (ipv6_header*)(pkt_data + l3_offset);
		// 检查 IPv6 版本号 (需要先转换 vtc_flow 字节序)
		uint32_t vtc_flow_host = ntohl(ip6h->ip6_ctlun.vtc_flow);
		uint8_t ip_version = (vtc_flow_host & 0xf0000000) >> 28;

		if (ip_version != 6) {
			printf("[%s] [Invalid IPv6 version: %u]\n", protocol_str, ip_version);
			return;
		}

		char src_ip_str[INET6_ADDRSTRLEN]; // INET6_ADDRSTRLEN 在 ws2tcpip.h (Win) 或 arpa/inet.h (POSIX) 定义
		char dst_ip_str[INET6_ADDRSTRLEN];

		// 处理 IPv6 的下一个头部（上层协议）类型
		u_int transport_header_offset = l3_offset + sizeof(ipv6_header); // 假设没有扩展头
		uint8_t next_protocol = ip6h->next_hdr;

		switch (next_protocol) {
		case IPPROTO_TCP: // 6
			protocol_str = "v6_TCP";
			// ... 解析 TCP 头部 (注意 transport_header_offset) ...
			th = (tcp_header*)((u_char*)ip6h + sizeof(ipv6_header)); // 简化，未考虑扩展头
			sport = ntohs(th->sport);
			dport = ntohs(th->dport);
			// printf("TCP Ports: %d -> %d", sport, dport);
			break;
		case IPPROTO_UDP: // 17
			protocol_str = "v6_UDP";
			// ... 解析 UDP 头部 ...
			uh = (udp_header*)((u_char*)ip6h + sizeof(ipv6_header)); // 简化
			sport = ntohs(uh->sport);
			dport = ntohs(uh->dport);
			// printf("UDP Ports: %d -> %d", sport, dport);
			break;
		default:
			printf("NextHeader: %d", next_protocol);
			break;
		}

		// 使用 inet_ntop 将二进制地址转换为字符串
		// 注意：inet_ntop 需要 AF_INET6 作为第一个参数
		if (inet_ntop(AF_INET6, &(ip6h->saddr), src_ip_str, INET6_ADDRSTRLEN) == NULL) {
			perror("inet_ntop src failed");
			strncpy_s(src_ip_str, "[invalid_src]", INET6_ADDRSTRLEN); // Fallback
		}
		if (inet_ntop(AF_INET6, &(ip6h->daddr), dst_ip_str, INET6_ADDRSTRLEN) == NULL) {
			perror("inet_ntop dst failed");
			strncpy_s(dst_ip_str, "[invalid_dst]", INET6_ADDRSTRLEN); // Fallback
		}

		printf("[%s][%4d] %s:%d -> %s:%d\n", protocol_str, header->len, src_ip_str, sport, dst_ip_str, dport);
		return; // Don't proceed to IP printing
	}
	//else if (ether_type == ETHERTYPE_ARP) {
	//	protocol_str = "ARP";
	//	// ARP parsing would go here if needed
	//	// No IP or Port info in the same way
	//	printf("[%s]\n", protocol_str); // Print ARP and return
	//	return; // Don't proceed to IP printing
	//}
	else {
		// Unknown/unhandled EtherType
		printf("[Other L3: 0x%04x]\n", ether_type);
		return; // Don't know how to parse further
	}
	// 打印源地址 & 目标地址
		// 协议类型 & 数据包长度 & 源 IP


	// IPv6
	// 其他协议已经在之前返回了
}

void log_error(const char* prefix, const char* message) {
	if (prefix) {
		fprintf(stderr, "ERROR [%s]: %s\n", prefix, message);
	}
	else {
		fprintf(stderr, "ERROR: %s\n", message);
	}
}
