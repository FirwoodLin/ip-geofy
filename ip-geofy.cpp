#pragma comment(lib,"ws2_32.lib")
#include <pcap.h>
#include <time.h>
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <ether_type.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "GetSystemDirectory 发生错误: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "SetDllDirectory 发生错误: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
typedef struct ethernet_header {
	u_char ether_dhost[6];	/* Destination host address */
	u_char ether_shost[6];	/* Source host address */
	u_short ether_type;		    /* IP? ARP? RARP? etc */
} ethernet_header;

/* 4 bytes IP address */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* TCP header (simplified, only ports needed for this example) */
typedef struct tcp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	// Other TCP fields...
} tcp_header;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);


int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp or udp"; // 初始：ip and udp
	struct bpf_program fcode;

	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "无法加载 Npcap\n");
		exit(1);
	}

	/* Retrieve the device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "pcap_findalldevs 发生错误: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
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
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1;d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open(d->name,	// name of the device
		65536,		// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,			// promiscuous mode
		1000,		// read timeout
		NULL,		// remote authentication
		errbuf		// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\n无法打开适配器。%s 不被 Npcap 支持\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	// Ethernet 是链路层协议，程序需要利用头部 14 字节解析信息，因此指定了只能使用 Ethernet。
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\n本程序仅支持以太网 Ethernet 网络。\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\n无法编译数据包过滤器，请检查语法。\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\n设置过滤器时发生错误。\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\n正在监听 %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
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
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	if (header->caplen < sizeof(ethernet_header)) {
		printf("[Packet too short for Ethernet Header]\n");
		return;
	}
	eth_hdr = (ethernet_header*)pkt_data;
	ether_type = ntohs(eth_hdr->ether_type); // Get EtherType in host byte order

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

	/* retireve the position of the ip header */
	const u_int ETHERNET_HEADER_LEN = 14;
	ih = (ip_header*)(pkt_data + ETHERNET_HEADER_LEN); //length of ethernet header

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
			protocol_str = "TCP";
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
			protocol_str = "UDP";
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
		case IPPROTO_ICMP: // Defined in ws2tcpip.h
			protocol_str = "ICMP";
			// No ports for ICMP in this context
			break;
		case IPPROTO_IGMP: // Defined in ws2tcpip.h
			protocol_str = "IGMP";
			// No ports for IGMP in this context
			break;
		default:
			protocol_str = "Other L4"; // Protocol number inside IP
			// sport and dport remain 0
			break;
		}

	}
	else if (ether_type == ETHERTYPE_ARP) {
		protocol_str = "ARP";
		// ARP parsing would go here if needed
		// No IP or Port info in the same way
		printf("[%s]\n", protocol_str); // Print ARP and return
		return; // Don't proceed to IP printing
	}
	else if (ether_type == ETHERTYPE_IPV6) {
		protocol_str = "IPv6";
		// IPv6 parsing would go here if needed
		printf("[%s]\n", protocol_str); // Print IPv6 and return
		return; // Don't proceed to IP printing
	}
	else {
		// Unknown/unhandled EtherType
		printf("[Unknown L3: 0x%04x]\n", ether_type);
		return; // Don't know how to parse further
	}
	// 如果有 IP 协议包
	if (ih != NULL) {
		// 协议类型 & 源 IP
		printf("[%s] %d.%d.%d.%d",
			protocol_str,
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4);

		// 目标 IP
		// Only print ports if they were successfully parsed
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
	// 其他协议已经在之前返回了
}
