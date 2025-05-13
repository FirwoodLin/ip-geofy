#pragma once
typedef struct ethernet_header {
	u_char ether_dhost[6];	/* Destination host MAC address */
	u_char ether_shost[6];	/* Source host MAC address */
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

typedef struct ipv6_header {
	union {
		struct {
			uint32_t version : 4;       // 版本号 (应为 6)
			uint32_t traffic_class : 8; // 流量类别
			uint32_t flow_label : 20;    // 流标签
		} ip6_un1; // 通常使用位域访问这些字段需要注意编译器差异和字节序
		uint32_t vtc_flow;             // 或者作为一个整体访问前4字节 (Version, Traffic Class, Flow Label)；注意使用前需要ntohl
	} ip6_ctlun; // 控制信息联合体

	uint16_t payload_len;              // 载荷长度 (不含IPv6基本头部的长度, 网络字节序)
	uint8_t  next_hdr;                 // 下一个头部类型 (例如 TCP, UDP, ICMPv6)
	uint8_t  hop_limit;                // 跳数限制 (相当于 IPv4 TTL)

	struct in6_addr saddr;             // 源 IPv6 地址 (128位 / 16字节)
	struct in6_addr daddr;             // 目的 IPv6 地址 (128位 / 16字节)

} ipv6_header;

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