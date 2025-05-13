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
			uint32_t version : 4;       // �汾�� (ӦΪ 6)
			uint32_t traffic_class : 8; // �������
			uint32_t flow_label : 20;    // ����ǩ
		} ip6_un1; // ͨ��ʹ��λ�������Щ�ֶ���Ҫע�������������ֽ���
		uint32_t vtc_flow;             // ������Ϊһ���������ǰ4�ֽ� (Version, Traffic Class, Flow Label)��ע��ʹ��ǰ��Ҫntohl
	} ip6_ctlun; // ������Ϣ������

	uint16_t payload_len;              // �غɳ��� (����IPv6����ͷ���ĳ���, �����ֽ���)
	uint8_t  next_hdr;                 // ��һ��ͷ������ (���� TCP, UDP, ICMPv6)
	uint8_t  hop_limit;                // �������� (�൱�� IPv4 TTL)

	struct in6_addr saddr;             // Դ IPv6 ��ַ (128λ / 16�ֽ�)
	struct in6_addr daddr;             // Ŀ�� IPv6 ��ַ (128λ / 16�ֽ�)

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