#pragma once
struct LocationInfo {
	std::string country;
	std::string province;
	std::string city;
};
struct PacketInfo {
	std::string src_ip;
	std::string dst_ip;

	uint16_t sport;
	uint16_t dport;

	LocationInfo src_loc; // ×·¼Ó
	LocationInfo dst_loc; // ×·¼Ó


	std::string transport_protocol;
	bool valid; // Flag to indicate if parsing was successful enough for printing

	PacketInfo() : sport(0), dport(0), valid(false) {}
};