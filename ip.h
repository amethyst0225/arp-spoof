#pragma once

#include <cstdint>
#include <string>

#pragma pack(push, 1)
struct IpHdr {
    uint8_t vhl_;
    uint8_t tos_;
    uint16_t len_;
    uint16_t id_;
    uint16_t off_;
    uint8_t ttl_;
    uint8_t p_;
    uint16_t sum_;
    uint32_t sip_;
    uint32_t dip_;
};
#pragma pack(pop)


struct Ip final {
	static const int Size = 4;
    static const size_t SIZE = 4; // IPv4 address size in bytes

	// constructor
	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);

	// casting operator
	operator uint32_t() const { return ip_; } // default
	explicit operator std::string() const;

	// comparison operator
	bool operator == (const Ip& r) const { return ip_ == r.ip_; }

	bool isLocalHost() const { // 127.*.*.*
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix == 0x7F;
	}

	bool isBroadcast() const { // 255.255.255.255
		return ip_ == 0xFFFFFFFF;
	}

	bool isMulticast() const { // 224.0.0.0 ~ 239.255.255.255
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix >= 0xE0 && prefix < 0xF0;
	}

protected:
	uint32_t ip_;
};
