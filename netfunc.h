#include <cstdio>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <netinet/ether.h>

#ifndef NETFUNC_H
#define NETFUNC_H

int getMyMACAddress(const char*, char*, size_t);
int getMyIPAddress(const char*, char*, size_t);
void create_eth_arp(uint8_t*,
	struct ether_addr, struct ether_addr, // eth s->d
	uint16_t, // arp op
	struct ether_addr, struct ether_addr, // arp ha s->d
	struct in_addr, struct in_addr // arp ip s->D
);
bool is_arp_reply(uint32_t, const uint8_t*, struct in_addr, struct ether_addr*);

#endif
