#include "netfunc.h"

int getMyMACAddress(const char *name, char *buf, size_t buflen) {
	snprintf(buf, buflen, "/sys/class/net/%s/eth0/address", name);
	FILE *fp = fopen(buf, "r");
	if (!fp) return -1;

	fgets(buf, buflen, fp);
	fclose(fp);
	return 0;
}

int getMyIPAddress(const char *name, char *buf, size_t buflen) {
	snprintf(buf, buflen, "ifconfig %s "
	"| grep -Eo \'inet (addr:)?([0-9]+\\.){3}[0-9]+\' "
	"| grep -Eo \'([0-9.]+)\'", name);
	FILE *fp = popen(buf, "r");
	if (!fp) return -1;

	fgets(buf, buflen, fp);
	fclose(fp);
	return 0;
}

void create_eth_arp(uint8_t *packet,
	struct ether_addr ethsrc, struct ether_addr ethdst, // eth s->d
	uint16_t arpop, // arp op
	struct ether_addr arphasrc, struct ether_addr arphadst, // arp ha s->d
	struct in_addr arpipsrc, struct in_addr arpipdst // arp ip s->D
) {
	const size_t IPV4_LEN = 4;
	// (1) eth
	struct ether_header* packet_eth = (struct ether_header*)packet;
	memcpy(packet_eth->ether_shost, &ethsrc, ETHER_ADDR_LEN);
	memcpy(packet_eth->ether_dhost, &ethdst, ETHER_ADDR_LEN);
	packet_eth->ether_type = ETHERTYPE_ARP;

	// (2) arp
	struct ether_arp* packet_arp = (struct ether_arp*)(packet + ETHER_HDR_LEN);
	packet_arp->arp_hrd = ARPHRD_ETHER;
	packet_arp->arp_pro = ETHERTYPE_IP; // ARP는 Protocol type을 Ethertype과 공유한다
	packet_arp->arp_hln = ETHER_ADDR_LEN;
	packet_arp->arp_pln = IPV4_LEN; // IPv4
	packet_arp->arp_op = arpop;
	memcpy(packet_arp->arp_sha, &arphasrc, ETHER_ADDR_LEN);
	memcpy(packet_arp->arp_tha, &arphadst, ETHER_ADDR_LEN);
	memcpy(packet_arp->arp_spa, &arpipsrc, IPV4_LEN);
	memcpy(packet_arp->arp_tpa, &arpipdst, IPV4_LEN);
}

bool is_arp_reply(uint32_t packet_len,
	const uint8_t *packet,
	struct in_addr target_ip,
	struct ether_addr* target_mac) {

	const struct ether_header *packet_eth = (const struct ether_header*)packet;
	if (packet_eth->ether_type != ETHERTYPE_ARP) return false;

	const struct ether_arp* packet_arp = (const struct ether_arp*)(packet + ETHER_HDR_LEN);
	if (packet_arp->arp_op != ARPOP_REPLY) return false;

	if (*(uint32_t*)&packet_arp->arp_tpa != *(uint32_t*)&target_ip) return false;
	memcpy(target_mac, packet_arp->arp_tha, ETHER_ADDR_LEN);

	return true;
}
