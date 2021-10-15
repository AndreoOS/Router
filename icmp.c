#include "icmp.h"

void icmp_echo_reply_with_my_mac(struct iphdr *ip_hdr,
								 struct icmphdr *icmp_hdr,
								 struct ether_header *eth_hdr,
								 packet m)
{
	// Send back the packet
	uint32_t daddr = ip_hdr->saddr;
	uint32_t saddr = ip_hdr->daddr;

	// The mac source is my mac
	uint8_t *sha = eth_hdr->ether_dhost;
	uint8_t *dha = eth_hdr->ether_shost;

	u_int8_t type = ICMP_ECHOREPLY;
	u_int8_t code = ICMP_ECHOREPLY;

	int interface = m.interface;
	int id = icmp_hdr->un.echo.id;
	int seq = icmp_hdr->un.echo.sequence;

	// Send an ICMP_REPLAY
	send_icmp(daddr, saddr, sha, dha, type, code, interface, id, seq);
}

void icmp_error(struct ether_header *eth_hdr,
				struct icmphdr *icmp_hdr,
				struct iphdr *ip_hdr,
				u_int8_t type,
				u_int8_t code,
				packet m)
{
	// Send back the packet
	uint32_t daddr = ip_hdr->saddr;
	uint32_t saddr = inet_addr(get_interface_ip(m.interface));

	// The mac source is my mac
	uint8_t *sha = eth_hdr->ether_dhost;
	uint8_t *dha = eth_hdr->ether_shost;

	int interface = m.interface;

	// Send an ICMP_REPLAY
	send_icmp_error(daddr, saddr, sha, dha, type, code, interface);
}

