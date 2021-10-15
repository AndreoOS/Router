#include <arp.h>

void arp_reply_with_my_mac(packet m, struct arp_header *arp_hdr)
{
	// Find my mac of the interface used by received package
	uint8_t mac[ETH_ALEN];
	get_interface_mac(m.interface, mac);

	// Complete the ip address
	uint32_t daddr = arp_hdr->spa;
	uint32_t saddr = arp_hdr->tpa;

	// Construct the ethernet header with the mac source =
	// my mac and the destination mac = the mac source of the
	// received package
	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	DIE(eth_hdr == NULL, "Can't alloc the ether_header.");
	build_ethhdr(eth_hdr, mac, arp_hdr->sha, TYPE);

	int interface = m.interface;
	uint16_t arp_op = htons(ARPOP_REPLY);

	// Send an ARP_REPLAY
	send_arp(daddr, saddr, eth_hdr, interface, arp_op);
}

void arp_request(struct route_table_entry *best_route, 
				uint8_t mac[ETH_ALEN])
{
	// Complete the ip address
	// The destination ip is the next_hop
	uint32_t daddr = best_route->next_hop;

	// The ip source is the router's ip
	uint32_t saddr = inet_addr(get_interface_ip(best_route->interface));

	// Construct the ethernet header with my mac as source and
	// broadcast address as destination 
	uint8_t dha[ETH_ALEN];
	memset(dha, 0xFF, ETH_ALEN);

	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	DIE(eth_hdr == NULL, "Can't alloc an ether_header.");
	build_ethhdr(eth_hdr, mac, dha, TYPE);

	int interface = best_route->interface;
	uint16_t arp_op = htons(ARPOP_REQUEST);

	// Send an ARP_REQUEST
	send_arp(daddr, saddr, eth_hdr, interface, arp_op);
}


