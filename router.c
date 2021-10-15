#include <router.h>

struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_len;


// Add a new arp_entry in the arp table, after
// an arp_replay
void update_arp_table(struct arp_entry new_entry)
{
	int i;
	// Add on the last position
	for (i = 0; i < arp_table_len; i++)
	{
		// Already exists
		if (new_entry.ip == arp_table[i].ip &&
			new_entry.mac == arp_table[i].mac)
		{
			break;
		}
	}

	// If isn't in the arp table
	// add a new entry
	if (i == arp_table_len)
	{
		arp_table[arp_table_len] = new_entry;
		arp_table_len++;
	}
}

// Return an arp entry using an ip given
struct arp_entry *get_arp_entry(__u32 ip)
{
	for (int i = 0; i < arp_table_len; i++)
	{
		if (arp_table[i].ip == ip)
		{
			return &arp_table[i];
		}
	}
	return NULL;
}

// Alloc an arp table with maximum MAX_ARP_ENTRY entries
void create_arp_table()
{
	arp_table = malloc(MAX_ARP_ENTRY * sizeof(struct arp_entry));
	DIE(arp_table == NULL, "Can't alloc the arp_table.");
}

// Parse the file to obtain a route table
// Store the route table in an array of
// structures
void parse_route_table(char *name_file)
{

	FILE *file = fopen(name_file, "r");
	DIE(file == NULL, "Can't open the route_table file.");

	rtable = malloc(MAX_R_ENTRY * sizeof(struct route_table_entry));
	DIE(rtable == NULL, "Can't alloc the route_table.");

	char line[MAX_LENGTH];
	char buf1[MAX_LENGTH], buf2[MAX_LENGTH], buf3[MAX_LENGTH], buf4[MAX_LENGTH];

	while (fgets(line, sizeof(line), file))
	{
		// Parse the line by space
		// Store the data in the rtable structure, transforming it
		sscanf(line, "%s %s %s %s\n", buf1, buf2, buf3, buf4);
		rtable[rtable_size].prefix = inet_addr(buf1);
		rtable[rtable_size].next_hop = inet_addr(buf2);
		rtable[rtable_size].mask = inet_addr(buf3);
		rtable[rtable_size].interface = atoi(buf4);

		rtable_size++;
	}

	fclose(file);
}

// Compare function to sort the route table entries by
// prefix and in case of equality by maximum mask
int cmpfunc(const void *a, const void *b)
{
	if ((*(struct route_table_entry *)a).prefix != (*(struct route_table_entry *)b).prefix)
	{
		return ((*(struct route_table_entry *)a).prefix - (*(struct route_table_entry *)b).prefix);
	}
	else
	{
		return ((*(struct route_table_entry *)a).mask - (*(struct route_table_entry *)b).mask);
	}
}

// Return a specific entry for an ip given 
// from the route table, using binary search
// Copyright: https://www.geeksforgeeks.org/binary-search/
struct route_table_entry *get_best_route(uint32_t dest_ip)
{
	int l = 0;
	int r = rtable_size - 1;

	while (l <= r)
	{
		int m = l + (r - l) / 2;

		// Check if I found the prefix
		if ((rtable[m].mask & dest_ip) == rtable[m].prefix)
		{
			// Search the maximum mask
			int ok = 1;
			while (((rtable[m].mask & dest_ip) == rtable[m].prefix) 
					&& (m < (rtable_size - 1)))
			{
				ok = 0;
				m++;
			}
			if (ok == 0)
			{
				return &rtable[m - 1];
			}
			else
			{
				return &rtable[m];
			}
		}
		else
		{
			// If the search prefix is ​​larger than the current one,
			// ignore the left half
			if ((rtable[m].mask & dest_ip) > rtable[m].prefix)
			{
				l = m + 1;
			}
			else
			{
				// Ignore the right half
				r = m - 1;
			}
		}
	}

	// The ip isn't in the route table
	return NULL;
}

// Update the queue
void dequeue_packets(queue *q_packets, uint8_t mac[ETH_ALEN],
					 struct arp_header *arp_hdr)
{
	// Dequeue the packets
	while (!queue_empty(*q_packets))
	{
		// First packet from queue
		packet *to_send = (packet *)peek(*q_packets);

		struct iphdr *ip_hdr_q_packet = (struct iphdr *)((*to_send).payload 
										+ sizeof(struct ether_header));
		struct ether_header *eth_hdr;
		eth_hdr = (struct ether_header *)(*to_send).payload;

		struct route_table_entry *best = get_best_route(ip_hdr_q_packet->daddr);

		
		// If it is not the package to be sent to the received mac
		// I don't take it out of the queue
		if (best->next_hop != arp_hdr->spa)
		{
			break;
		}
		// It's the right package, taking it out of the queue
		else
		{
			to_send = (packet *)queue_deq(*q_packets);
		}

		// Complete the destination mac address for the packet from
		// the queue
		complete_mac_ether_hdr(eth_hdr, mac, arp_hdr);

		// Send packet
		send_packet(best->interface, to_send);
	}
}

void enqueue_packet(queue *q_packets, packet m,
					struct route_table_entry *best_route)
{
	// Put the package in the queue and update the interface
	m.interface = best_route->interface;

	packet *copy_m = malloc(sizeof(m));
	DIE(copy_m == NULL, "Can't alloc a packet.");
	memcpy(copy_m, &m, sizeof(m));

	queue_enq(*q_packets, copy_m);
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc, i;

	init(argc - 2, argv + 2);

	// Create the package queue
	queue q_packets = queue_create();

	// Parse the route table
	parse_route_table(argv[1]);

	// Create (and alloc) the arp table
	create_arp_table();

	// Sort the array of structures, extracted from the route table file
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), cmpfunc);

	while (1)
	{
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct arp_header *arp_hdr = parse_arp(m.payload);
		struct icmphdr *icmp_hdr = parse_icmp(m.payload);
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload 
								+ sizeof(struct ether_header));

		// If is an arp packet
		if (arp_hdr != NULL)
		{
			// If is an arp_request and it is for me
			if (((ntohs(arp_hdr->op)) == ARPOP_REQUEST) 
				&& (inet_addr(get_interface_ip(m.interface)) == arp_hdr->tpa))
			{
				arp_reply_with_my_mac(m, arp_hdr);
				continue;
			}

			// If is an arp_replay and the mac received it isn't in the
			// arp table, update the arp table with a new entry
			// (arp_hdr.spa, arp_hdr->sha)
			// Dequeue the packet
			if ((ntohs(arp_hdr->op)) == ARPOP_REPLY)
			{
				// Extact the ip and the mac received
				uint32_t daddr = arp_hdr->spa;
				uint8_t mac[ETH_ALEN];
				for (i = 0; i < ETH_ALEN; i++)
				{
					mac[i] = arp_hdr->sha[i];
				}

				// Construct a new entry in the arp table
				struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
				DIE(new_entry == NULL, "Can't alloc a new_entry in arp_table.");

				memcpy(&new_entry->ip, &daddr, sizeof(daddr));
				memcpy(&new_entry->mac, &mac, sizeof(mac));

				// Update the table
				update_arp_table(*new_entry);

				// Dequeue the packet
				dequeue_packets(&q_packets, mac, arp_hdr);
				continue;
			}
		}

		// If is an ip packet
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		{
			// If it is for router
			if ((inet_addr(get_interface_ip(m.interface))) == ip_hdr->daddr)
			{
				// If is an icmp packet, reply only if is an icmp_echo_request
				if (icmp_hdr != NULL)
				{
					// If is icmp_echo_request
					if (icmp_hdr->type == ICMP_ECHO)
					{
						icmp_echo_reply_with_my_mac(ip_hdr, icmp_hdr, eth_hdr, m);
						continue;
					}
					continue;
				}
				continue;
			}

			// If ttl <= 1, send an icmp time excedeed
			if (ip_hdr->ttl <= 1)
			{
				icmp_error(eth_hdr, icmp_hdr, ip_hdr,
						   ICMP_TIME_EXCEEDED, 0, m);
				continue;
			}

			// Verify the checksum
			if (ip_checksum(ip_hdr, sizeof(struct iphdr)))
			{
				continue;
			}


			// If it's an ip packet and it's not intended for the router
			// have to pass it on

			// I'm looking in the routing table for the ip of the next_hop
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

			// It wasn't found in the routing table, so is
			// unreachable destination
			if (best_route == NULL)
			{
				icmp_error(eth_hdr, icmp_hdr, ip_hdr,
						   ICMP_DEST_UNREACH, ICMP_ECHOREPLY, m);

				continue;
			}

			// Update the ttl and the checksum using RFC 1624 algorithm
			bonus_checksum(ip_hdr);

			// If exist a next_hop, I'm looking for its mac in the arp table
			struct arp_entry *match_arp_entry = get_arp_entry(ip_hdr->daddr);

			// If I find the mac in the arp table, send that packet
			if (match_arp_entry != NULL)
			{
				// The source mac will be my mac, on the interface I 
				// communicate with next_hop
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);

				// The destination mac is the mac found in the arp table
				memcpy(eth_hdr->ether_dhost, &match_arp_entry->mac,
					   sizeof(match_arp_entry->mac));

				send_packet(best_route->interface, &m);
				continue;
			}

			// If I can't find the mac address in the arp table
			// I generate an arp_request for the daddr ip
			// and put the package in the queue
			else
			{
				uint8_t mac[ETH_ALEN];
				get_interface_mac(best_route->interface, mac);

				// I put the package in the queue and 
				// update the interface
				enqueue_packet(&q_packets, m, best_route);

				arp_request(best_route, mac);
				continue;
			}
		}
	}
	free(rtable);
	free(arp_table);
}
