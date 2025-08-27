#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "ip.h"
#include "ether.h"
#include "icmp.h"
// handle arp packet
// If the dest ip address of this arp packet is not equal to the ip address of the incoming iface, drop it.
// If it is an arp request packet, send arp reply to the destination, insert the ip->mac mapping into arpcache.
// If it is an arp reply packet, insert the ip->mac mapping into arpcache.
// Tips:
// You can use functions: htons, htonl, ntohs, ntohl to convert host byte order and network byte order (16 bits use ntohs/htons, 32 bits use ntohl/htonl).
// You can use function: packet_to_ether_arp() in arp.h to get the ethernet header in a packet.
void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *arp = packet_to_ether_arp(packet);
	log(INFO, "received ARP packet: op=%d, sha="ETHER_STRING", spa="IP_FMT", tha="ETHER_STRING", tpa="IP_FMT,
		ntohs(arp->arp_op), ETHER_FMT(arp->arp_sha), NET_IP_FMT_STR(arp->arp_spa),
		ETHER_FMT(arp->arp_tha), NET_IP_FMT_STR(arp->arp_tpa));
	log(INFO, "iface ip: "IP_FMT, HOST_IP_FMT_STR(iface->ip));
	if (ntohl(arp->arp_tpa) != iface->ip) {
		return;
	}
	if (ntohs(arp->arp_op) == ARPOP_REQUEST) {
		arp_send_reply(iface, arp);
		arpcache_insert(arp->arp_spa, arp->arp_sha);
	} else if (ntohs(arp->arp_op) == ARPOP_REPLY) {
		arpcache_insert(arp->arp_spa, arp->arp_sha);
	}
}

// send an arp reply packet
// Encapsulate an arp reply packet, send it out through iface_send_packet.
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	log(INFO, "send reply");
	int arp_len = ETHER_HDR_SIZE + sizeof(struct ether_arp);
	char *packet = malloc(arp_len);
	struct ether_header *eh = (struct ether_header *)packet;
	struct ether_arp *arp_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);

	// fill ethernet header
	eh->ether_type = htons(ETH_P_ARP);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	memcpy(eh->ether_dhost, req_hdr->arp_sha, ETH_ALEN);

	// fill arp header
	arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr->arp_pro = htons(ETH_P_IP);
	arp_hdr->arp_hln = ETH_ALEN;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARPOP_REPLY);
	memcpy(arp_hdr->arp_sha, iface->mac, ETH_ALEN);
	arp_hdr->arp_spa = ntohl(iface->ip);
	memcpy(arp_hdr->arp_tha, req_hdr->arp_sha, ETH_ALEN);
	arp_hdr->arp_tpa = req_hdr->arp_spa;

	iface_send_packet(iface, packet, arp_len);
	// free(packet);
}

// send an arp request
// Encapsulate an arp request packet, send it out through iface_send_packet.
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	log(INFO, "send arp request for "IP_FMT, HOST_IP_FMT_STR(dst_ip));
	int arp_len = ETHER_HDR_SIZE + sizeof(struct ether_arp);
	char *packet = malloc(arp_len);
	struct ether_header *eh = (struct ether_header *)packet;
	struct ether_arp *arp_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);

	// fill ethernet header
	eh->ether_type = htons(ETH_P_ARP);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	memset(eh->ether_dhost, 0xff, ETH_ALEN);

	// fill arp header
	arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr->arp_pro = htons(ETH_P_IP);
	arp_hdr->arp_hln = ETH_ALEN;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARPOP_REQUEST);
	memcpy(arp_hdr->arp_sha, iface->mac, ETH_ALEN);
	arp_hdr->arp_spa = htonl(iface->ip);
	memset(arp_hdr->arp_tha, 0, ETH_ALEN);
	arp_hdr->arp_tpa = htonl(dst_ip);

	iface_send_packet(iface, packet, arp_len);
	// free(packet);
}

// send (IP) packet through arpcache lookup
// Lookup the mac address of dst_ip in arpcache.
// If it is found, fill the ethernet header and emit the packet by iface_send_packet.
// Otherwise, pending this packet into arpcache and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	eh->ether_type = htons(ETH_P_IP);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	u8 mac[ETH_ALEN];
	log(INFO, "look for MAC address of IP "IP_FMT, NET_IP_FMT_STR(dst_ip));
	if (arpcache_lookup(dst_ip, mac)) {
		log(INFO, "find");
		memcpy(eh->ether_dhost, mac, ETH_ALEN);

		iface_send_packet(iface, packet, len);
	} else {
		log(INFO, "not found");
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
