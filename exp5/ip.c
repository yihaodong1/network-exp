#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// If the packet is ICMP echo request and the destination IP address is equal to the IP address of the iface, send ICMP echo reply.
// Otherwise, forward the packet.
// Tips:
// You can use struct iphdr *ip = packet_to_ip_hdr(packet); in ip.h to get the ip header in a packet.
// You can use struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip); in ip.h to get the icmp header in a packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
	u32 daddr = ntohl(ip->daddr);
	log(INFO, "iface if: "IP_FMT" daddr: "IP_FMT", protocol: %d, length: %d", 
		HOST_IP_FMT_STR(iface->ip), HOST_IP_FMT_STR(daddr), ip->protocol, ntohs(ip->tot_len));
	if (icmp->type == ICMP_ECHOREQUEST && daddr == iface->ip) {
		icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
	} else {
		ip_forward_packet(ip->daddr, packet, len);
	}
}

// When forwarding the packet, you should check the TTL, update the checksum and TTL.
// Then, determine the next hop to forward the packet, then send the packet by iface_send_packet_by_arp.
// The interface to forward the packet is specified by longest_prefix_match.
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	if(ip->ttl == 0 || (ip->ttl - 1) == 0) {
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
	}else{
		rt_entry_t *rt = longest_prefix_match(ntohl(ip->daddr));
		if(rt){
			ip->ttl -= 1;
			ip->checksum = ip_checksum(ip);
			iface_info_t *iface = rt->iface;
			if(rt->gw == 0){
				// next hop in the same network with iface
				iface_send_packet_by_arp(iface, ip->daddr, packet, len);
			}else{
				iface_send_packet_by_arp(iface, htonl(rt->gw), packet, len);
			}
		}else{
			log(INFO, "No route to host");
			icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		}
	}
}
