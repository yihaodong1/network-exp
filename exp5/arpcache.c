#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include "log.h"
#include "ip.h"

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweep thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// look up the IP->mac mapping, need pthread_mutex_lock/unlock
// Traverse the table to find whether there is an entry with the same IP and mac address with the given arguments.
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	pthread_mutex_lock(&arpcache.lock);
	ip4 = ntohl(ip4);
	for(int i = 0; i < MAX_ARP_SIZE; i++) {
		if(arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4) {
			memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
			pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// insert the IP->mac mapping into arpcache, need pthread_mutex_lock/unlock
// If there is a timeout entry (attribute valid in struct) in arpcache, replace it.
// If there isn't a timeout entry in arpcache, randomly replace one.
// If there are pending packets waiting for this mapping, fill the ethernet header for each of them, and send them out.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(用arp_req结构体封装)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	pthread_mutex_lock(&arpcache.lock);
	ip4 = ntohl(ip4);
	int replace_idx;
	for(replace_idx = 0; replace_idx < MAX_ARP_SIZE; replace_idx++) {
		if(arpcache.entries[replace_idx].valid && arpcache.entries[replace_idx].ip4 == ip4) {
			log(INFO, "update arpcache entry for "IP_FMT"->"ETHER_STRING, HOST_IP_FMT_STR(ip4), ETHER_FMT(mac));
			break;
		}
	}
	for(replace_idx = 0; replace_idx < MAX_ARP_SIZE; replace_idx++) {
		if(!arpcache.entries[replace_idx].valid) {
			// Insert the new entry
			break;
		}
	}
	// If there is no valid entry, find a random entry to replace
	if(replace_idx == MAX_ARP_SIZE)
		replace_idx = rand() % MAX_ARP_SIZE;
	// Insert the new entry
	arpcache.entries[replace_idx].valid = 1;
	arpcache.entries[replace_idx].ip4 = ip4;
	arpcache.entries[replace_idx].added = time(NULL);
	memcpy(arpcache.entries[replace_idx].mac, mac, ETH_ALEN);
	log(INFO, "insert "IP_FMT"->"ETHER_STRING, HOST_IP_FMT_STR(ip4), ETHER_FMT(mac));
	struct arp_req *arpreq_pos, *arpreq_q;
	list_for_each_entry_safe(arpreq_pos, arpreq_q, &(arpcache.req_list), list) {
		if(ip4 == arpreq_pos->ip4) {
			log(INFO, "found pending packets for "IP_FMT, HOST_IP_FMT_STR(ip4));
			struct cached_pkt *pkt_pos, *pkt_q;
			list_for_each_entry_safe(pkt_pos, pkt_q, &(arpreq_pos->cached_packets), list) {
				struct ether_header *eh = (struct ether_header *)pkt_pos->packet;
				memcpy(eh->ether_dhost, mac, ETH_ALEN);
				iface_send_packet(arpreq_pos->iface, pkt_pos->packet, pkt_pos->len);
				list_delete_entry(&(pkt_pos->list));
				free(pkt_pos);
			}
			list_delete_entry(&(arpreq_pos->list));
			free(arpreq_pos);
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
}

// append the packet to arpcache
// Look up in the list which stores pending packets, if there is already an entry with the same IP address and iface, 
// which means the corresponding arp request has been sent out, just append this packet at the tail of that entry (The entry may contain more than one packet).
// Otherwise, malloc a new entry with the given IP address and iface, append the packet, and send arp request.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	pthread_mutex_lock(&arpcache.lock);
	ip4 = ntohl(ip4);
	log(INFO, "append packet for "IP_FMT", iface: %s", HOST_IP_FMT_STR(ip4), iface->name);
	struct arp_req *req_entry = NULL;
	list_for_each_entry(req_entry, &arpcache.req_list, list) {
		if(req_entry->ip4 == ip4 && req_entry->iface == iface) {
			// Found the existing entry, append the packet
			struct cached_pkt *new_pkt = malloc(sizeof(struct cached_pkt));
			new_pkt->packet = packet;
			new_pkt->len = len;
			list_add_tail(&(new_pkt->list), &(req_entry->cached_packets));
			pthread_mutex_unlock(&arpcache.lock);
			return;
		}
	}
	// No existing entry found, create a new one
	req_entry = malloc(sizeof(struct arp_req));
	req_entry->retries = 1;
	time(&req_entry->sent);
	req_entry->ip4 = ip4;
	req_entry->iface = iface;
	init_list_head(&(req_entry->cached_packets));
	struct cached_pkt *new_pkt = malloc(sizeof(struct cached_pkt));
	new_pkt->packet = packet;
	new_pkt->len = len;
	list_add_tail(&(new_pkt->list), &(req_entry->cached_packets));
	list_add_tail(&(req_entry->list), &(arpcache.req_list));
	arp_send_request(iface, ip4);
	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
// for IP->mac entry, if the entry has been in the table for more than 15 seconds, remove it from the table
// for pending packets, if the arp request is sent out 1 second ago, while the reply has not been received, retransmit the arp request
// If the arp request has been sent 5 times without receiving arp reply, for each pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these packets
// tips
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		time_t now = time(NULL);
		for(int i = 0; i < MAX_ARP_SIZE; i++) {
			if(arpcache.entries[i].valid && now - arpcache.entries[i].added > ARP_ENTRY_TIMEOUT) {
				arpcache.entries[i].valid = 0;
				log(INFO, "remove arpcache entry for "IP_FMT, HOST_IP_FMT_STR(arpcache.entries[i].ip4));
			}
		}
		struct arp_req *pos;
		list_for_each_entry(pos, &arpcache.req_list, list) {
			if(now - pos->sent >= 1) {
				if(pos->retries >= ARP_REQUEST_MAX_RETRIES) {
					log(INFO, "arp request for "IP_FMT" retries times exceed", HOST_IP_FMT_STR(pos->ip4));
					struct cached_pkt *pkt_pos, *pkt_q;
					list_for_each_entry_safe(pkt_pos, pkt_q, &(pos->cached_packets), list) {
						icmp_send_packet(pkt_pos->packet, pkt_pos->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
						list_delete_entry(&(pkt_pos->list));
						free(pkt_pos->packet);
						free(pkt_pos);
					}
					list_delete_entry(&(pos->list));
					free(pos);
					break;
				} else {
					arp_send_request(pos->iface, pos->ip4);
					pos->retries++;
					time(&pos->sent);
				}
			}
		}
	}

	return NULL;
}
