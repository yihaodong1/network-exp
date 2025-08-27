#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// icmp_send_packet has two main functions:
// 1.handle icmp packets sent to the router itself (ICMP ECHO REPLY).
// 2.when an error occurs, send icmp error packets.
// Note that the structure of these two icmp packets is different, you need to malloc different sizes of memory.
// Some function and macro definitions in ip.h/icmp.h can help you.
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	struct iphdr *in_ip = packet_to_ip_hdr(in_pkt);
	struct icmphdr *in_icmp = (struct icmphdr *)IP_DATA(in_ip);
	struct iphdr *ip;
	int icmp_len = len - ETHER_HDR_SIZE - IP_HDR_SIZE(in_ip);
	char *packet = NULL;
	int total_len = 0;
	switch (type) {
		case ICMP_ECHOREPLY: {
			total_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len;
			packet = malloc(total_len);
			ip = packet_to_ip_hdr(packet);

			// fill ip header

			struct icmphdr *icmp = (struct icmphdr *)((u8*)ip + IP_BASE_HDR_SIZE);
			// fill icmp header
			icmp->type = type;
			icmp->code = code;
			icmp->icmp_identifier = in_icmp->icmp_identifier;
			icmp->icmp_sequence = in_icmp->icmp_sequence;
			memcpy((char *)icmp + ICMP_HDR_SIZE, 
			(char *)in_icmp + ICMP_HDR_SIZE, icmp_len - ICMP_HDR_SIZE);
			icmp->checksum = icmp_checksum(icmp, icmp_len);
			log(INFO, "send ICMP ECHOREPLY: "IP_FMT" -> "IP_FMT, 
				NET_IP_FMT_STR(ip->saddr), NET_IP_FMT_STR(ip->daddr));

			break;
		}
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED: {
			// handle ICMP_TIME_EXCEEDED
			// in_ip->ttl += 1;
			// in_ip->checksum = ip_checksum(in_ip);

			total_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + IP_HDR_SIZE(in_ip) + ICMP_COPIED_DATA_LEN;
			icmp_len = total_len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE;
			packet = malloc(total_len);
			ip = packet_to_ip_hdr(packet);

			// struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
			// icmp->type = type;
			// icmp->code = code;
			// icmp->icmp_identifier = 0;
			// icmp->icmp_sequence = 0;
			// // icmp->icmp_identifier = in_icmp->icmp_identifier;
			// // icmp->icmp_sequence = in_icmp->icmp_sequence;
			// memcpy((char *)icmp + ICMP_HDR_SIZE, (char *)in_ip, 
			// IP_HDR_SIZE(in_ip) + ICMP_COPIED_DATA_LEN);
			// icmp->checksum = icmp_checksum(icmp, icmp_len);

			struct icmphdr *icmp = (struct icmphdr *)((u8*)ip + IP_BASE_HDR_SIZE);
			// fill icmp header
			icmp->type = type;
			icmp->code = code;
			icmp->icmp_identifier = 0;
			icmp->icmp_sequence = 0;
			memcpy((char *)icmp + ICMP_HDR_SIZE, 
			(char *)in_ip, icmp_len - ICMP_HDR_SIZE);
			// memcpy((char *)icmp + ICMP_HDR_SIZE,
			// (char *)in_ip + IP_HDR_SIZE(in_ip), ICMP_COPIED_DATA_LEN);
			icmp->checksum = icmp_checksum(icmp, icmp_len);
			// icmp->checksum = icmp_checksum(icmp, ICMP_HDR_SIZE + ICMP_COPIED_DATA_LEN);

			log(INFO, "checksum: 0x%x", icmp->checksum);
			log(INFO, "send ICMP %s: "IP_FMT" -> "IP_FMT, 
				type == ICMP_DEST_UNREACH ? "DEST_UNREACH" : "TIME_EXCEEDED",
				NET_IP_FMT_STR(ip->saddr), NET_IP_FMT_STR(ip->daddr));
			break;
		}
		default:
			log(ERROR, "Unknown icmp type: %d, code: %d", type, code);
	}
	if(packet){
		log(INFO, "icmplen: %d, total len: %d", icmp_len, total_len);
		ip_init_hdr(ip, ntohl(in_ip->daddr), ntohl(in_ip->saddr), 
			icmp_len + IP_BASE_HDR_SIZE, IPPROTO_ICMP);
		ip_send_packet(packet, total_len);
		// free(packet);
	}
}
void icmp_send_packet1(const char* in_pkt, int len, u8 type, u8 code)
{
  int icmp_len; // [rsp+30h] [rbp-40h]
  uint32_t in_daddr; // [rsp+34h] [rbp-3Ch]
  uint32_t in_saddr; // [rsp+38h] [rbp-38h]
  u32 *in_ip; // [rsp+40h] [rbp-30h]
  uint32_t *in_icmp; // [rsp+48h] [rbp-28h]
  void *s; // [rsp+50h] [rbp-20h]
  char* ip; // [rsp+58h] [rbp-18h]
  char* entry; // [rsp+68h] [rbp-8h]

  in_ip = (uint32_t *)packet_to_ip_hdr(in_pkt);
  in_icmp = &in_ip[*(char *)in_ip & 0xF];
  if ( type )
  {
    icmp_len = 4 * (*(char *)in_ip & 0xF) + 16;
    len = 4 * (*(char *)in_ip & 0xF) + 50;
  }
  else
  {
    icmp_len = ntohs(*((uint16_t *)in_ip + 1)) - 4 * (*(char *)in_ip & 0xF);
  }
  s = malloc(len);
  if ( !s )
  {
	log(ERROR, "malloc packet failed when sending icmp packet.");
  }
  memset(s, 0, len);
  ip = (char *)packet_to_ip_hdr(s);
  *(char *)(ip + 20) = type;
  *(char *)(ip + 21) = code;
  if ( type )
  {
    memcpy((void *)(ip + 28), in_ip, icmp_len - 8LL);
  }
  else
  {
    *(uint16_t *)(ip + 24) = *((uint16_t *)in_icmp + 2);
    *(uint16_t *)(ip + 26) = *((uint16_t *)in_icmp + 3);
    memcpy((void *)(ip + 28), in_icmp + 2, icmp_len - 8LL);
  }
  *(uint16_t *)(ip + 22) = icmp_checksum((struct icmphdr*)(ip + 20), (unsigned int)icmp_len);
  in_saddr = ntohl(in_ip[3]);
  if ( !type )
  {
    in_daddr = ntohl(in_ip[4]);
LABEL_17:
    ip_init_hdr((struct iphdr *)ip, in_daddr, in_saddr, (uint16_t)(icmp_len + 20), 1);
	log(INFO, "icmplen: %d, total len: %d", icmp_len, len);
    ip_send_packet(s, (unsigned int)len);
    return;
  }
  entry = (char *)longest_prefix_match(in_saddr);
  if ( entry )
  {
    in_daddr = *(uint32_t *)(*(uint64_t *)(entry + 48) + 32LL);
    goto LABEL_17;
  }
  log(ERROR, "could not route packet");
  free(s);
}
