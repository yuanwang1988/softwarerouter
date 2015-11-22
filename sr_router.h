/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;
struct sr_nat;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
    
    /* -- nat --*/
    int nat_mode;
    struct sr_nat* nat;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );


/*new*/
void send_arp_request(struct sr_instance* sr, struct sr_if* in_iface, uint32_t dest_ip);
void send_icmp_message(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* in_iface, uint8_t icmp_type, uint8_t icmp_code);
struct sr_rt* search_routing_table(struct sr_instance* sr, uint8_t * packet);

/* declaration of functions Oct12-zili*/
int chk_dest_ether_addr(struct sr_ethernet_hdr* ether_hdr, struct sr_if* iface);
void sr_handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* in_iface, struct sr_ethernet_hdr* ether_hdr);
void sr_handle_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* interface, struct sr_ethernet_hdr* ether_hdr);
int check_dest_ip_addr(struct sr_ip_hdr* ip_hdr, struct sr_instance* sr);
void forward_packet(struct sr_instance* sr, uint8_t* to_send_packet, unsigned int len, struct sr_if* in_iface);
struct sr_rt* search_routing_table(struct sr_instance* sr, uint8_t * packet);
struct sr_rt *sr_longest_prefix_match(struct sr_instance* sr, struct in_addr addr);

/* Yuan */
void sr_nat_handle_ip(struct sr_instance* sr, struct sr_nat *nat, uint8_t * packet, unsigned int len, struct sr_if* in_iface, struct sr_ethernet_hdr* ether_hdr);
void sr_nat_handle_icmp(struct sr_instance* sr, struct sr_nat *nat, uint8_t * packet, unsigned int len, struct sr_if* in_iface, struct sr_ethernet_hdr* ether_hdr);
struct sr_if* sr_match_dst_ip_to_iface(struct sr_instance* sr, struct sr_ip_hdr* ip_hdr);
struct sr_if* sr_get_outgoing_interface(struct sr_instance* sr, uint32_t ip);
int sr_check_if_internal(struct sr_if* in_iface);

/* Chenguang */

void sr_nat_handle_tcp(struct sr_instance* sr, struct sr_nat *nat, uint8_t * packet, unsigned int len, struct sr_if* in_iface, struct sr_ethernet_hdr* ether_hdr);
uint32_t tcp_cksum(struct sr_ip_hdr *ipHdr, struct sr_tcp_hdr *tcpHdr, int total_len);
int ip_cksum(struct sr_ip_hdr* ip_hdr);
int icmp_cksum(struct sr_ip_hdr* ip_hdr, struct sr_icmp_hdr* icmp_hdr);



#endif /* SR_ROUTER_H */
