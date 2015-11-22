/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include <stdint.h>
/*#include <malloc.h>*/
#include "stdlib.h"
#include <string.h>
#include <arpa/inet.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* fill in code here */

    struct sr_if* in_iface = sr_get_interface(sr, interface); /*packet come in from this interface*/
    struct sr_ethernet_hdr* ether_hdr = (struct sr_ethernet_hdr*)packet;

    /*printf("---------------start first print: all possible headers-------------");
    print_hdrs(packet, len);
    printf("---------------end first print: all possible headers-------------");*/

	if(chk_dest_ether_addr(ether_hdr, in_iface)) /*check dest ethernet address*/
	{
        uint16_t ether_type = ether_hdr->ether_type;
        if(htons(ether_type) == ethertype_ip) /*it's ip packet*/
        {
        	Debug("\nReceived IP Packet, length = %d. Call handle_ip_packet\n", len);
			if (sr->nat_mode == 1) {
				Debug("NAT mode activated");
				sr_nat_handle_ip(sr, &(sr->nat), packet, len, in_iface, ether_hdr);
			}
			else {
				Debug("NAT mode inactive; run normal simple router");
				sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
			}
        }
        else if(htons(ether_type) == ethertype_arp) /*it's arp packet*/
        {
        	Debug("\nReceived ARP Packet, length = %d. Call handle_arp_packet\n", len);
	        sr_handle_arp_packet(sr, packet, len, in_iface, ether_hdr);
        }
	}
}/* end sr_ForwardPacket */

/*
 * handle ip packet
 */
void sr_handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* in_iface, struct sr_ethernet_hdr* ether_hdr)
{
	/*New*/
	if (len < sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr))
    {
        printf("ERROR: Ethernet frame did not meet minimum Ethernet + IP length. Dropping. \n");
        return;
    }

	struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));  
    
	/*New*/
	if (len < sizeof(struct sr_ethernet_hdr) + ip_hdr->ip_hl*4)
    {
        printf("ERROR: Ethernet frame did not meet minimum Ethernet + IP calculated length. Dropping. \n");
        return;
    }  

	/*IP checksum*/
	uint16_t rcv_cksum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	/*New*/
	/*uint16_t cal_cksum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));*/
	uint16_t cal_cksum = cksum(ip_hdr, ip_hdr->ip_hl*4);

	if (cal_cksum != rcv_cksum)
	{
		Debug("\nChecksum incorrect; Drop Packet\n");
        return;
	}	

	if(check_dest_ip_addr(ip_hdr, sr) == 1) /*dest is router*/
	{
		/*if(ip_hdr->ip_ttl < 1)
       	        {
               		 Debug("\nTTL less than or equal to 1; Drop Packet\n");
               		 send_icmp_message(sr, packet, len, in_iface, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE);
                	 return;
        	}

		Debug("\nIP packet; destination -> router\n");
		uint8_t protocol_type = ip_hdr->ip_p;*/
		
		/*printf("\n*******************print protocol_type:%d, ip_protocol_icmp:%d***************************\n", protocol_type,ip_protocol_icmp);*/
		
		/* judge type : icmp echo or not*/
        uint8_t protocol_type = ip_hdr->ip_p;
		if(protocol_type == ip_protocol_icmp) /*it's an icmp packet*/
		{
			Debug("\nIP packet; destination -> router; type = ICMP\n");
			struct sr_icmp_hdr* icmp_hdr= (struct sr_icmp_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

			/*ICMP checksum*/
			/*New*/
			uint16_t icmp_expected_cksum;
            uint16_t icmp_received_cksum;

            icmp_received_cksum = icmp_hdr->icmp_sum;
            icmp_hdr->icmp_sum = 0;
            icmp_expected_cksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4);

            if (icmp_received_cksum != icmp_expected_cksum)
            {
                printf("ERROR: ICMP packet checksum. Dropping. \n");
                return;
            }
			/*ICMP checksum end*/

			if(icmp_hdr->icmp_type == ICMP_ECHO_REQUEST_TYPE && icmp_hdr->icmp_code == ICMP_ECHO_REQUEST_CODE) /*it' an icmp echo request*/
			{
				Debug("\nIP packet; destination -> router; IP type = ICMP; ICMP type = Echo\n");
				/*send an echo reply.*/

				/*fill icmp message*/
				struct sr_icmp_hdr* to_send_icmp_hdr = ((struct sr_icmp_hdr*)malloc(sizeof(struct sr_icmp_hdr)));

				to_send_icmp_hdr->icmp_type = ICMP_ECHO_REPLY_TYPE;   /*type*/
				to_send_icmp_hdr->icmp_code = ICMP_ECHO_REPLY_CODE;   /*code*/
				to_send_icmp_hdr->icmp_sum =  0;                      /*checksum*/

				/*fill ip message*/

				struct sr_ip_hdr* to_send_ip_hdr = ((struct sr_ip_hdr*)malloc(sizeof(struct sr_ip_hdr)));

                to_send_ip_hdr->ip_v = ip_hdr->ip_v;
                to_send_ip_hdr->ip_hl = ip_hdr->ip_hl;

                to_send_ip_hdr->ip_tos = ip_hdr->ip_tos;     /*type of service*/
                to_send_ip_hdr->ip_len = ip_hdr->ip_len;     /*total length*/
                to_send_ip_hdr->ip_id = ip_hdr->ip_id;       /*identification*/
                to_send_ip_hdr->ip_off = ip_hdr->ip_off;     /*offset*/
                to_send_ip_hdr->ip_ttl = 64;                 /*TTL = 64*/
                to_send_ip_hdr->ip_p = ip_hdr->ip_p;         /*protocol*/
                to_send_ip_hdr->ip_sum = 0;                  /*checksum*/
                to_send_ip_hdr->ip_src = ip_hdr->ip_dst;     /*source IP address*/
                to_send_ip_hdr->ip_dst = ip_hdr->ip_src;     /*destination IP address*/

                /*to_send_ip_hdr->ip_sum = cksum(to_send_ip_hdr, sizeof(struct sr_ip_hdr)); */ /* recalculate checksum need information of other parts of header.*/
				/*New*/
				to_send_ip_hdr->ip_sum = cksum(to_send_ip_hdr, to_send_ip_hdr->ip_hl*4);

				/*encapsulate in ethernet frame.*/
				
				struct sr_ethernet_hdr* to_send_ether_hdr = (struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));

				int i;
                for (i = 0; i < ETHER_ADDR_LEN; i++)
                {
                    to_send_ether_hdr->ether_dhost[i] = 255;  /*destination address : broadcast*/
                } 

                for (i = 0; i < ETHER_ADDR_LEN; i++)
                {
                    to_send_ether_hdr->ether_shost[i] = ((uint8_t)(in_iface->addr[i]));  /*source address*/
                }         
                to_send_ether_hdr->ether_type = ether_hdr->ether_type;


                /*assemble the packet header*/
                uint8_t * to_send_packet = ((uint8_t*)(malloc(sizeof(uint8_t)*len)));

                memcpy(to_send_packet, to_send_ether_hdr, sizeof(struct sr_ethernet_hdr));
                memcpy(to_send_packet + sizeof(struct sr_ethernet_hdr), to_send_ip_hdr, sizeof(struct sr_ip_hdr));
                memcpy(to_send_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), to_send_icmp_hdr, sizeof(struct sr_icmp_hdr));

                /*assamble data into packet*/
                unsigned int n;
                for (n = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr); n < len; n++)
                {
                    to_send_packet[n] = packet[n];
                }


                /*icmp checksum check both icmp header and data, need to be ralculated after forming a whole packet*/
				struct sr_icmp_hdr* final_icmp_hdr = (struct sr_icmp_hdr*)(to_send_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
				final_icmp_hdr->icmp_sum = cksum(to_send_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), len - (sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)));


				/*look up routing table*/
				/*New*/
				struct in_addr dest_ip_ad;
				dest_ip_ad.s_addr = to_send_ip_hdr->ip_dst;
				struct sr_rt* result_route = sr_longest_prefix_match(sr, dest_ip_ad);
				/*struct sr_rt* result_route = search_routing_table(sr, to_send_packet);*/
				if (result_route == NULL)
				{
					send_icmp_message(sr, packet, len, in_iface, 3, 0);
					return;
				}
				/*end look up routing table*/

				struct sr_if* out_iface = sr_get_interface(sr, result_route->interface);
	            struct in_addr next_hop_ip = result_route->gw;
	            Debug("\nIP packet; destination -> router; type = ICMP; ICMP type = Echo; \n");
	            
				if (out_iface != NULL)
				{
					Debug("\nIP packet; destination -> router; type = ICMP; ICMP type = Echo; Call ARP Lookup \n");
					struct sr_ethernet_hdr* ether_hdr = (struct sr_ethernet_hdr*)to_send_packet;
					for(i=0; i< ETHER_ADDR_LEN ; i++)
					{
						ether_hdr->ether_shost[i]=out_iface->addr[i];
					}
					sr_check_and_send_arp(sr, to_send_packet, next_hop_ip.s_addr, out_iface, len);
				}
				else
				{
					Debug("Error: When handle IP packet, cannot found out_iface");
				}

                /*free headers*/
                free(to_send_icmp_hdr);
                free(to_send_ip_hdr);
                free(to_send_ether_hdr);
			}
			else /*it's an icmp but not an icmp echo*/
			{
				printf("ERROR: ICMP packet was not an echo request. Dropping. \n");
                return;
			}
		}
		else /*it's a tcp or udp packet*/
		{
			/*send icmp port unreachable*/
			Debug("\nIP packet; destination -> router; type = not ICMP; Respond with ICMP msg - destination not reachable \n");
			struct sr_ip_hdr* to_send_ip_hdr = (struct sr_ip_hdr*)(packet+sizeof(struct sr_ethernet_hdr));
			to_send_ip_hdr->ip_sum = rcv_cksum;
			send_icmp_message(sr, packet, len, in_iface, ICMP_DESTINATION_UNREACHABLE_TYPE, ICMP_PORT_UNREACHABLE_CODE);
		}
	}
	else  /*dest is not our router, we should forward it*/
	{
	    if(ip_hdr->ip_ttl <= 1)
  	    {
          	Debug("\nTTL less than or equal to 1; Drop Packet\n");
            send_icmp_message(sr, packet, len, in_iface, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE);
            return; /*drop the packet*/
        }

		Debug("\nIP packet; destination -> not router; call forward_packet \n");
		forward_packet(sr, packet, len, in_iface);
	}

}

/*
 * check if dest ip is one of our router's interfaces
 */
int check_dest_ip_addr(struct sr_ip_hdr* ip_hdr,struct sr_instance* sr)
{
	struct sr_if* from_if = sr -> if_list;
    
	while(from_if != NULL)
    {
        if (ip_hdr->ip_dst == from_if->ip) /* dest is router*/
        {
            return 1;
        }
        from_if = from_if->next;
    }

    return 0; /*dest is another.*/
}

/*
 * send icmp type3 message
 */
void send_icmp_message(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* in_iface, uint8_t icmp_type, uint8_t icmp_code)  /*icmp type3*/
{
	Debug("\nsend_icmp_message called\n");
	/*printf("\n=================ICMP Header: %d==========================\n",sizeof(struct sr_icmp_t3_hdr));*/
	struct sr_ethernet_hdr* ether_hdr = (struct sr_ethernet_hdr*)packet;
    struct sr_ip_hdr* ip_hdr = ((struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr)));
	
	/*constrcut an icmp message*/
	struct sr_icmp_t3_hdr* to_send_icmp_hdr = (struct sr_icmp_t3_hdr*)(malloc(sizeof(struct sr_icmp_t3_hdr)));

	to_send_icmp_hdr->icmp_type = icmp_type;  /*type*/
	to_send_icmp_hdr->icmp_code = icmp_code;  /*code*/
	to_send_icmp_hdr->icmp_sum = 0;           /*checksum*/
	/*New*/
	to_send_icmp_hdr->unused = 0;
	to_send_icmp_hdr->next_mtu = 0;
	/*end new*/
	memcpy(to_send_icmp_hdr->data, ip_hdr, sizeof(struct sr_ip_hdr)+8);
	/*New*/
	to_send_icmp_hdr->icmp_sum = cksum(to_send_icmp_hdr,sizeof(to_send_icmp_hdr)+28);
	/*end new*/

	/*ecapsulate in ip message*/
	struct sr_ip_hdr* to_send_ip_hdr = (struct sr_ip_hdr*)(malloc(sizeof(struct sr_ip_hdr)));

    /*to_send_ip_hdr->ip_v = ip_hdr->ip_v;*/
    /*to_send_ip_hdr->ip_hl = ip_hdr->ip_hl;*/
	/*to_send_ip_hdr->ip_tos = ip_hdr->ip_tos;*/  /*type of service*/
	/*to_send_ip_hdr->ip_off = ip_hdr->ip_off;*/  /*offset*/
	/*New*/
	to_send_ip_hdr->ip_v = 4;
    to_send_ip_hdr->ip_hl = 5;
    to_send_ip_hdr->ip_tos = 0;
    to_send_ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));  /*total length*/
    to_send_ip_hdr->ip_id = ip_hdr->ip_id;    /*identification*/
    to_send_ip_hdr->ip_off = htons(0x4000);  /*offset*/
    to_send_ip_hdr->ip_ttl = 64;              /*TTL*/
    to_send_ip_hdr->ip_p = ip_protocol_icmp;  /*protocol*/
    to_send_ip_hdr->ip_sum = 0;               /*checksum*/
	to_send_ip_hdr->ip_dst = ip_hdr->ip_src; /*destination ip address*/
    /*if (icmp_type == 11)  
    {
		to_send_ip_hdr->ip_src = in_iface->ip;
    }
    else
    {
       to_send_ip_hdr->ip_src = ip_hdr->ip_dst; 
    }*/

	/*New*/
	struct in_addr dest_ip_ad;
    dest_ip_ad.s_addr = ip_hdr->ip_src;
    struct sr_rt *rt = sr_longest_prefix_match(sr, dest_ip_ad);
        
    struct sr_if *  outgoing_interface = sr_get_interface(sr, rt->interface);
    to_send_ip_hdr->ip_src = outgoing_interface->ip;  
	/*end new*/

    if (to_send_icmp_hdr->icmp_code == ICMP_HOST_UNREACHABLE_CODE)
    {
    to_send_ip_hdr->ip_src = in_iface->ip;
    }

    to_send_ip_hdr->ip_sum = cksum(((uint8_t*)(to_send_ip_hdr)), sizeof(struct sr_ip_hdr)); /*recalculate checksum*/


    /*encapsulate in ethernet frame.*/
	struct sr_ethernet_hdr* to_send_ether_hdr = (struct sr_ethernet_hdr*)(malloc(sizeof(struct sr_ethernet_hdr)));
	int i = 0;
    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
        to_send_ether_hdr->ether_dhost[i] = 255; /*destination address : broadcast*/
    }
    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
        to_send_ether_hdr->ether_shost[i] = ((uint8_t)(in_iface->addr[i])); /*source address*/
    }         
    to_send_ether_hdr->ether_type = ether_hdr->ether_type; /*type*/


    /*assemble the whole packet*/
    uint8_t * to_send_packet = ((uint8_t*)(malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr))));

    memcpy(to_send_packet, to_send_ether_hdr, sizeof(struct sr_ethernet_hdr));
    memcpy(to_send_packet + sizeof(struct sr_ethernet_hdr), to_send_ip_hdr, sizeof(struct sr_ip_hdr));
    memcpy(to_send_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), to_send_icmp_hdr, sizeof(struct sr_icmp_t3_hdr));


    /*copy the ip header that trrigered the error with 64bits original data*/
    /*memcpy(to_send_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr), ip_hdr, sizeof(struct sr_ip_hdr));
    unsigned int j = 0;
    for (j = 0; j < 8; j++)
    {
        to_send_packet[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr) + sizeof(struct sr_ip_hdr) + i] = packet[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + i];
    }*/

    /*icmp checksum check both icmp header and data, need to be ralculated after forming a whole packet*/
	/*((struct sr_icmp_t3_hdr*)(to_send_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)))->icmp_sum = cksum(to_send_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), sizeof(struct sr_icmp_t3_hdr) );*/


	/*look up routing table*/
	/*New*/
	struct sr_rt* result_route;
	struct in_addr dest_ip_addr;
    dest_ip_addr.s_addr = to_send_ip_hdr->ip_dst;
    result_route = sr_longest_prefix_match(sr, dest_ip_addr);
	/*end look up routing table*/

	if (result_route == NULL)
	{
		send_icmp_message(sr, packet, len, in_iface, 3, 0);
		return;
	}
    struct sr_if* out_iface = sr_get_interface(sr, result_route->interface);
	struct in_addr next_hop_ip = result_route->gw;
	            
	if (out_iface != NULL)
	{
	    struct sr_ethernet_hdr* ether_hdr = (struct sr_ethernet_hdr*)to_send_packet;
        for(i=0; i< ETHER_ADDR_LEN ; i++)
		{
            ether_hdr->ether_shost[i]=out_iface->addr[i];
        }
	    sr_check_and_send_arp(sr, to_send_packet, next_hop_ip.s_addr, out_iface, sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)+sizeof(struct sr_icmp_t3_hdr));
	}
	else
	{
		
	}

    /*free headers*/
    free(to_send_icmp_hdr);
    free(to_send_ip_hdr);
    free(to_send_ether_hdr);
}

/*
 * forward the packet
 */
void forward_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* in_iface)
{
	Debug("\nforward_packet called\n");

	printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	printf("len = %d\n", len);
	printf("sizeof(uint8_t) = %ud\n", sizeof(uint8_t));
	printf("sizeof(uint8_t)*len = %ud\n", sizeof(uint8_t)*len);
	printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");

	uint8_t * to_send_packet = ((uint8_t*)(malloc(sizeof(uint8_t)*len)));
	memcpy(to_send_packet, packet, len);
	
	struct sr_ip_hdr* to_send_ip_hdr = (struct sr_ip_hdr*)(to_send_packet + sizeof(struct sr_ethernet_hdr));
	
	/*update TTL and checksum*/
	to_send_ip_hdr->ip_ttl--;
	to_send_ip_hdr->ip_sum = 0;
	/*ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));*/
	/*New*/
	to_send_ip_hdr->ip_sum = cksum(to_send_ip_hdr, to_send_ip_hdr->ip_hl*4);

	/*look up routing table*/
	/*New*/
	struct in_addr dest_ip_ad;
	dest_ip_ad.s_addr = to_send_ip_hdr->ip_dst;
	struct sr_rt* result_route = sr_longest_prefix_match(sr, dest_ip_ad);
	/*struct sr_rt* result_route = search_routing_table(sr, to_send_packet);*/
	if (result_route == NULL)
	{
		send_icmp_message(sr, to_send_packet, len, in_iface, 3, 0);/*net unreachable            packet??????????????????????????*/
		return;
	}

	struct sr_if* out_iface = sr_get_interface(sr, result_route->interface);
	struct in_addr next_hop_ip = result_route->gw;
	            
	if (out_iface != NULL)
	{ 
	 	struct sr_ethernet_hdr* to_send_ether_hdr = (struct sr_ethernet_hdr*)to_send_packet;
        int i;
		for(i=0; i< ETHER_ADDR_LEN ; i++)
		{
			to_send_ether_hdr->ether_shost[i]=out_iface->addr[i];
        }
		/*struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));*/

		/*printf("------------ttl: %d---------------", ip_hdr->ip_ttl);*/
		sr_check_and_send_arp(sr, to_send_packet, next_hop_ip.s_addr, out_iface,len);

	}
	else
	{
		
	}
}

/*
 * handle arp packet
 */
void sr_handle_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* interface, struct sr_ethernet_hdr* ether_hdr)
{
	Debug("\nhandle_arp_packet called\n");
	struct sr_arp_hdr* arp_hdr = ((struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr)));

	unsigned short arp_opcode = arp_hdr->ar_op;
	if(htons(arp_opcode) == arp_op_request) /*it's an arp request*/
	{
		Debug("\nARP request received; sending ARP reply\n");
		/*construct an arp reply and send it back.*/
		struct sr_arp_hdr* to_send_arp = (struct sr_arp_hdr*)(malloc(sizeof(struct sr_arp_hdr)));

		/*fill fields of arp message*/
		to_send_arp->ar_hrd = arp_hdr->ar_hrd; /*hardware type*/
		to_send_arp->ar_pro = arp_hdr->ar_pro; /*protocol type*/
		to_send_arp->ar_hln = arp_hdr->ar_hln; /*hardware address length*/
		to_send_arp->ar_pln = arp_hdr->ar_pln; /*protocol address length*/
		to_send_arp->ar_op = ntohs(arp_op_reply);     /*opcode*/
		int i = 0;
		for (i = 0; i < ETHER_ADDR_LEN; i++)
        {
            to_send_arp->ar_sha[i] = ((unsigned char)(interface->addr[i])); /*source software address*/
        }
		
		to_send_arp->ar_sip = arp_hdr->ar_tip; /*source protocol address*/
        
		for (i = 0; i < ETHER_ADDR_LEN; i++)
        {
            to_send_arp->ar_tha[i] = arp_hdr->ar_sha[i]; /*destination hardware address*/
        }

		to_send_arp->ar_tip = arp_hdr->ar_sip; /*destination protocol address*/


		/*encapsulate arp in ethernet.*/
		struct sr_ethernet_hdr* to_send_ether_frame = (struct sr_ethernet_hdr*)(malloc(sizeof(struct sr_ethernet_hdr))); /* the ethernet packet to be sent*/

        for (i = 0; i < ETHER_ADDR_LEN; i++)
        {
            to_send_ether_frame->ether_dhost[i] = ether_hdr->ether_shost[i]; /*destination address*/
        }
        for (i = 0; i < ETHER_ADDR_LEN; i++)
        {
            to_send_ether_frame->ether_shost[i] = ((uint8_t)(interface->addr[i])); /*source address*/
        }
        to_send_ether_frame->ether_type = ether_hdr->ether_type;
	 

	    /*assemble a whole packet and send it.*/
	    uint8_t* to_send_packet = ((uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)));
		memcpy(to_send_packet, to_send_ether_frame, sizeof(struct sr_ethernet_hdr));
	    memcpy(to_send_packet + sizeof(struct sr_ethernet_hdr), to_send_arp, sizeof(struct sr_arp_hdr));

        sr_send_packet(sr, ((uint8_t*)(to_send_packet)), sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), interface->name);  /*why just a header?????*/
	    Debug("ARP reply packet sent");
        print_hdrs(to_send_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));

		/*free the memory.*/
        free(to_send_packet);
        free(to_send_arp);
		free(to_send_ether_frame);
	}
	else if(htons(arp_opcode) == arp_op_reply) /*receive an arp reply*/
	{
		Debug("\nARP reply received; calling handle_arpreply\n");
		/*Cache it. go through my request queue and send outstanding packets.*/
		sr_handle_arpreply(sr, ether_hdr->ether_shost, arp_hdr->ar_sip, interface);
	}
	else
	{
		
	}
}

/*
 * send arp request
 */
void send_arp_request(struct sr_instance* sr, struct sr_if* in_iface, uint32_t dest_ip)
{
	Debug("\nsend_arp_request called\n");
	struct sr_arp_hdr* to_send_arp = (struct sr_arp_hdr*)(malloc(sizeof(struct sr_arp_hdr)));

	to_send_arp->ar_hrd = htons(arp_hrd_ethernet); /*hardware type*/
	to_send_arp->ar_pro = htons(ethertype_ip);     /*protocol type*/
    to_send_arp->ar_hln = ETHER_ADDR_LEN;          /*hardware address length*/
    to_send_arp->ar_pln = 4;                      /*protocol address length*/
	to_send_arp->ar_op = htons(arp_op_request);    /*operation code*/
    int i = 0;
    for (i = 0; i < ETHER_ADDR_LEN; i++)       /*source hardware address*/
    {
        to_send_arp->ar_sha[i] = ((uint8_t)(in_iface->addr[i]));
    }
    to_send_arp->ar_sip = in_iface->ip;            /*source protocol address*/
    for (i = 0; i < ETHER_ADDR_LEN; i++)       /*target hardware address*/
    {
        to_send_arp->ar_tha[i] = 255;
    }
    to_send_arp->ar_tip = dest_ip;                 /*target protocol address*/

	/*encapsulate in ethernet frame*/
	struct sr_ethernet_hdr* to_send_ether_hdr = (struct sr_ethernet_hdr*)(malloc(sizeof(struct sr_ethernet_hdr)));
    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
        to_send_ether_hdr->ether_dhost[i] = 255;   /*dest*/
    }
    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
        to_send_ether_hdr->ether_shost[i] = ((uint8_t)(in_iface->addr[i]));   /*source*/
    }
	to_send_ether_hdr->ether_type = htons(ethertype_arp);    /*type*/

	/*assemble the packet*/
	uint8_t* to_send_packet = ((uint8_t*)(malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr))));
    memcpy(to_send_packet, to_send_ether_hdr, sizeof(struct sr_ethernet_hdr));
    memcpy(to_send_packet + sizeof(struct sr_ethernet_hdr), to_send_arp, sizeof(struct sr_arp_hdr));

	print_hdrs(to_send_packet,sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arp_hdr));
	/*send the packet*/
	sr_send_packet(sr, to_send_packet, sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arp_hdr), in_iface->name);

    /*free the memory.*/
    free(to_send_packet);
    free(to_send_arp);
    free(to_send_ether_hdr);
}

/*
 * check dest ethernet address (6 bytes)
 */
int chk_dest_ether_addr(struct sr_ethernet_hdr* ether_hdr, struct sr_if* iface)
{
	Debug("\ncheck_dest_ether_addr called\n");
	int i = 0;
    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
        if (ether_hdr->ether_dhost[i] != 255)  /*dest is not broadcast address*/
        {
            if (ether_hdr->ether_dhost[i] != ((uint8_t)(iface->addr[i]))) /*dest is not the interface where it came from*/
            {
            	Debug("\nError - check_dest_ether_addr detected error\n");
                return 0; /*error*/
            }
        }
    }
    Debug("\ncheck_dest_ether_addr OK\n");
    return 1; /*correct*/
}

/*
 * return the sr_rt of a dest ip from routing table
 */
struct sr_rt* search_routing_table(struct sr_instance* sr, uint8_t * packet)
{
	Debug("\nsearch_routing_table called\n");
	/*Yuan -> check with Chenguang on how to debug*/
	struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    /*lookup route table*/
	struct sr_rt* rt_item = sr->routing_table;
	struct sr_rt* default_route = NULL;
	struct sr_rt* result_route = NULL;  /*²é±íµÃµ½µÄÂ·ÓÉ½á¹û*/
	/*search route table item by item*/
    while(rt_item != NULL)
	{
		if (rt_item->dest.s_addr == 0) /*dest ip = 0.0.0.0*/
		{
			default_route = rt_item; /*Ä¬ÈÏÂ·ÓÉ*/
		}
		else
		{
			if (result_route == NULL)/* not hit*/
			{
				if ((rt_item->dest.s_addr & rt_item->mask.s_addr) == (ip_hdr->ip_dst & rt_item->mask.s_addr)) /*Ã»×ö×î³¤Ç°×ºÆ¥Åä£¬ÎÒÃÇÒª×ö£¿£¿£¿£¿£¿£¿*/
				{
					result_route = rt_item;
				}
			}
		}

		rt_item = rt_item->next;
	}

	struct sr_if* out_iface;
	struct in_addr next_hop_ip;

	if (result_route != NULL) /*ÕÒµ½ÁËÆ¥ÅäµÄÂ·ÓÉ±íÏî*/
	{
		out_iface = sr_get_interface(sr, result_route->interface);
		next_hop_ip = result_route->gw;
	}
	/*else if (default_route != NULL) 
	{
		out_iface = sr_get_interface(sr, default_route->interface);
		next_hop_ip = default_route->gw;

		result_route = default_route;
	}*/
	else
	{
		
	}
	return result_route;
}

/*
 * perform longest prefix match
 */
struct sr_rt *sr_longest_prefix_match(struct sr_instance* sr, struct in_addr addr)
{
    struct sr_rt* lpm = NULL;
    uint32_t lpm_len = 0;
    struct sr_rt* rt = sr->routing_table;
  
    while( rt != 0 ) 
    {
        if (((rt->dest.s_addr & rt->mask.s_addr) == (addr.s_addr & rt->mask.s_addr)) &&
              (lpm_len <= rt->mask.s_addr)) 
        {
              
            lpm_len = rt->mask.s_addr;
            lpm = rt;
        }
        
        rt = rt->next;
    }
    
    return lpm;
}


/*Yuan Code Start ============================================================================*/

void sr_nat_handle_ip(struct sr_instance* sr, struct sr_nat *nat, uint8_t * packet, unsigned int len, struct sr_if* in_iface, struct sr_ethernet_hdr* ether_hdr) {
    /*extract information from ip header needed to determine if icmp or tcp*/
    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    if (ip_hdr->ip_p == ip_protocol_icmp) {
        sr_nat_handle_icmp(sr, nat, packet, len, in_iface, ether_hdr);
    }
    else if (ip_hdr->ip_p == ip_protocol_tcp) {
        sr_nat_handle_tcp(sr, nat, packet, len, in_iface, ether_hdr);
    }
    else {
        return;
    }
}

    void sr_nat_handle_icmp(struct sr_instance* sr, struct sr_nat *nat, uint8_t * packet, unsigned int len, struct sr_if* in_iface, struct sr_ethernet_hdr* ether_hdr) {
        assert(sr);
        assert(nat);
        assert(packet);
        assert(len);
        assert(in_iface);
        
        /*extract information from ip header needed for processing icmp packet*/
        struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
        uint32_t src_ip_original = ip_hdr->ip_src;
        uint32_t dst_ip_original = ip_hdr->ip_dst;
        
        /*extract information from icmp header needed for processing icmp packet*/
        /*assumes this is a icmp echo or reply message for now; will recast later in the decision tree if diff type */
        struct sr_icmp_hdr* icmp_hdr= (struct sr_icmp_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
        uint8_t icmp_type = icmp_hdr->icmp_type; /*the icmp type is in the same location for icmp echo and icmp type 3*/
        uint16_t icmp_id_original = icmp_hdr->icmp_iden; /*this assumes icmp echo request or reply*/
        
        /*Perform checksum calculations*/
        if (ip_hdr->ip_sum != ip_cksum(ip_hdr)) {
            Debug("ICMP Packet - IP checksum failed; Drop");
            return;
        }
        if (icmp_hdr->icmp_sum != icmp_cksum(ip_hdr, icmp_hdr)) {
            Debug("ICMP Packet - ICMP checksum failed; Drop");
            return;
        }
        
        /*determine if the dest_ip is one of the router's interfaces*/
        struct sr_if* for_router_iface = sr_match_dst_ip_to_iface(sr, ip_hdr);
        
        /*if the dst_ip is not one of the router interfaces or in our routing table*/
        /*call simple router to send icmp t3 msg*/
        struct in_addr dest_ip_ad;
        dest_ip_ad.s_addr = dst_ip_original;
        if(!(for_router_iface)&&!(sr_longest_prefix_match(sr, dest_ip_ad))){
            Debug("ICMP packet - dst ip is not router interface or in routing table; respond with icmp t3 msg - net unreachable");
            /*call simple router*/
            sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
            return;
        }
        
        if(sr_check_if_internal(in_iface))
        {
            /*if the ICMP packet is from inside NAT*/
            
            /*check if the icmp packet is for router's interface or for inside NAT*/
            /*then call simple router*/
            if((for_router_iface)||sr_check_if_internal(sr_get_outgoing_interface(sr, dst_ip_original)))
            {
                
                
                /*call simple router*/
                sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
                return;
            }
            
            else
            {
                /*the icmp packet is from inside to outside; we will only process echo request
                 if the ICMP packet is an echo request from inside NAT to outside NAT, then we need to do translation*/
                if(icmp_type == ICMP_ECHO_REQUEST_TYPE)
                {
                    /*if ICMP packet is an echo request from inside NAT to outside NAT*/
                    
                    Debug("Client send icmp echo request to outside NAT");
                    
                    struct sr_nat_mapping* nat_map = sr_nat_lookup_internal(nat, src_ip_original, icmp_id_original, nat_mapping_icmp);
                    if (nat_map == NULL)
                    {
                        struct sr_if * out_iface = sr_get_outgoing_interface(sr, dst_ip_original);
                        struct sr_nat_mapping* nat_map = sr_nat_insert_mapping(nat, src_ip_original, icmp_id_original, nat_mapping_icmp, sr, out_iface->name);
                    }
                    ip_hdr->ip_src = nat_map->ip_ext;
                    icmp_hdr->icmp_iden = nat_map->aux_ext;
                    /*update check sums*/
                    ip_hdr->ip_sum = 0;
                    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
                    
                    int icmp_offset = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - icmp_offset);
                    
                    /*call simple router*/
                    sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
                    return;
                }
                else
                {
                    /*if ICMP packet is a type 3 error msg from inside NAT to outside NAT*/
                    struct sr_icmp_t3_hdr* icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
                    
                    Debug("Client sends type 3 or type 11 icmp message to outside NAT");
                }
            }
        }
        else if (!(sr_check_if_internal(in_iface))) {
            /*if the ICMP packet is from outside NAT
             then we will only handle echo reply and echo request to the external interface of router
             Ä
             check if the dest_ip not router interface
             then it can be for external host -> simple router; anything else we drop*/
            if(!(for_router_iface)){
                if (!(sr_check_if_internal(sr_get_outgoing_interface(sr, dst_ip_original)))){
                    /*call simple router*/
                    sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
                    return;
                }
                else{
                    /*drop packet*/
                    return;
                }
            }
            else{
                /*the icmp packet is for router interface
                 if it is an echo request, we will echo reply from the router's external interface
                 if it is an echo reply, we will do NAT translate and forward to internal client*/
                if (icmp_type == ICMP_ECHO_REQUEST_TYPE){
                    /*call simple router*/
                    sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
                    return;
                }
                else if(icmp_type == ICMP_ECHO_REPLY_TYPE){
                    Debug("Client send icmp echo request to outside NAT");
                    
                    struct sr_nat_mapping* nat_map = sr_nat_lookup_external(nat, icmp_id_original, nat_mapping_icmp);
                    if (nat_map == NULL){
                        /*if the icmp echo reply does not match any icmp echo request that we sent*/
                        /*drop*/
                        return;
                    }
                    ip_hdr->ip_dst = nat_map->ip_int;
                    icmp_hdr->icmp_iden = nat_map->aux_int;
                    /*update check sums*/
                    ip_hdr->ip_sum = 0;
                    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
                    
                    int icmp_offset = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - icmp_offset);
                    
                    /*call simple router*/
                    sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
                    return;
                }
                else
                {
                    Debug("ICMP type 3 or 11 msg from outside NAT to inside NAT");
                }
                
            }
            
            
            
            /*check if the dest_ip is for router
             
             if the dest_ip is not for router or external host, we drop the packet*/
            
        }
        
        else{
            
            
            /*call simple router*/
            Debug("Default behavior - call simple router; need to see if this is acceptable");
            sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
            return;
        }
        
        
        
    }
    
    /*function to return i_face struct of the router if the dest ip is for the i_face of the router*/
    struct sr_if* sr_match_dst_ip_to_iface(struct sr_instance* sr, struct sr_ip_hdr* ip_hdr)
    {
        assert(sr);
        assert(ip_hdr);
        struct sr_if* router_if = sr->if_list;
        
        while(router_if != NULL)
        {
            if (ip_hdr->ip_dst == router_if->ip) /* dest is router*/
            {
                return router_if;
            }
            router_if = router_if->next;
        }
        
        return NULL; /*dest is another.*/
    }
    
    
    /*function to map ip address to interface*/
    struct sr_if* sr_get_outgoing_interface(struct sr_instance* sr, uint32_t ip){
        assert(sr);
        assert(ip);
        
        struct in_addr dest_ip_ad;
        dest_ip_ad.s_addr = ip;
        struct sr_rt* result_route = sr_longest_prefix_match(sr, dest_ip_ad);
        char out_iface_name = result_route->interface;
        struct out_iface* out_iface = sr_get_interface(sr, out_iface_name);
        
        return out_iface;
    }
    
    
    /*function to check whether the receiving interface is internal or external*/
    int sr_check_if_internal(struct sr_if* in_iface){
        return strcmp(in_iface->name, "eth1");
    }
    
    /*Yuan Code Ends ============================================================================*/
    
    
    /*Chenguang Code Start=======================================================================*/
    
    void sr_nat_handle_tcp(struct sr_instance* sr, struct sr_nat *nat, uint8_t * packet, unsigned int len, struct sr_if* in_iface, struct sr_ethernet_hdr* ether_hdr)
    {
        /*extract information from ip header needed for processing icmp packet*/
        struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
        uint32_t src_ip_original = ip_hdr->ip_src;
        
        /*extract information from icmp header needed for processing icmp packet*/
        struct sr_tcp_hdr* tcp_hdr= (struct sr_tcp_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
        uint16_t tcp_src_port_original = tcp_hdr->src_port;
        uint16_t tcp_dst_port_original = tcp_hdr->dst_port;
        
        
        /*determine the outgoing interface*/
        uint32_t dst_ip = ip_hdr->ip_dst; /*use ip_dst to determine whether the destination is inside or outside of NAT*/
        struct sr_if* for_router_iface = sr_match_dst_ip_to_iface(sr, ip_hdr);
        
        /*Perform checksum calculations*/
        if (ip_hdr->ip_sum != ip_cksum(ip_hdr)) {
            Debug("ICMP Packet - IP checksum failed; Drop");
            return;
        }
        /*Sanity check on TCP packet*/
        /*We need to check TCP sum now since we will be updating it later*/
        if(tcp_cksum(ip_hdr, tcp_hdr, len) != 0){
            Debug("TCP packet received - TCP checksum failed; drop packet");
            return;
        }
        
        
        /*if the dst_ip is not one of the router interfaces or in our routing table*/
        /*call simple router to send icmp t3 msg*/
        struct in_addr dest_ip_ad;
        dest_ip_ad.s_addr = dst_ip;
        if(!(for_router_iface)&&!(sr_longest_prefix_match(sr, dest_ip_ad))){
            Debug("TCP packet received - dst ip is not router interface or in routing table; respond with icmp t3 msg - net unreachable");
            /*call simple router*/
            sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
            return;
        }
        
        
        if(sr_check_if_internal(in_iface))/*packet is from inside*/
        {
            if((for_router_iface)||sr_check_if_internal(sr_get_outgoing_interface(sr, dst_ip))) /*packet is for router or packet is for inside clients*/
            {
                /*call simple router*/
                sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
                return;
            }
            else /*packet is going outside*/
            {
                struct sr_nat_mapping* nat_map = sr_nat_lookup_internal(nat, src_ip_original, tcp_src_port_original, nat_mapping_tcp);
                if (nat_map == NULL)
                {
                    struct sr_if * out_iface = sr_get_outgoing_interface(sr, dst_ip);
                    struct sr_nat_mapping* nat_map = sr_nat_insert_mapping(nat, src_ip_original, tcp_src_port_original, nat_mapping_tcp, sr, out_iface->name);
                }
                
                /*lock*/
                pthread_mutex_lock(&((sr->nat)->lock));
                
                /*look up tcp connections*/
                struct sr_nat_connection *tcp_con = sr_nat_lookup_tcp_con(nat_map, dst_ip);/*sr_nat_lookup_tcp_con*/
                
                /*if there is no tcp connection, create a tcp connection*/
                if (tcp_con == NULL)
                {
                    tcp_con = sr_nat_insert_tcp_con(nat_map, dst_ip);/*sr_nat_insert_tcp_con*/
                }
                
                switch (tcp_con->tcp_state)
                {
                    case CLOSED:
                        if (ntohl(tcp_hdr->ack_num) == 0 && tcp_hdr->syn && !tcp_hdr->ack)/*sent SYN*/
                        {
                            tcp_con->client_isn = ntohl(tcp_hdr->seq_num);	/*set client ISN*/
                            tcp_con->tcp_state = SYN_SENT;					/*change TCP connection state*/
                        }
                        break;
                        
                    case SYN_RCVD:
                        if (ntohl(tcp_hdr->seq_num) == tcp_con->client_isn + 1 && ntohl(tcp_hdr->ack_num) == tcp_con->server_isn + 1 && !tcp_hdr->syn)/*This is our second packet, sent ACK, for both 3-way and simultaneous open*/
                        {
                            tcp_con->client_isn = ntohl(tcp_hdr->seq_num);	/*not isn, just keep client sequence number, not used*/
                            tcp_con->tcp_state = ESTABLISHED;					/*change TCP connection state*/
                        }
                        break;
                        
                    case ESTABLISHED:
                        if (tcp_hdr->fin && tcp_hdr->ack) /*sent FIN*/
                        {
                            tcp_con->client_isn = ntohl(tcp_hdr->seq_num);   /*not isn, just keep client sequence number, not used*/
                            tcp_con->tcp_state = CLOSED;					   /*change TCP connection state*/
                        }
                        break;
                        
                    default:
                        break;
                }
                tcp_con->last_updated = time(NULL);
                /*unlock*/
                pthread_mutex_unlock(&((sr->nat)->lock));
                /* End of critical section. */
                
                
                ip_hdr->ip_src = nat_map->ip_ext;
                tcp_hdr->src_port = htons(nat_map->aux_ext);
                
                /*checksum*/
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
                
                tcp_hdr->sum = tcp_cksum(ip_hdr, tcp_hdr, len);
                assert(tcp_hdr->sum);
                
                /*call simple router*/
                sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
                return;
            }
        }
        else if(!sr_check_if_internal(in_iface)) /*packet is from outside*/
        {
            if(!(for_router_iface))/*if it's not for router*/
            {
                if (!(sr_check_if_internal(sr_get_outgoing_interface(sr, dst_ip))))/*if its outgoing port is outside, then just use simple router to deal with it*/
                {
                    /*call simple router*/
                    sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
                    return;
                }
                else/*if it is to inside, drop it*/
                {
                    /*drop packet*/
                    return;
                }
            }
            else /*Inbound packet -> if it is for the router, use NAT*/
            {
                struct sr_nat_mapping *nat_map = sr_nat_lookup_external(&(sr->nat), ntohs(tcp_hdr->dst_port), nat_mapping_tcp);
                if(nat_map == NULL)
                {
                    return;
                }
                else
                {
                    /*lock*/
                    pthread_mutex_lock(&((sr->nat)->lock));
                    
                    struct sr_nat_connection *tcp_con = sr_nat_lookup_tcp_con(nat_map, src_ip_original);
                    if (tcp_con == NULL)
                    {
                        tcp_con = sr_nat_insert_tcp_con(nat_map, src_ip_original);
                    }
                    
                    switch (tcp_con->tcp_state)
                    {
                        case SYN_SENT:
                            if (ntohl(tcp_hdr->ack_num) == tcp_con->client_isn + 1 && tcp_hdr->syn && tcp_hdr->ack)
                            {
                                tcp_con->server_isn = ntohl(tcp_hdr->seq_num);
                                tcp_con->tcp_state = SYN_RCVD;
                            }
                            /* Simultaneous open */
                            else if (ntohl(tcp_hdr->ack_num) == 0 && tcp_hdr->syn && !tcp_hdr->ack)
                            {
                                tcp_con->server_isn = ntohl(tcp_hdr->seq_num);
                                tcp_con->tcp_state = SYN_RCVD;
                            }
                            break;
                        default:
                            break;
                    }
                    tcp_con->last_updated = time(NULL);
                    /*unlock*/
                    pthread_mutex_unlock(&((sr->nat)->lock));
                    
                    ip_hdr->ip_dst = nat_map->ip_int;
                    tcp_hdr->dst_port = htons(nat_map->aux_int);
                    
                    /*checksum*/
                    ip_hdr->ip_sum = 0;
                    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
                    
                    tcp_hdr->sum = tcp_cksum(ip_hdr, tcp_hdr, len);
                    
                    /*call simple router*/
                    sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
                    return;
                }
            }
            
        }
        
    }
    
    /*
     * calculate TCP checksum
     */
    uint32_t tcp_cksum(struct sr_ip_hdr *ipHdr, struct sr_tcp_hdr *tcpHdr, int total_len)
    {
        
        uint8_t *pseudo_tcp;
        struct sr_tcp_psuedo_hdr *tcp_psuedo_hdr;
        
        int tcp_len = total_len - (sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
        int pseudo_tcp_len = sizeof(struct sr_tcp_psuedo_hdr) + tcp_len;
        
        tcp_psuedo_hdr = malloc(sizeof(struct sr_tcp_psuedo_hdr));
        memset(tcp_psuedo_hdr, 0, sizeof(struct sr_tcp_psuedo_hdr));
        
        tcp_psuedo_hdr->ip_src = ipHdr->ip_src;
        tcp_psuedo_hdr->ip_dst = ipHdr->ip_dst;
        tcp_psuedo_hdr->ip_p = ipHdr->ip_p;
        tcp_psuedo_hdr->tcp_len = htons(tcp_len);
        
        uint16_t currCksum = tcpHdr->sum;
        tcpHdr->sum = 0;
        
        pseudo_tcp = malloc(sizeof(struct sr_tcp_psuedo_hdr) + tcp_len);
        memcpy(pseudo_tcp, (uint8_t *) tcp_psuedo_hdr, sizeof(struct sr_tcp_psuedo_hdr));
        memcpy(&(pseudo_tcp[sizeof(struct sr_tcp_psuedo_hdr)]), (uint8_t *) tcpHdr, tcp_len);
        tcpHdr->sum = currCksum;
        
        uint16_t calcCksum = cksum(pseudo_tcp, pseudo_tcp_len);
        
        /* Clear out memory used for creation of complete tcp packet */
        free(tcp_psuedo_hdr);
        free(pseudo_tcp);
        
        return calcCksum;
    }
    
    
    int ip_cksum(struct sr_ip_hdr* ip_hdr) {
        /*IP checksum*/
        uint16_t rcv_cksum = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;
        /*New*/
        /*uint16_t cal_cksum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));*/
        uint16_t cal_cksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        /*reset check sum*/
        ip_hdr->ip_sum = rcv_cksum;
        
        return cal_cksum;
    }
    
    int icmp_cksum(struct sr_ip_hdr* ip_hdr, struct sr_icmp_hdr* icmp_hdr) {
        uint16_t icmp_expected_cksum;
        uint16_t icmp_received_cksum;
        
        icmp_received_cksum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        icmp_expected_cksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4);
        
        /*reset check sum*/
        icmp_hdr->icmp_sum = icmp_received_cksum;
        
        return icmp_expected_cksum;
        /*ICMP checksum end*/
    }
    
    
    /*Chenguang Code End=========================================================================*/
    

