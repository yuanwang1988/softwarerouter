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
	        sr_handle_ip_packet(sr, packet, len, in_iface, ether_hdr);
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
	struct sr_rt* result_route = NULL;  /*查表得到的路由结果*/
	/*search route table item by item*/
    while(rt_item != NULL)
	{
		if (rt_item->dest.s_addr == 0) /*dest ip = 0.0.0.0*/
		{
			default_route = rt_item; /*默认路由*/
		}
		else
		{
			if (result_route == NULL)/* not hit*/
			{
				if ((rt_item->dest.s_addr & rt_item->mask.s_addr) == (ip_hdr->ip_dst & rt_item->mask.s_addr)) /*没做最长前缀匹配，我们要做？？？？？？*/
				{
					result_route = rt_item;
				}
			}
		}

		rt_item = rt_item->next;
	}

	struct sr_if* out_iface;
	struct in_addr next_hop_ip;

	if (result_route != NULL) /*找到了匹配的路由表项*/
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
