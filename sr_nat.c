
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <time.h>
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"

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
		DEBUG("ICMP Packet - IP checksum failed; Drop");
		return;
	}
	if (icmp_hdr->icmp_sum != icmp_cksum(ip_hdr, icmp_hdr)) {
		DEBUG("ICMP Packet - ICMP checksum failed; Drop");
		return;
	}
    
    /*determine if the dest_ip is one of the router's interfaces*/
    struct sr_if* for_router_iface = sr_match_dst_ip_to_iface(sr, ip_hdr);

    /*if the dst_ip is not one of the router interfaces or in our routing table*/
    /*call simple router to send icmp t3 msg*/
    if(!(for_router_iface)&&!(sr_longest_prefix_match(sr, dst_ip_original))){
        DEBUG("ICMP packet - dst ip is not router interface or in routing table; respond with icmp t3 msg - net unreachable");
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
                
                DEBUG("Client send icmp echo request to outside NAT");
                
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
                
                DEBUG("Client sends type 3 or type 11 icmp message to outside NAT");
            }
        }
    }
    else if (!(sr_check_if_internal(in_iface))) {
        /*if the ICMP packet is from outside NAT
         then we will only handle echo reply and echo request to the external interface of router
         ƒ
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
                DEBUG("Client send icmp echo request to outside NAT");
                
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
                DEBUG("ICMP type 3 or 11 msg from outside NAT to inside NAT");
            }
            
        }
        
        
        
        /*check if the dest_ip is for router
         
         if the dest_ip is not for router or external host, we drop the packet*/
        
    }
    
    else{
        
        
		/*call simple router*/
		DEBUG("Default behavior - call simple router; need to see if this is acceptable");
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
    
    struct sr_rt* result_route = sr_longest_prefix_match(sr, ip);
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
		DEBUG("ICMP Packet - IP checksum failed; Drop");
		return;
	}
    /*Sanity check on TCP packet*/
    /*We need to check TCP sum now since we will be updating it later*/
    if(tcp_cksum(ip_hdr, tcp_hdr, len) != 0){
        DEBUG("TCP packet received - TCP checksum failed; drop packet");
        return;
    }


    /*if the dst_ip is not one of the router interfaces or in our routing table*/
    /*call simple router to send icmp t3 msg*/
    if(!(for_router_iface)&&!(sr_longest_prefix_match(sr, dst_ip))){
        DEBUG("TCP packet received - dst ip is not router interface or in routing table; respond with icmp t3 msg - net unreachable");
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
            pthread_mutex_lock(&((sr->nat).lock));
            
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
            pthread_mutex_unlock(&((sr->nat).lock));
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
        else /*if it is for the router, use NAT*/
        {
            struct sr_nat_mapping *nat_map = sr_nat_lookup_external(&(sr->nat), ntohs(tcp_hdr->dst_port), nat_mapping_tcp);
            if(nat_map == NULL)
            {
                return;
            }
            else
            {
                /*lock*/
                pthread_mutex_lock(&((sr->nat).lock));
                
                struct sr_nat_connection *tcp_con = sr_nat_lookup_tcp_con(nat_map, src_ip);
                if (tcp_con == NULL)
                {
                    tcp_con = sr_nat_insert_tcp_con(nat_map, src_ip);
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
                pthread_mutex_unlock(&((sr->nat).lock));
                
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
uint32_t tcp_cksum(struct sr_ip_hdr_t *ipHdr, struct sr_tcp_hdr_t *tcpHdr, int total_len)
{
    
    uint8_t *pseudo_tcp;
    sr_tcp_psuedo_hdr_t *tcp_psuedo_hdr;
    
    int tcp_len = total_len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    int pseudo_tcp_len = sizeof(sr_tcp_psuedo_hdr_t) + tcp_len;
    
    tcp_psuedo_hdr = malloc(sizeof(sr_tcp_psuedo_hdr_t));
    memset(tcp_psuedo_hdr, 0, sizeof(sr_tcp_psuedo_hdr_t));
    
    tcp_psuedo_hdr->ip_src = ipHdr->ip_src;
    tcp_psuedo_hdr->ip_dst = ipHdr->ip_dst;
    tcp_psuedo_hdr->ip_p = ipHdr->ip_p;
    tcp_psuedo_hdr->tcp_len = htons(tcp_len);
    
    uint16_t currCksum = tcpHdr->sum;
    tcpHdr->sum = 0;
    
    pseudo_tcp = malloc(sizeof(sr_tcp_psuedo_hdr_t) + tcp_len);
    memcpy(pseudo_tcp, (uint8_t *) tcp_psuedo_hdr, sizeof(sr_tcp_psuedo_hdr_t));
    memcpy(&(pseudo_tcp[sizeof(sr_tcp_psuedo_hdr_t)]), (uint8_t *) tcpHdr, tcp_len);
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


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  /*
  struct sr_nat_mapping *currentMapps = nat->mappings;
  struct sr_nat_mapping *tempMapps;
  struct sr_nat_connection *currentConns = currentMapps->conns;
  struct sr_nat_connection *tempConns;
    
  while (currentMapps)
  {
      while (currentConns) {
          tempConns = currentConns;
          currentConns = currentConns->next;
          free(tempConns);
      }
      tempMapps = currentMapps;
      currentMapps = currentMapps->next;
      free(tempMapps);
  }
  */
  
  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    struct sr_nat_mapping *currMapps, *nextMapps = NULL;
    struct sr_nat_connection *currConns, *nextConns = NULL;
    currMapps = nat->mappings;

      while (currMapps) {
          nextMapps = currMapps->next;
          if (currMapps->type == nat_mapping_icmp) {
              if (difftime(curtime, currMapps->last_updated) > nat->icmp_query_timeout) { /* > or >= */
                  /* ICMP timeout, clean it up */
                  nat_mapping_destroy(nat, currMapps);
              }
          } else if(currMapps->type == nat_mapping_tcp) {
              currConns = currMapps->conns;
              while (currConns)
              {
                  nextConns = currConns->next;
                  if (currConns->tcp_state == ESTABLISHED && difftime(curtime, currMapps->last_updated) > nat->tcp_estb_timeout ||
                      currConns->tcp_state != ESTABLISHED && difftime(curtime, currMapps->last_updated) > nat->tcp_trns_timeout) {
                      /* This connection has timed out, clean it up */
                      tcp_conn_destroy(currMapps, currConns);
                  }
                  currConns = nextConns;
              }
              /* reset currConns pointer to the first conns*/
              currConns = currMapps->conns;
              if (!currConns) {
                  /* No connection exists for this mapping, clean it up */
                  nat_mapping_destroy(nat, currMapps);
              }
              
              /*=========TODO: handle 6 secconds==================*/
          }
          currMapps = nextMapps;
      }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy, *currentMapps = NULL;
  currentMapps = nat->mappings;
  printf("Looking mapping for external aux: %d\n",aux_ext);

    /*----TODO: FREE THIS-----*/
    while (currentMapps) {
        if (currentMapps->type == type && currentMapps->aux_ext == aux_ext) {
            copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, currentMapps, sizeof(struct sr_nat_mapping));
            printf("Hit!");
            break;
        }
        currentMapps = currentMapps->next;
    }
  currentMapps->last_updated = time(NULL);
  pthread_mutex_unlock(&(nat->lock));
  return currentMapps;
  /*return copy;*/
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_mapping *copy, *currentMapps = NULL;
    currentMapps = nat->mappings;
    printf("Looking mapping for internal aux: %d\n",aux_int);
    
    /*----TODO: FREE THIS-----*/
    while (currentMapps) {
        if (currentMapps->type == type && currentMapps->aux_int == aux_int && currentMapps->ip_int == ip_int) {
            copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, currentMapps, sizeof(struct sr_nat_mapping));
            printf("Hit!");
            break;
        }
        currentMapps = currentMapps->next;
    }
  currentMapps->last_updated = time(NULL);
  pthread_mutex_unlock(&(nat->lock));
  return currentMapps;
  /*return copy;*/
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, struct sr_instance* sr, char* interface) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  assert(mapping);

  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->ip_ext = sr_get_interface(sr, interface)->ip;
  mapping->aux_int = aux_int;
  if (type == nat_mapping_icmp) {
        mapping->aux_ext = iden_gen(nat);
  }else if (type == nat_mapping_tcp){
        mapping->aux_ext = port_gen(nat);
  }
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  
  struct sr_nat_mapping *currentMapps = nat->mappings;
  nat->mappings = mapping;
  mapping->next = currentMapps;
  /*
  mapping->next = currentMapps->next;
  currentMapps->next = mapping;
  */
  /*struct sr_nat_mapping *copy = mapping;*/
  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

int port_gen(struct sr_nat* nat)
{
    pthread_mutex_lock(&(nat->lock));
    
    uint16_t *available_ports = nat->available_ports;
    int i;
    
    for (i = MIN_PORT; i <= TOTAL_PORTS; i++) {
        if (available_ports[i] == 0) {
            available_ports[i] = 1;
            printf("Port allocated: %d\n", i);
            
            pthread_mutex_unlock(&(nat->lock));
            return i;
        }
    }
    
    pthread_mutex_unlock(&(nat->lock));
    return -1;
}


int iden_gen(struct sr_nat* nat)
{
    pthread_mutex_lock(&(nat->lock));
    
    uint16_t *available_icmp_identifiers = nat->available_icmp_identifiers;
    int i;
    
    for (i = MIN_ICMP_IDENTIFIER; i <= TOTAL_ICMP_IDENTIFIERS; i++) {
        if (available_icmp_identifiers[i] == 0) {
            available_icmp_identifiers[i] = 1;
            printf("ICMP identifier allocated: %d\n", i);
            
            pthread_mutex_unlock(&(nat->lock));
            return i;
        }
    }
    
    pthread_mutex_unlock(&(nat->lock));
    return -1;

}

void nat_mapping_destroy(struct sr_nat * nat, struct sr_nat_mapping * mappings)
{

    struct sr_nat_mapping *prev, *current, *next = NULL;
    struct sr_nat_connection *currConns, *nextConns, *temp = NULL;
    if (mappings) {
        /* free mappings*/
        for (current = nat->mappings; current != NULL; current = current->next) {
            if (current == mappings) {
                if (prev) {
                    next = current->next;
                    prev->next = next;
                } else {
                    next = current->next;
                    nat->mappings = next;
                }
                break;
            }
            prev = current;
        }
        /* free port or identifier */
        if (mappings->type == nat_mapping_icmp) {
            nat->available_icmp_identifiers[mappings->aux_ext] = 0;
        } else if (mappings->type == nat_mapping_tcp) {
            nat->available_ports[mappings->aux_ext] = 0;
            
        }
        /* free tcp connections */
        for (currConns = mappings->conns; currConns != NULL; currConns = temp) {
            if (currConns) {
                temp = currConns->next;
                free(currConns);
            }
        }
        free(mappings);
    }

}

void tcp_conn_destroy(struct sr_nat_mapping * mappings, struct sr_nat_connection * connections){
    struct sr_nat_connection *prev, *current, *next = NULL;
    
    if (connections) {
        /* free connections*/
        for (current = mappings->conns; current != NULL; current = current->next) {
            if (current == connections) {
                if (prev) {
                    next = current->next;
                    prev->next = next;
                } else {
                    next = current->next;
                    mappings->conns = next;
                }
                break;
            }
            prev = current;
        }
    free(connections);
    }
    
}

void check_tcp_conns(struct sr_nat *nat, struct sr_nat_mapping * mappings){
    struct sr_nat_connection *currentConns, *nextConns;
    currentConns = mappings->conns;
    time_t curtime = time(NULL);
    
    while (currentConns) {
        nextConns = currentConns->next;
        
        if (currentConns->tcp_state == ESTABLISHED) {
            if (difftime(curtime, currentConns->last_updated) > nat->tcp_estb_timeout) {
                tcp_conn_destroy(mappings, currentConns);
            }
            else if (difftime(curtime, currentConns->last_updated) > nat->tcp_trns_timeout){
                tcp_conn_destroy(mappings, currentConns);
            }
        }
        currentConns = nextConns;
    }
    
    
}

struct sr_nat_connection *sr_nat_lookup_tcp_con(struct sr_nat_mapping * mappings, uint32_t ip_con){ /* server ip*/
    struct sr_nat_connection *currentConns = mappings->conns;
    
    while (currentConns) {
        if (currentConns->ip == ip_con) {
            currentConns->last_updated = time(NULL);
            return currentConns;
        }
        currentConns = currentConns->next;
    }
    return NULL;
    
}

struct sr_nat_connection *sr_nat_insert_tcp_con(struct sr_nat_mapping * mappings, uint32_t ip_con){
    struct sr_nat_connection *newConns = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
    assert(newConns);
    
    newConns->ip = ip_con;
    newConns->tcp_state = CLOSED;
    
    struct sr_nat_connection *currConns = mappings->conns;
    mappings->conns = newConns;
    newConns->next = currConns;
    
    newConns->last_updated = time(NULL);
    
    return newConns;
}
