
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <time.h>
#include "sr_if.h"

/*Yuan Code Start ============================================================================*/

void sr_nat_handle_icmp(struct sr_instance* sr, struct sr_nat *nat, uint8_t * packet, unsigned int len, struct sr_if* in_iface, struct sr_ethernet_hdr* ether_hdr) {
    assert(nat);
    assert(sr);
    assert(packet);
    assert(len);
    assert(in_iface);
    
    /*extract information from ip header needed for processing icmp packet*/
    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    uint32_t src_ip_original = ip_hdr->ip_src;
    
    /*extract information from icmp header needed for processing icmp packet*/
    struct sr_icmp_hdr* icmp_hdr= (struct sr_icmp_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
    uint16_t icmp_id_original = icmp_hdr->icmp_iden;
    uint8_t icmp_type = icmp_hdr->icmp_type;
    
    /*determine the outgoing interface*/
    uint32_t dst_ip = ip_hdr->ip_dst; /*use ip_dst to determine whether the destination is inside or outside of NAT*/
    struct sr_if* for_router_iface = sr_match_dst_ip_to_iface(sr, ip_hdr);
    
    DEBUG("Consider: we may want to reject the dest ip that is not router's interface and not in routing table");
    if(sr_check_if_internal(in_iface)){
        /*if the ICMP packet is from inside NAT*/
        
        /*check if the icmp packet is for router's interface or for inside NAT*/
        /*then call simple router*/
        if((for_router_iface)||!(sr_check_if_internal(sr_ip_to_iface(sr, dst_ip)))) {
            
            call simple router
        }
        
        else {
            /*the icmp packet is from inside to outside; we will only process echo request
            if the ICMP packet is an echo request from inside NAT to outside NAT, then we need to do translation*/
            if(icmp_type == ICMP_ECHO_REQUEST_TYPE){
                /*if ICMP packet is an echo request from inside NAT to outside NAT*/
                
                DEBUG("Client send icmp echo request to outside NAT")
                
                struct sr_nat_mapping* nat_map = sr_nat_lookup_internal(nat, src_ip_original, icmp_id_original, nat_mapping_icmp);
                if (nat_map == NULL){
                    struct sr_nat_mapping* nat_map = sr_nat_insert_mapping(nat, sr_ip_original, icmp_id_original, nat_mapping_icmp, sr, out_iface->name);
                }
                ip_hdr->ip_src = nat_map->ip_ext;
                icmp_hdr->icmp_iden = nat_map->aux_ext;
                /*update check sums*/
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
                
                int icmp_offset = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->ip_sum = cksum(icmp_hdr, len - icmp_offset);
                
                call simple router
            }
        }
        else{
            /*if ICMP packet is a type 3 error msg from inside NAT to outside NAT*/
            struct sr_icmp_t3_hdr* icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
            
            DEBUG("Client sends type 3 or type 11 icmp message to outside NAT")
        }
        call simple router
    }
    else if (!(sr_check_if_internal(in_iface))) {
        /*if the ICMP packet is from outside NAT
        then we will only handle echo reply and echo request to the external interface of router
        
        check if the dest_ip not router interface
        then it can be for external host -> simple router; anything else we drop*/
        if(!(for_router_iface)){
            if (!(sr_check_if_internal(sr_ip_to_iface(sr, dst_ip)))){
                call simple router
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
                call simple router
            }
            else if(icmp_type == ICMP_ECHO_REPLY_TYPE){
                DEBUG("Client send icmp echo request to outside NAT")
                
                struct sr_nat_mapping* nat_map = sr_nat_lookup_external(nat, src_ip_original, icmp_id_original, nat_mapping_icmp);
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
                icmp_hdr->ip_sum = cksum(icmp_hdr, len - icmp_offset);
                
                call simple router
            }
            else{
                DEBUG("ICMP type 3 or 11 msg from outside NAT to inside NAT")
            }
            
        }
        
        
        
        /*check if the dest_ip is for router
        
        if the dest_ip is not for router or external host, we drop the packet*/
        
    }
    
    else{
        
        
        call simple router
        
    }
    
    
    
}

/*function to return i_face struct of the router if the dest ip is for the i_face of the router*/
struct sr_if* sr_match_dst_ip_to_iface(struct sr_instance* sr, struct sr_ip_hdr* ip_hdr)
{
    struct sr_if* router_if = sr -> if_list;
    
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
struct sr_if* sr_ip_to_iface(struct sr_instance* sr, uint32_t ip){
    assert(sr)
    assert(ip)
    
    struct sr_rt* result_route = sr_longest_prefix_match(sr, ip);
    char out_iface_name = result_route->interface;
    struct out_iface* out_iface = sr_get_interface(sr, out_iface_name);
    
    return out_iface;
}


/*function to check whether the receiving interface is internal or external*/
int sr_check_if_internal(struct sr_if* in_iface){
    return strcmp(iface->name, "eth1");
}

/*Yuan Code Ends ============================================================================*/


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
    
  pthread_mutex_unlock(&(nat->lock));
  return copy;
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
        if (currentMapps->type == type && currentMapps->aux_int == aux_int) {
            copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, currentMapps, sizeof(struct sr_nat_mapping));
            printf("Hit!");
            break;
        }
        currentMapps = currentMapps->next;
    }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
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
  mapping->next = currentMapps->next;
  currentMapps->next = mapping;
  
  struct sr_nat_mapping *copy = mapping;
  pthread_mutex_unlock(&(nat->lock));
  return copy;
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
    struct sr_nat_connection *currConns, *nextConns = NULL;
    if (mappings) {
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
        for (currConns = mappings->conns; currConns != NULL; currConns = currConns->next) {
            if (currConns) {
                free(currConns);
            }
        }
        free(mappings);
    }

}
