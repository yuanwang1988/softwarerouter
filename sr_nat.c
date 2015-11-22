
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <time.h>
#include "sr_if.h"
#include "sr_protocol.h"


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