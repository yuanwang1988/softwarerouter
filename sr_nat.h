
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#define MAX_PORT 65535
#define MIN_PORT 1024
#define TOTAL_PORTS MAX_PORT - MIN_PORT

#define MAX_ICMP_IDENTIFIER 65535
#define MIN_ICMP_IDENTIFIER 1
#define TOTAL_ICMP_IDENTIFIERS MAX_ICMP_IDENTIFIER - MIN_ICMP_IDENTIFIER

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
    CLOSE_WAIT,
    CLOSED,
    CLOSING,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    LAST_ACK,
    LISTEN,
    SYN_RCVD,
    SYN_SENT,
    TIME_WAIT
} sr_tcp_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip;
  uint32_t client_isn;
  uint32_t server_isn;
  time_t last_updated;
  sr_tcp_state tcp_state;

  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;

  /* add command parameters */
  unsigned int icmp_query_timeout;
  unsigned int tcp_estb_timeout;
  unsigned int tcp_trns_timeout;

  /* Mapping of available ports */
  uint16_t available_ports[TOTAL_PORTS];
  /* Mapping of available ICMP identifiers */
  uint16_t available_icmp_identifiers[TOTAL_ICMP_IDENTIFIERS];

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};
void sr_nat_handle_icmp(struct sr_instance* sr, struct sr_nat *nat, uint8_t * packet, unsigned int len, struct sr_if* in_iface, struct sr_ethernet_hdr* ether_hdr);
struct sr_if* sr_match_dst_ip_to_iface(struct sr_instance* sr, struct sr_ip_hdr* ip_hdr);
struct sr_if* sr_ip_to_iface(struct sr_instance* sr, uint32_t ip);
int sr_check_if_internal(struct sr_if* in_iface);

int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, struct sr_instance* sr, char* interface);

int port_gen(struct sr_nat* nat);
int iden_gen(struct sr_nat* nat);
void nat_mapping_destroyg(struct sr_nat *, struct sr_nat_mapping *);

#endif