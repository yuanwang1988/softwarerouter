#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

#include <stdint.h>
#include "sr_router.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    /* Fill this in */
    struct sr_arpreq *req;
    struct sr_arpreq *req_temp;
    struct sr_arpcache cache = sr->cache;
    /*sr_arpcache_sweepreqs disabled for testing purposes, need to re-enable before submitting*/

    for (req = cache.requests; req != NULL; req = req_temp) 
	{
        req_temp=req->next;
        sr_handle_arpreq(sr, req);
    }
}

/*
 * When we want to send an ip packet, we need to firstly check arp acache.
 */
void sr_check_and_send_arp(struct sr_instance* sr, uint8_t* packet, uint32_t next_hop_ip, struct sr_if* out_iface, unsigned int len)
{
        Debug("\ncheck_and_send_arp called\n");
        struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip); 

        if(entry) 
		{ 
            Debug("\narp_cache hit!\n");
            next_hop_ip = entry->ip;

            int i;
            for (i = 0; i < ETHER_ADDR_LEN; i++)
			{
                packet[i] = entry->mac[i];
            }

            sr_send_packet(sr, packet, len, out_iface->name);

            free(packet);
            free(entry);
        }
        else
		{
            Debug("\narp_cache miss; call handle_arppreq\n");
			struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet, len, out_iface->name);
			free(packet);
            sr_handle_arpreq(sr, req);
        }
}

/*
 * handle arp reply
 */
void sr_handle_arpreply(struct sr_instance* sr, unsigned char *mac, uint32_t ip, struct sr_if* iface)
{
	/*      
	if(ip == 167985324)
	{return;}
	*/
	 Debug("\nhandle_arpreply called\n");
	 Debug("mac: %s, ip: %d, interface: %s", mac, ip, iface->name); 
	    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), mac, ip);

	
        struct sr_packet *packet;
        if(req)
		{
            Debug("\nhandle_arpreply -> sending out packets waiting for the arp_reply\n");
	    
            for(packet = req->packets; packet != NULL; packet = packet->next)
			{
		int i;
           	 for (i = 0; i < ETHER_ADDR_LEN; i++)
                        {
                packet->buf[i]= mac[i];
            }
                printf("---------------before send packet----------------\n");
				print_hdrs(packet->buf, packet->len);
				sr_send_packet(sr, packet->buf, packet->len, iface->name);    
                /*printf("--------------------i-------------------------: %d\n", i);i++;*/
				/*free(packet->buf);*/
		
            }

			sr_arpreq_destroy(&(sr->cache), req);
			Debug("Hey, finished sending packets");

        }
}

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req){
    /*Debug("\nsr_handle_arpreq called\n");*/
    time_t     now;
    now = time(NULL);
    
    struct sr_arpcache *cache = &(sr->cache);
    /*if the arp_request has never been sent before or if the last time the 
    arp_request was sent was more than 1 second ago*/

    if ((req->times_sent == 0)||(difftime(now, req->sent)> 1.0)){
        /*Debug("\nARP request not previously sent or have not been sent within the last second\n");*/
        if (req->times_sent >= 5)
		{
            /*Debug("\nARP request was sent 5 times previously; destroy ARP request\n");*/
            /*loop through all of the IP packets waiting for the request,
            call function to send ICMP msg -> host_unreachable*/
            struct sr_packet *packet;
            for(packet = req->packets; packet != NULL; packet = packet->next)
			{
				/*这里的interface是outgoing interface，有问题，send_icmp_message要的是in_interface*/
				send_icmp_message(sr, packet->buf, sizeof(struct sr_packet), sr_get_interface(sr, req->packets->iface), ICMP_DESTINATION_UNREACHABLE_TYPE, ICMP_HOST_UNREACHABLE_CODE);
            }
            sr_arpreq_destroy(cache, req);
        }
        else
		{
            /*Debug("\nSending ARP request\n");*/
			/*这里的interface是outgoing interface，有问题，send_icmp_message要的是in_interface*/
			printf("interface: %s", req->packets->iface);
			send_arp_request(sr, sr_get_interface(sr, req->packets->iface), req->ip);
			req->sent = now;
            req->times_sent++;
		}
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

