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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */

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
    
    /* TODO: (opt) Add initialization code here */

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d\n",len);

  /* TODO: Add forwarding logic here */

  struct sr_ethernet_hdr_t* ehdr;
  ehdr = (struct sr_ethernet_hdr_t*)packet;
  uint8_t* destAddr = malloc(sizeof(uint8_t)*ETHER_ADDR_LEN);
  uint8_t* srcAddr = malloc(sizeof(uint8_t)*ETHER_ADDR_LEN);
  memcpy(destAddr, ehdr->ether_dhost, sizeof(uint8_t)*ETHER_ADDR_LEN);
  memcpy(srcAddr, ehdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);


  /* ARP Packet */
  if(ether_type(packet) == ethertype_arp){
    sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    uint32_t senderIP = arpHdr->ar_sip;
    uint32_t targetIP = arpHdr->ar_tip;
    sr_if* entry = sr_get_interface(sr, tip); // Defined by self, overloaded existing

    // ARP request
    if(arpHdr->ar_op == htons(arp_op_request)){

      uint32_t tip = arpHdr->tip;
      
      if(entry !=0){
        // ARP request for one of existing interfaces
        // update cin cache if already present else insert
        sr_arpcache_insert(sr->cache, arpHdr->ar_sha,senderIP);

        // sending ARP reply, Ower writing old ARP Packet
        memcpy(ehdr->ether_dhost, arpHdr->ar_sha, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(ehdr->ether_shost, entry->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
        // Ether Type already ARP

        // Most feild aleady set
        memcpy(arpHdr->ar_tha, arpHdr->ar_sha, sizeof(uint8_t)*ETHER_ADDR_LEN)
        arpHdr->ar_tip = senderIP;
        memcpy(arpHdr->ar_sha, entry->addr, ETHER_ADDR_LEN);
        arpHdr->ar_sip = targetIP;
        arpHdr->ar_op = htons(arp_op_reply);

        sr_send_packet(sr, packet, len, entry->name);

      }
    }

    if(arpHdr->ar_op== htons(arp_op_reply)){

      // Add to cache, if already present update
      sr_arpreq* arpreq = sr_arpcache_insert(&(sr->cache), arpHdr->sha, senderIP);
      sr_packet* currPkt;
      uint8_t* pkt;

      currPkt = arpreq->packets;
      while(currPkt!=NULL){

        pkt = malloc(sizeof(uint8_t)*currPkt->len);

        sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)currPkt->buf;
        memcpy(ehdr, entry->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(ehdr, arpHdr->ar_sha, sizeof(uint8_t)*ETHER_ADDR_LEN);

        memcpy(pkt, ehdr, sizeof(uint8_t)*currPkt->len);

        currPkt = currPkt->next;
      }
      sr_arpreq_destroy(&(sr->cache), arpreq);

    }

  }
  
  /* IP Packet */
  if(ether_type(packet) == ethertype_ip){
    struct sr_ip_hdr_t* ip_hdr;
    ip_hdr = (struct sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    if(ip_hdr->ip_sum != cksum((packet+sizeof(sr_ethernet_hdr_t)), len - sizeof(sr_ethernet_hdr_t)))
      //drop packet
    int minlength = sizeof(sr_ethernet_hdr_t);
    if(length < minlength)
      //drop packet

  }  

}/* -- sr_handlepacket -- */


/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  /* TODO: Fill this in */
  time_t now = time(NULL);
    if(difftime(now,req->sent) > 1.0){
        if(req->times_sent >= 5){
            host_unreachable(sr, req);
            sr_arpreq_destroy(req);
        }
        else{
            sr_arpreq_send(src, req->ip);
            req->sent = now;
            req->times_sent++;
        }
    }
  
}

void host_unreachable(struct sr_instance* sr, struct sr_arpreq* req){
  sr_packet* packet = req->packets;

  while(packet!=NULL){
    sr_icmp_send(3, 1, sr);
    packet = packet->next;
  }

}

/*Send an ARP request*/
void sr_arpreq_send(struct sr_instance *sr, uint32_t ip){
  
  int packetlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr__t);
  uint8_t *arp_pkt = malloc(packetlen);

  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)arp_pkt;
  memcpy(ehdr->ether_dhost,0xff,ETHER_ADDR_LEN) 

  sr_if* curr_if = sr->if_list;

  uint8_t *send_pkt;
  while(curr_if!=NULL){
    
    memcpy(ehdr->ether_shost, (uint8_t *)curr_if->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    ehdr->ether_type = htons(ethertype_arp);

    sr_arp_hdr_t* arphdr = (sr_arp_hdr_t *)(arp_pkt + sizeof(sr_ethernet_hdr_t));

    arphdr->ar_hrd = htons(1);
    arphdr->ar_pro = htons(2048);
    arphdr->ar_hln = 6;
    arphdr->ar_pln = 4;
    arphdr->ar_op = htons(arp_op_request);
    memcpy(arphdr->ar_sha, curr_if->addr, ETHER_ADDR_LEN);
    arphdr->sip = curr_if->ip;
    memcpy(arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
    arphdr->tip = ip;

    send_pkt = malloc(packetlen);
    memcpy(send_pkt, ehdr, packetlen);
    sr_send_packet(sr, send_pkt, packetlen, curr_if->name);
    curr_if = curr_if->next;
  }

}

void sr_arpreply_send(struct sr_instance *sr, uint32_t ip){

}

void sr_icmp_send(uint8_t type, uint8_t code, struct sr_instance* sr){

  int packetlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ic)
}