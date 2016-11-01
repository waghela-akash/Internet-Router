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
struct sr_rt* sr_longest_prefix(struct sr_rt *rt, uint32_t ip){
  struct sr_rt *curr=rt;
  struct sr_rt *match=NULL;
  int matchLen=0;
  while(curr!=NULL){
    int cnt=0;
    /*printf("*************************************\n");
    print_addr_ip_int(ip); print_addr_ip_int(curr->dest.s_addr); print_addr_ip_int(curr->mask.s_addr);*/
    
    unsigned long int mip = (unsigned long int) curr->dest.s_addr;
    unsigned long int mask = (unsigned long int) curr->mask.s_addr;
    unsigned long int cip = (unsigned long int) ip;
    /*printf("%ld\n",mask);*/
    while(mask & (2<<(30-cnt))){
      if((cip & (2<<(30-cnt))) != (mip & (2<<(30-cnt))))
        break;
      cnt++;
    }
    /*printf("%d\n",cnt);*/
    if(matchLen < cnt){
      matchLen = cnt;
      match = curr;
    }
    curr = curr->next;
  }
  return match;
}

struct sr_if* sr_get_interface_ip(struct sr_instance* sr, uint32_t name){
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(name);
    assert(sr);
    if_walker = sr->if_list;

    while(if_walker){
       if(if_walker->ip==name)
        { return if_walker; }
        if_walker = if_walker->next;
    }

    return 0;
} /* -- sr_get_interface -- */

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
  print_hdrs(packet, len);
  /* TODO: Add forwarding logic here */

  sr_ethernet_hdr_t *ehdr;
  ehdr = (sr_ethernet_hdr_t *)packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t)*ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t)*ETHER_ADDR_LEN);
  memcpy(destAddr, ehdr->ether_dhost, sizeof(uint8_t)*ETHER_ADDR_LEN);
  memcpy(srcAddr, ehdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);


  /* ARP Packet */
  if(ethertype(packet) == ethertype_arp){
    printf("------> Received ARP packet\n");

    sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    print_hdr_arp(arpHdr);

    uint32_t senderIP = arpHdr->ar_sip;
    unsigned char senderHA[ETHER_ADDR_LEN];
    memcpy(senderHA, arpHdr->ar_sha, ETHER_ADDR_LEN);
    uint32_t targetIP = arpHdr->ar_tip;
    /*uint8_t *targetHA = malloc(sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(targetHA, arpHdr->ar_tha, sizeof(uint8_t)*ETHER_ADDR_LEN);*/

    /* Defined by self, overloaded existing */
    struct sr_if *entry = sr_get_interface_ip(sr, targetIP); 

    /* ARP request */
    if(arpHdr->ar_op == htons(arp_op_request)){
      printf("------> ARP request\n");  
      if(entry !=0){

        printf("------> ARP request of my interface\n"); 
        /* ARP request for one of existing interfaces
         update cin cache if already present else insert */
        sr_arpcache_insert(&(sr->cache), senderHA, senderIP);

        /* sending ARP reply, Ower writing old ARP Packet */
        memcpy(ehdr->ether_dhost, (uint8_t *)senderHA, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(ehdr->ether_shost, (uint8_t *)entry->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
        /* Ether Type already ARP */

        /* Most feild aleady set */
        memcpy(arpHdr->ar_tha, (uint8_t *)senderHA, sizeof(uint8_t)*ETHER_ADDR_LEN);
        arpHdr->ar_tip = senderIP;
        memcpy(arpHdr->ar_sha, (uint8_t *)entry->addr, ETHER_ADDR_LEN);
        arpHdr->ar_sip = targetIP;
        arpHdr->ar_op = htons(arp_op_reply);
        print_hdrs(packet, len);
        sr_send_packet(sr, packet, len, entry->name);

      }
      printf("------> ARP request done!\n"); 
    }

    else if(arpHdr->ar_op== htons(arp_op_reply)){
      printf("------> ARP reply\n");
      /* Add to cache, if already present update */
      struct sr_arpreq* arpreq = sr_arpcache_insert(&(sr->cache), senderHA, senderIP);

      if(arpreq!=NULL){
        printf("------> Sending Waiting packets\n");
        struct sr_packet* currPkt;
        uint8_t* pkt;

        currPkt = arpreq->packets;
        while(currPkt!=NULL){
          pkt = malloc(sizeof(uint8_t)*currPkt->len);

          sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)currPkt->buf;
          memcpy(ehdr->ether_shost, (uint8_t *)entry->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
          memcpy(ehdr->ether_dhost, (uint8_t *)senderHA, sizeof(uint8_t)*ETHER_ADDR_LEN);

          memcpy(pkt, ehdr, sizeof(uint8_t)*currPkt->len);
          /*print_hdrs(pkt, currPkt->len);*/
          sr_send_packet(sr, pkt, currPkt->len, entry);

          currPkt = currPkt->next;
        }
        sr_arpreq_destroy(&(sr->cache), arpreq);
      }
      
      printf("------> ARP reply Done\n");
    }

  }
  
  /* IP Packet */
  
  else if(ethertype(packet) == ethertype_ip){
    printf("------> Received IP packet\n");
    sr_ip_hdr_t* ip_hdr;
    ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    print_hdr_ip(ip_hdr);

    /* Check if valid Packet */
    uint32_t srcIP = ip_hdr->ip_src;
    uint32_t dstIP = ip_hdr->ip_dst;
    struct sr_if *entry = sr_get_interface_ip(sr, dstIP);
    struct sr_rt *lpm = sr_longest_prefix(sr->routing_table, dstIP);

    print_addr_ip_int(dstIP);
    /*sr_print_routing_table(sr);*/
    
    if(lpm==NULL){
      printf("------> IP Not Reachable Send ICMP error type 3 code 0\n");
      sr_icmp_send(packet, dstIP, 3, 0, sr);
    }
    else{
      printf("------> IP Found ");
      sr_print_routing_entry(lpm);
      if(entry==NULL){
        printf("------> IP Not in my interface\n");
        ip_hdr->ip_ttl--;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        if(ip_hdr->ip_ttl <= 0){
          printf("------> Timed Out Send ICMP error type 11 code 0\n");
          sr_icmp_send(packet, dstIP,11, 0, sr);
        }
        else{
          uint32_t nextHop = (uint32_t) lpm->gw.s_addr;
          struct sr_arpentry *arpQuery = sr_arpcache_lookup(&(sr->cache), nextHop);

          if(arpQuery!=NULL){
            printf("------> Found Next-Hop in cache, forward packet\n");
            
            struct sr_if *sendIF = sr_get_interface(sr, lpm->interface);

            memcpy(ehdr->ether_shost, (uint8_t *)sendIF->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
            memcpy(ehdr->ether_dhost, (uint8_t *)arpQuery->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);

            print_hdrs(packet, len);
            sr_send_packet(sr, packet, len, sendIF);
          }
          else{
            printf("------> Next-Hop not in cache, send ARP request\n");
            struct sr_arpreq *nextHopARP = sr_arpcache_queuereq(&(sr->cache), nextHop, packet, len, &(lpm->interface));
            handle_arpreq(sr, nextHopARP);
          }
        }
      }
      else{
        printf("------> IP in my interface\n");

        if(ip_protocol(ip_hdr)==ip_protocol_icmp){
          
          int offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
          struct sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t *)(packet + offset); 
          print_hdr_icmp(icmp);
          /*For an echo, send a reply*/

        }
        else{
          printf("------> Not an ICMP packet, Send ICMP error Port unreachable (type 3, code 3)\n");
          sr_icmp_send(packet, dstIP, 3, 3, sr);
        }

      }
      
    }

  }

}/* -- sr_handlepacket -- */


/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  /* TODO: Fill this in */
  time_t now = time(NULL);
  if(difftime(now,req->sent) > 1.0){
      if(req->times_sent >= 5){
          host_unreachable(sr, req);
          sr_arpreq_destroy(sr, req);
      }
      else{
          sr_arpreq_send(sr, req->ip);
          req->sent = now;
          req->times_sent++;
      }
  }
  else
    printf("#### Time Not elapsed\n");
  
}

void host_unreachable(struct sr_instance* sr, struct sr_arpreq* req){
  struct sr_packet* packet = req->packets;

  while(packet!=NULL){
    sr_ip_hdr_t *pkt = (sr_ip_hdr_t *)(packet->buf + sizeof(sr_ethernet_hdr_t));
    sr_icmp_send(pkt, pkt->ip_src, 3, 1, sr);
    packet = packet->next;
  }

}

/*Send an ARP request*/
void sr_arpreq_send(struct sr_instance *sr, uint32_t ip){

  printf("------> Sending ARP request for\n");
  print_addr_ip_int(ip);
  
  int packetlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *arp_pkt = malloc(packetlen);

  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)arp_pkt;
  memset(ehdr->ether_dhost,0xff,ETHER_ADDR_LEN); 

  struct sr_if* curr_if = sr->if_list;

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
    arphdr->ar_sip = curr_if->ip;
    memset(arphdr->ar_tha, 0, ETHER_ADDR_LEN);
    arphdr->ar_tip = ip;

    send_pkt = malloc(packetlen);
    memcpy(send_pkt, ehdr, packetlen);
    /*print_hdrs(send_pkt, packetlen);*/
    sr_send_packet(sr, send_pkt, packetlen, curr_if->name);
    curr_if = curr_if->next;
  }

}

void sr_icmp_send(uint8_t *ipPacket, uint32_t destIP,uint8_t type, uint8_t code, struct sr_instance* sr){

  printf("------> Got ICMP error of Type: %d, Code: %d\n",type, code);
  printf("------> Function Coming Soon...\n");
  
  int packetlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *packet = malloc(packetlen);
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmphdr = (sr_icmp_t3_hdr_t *)(iphdr + sizeof(sr_ip_hdr_t));

  ehdr->ether_type = htons(ethertype_ip);

  /*Source Entries and cksum remaining, rest are same*/
  iphdr->ip_dst = destIP;
  iphdr->ip_ttl = 64;
  iphdr->ip_p = ip_protocol_icmp;

  icmphdr->icmp_code = code;
  icmphdr->icmp_type = type;
  memcpy(icmphdr->data, ipPacket, ICMP_DATA_SIZE);
  icmphdr->icmp_sum = 0;
  icmphdr->icmp_sum = cksum(icmphdr, sizeof(sr_icmp_t3_hdr_t));

  struct sr_rt *lpm = sr_longest_prefix(sr->routing_table, destIP);

  if(lpm!=NULL){
    printf("------> Found LPM\n");

    uint32_t nextHop = (uint32_t) lpm->gw.s_addr;
    struct sr_arpentry *arpQuery = sr_arpcache_lookup(&(sr->cache), nextHop);

    struct sr_if *entry = sr_get_interface(sr, lpm->interface);
    memcpy(ehdr->ether_shost, (uint8_t *)entry->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

    iphdr->ip_src = entry->ip;
    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

    /*Same as routine as earlier, Look above in ip packet*/
    if(arpQuery==NULL){
      
      /*Same as Earlier*/
      printf("------> Next-Hop not in cache, send ARP request\n");

      struct sr_arpreq *nextHopARP = sr_arpcache_queuereq(&(sr->cache), nextHop, packet, packetlen, &(lpm->interface));

      handle_arpreq(sr, nextHopARP);

    }
    else{
      printf("------> Found Next-Hop in cache, forward packet\n");
            
      memcpy(ehdr->ether_dhost, (uint8_t *)arpQuery->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);

      print_hdrs(packet, packetlen);
      sr_send_packet(sr, packet, packetlen, entry->name);

    }    

  }
  printf("------> Send ICMP error processed\n");

}