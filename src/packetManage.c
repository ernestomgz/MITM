#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>


#include <arpa/inet.h>
#include <libnet.h>


#include "packetManage.h"
#include "utils.h"



void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    TCP_packet *tcp=malloc(sizeof(TCP_packet));
    ARP_packet *arp=malloc(sizeof(ARP_packet));

    //printf("\n *** start of the packet ***\n");

   if(ARP_packet_construct(arp,header,packet)!=-1){
       printf("ARP packet detected\n");
       //do thing with arp object
       ARP_free(arp);
       return;
    }

   if(TCP_packet_construct(tcp,header,packet)!=-1){
        printf("TCP packet detected in port %d\n",ntohs(tcp->tcp_header_t->th_dport));
            if (ntohs(tcp->tcp_header_t->th_dport)==21){
                //read and reesend to victim
            }


	    TCP_free(tcp);
       return;
    }
        //printf("Error obtaining packet type\n");

}
