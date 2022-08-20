#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "packetManage.h"
#include "utils.h"



void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    TCP_packet tcp;
    ARP_packet arp;

   if(ARP_packet_construct(&arp,header,packet)==-1){
        printf("Error generating arp packet");
        return;
    }

   if(TCP_packet_construct(&tcp,header,packet)==-1){
        printf("Error generating tcp packet");
        return;
    }


    printf("\nthe payload is:");
    printPayload(tcp.payload,tcp.payload_length);

    return;
}




