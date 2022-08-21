
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "packetManage.h"

int ARP_packet_construct(ARP_packet* arp,const struct pcap_pkthdr* packet_header,const u_char* packet){

    
    arp->eth_header_t= (struct ether_header *) packet;

    if(ntohs(arp->eth_header_t->ether_type)!=ETHERTYPE_ARP){
        return -1;
    }
    arp->arp_header_t= (struct ether_arp *) (packet + ETHER_ADDR_LEN+ETHER_ADDR_LEN+2);

    return 0;


}

int TCP_packet_construct(TCP_packet* tcp,const struct pcap_pkthdr* packet_header,const u_char* packet){
    tcp->packet_header_t=calloc(sizeof(struct pcap_pkthdr),1);
    tcp->packet_header_t=packet_header;

    //ethernet header is defined
    tcp->ethernet_header_length=14;
    tcp->eth_header_t = (struct ether_header *) packet;
    tcp->ethernet_header=calloc(sizeof(u_char),tcp->ethernet_header_length);
    memcpy(tcp->ethernet_header,packet,tcp->ethernet_header_length);

    //from ethernet header we know if contains an ip header
    if (ntohs(tcp->eth_header_t->ether_type) != ETHERTYPE_IP) {
        //Not an IP packet, skiping
        return -1;
    }

    // ip header is defined
    u_char *ip_header=packet+tcp->ethernet_header_length;
    tcp->ip_header_length = ((*ip_header ) & 0x0F);
    tcp->ip_header_length = tcp->ip_header_length * 4;
    tcp->ip_header=calloc(tcp->ip_header_length,sizeof(u_char));
    memcpy(tcp->ip_header,packet+tcp->ethernet_header_length,tcp->ip_header_length);

    //from ip header we know if contains an tcp header
    tcp->protocol = *(tcp->ip_header + 9);     // Comienzo de la cabecera del protocolo
    if (tcp->protocol != IPPROTO_TCP) {
        //not a tcp packet , skiping
        return -1;
    }


    tcp->tcp_header_length = ((*(packet + tcp->ethernet_header_length + tcp->ip_header_length + 12)) & 0xF0) >> 4;
    tcp->tcp_header_length = tcp->tcp_header_length * 4;
    tcp->tcp_header=calloc(tcp->tcp_header_length,sizeof(u_char));
    memcpy(tcp->tcp_header,packet+tcp->ethernet_header_length+tcp->ip_header_length,tcp->tcp_header_length);
    tcp->tcp_header_t = (struct tcphdr *) tcp->tcp_header;

    // port is defined
    tcp->port = calloc(sizeof(u_char), 2);
    memcpy(tcp->port,tcp->tcp_header+2,2);

    // because we know is a tcp packet, we obtain its payload
    tcp->total_headers_size=tcp->ethernet_header_length + tcp->ip_header_length + tcp->tcp_header_length;
    tcp->payload_length = tcp->packet_header_t->caplen - (tcp->total_headers_size);
    tcp->payload=calloc(tcp->payload_length,sizeof(u_char));
    memcpy(tcp->payload,packet+tcp->ethernet_header_length+tcp->ip_header_length+tcp->tcp_header_length,tcp->payload_length);

    return 0;
}

void printPayload(const u_char* payload, int payload_length){
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;

        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }

        printf("\n\n");
    }
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet total length %d\n", packet_header.len);

    int ethernet_header_length = 14;                            // Constante
    const u_char* ip_header = packet+ethernet_header_length;    // Cabecera IP
    u_char protocol = *(ip_header + 9);                         // Protocolo

    /*
    Lo siguiente mostrará un número que puede verse en:
    https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    */

    printf("Packet type %02d\n\n", (unsigned int) protocol);
    
    //if (protocol != IPPROTO_TCP) {}
}

void ARP_free(ARP_packet* arp){
    //free structures in arp 
   
    //struct ether_header* eth_header_t; 
    //free(arp->arp_header_t);
   free(arp);
}
void TCP_free(TCP_packet* tcp){
    //free structures inee(tcp->ethernet_header);
    free(tcp->ip_header);
    free(tcp->tcp_header);
    free(tcp->payload);
    free(tcp->port);

    free(tcp);
}
