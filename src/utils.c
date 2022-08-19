
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "packetManage.h"

int TCP_packet_construct(TCP_packet* tcp,const struct pcap_pkthdr* packet_header,const u_char* packet){
    //constante
    tcp->packet_header=calloc(sizeof(struct pcap_pkthdr),1);
    tcp->packet_header=packet_header;

    tcp->ethernet_header_length=14;
    tcp->eth_header = (struct ether_header *) packet;
    tcp->ethernet_header=calloc(sizeof(u_char),tcp->ethernet_header_length);
    memcpy(tcp->ethernet_header,packet,tcp->ethernet_header_length);

    // Comprobar si es un paquete IP
    if (ntohs(tcp->eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return -1;
    }

    u_char *ip_header=packet+tcp->ethernet_header_length;
    tcp->ip_header_length = ((*ip_header ) & 0x0F);
    tcp->ip_header_length = tcp->ip_header_length * 4;
    tcp->ip_header=calloc(tcp->ip_header_length,sizeof(u_char));
    memcpy(tcp->ip_header,packet+tcp->ethernet_header_length,tcp->ip_header_length);

    tcp->protocol = *(tcp->ip_header + 9);     // Comienzo de la cabecera del protocolo
    if (tcp->protocol != IPPROTO_TCP) {
        printf("Not a TCP packet(type:%02d). Skipping...\n",(unsigned int)tcp->protocol );
        return -1;
    }


    tcp->tcp_header_length = ((*(packet + tcp->ethernet_header_length + tcp->ip_header_length + 12)) & 0xF0) >> 4;
    tcp->tcp_header_length = tcp->tcp_header_length * 4;
    tcp->tcp_header=calloc(tcp->tcp_header_length,sizeof(u_char));
    memcpy(tcp->tcp_header,packet+tcp->ethernet_header_length+tcp->ip_header_length,tcp->tcp_header_length);

    tcp->port = calloc(sizeof(u_char), 2);
    memcpy(tcp->port,tcp->tcp_header+2,2);
    printf("the port is in hex %02x%02x",*tcp->port,*(tcp->port+1));

    tcp->total_headers_size=tcp->ethernet_header_length + tcp->ip_header_length + tcp->tcp_header_length;

    tcp->payload_length = tcp->packet_header->caplen - (tcp->total_headers_size);
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

