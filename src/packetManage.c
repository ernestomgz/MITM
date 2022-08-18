#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "packetManage.h"

typedef struct TCP_packet{

    struct pcap_pkthdr* packet_header;
    struct ether_header* eth_header;

    //all the headers in a tcp

     u_char* packet;
     u_char* ethernet_header;
     u_char *ip_header; // packet + ethernet_header_length;     const u_char *tcp_header;
     u_char *tcp_header; // packet + ethernet_header_length;     const u_char *tcp_header;
     u_char *payload;
     u_char *protocol; //in this program we are going to use only FTP and ARP

    // Longitud de las cabeceras (bytes)
    int ethernet_header_length;    // Constante
    int ip_header_length;           // = 9
    int tcp_header_length;          //=tcp_header_length * 4;
    int payload_length;             //= 
    int total_headers_size;         // = ethernet_header_length+ip_header_length+tcp_header_length;
                                    //


}TCP_packet;

int TCP_packet_construct(TCP_packet* tcp,const struct pcap_pkthdr* packet_header,const u_char* packet){
    //constante
    tcp->packet_header=sizeof(struct pcap_pkthdr);
    tcp->packet_header=packet_header;

    tcp->ethernet_header_length=14;
    tcp->eth_header = (struct ether_header *) packet;
    tcp->ethernet_header=calloc(sizeof(u_char),tcp->ethernet_header_length);
    memcpy(tcp->ethernet_header,packet,tcp->ethernet_header_length);

    u_char *ip_header=packet+tcp->ethernet_header_length;
    tcp->ip_header_length = ((*ip_header ) & 0x0F);
    tcp->ip_header_length = tcp->ip_header_length * 4;
    tcp->ip_header=calloc(tcp->ip_header_length,sizeof(u_char));
    memcpy(tcp->ip_header,packet+tcp->ethernet_header_length,tcp->ip_header_length);

    // Comprobar si es un paquete IP
    if (ntohs(tcp->eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return -1;
    }

    tcp->tcp_header_length = ((*(packet + tcp->ethernet_header_length + tcp->ip_header_length + 12)) & 0xF0) >> 4;
    tcp->tcp_header_length = tcp->tcp_header_length * 4;
    tcp->tcp_header=calloc(tcp->tcp_header_length,sizeof(u_char));
    memcpy(tcp->tcp_header,packet+tcp->ethernet_header_length+tcp->ip_header_length,tcp->tcp_header_length);
    printf("tcp_header  %02x:%02x",*(tcp->tcp_header),*(tcp->tcp_header+1));

//    u_char protocol = *(tcp->ip_header + 9);     // Comienzo de la cabecera del protocolo
//    u_char protocol;
//    protocol =*(tcp->tcp_header + 1);     // Comienzo de la cabecera del protocolo
    //sprintf(tcp->protocol,"%02d",(unsigned int)protocol);

    // Comprobar si es un paquete TCP
//    if (protocol != IPPROTO_TCP) {
//        printf("Not a TCP packet(type:%02d). Skipping...\n",(unsigned int)protocol );
//        return -1;
//    }
//
//
//
//    tcp->tcp_header_length = ((*(tcp->tcp_header + 12)) & 0xF0) >> 4;
//    tcp->tcp_header_length = tcp->tcp_header_length * 4;
//    tcp->tcp_header=calloc(tcp->tcp_header_length,sizeof(u_char));
//    memcpy(tcp->tcp_header,tcp->ip_header+tcp->ip_header_length,tcp->tcp_header_length);
//
//    
//    tcp->total_headers_size=tcp->ethernet_header_length + tcp->ip_header_length + tcp->tcp_header_length;
//
//    tcp->payload_length = tcp->packet_header->caplen - (tcp->total_headers_size);
//    tcp->payload=calloc(tcp->payload_length,sizeof(u_char));
//    memcpy(tcp->payload,tcp->tcp_header+tcp->tcp_header_length,tcp->total_headers_size);

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


void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    TCP_packet tcp;

   if(TCP_packet_construct(&tcp,header,packet)==-1){
        printf("error generating tcp packet");
        return;
    }

    printf("the payload is:");
    //printPayload(tcp.payload,tcp.payload_length);

    return;
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
