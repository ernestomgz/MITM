#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "packetManage.h"

typedef struct TCP_packet{

    struct pcap_pkthdr packet_header;
    struct ether_header eth_header;

    //all the headers in a tcp

     u_char* packet;
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

int TCP_packet_construct(TCP_packet* tcp,const u_char* packet, struct pcap_pkthdr packet_header){
    //constante
    tcp->ethernet_header_length=14;

    tcp->packet_header=packet_header;

    memcpy(tcp->packet,packet,strlen(packet));
    struct ether_header* eth_header;
    (struct ether_header *) packet;
    tcp->eth_header = (struct ether_header *) packet;

    //struct ether_header *eth_header;
    //eth_header = (struct ether_header *) packet;

    tcp.ip_header_length = ((*tcp.ip_header) & 0x0F);
    tcp.ip_header_length = tcp.ip_header_length * 4;


    u_char protocol = *(tcp.ip_header + 9);     // Comienzo de la cabecera del protocolo
    sprintf(tcp.protocol,"%02d",(unsigned int)protocol);


    tcp.tcp_header = tcp.packet + tcp.ethernet_header_length + tcp.ip_header_length;    // Comienzo de la cabecera TCP
    tcp.tcp_header_length = ((*(tcp.tcp_header + 12)) & 0xF0) >> 4;
    tcp.tcp_header_length = tcp.tcp_header_length * 4;
    
    tcp.total_headers_size=ethernet_header_length + ip_header_length + tcp_header_length;

    tcp.payload_length = header->caplen - (tcp.total_headers_size);
    tcp.payload = tcp.packet + tcp.total_headers_size;


    // Comprobar si es un paquete IP
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return -1;
    }

    
    tcp.tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;

    tcp.ip_header = packet + ethernet_header_length;    // Comienzo de la cabecera IP
    return ;
}



void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Castea el paquete a una estructura de tipo ethernet.
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    // Comprobar si es un paquete IP
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /*
    La longitud total del paquete, incluyendo todos los encabezados
    y el payload, se almacena en 'header->len', 'header->caplen'.

    'caplen' es la cantidad realmente disponible, y 'len' es la longitud total
    del paquete, incluso si es mayor que lo que se ha capturado actualmente.
    
    Si la longitud de la captura establecida con 'pcap_open_live()'
    es demasiado pequeña, puede que no tenga la totalidad del paquete.
    */

    printf("Total packet available: (%d/%d) bytes\n",header->len, header->caplen);

    // Punteros donde empiezan varias cabeceras
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    // Longitud de las cabeceras (bytes)
    int ethernet_header_length = 14;    // Constante
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    TCP_packet tcp;

    if(TCP_packet_construct(&tcp,packet,packet_header)==1){
        return;
    }
    

    /*
    La segunda mitad del primer byte de 'ip_header'
    contiene la longitud de la cabecera IP (IHL)
    */

    ip_header_length = ((*ip_header) & 0x0F);

    /*
    El IHL es el número de segmentos de 32 bits.
    Multiplicarlo por 4 para obtener una cantidad
    de bytes para el puntero aritmético.
    */

    ip_header_length = ip_header_length * 4;
    
    print_packet_info(packet,*header);
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
    
    /*
    Sabiendo dónde está la cabecera IP, se puede inspeccionar para obtener
    el número de protocolo para comprobar que es TCP antes de continuar.
    El protocolo siempre está en la posición #10 de la cabecera IP.
    */

    u_char protocol = *(ip_header + 9);     // Comienzo de la cabecera del protocolo

    // Comprobar si es un paquete TCP
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n");
        return;
    }

    /*
    Agregar las longitudes de las cabeceras Ethernet e IP al comienzo
    del paquete para encontrar el comienzo de la cabecera TCP.
    */
    
    tcp_header = packet + ethernet_header_length + ip_header_length;    // Comienzo de la cabecera TCP

    /*
    La longitud de la cabecera TCP se almacena en la primera mitad del byte 12 de la cabecera TCP.
    Por lo tanto, si se quiere obtener el valor de la segunda mitad del byte, debe desplazarse a la
    parte inferior del byte para que se use el valor más significativo (en lugar del menos significativo).
    */

    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;

    /*
    La cabecera TCP almacenada en esos 4 bits representa cuántas palabras de 32-bits hay en la cabecera.
    Al igual que con la longitud de la cabecera IP, multiplicar por 4 para obtener una cantidad de bytes.
    */

    tcp_header_length = tcp_header_length * 4;

    printf("TCP header length in bytes: %d\n", tcp_header_length);

    // Agregar todos los tamaños para encontrar el desplazamiento del payload
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);

    payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);

    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

    // Mostrar la carga (payload) en ASCII
    return;
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
