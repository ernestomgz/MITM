#ifndef PKT_MNG 
#define PKT_MNG

typedef struct TCP_packet{

    struct pcap_pkthdr* packet_header;
    struct ether_header* eth_header;

    //all the headers in a tcp

     u_char* packet;
     u_char* ethernet_header;
     u_char *ip_header; // packet + ethernet_header_length;     const u_char *tcp_header;
     u_char *tcp_header; // packet + ethernet_header_length;     const u_char *tcp_header;
     u_char *payload;
     u_char protocol; //in this program we are going to use only FTP and ARP
     u_char *port;

    // Longitud de las cabeceras (bytes)
    int ethernet_header_length;    // Constante
    int ip_header_length;           // = 9
    int tcp_header_length;          //=tcp_header_length * 4;
    int payload_length;             //= 
    int total_headers_size;         // = ethernet_header_length+ip_header_length+tcp_header_length;
                                    //


}TCP_packet;

typedef struct ARP_packet{
    struct ether_header* eth_header; //= (struct etherhdr *) packet;
    struct ether_arp *arp_packet;
    

}ARP_packet;


/**
 * @brief Encuentra la carga (payload) de un paquete.
 * 
 * @param[in] pcap_pkthdr   Manejador del paquete.
 * 
 * @return Código de salida (0: correcto, -1: error).
 */
void my_packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);



#endif
