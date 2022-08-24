#ifndef PKT_MNG 
#define PKT_MNG

typedef struct TCP_packet{

	struct pcap_pkthdr* packet_header_t;
	struct ether_header* eth_header_t;
	struct tcphdr* tcp_header_t;

	//all the headers in a tcp

	u_char* packet;
	u_char* ethernet_header;
	u_char *ip_header; 
	u_char *tcp_header; 
	u_char *payload;
	u_char protocol; 
	u_char *port;

	// Headers length
	int ethernet_header_length;    // Constante
	int ip_header_length;           // = 9
	int tcp_header_length;          //=*tcp_header_length * 4;
	int payload_length;      
	int total_headers_size;	//all headers-calen



}TCP_packet;

typedef struct ARP_packet{
	//ethernet header struct
	struct ether_header* eth_header_t; 
	struct libnet_ether_addr* source;
	struct libnet_ether_addr* destination;
	//arp header struct
	struct ether_arp *arp_header_t;

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
