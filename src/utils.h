#ifndef UTILS
#define UTILS


/**
 * @brief Obtiene los distintos header de cada uno de los protocolos(ethernet, ip, tcp) ademas del payload.
 *        Ademas ofrece la longitud de cada uno de lo headers de los protocolos. Muy util para imprimirlos.
 *
 * @param[in] TCP_packet*   Puntero a la estructura tcp creada.
 * @param[in] pcap_pkthdr   Manejador del paquete.
 * @param[in] packet   Array con todo el paquete.
 * 
 * @return Código de salida (0: correcto, -1: error).
 */
int TCP_packet_construct(TCP_packet* ,const struct pcap_pkthdr* ,const u_char*);

/**
 * @brief Obtiene los distintos header de cada uno de los protocolos(ethernet, ip, tcp) ademas del payload.
 *        Ademas ofrece la longitud de cada uno de lo headers de los protocolos. Muy util para imprimirlos.
 *
 * @param[in] TCP_packet*   Puntero a la estructura tcp creada.
 * @param[in] pcap_pkthdr   Manejador del paquete.
 * @param[in] packet   Array con todo el paquete.
 * 
 * @return Código de salida (0: correcto, -1: error).
 */
int ARP_packet_construct(ARP_packet* ,const struct pcap_pkthdr* ,const u_char*);

/**
 * TODO
 */
ARP_gratuitous_request(
        struct in_addr* ip_atk,
        struct libnet_ether_addr* mac_atk,
        struct in_addr* ip_fake,
        struct in_addr* ip_trg,
        struct libnet_ether_addr* mac_trg,
        struct in_addr* ip_brd,
        libnet_t* l);

/**
 * @brief Mostrar información de un paquete.
 * 
 * @param[in] pcap_packet   Paquete.
 */
void print_packet_info(const u_char*, struct pcap_pkthdr);

/**
 * @brief compares two macs
 *
 * @param two macs in struct libnet_ether_addr
 */
int maccmp(struct libnet_ether_addr* , struct libnet_ether_addr* );


/**
 * @brief Mostrar información de un paquete.
 * 
 * @param[in] pcap_packet   Paquete.
 */
void printPayload(const u_char* , int );

/**
 * @brief Envia una respuesta arp gratuita. Puede ser usado tanto de forma convencional como maliciosa.
 * 
 * @param[in] struct in_addr ip victima 1.
 * @param[in] struct libnet_ether_addr mac victima 1
 * @param[in] struct in_addr ip victima 2.
 * @param[in] struct libnet_ether_addr mac victima 2
 */
int gratuitous_ARP(struct in_addr,struct libnet_ether_addr,struct in_addr,struct libnet_ether_addr);

//free arp and tcp packets
void ARP_free(ARP_packet*);
void TCP_free(TCP_packet*);

//sends an arp packet:
//		      ↓ ↓ ↓ ↓ ↓ (destiny) ↓ ↓ ↓ ↓ ↓ ↓		 ↓ ↓ ↓ ↓ ↓ (how we want to be saved) ↓ ↓ ↓ ↓ ↓ ↓
void sendARP(struct libnet_ether_addr* ,struct in_addr  ,struct in_addr  ,struct libnet_ether_addr* ,libnet_t* );

//reply an arp packet:
//		      ↓ ↓ ↓ ↓ ↓ (destiny) ↓ ↓ ↓ ↓ ↓ ↓		 ↓ ↓ ↓ ↓ ↓ (how we want to be saved) ↓ ↓ ↓ ↓ ↓ ↓
void replyARP(struct libnet_ether_addr* ,struct in_addr  ,struct in_addr  ,struct libnet_ether_addr* ,libnet_t* );


#endif

