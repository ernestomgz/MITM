#ifndef PKT_MNG 
#define PKT_MNG


/**
 * @brief Encuentra la carga (payload) de un paquete.
 * 
 * @param[in] pcap_pkthdr   Manejador del paquete.
 * 
 * @return Código de salida (0: correcto, -1: error).
 */
void my_packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);

/**
 * @brief Mostrar información de un paquete.
 * 
 * @param[in] pcap_packet   Paquete.
 */
void print_packet_info(const u_char*, struct pcap_pkthdr);


typedef struct tcp_packet{


}tcp_packet;


#endif
