#ifndef UTILS
#define UTILS

//#include "packetManage.h"


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
 * @brief Mostrar información de un paquete.
 * 
 * @param[in] pcap_packet   Paquete.
 */
void print_packet_info(const u_char*, struct pcap_pkthdr);


/**
 * @brief Mostrar información de un paquete.
 * 
 * @param[in] pcap_packet   Paquete.
 */
void printPayload(const u_char* , int );


#endif
