// Código extraído de: https://www.devdungeon.com/content/using-libpcap-c

#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>


/// --------------------------------------------------------------------------------------------------------------------


// Manejador de eventos de captura de paquetes
void my_packet_handler(
    u_char *args,                       /* Argumentos de la captura */
    const struct pcap_pkthdr *header,   /* Cabecera del paquete */
    const u_char *packet                /* Paquete capturado */
);

// Mostrar información de un paquete
void print_packet_info(
    const u_char *packet,               /* Paquete */
    struct pcap_pkthdr packet_header    /* Cabecera */
);


/// --------------------------------------------------------------------------------------------------------------------


/**
 * @brief Función principal del programa.
 * 
 * @param argc  Número de argumentos
 * @param argv  Argumentos de entrada
 * 
 * @return int  Código de salida (0: correcto, 1: error)
 */
int main(int argc, char *argv[]) {
    char *device;                           // Dispositivo de red
    char error_buffer[PCAP_ERRBUF_SIZE];    // Buffer de error
    pcap_t *handle;                         // Manejador de captura
    int timeout_limit = 10000;              // Tiempo de espera de la captura (ms)

    device = pcap_lookupdev(error_buffer);  // Buscar dispositivo de red

    // Verificar si se encontró un dispositivo de red
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);

        return 1;
    }

    // Abrir el dispositivo de red
    handle = pcap_open_live(
            device,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
        );

    // Verificar si se pudo abrir el dispositivo de red
    if (handle == NULL) {
         fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);

         return 2;
    }

    // Capturar paquetes 
    pcap_loop(
        handle,                 /* Manejador de captura */
        0,                      /* Capturar infinitamente */
        my_packet_handler,      /* Manejador de captura de paquetes */
        NULL);                  /* Argumentos de la captura */

    return 0;
}


// Manejador de eventos de captura de paquetes (implementación)
void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
    print_packet_info(packet_body, *packet_header);

    return;
}

// Mostrar información de un paquete (implementación)
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    // Longitud del paquete (capturado y original)
    printf("Longitud de captura  : %d\n", packet_header.caplen);
    printf("Longitud del paquete : %d\n", packet_header.len);

    // Mostrar la fecha y hora de la captura
    printf("Marca de tiempo      : %s", ctime((const time_t *)&packet_header.ts.tv_sec));

    // Mostrar la dirección MAC de origen y destino
    printf("MAC del emisor       : %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("MAC del receptor     : %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

    // Mostrar el tipo de protocolo de la capa de enlace
    printf("Tipo de Ethernet     : %02x:%02x\n", packet[12], packet[13]);
}
