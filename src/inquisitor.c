#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "packetManage.h"


int main(int argc, char *argv[]) {
    char error_buffer[PCAP_ERRBUF_SIZE];    // Buffer to capture errors
    int timeout_limit = 10000;              // Timeout limit (in ms)
    int snapshot_length = 1024;             // How many bytes to capture
    int total_packet_count = 200;           // How many packets to capture

    /* automatically detects the device(eth0 or other) */
    char *device = pcap_lookupdev(error_buffer); 
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    /* Open device for live capture */
    pcap_t *handle = pcap_open_live(device,snapshot_length,0,timeout_limit,error_buffer);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return 2;
     }






    u_char *my_arguments=NULL;

    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);

    return 0;
}
