#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <libnet.h>

#include "packetManage.h"
#include "utils.h"
#include "targets.h"


int main(int argc, char *argv[]) {
    char error_buffer[PCAP_ERRBUF_SIZE];    // Buffer to capture errors
    int timeout_limit = 10000;              // Timeout limit (in ms)
    int snapshot_length = 1024;             // How many bytes to capture
    int total_packet_count = 200;           // How many packets to capture


    /* automatically detects the device(eth0 or other) */
    pcap_if_t* alldevs;
    int devStatus = pcap_findalldevs(&alldevs, error_buffer); 
    printf("dev is : %s\n",alldevs->name);




    if (devStatus==-1) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }
    /* Open device for live capture */
    pcap_t *handle = pcap_open_live(alldevs->name,snapshot_length,0,timeout_limit,error_buffer);

    libnet_t *l = libnet_init(LIBNET_LINK,alldevs->name,error_buffer);

    char errbuf[LIBNET_ERRBUF_SIZE];

    construct_targets(l,argc,argv);


    u_char *my_arguments=NULL;

    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);

    pcap_freealldevs(alldevs);

    return 0;
}
