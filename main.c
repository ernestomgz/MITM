#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#include "libnet.h"


int main(int argc, char* argv[]){
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

    char* device = "any";  //this define the interface, can be eth0, wlan0 or any (all interfaces),
    pcap_t* devices = pcap_create(device,error_buffer);

    if(pcap_activate(devices)!=0){
        printf("error activating");
    }

    /* Find a device */
//    device = pcap_lookupdev(error_buffer);
//    if (device == NULL) {
//        printf("Error finding device: %s\n", error_buffer);
//        return 1;
//    }

    //printf("Network device found: %s\n", device);
    return 0;

}
