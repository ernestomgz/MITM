#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <string.h>

#include "targets.h"


	u_int32_t ip_addr;
    struct in_addr ip_attacker;
	struct libnet_ether_addr *mac_attacker;
    //mac_attacker=calloc(sizeof(struct libnet_ether_addr));
    struct in_addr ip_victim1;
	struct libnet_ether_addr *mac_victim1;
    //mac_victim1=calloc(sizeof(struct libnet_ether_addr));
    struct in_addr ip_victim2;
	struct libnet_ether_addr *mac_victim2;
    //mac_victim2=calloc(sizeof(struct libnet_ether_addr));
    struct libnet_ether_addr *mac_bcast;
    //mac_bcast=calloc(sizeof(struct libnet_ether_addr));

    void construct_targets(libnet_t *l ,int argc ,char *argv[]){
        ip_addr = libnet_get_ipaddr4(l);
        //ip_attacker=*(struct in_addr*) &ip_attacker;
        if ( ip_addr != -1 )
            printf("IP address: %s\n", libnet_addr2name4(ip_addr, LIBNET_DONT_RESOLVE));
        else
            fprintf(stderr, "Couldn't get own IP address: %s\n", libnet_geterror(l));

        mac_attacker= libnet_get_hwaddr(l);
        if ( mac_attacker!= NULL )
            printf("MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",\
                    mac_attacker->ether_addr_octet[0],\
                    mac_attacker->ether_addr_octet[1],\
                    mac_attacker->ether_addr_octet[2],\
                    mac_attacker->ether_addr_octet[3],\
                    mac_attacker->ether_addr_octet[4],\
                    mac_attacker->ether_addr_octet[5]);
        else
            fprintf(stderr, "Couldn't get own MAC address: %s\n", libnet_geterror(l));
        
    // TODO: verbose mode ('-v')
    // Check arguments cuantity.
    if (argc != 5) {
        printf("Usage: %s <Source IP> <Source MAC> <Destination IP> <Destination MAC>\n", argv[0]);
        exit(0);
    }

    /*
    'sscanf' it's like an inverse 'printf' function: it parse a string and extract data from it.
    */

    // Source IP and MAC addresses.
    ip_victim1.s_addr = inet_addr(argv[1]);
    sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        mac_victim1->ether_addr_octet[0], mac_victim1->ether_addr_octet[1], mac_victim1->ether_addr_octet[2],
        mac_victim1->ether_addr_octet[3], mac_victim1->ether_addr_octet[4], mac_victim1->ether_addr_octet[5]);

        if ( mac_victim1!= NULL ){
            printf("MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",\
                    mac_attacker->ether_addr_octet[0],\
                    mac_attacker->ether_addr_octet[1],\
                    mac_attacker->ether_addr_octet[2],\
                    mac_attacker->ether_addr_octet[3],\
                    mac_attacker->ether_addr_octet[4],\
                    mac_attacker->ether_addr_octet[5]);
        }
    // Destination IP and MAC addresses.
    ip_victim2.s_addr = inet_addr(argv[3]);
    sscanf(argv[4], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &mac_victim2->ether_addr_octet[0], &mac_victim2->ether_addr_octet[1], &mac_victim2->ether_addr_octet[2],
        &mac_victim2->ether_addr_octet[3], &mac_victim2->ether_addr_octet[4], &mac_victim2->ether_addr_octet[5]);
    
    // Broadcast MAC address.
    memset(mac_bcast, 0xff, sizeof(mac_bcast));
    
    return 0;
}


   
  