#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <string.h>


extern u_int32_t ip_addr;
extern struct in_addr ip_attacker;
extern struct libnet_ether_addr *mac_attacker;
extern struct in_addr ip_victim1;
extern struct libnet_ether_addr *mac_victim1;
extern struct in_addr ip_victim2;
extern struct libnet_ether_addr *mac_victim2;
extern struct libnet_ether_addr *mac_bcast;

int printIPandMAC(struct in_addr ip, struct libnet_ether_addr* mac){
	if ( ip.s_addr != -1 )
		printf("IP address: %s\n", libnet_addr2name4(ip.s_addr, LIBNET_DONT_RESOLVE));
	else
		return -1;

	if ( mac!= NULL )
		printf("MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",\
				mac->ether_addr_octet[0],\
				mac->ether_addr_octet[1],\
				mac->ether_addr_octet[2],\
				mac->ether_addr_octet[3],\
				mac->ether_addr_octet[4],\
				mac->ether_addr_octet[5]);
	else
		return -1;
	return 0;
}

//initialize IPs and MACs of attacker victim1 and victim2
void construct_targets(libnet_t *l ,int argc ,char *argv[]){
	//attacker IP and MAC addresses
	ip_addr = libnet_get_ipaddr4(l);
	ip_attacker.s_addr=ip_addr;
	mac_attacker= libnet_get_hwaddr(l);

	if(printIPandMAC(ip_attacker,mac_attacker)!=0)
		fprintf(stderr, "Couldn't get own address: %s\n", libnet_geterror(l));


	/*
	 *'sscanf' it's like an inverse 'printf' function: it parse a string and extract data from it.
	 */

    // victim1  IP and MAC addresses.
    ip_victim1.s_addr = inet_addr(argv[1]);
    
    mac_victim1=calloc(1,sizeof(struct libnet_ether_addr));
    sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &mac_victim1->ether_addr_octet[0], &mac_victim1->ether_addr_octet[1], &mac_victim1->ether_addr_octet[2],
        &mac_victim1->ether_addr_octet[3], &mac_victim1->ether_addr_octet[4], &mac_victim1->ether_addr_octet[5]);

    if(printIPandMAC(ip_victim1,mac_victim1)!=0)
		fprintf(stderr, "Couldn't get own address: %s\n", libnet_geterror(l));


    
    // victim2  IP and MAC addresses.
    ip_victim2.s_addr = inet_addr(argv[3]);

    mac_victim2=calloc(1,sizeof(struct libnet_ether_addr));
    sscanf(argv[4], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &mac_victim2->ether_addr_octet[0], &mac_victim2->ether_addr_octet[1], &mac_victim2->ether_addr_octet[2],
        &mac_victim2->ether_addr_octet[3], &mac_victim2->ether_addr_octet[4], &mac_victim2->ether_addr_octet[5]);
    
    if(printIPandMAC(ip_victim2,mac_victim2)!=0)
	    fprintf(stderr, "Couldn't get own address: %s\n", libnet_geterror(l));



    // Broadcast MAC address.
    mac_bcast=calloc(1,sizeof(struct libnet_ether_addr));
    memset(mac_bcast, 0xff, sizeof(mac_bcast));
    
    return 0;
}


   
  
