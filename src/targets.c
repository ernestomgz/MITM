#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <libnet.h>

#include "targets.h"

	//u_int32_t ip_addr;
	u_int32_t ip_addr;
    extern struct in_addr ip_attacker;
	extern struct libnet_ether_addr *mac_attacker=calloc(sizeof(struct libnet_ether_addr);
    extern struct in_addr ip_victim1=0;
	extern struct libnet_ether_addr *mac_victim1=calloc(sizeof(struct libnet_ether_addr);
    extern struct in_addr ip_victim2=0;
	extern struct libnet_ether_addr *mac_victim2=calloc(sizeof(struct libnet_ether_addr);


        void construct_targets(LIBNETKJ* l ,int argc,char* argv[]){
	ip_addr = libnet_get_ipaddr4(l);
    ip_attacker=*(struct in_addr*) &ip_attacker;
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
}
