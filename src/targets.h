#ifndef TARGETS
#define TARGETS

extern u_int32_t ip_addr;
extern struct in_addr ip_attacker;
extern struct libnet_ether_addr *mac_attacker;
extern struct in_addr ip_victim1;
extern struct libnet_ether_addr *mac_victim1;
extern struct in_addr ip_victim2;
extern struct libnet_ether_addr *mac_victim2;

extern struct libnet_ether_addr *mac_bcast;

void construct_targets(libnet_t*,int,char*[]);
#endif
