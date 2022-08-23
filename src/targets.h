#ifndef TARGETS
#define TARGETS

//IP and MAC from attacker
u_int32_t ip_addr;
struct in_addr ip_attacker;
struct libnet_ether_addr *mac_attacker;

//IP and MAC from victim1
struct in_addr ip_victim1;
struct libnet_ether_addr *mac_victim1;

//IP and MAC from victim2
struct in_addr ip_victim2;
struct libnet_ether_addr *mac_victim2;

//broadcast
struct libnet_ether_addr *mac_bcast;

/*
 * @brief prints ip and mac in console
 *
 * param struct in_addr 
 * param struct libnet_ehter_addr 
 *
 * @return 0 correct or 1 error that can be read from pcap error buffer
 */
int printIPandMAC(struct in_addr ip, struct libnet_ether_addr* mac);

/*
 * @brief initialize attacker and victims MAC and IP
 *
 * @param libnet_t* libnet context
 * @param int number of arguments
 * @param char*[] arguments
 *
 * @return no return if error can be read in pcap error buffer
 * 
 */
void construct_targets(libnet_t*,int,char*[]);
#endif
