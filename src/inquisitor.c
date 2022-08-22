/**
 * @file    inquisitor.c
 * @author  Ernesto Martínez Gómez (@ernestomgz),
 *          Antonio J. Galán Herrera (@15Galan)
 * @brief   Proof of Concept of a 'Man In The Middle' attack ('ARP Spoofing').
 * @date    2022-08-17
 * @version 0.1
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "packetManage.h"


// ---------------------------------------------------------------------------------------------------------------------


// extern int verbose;                  // Verbose mode // TODO

struct in_addr src_ip;                 // Source IP address
struct libnet_ether_addr src_mac;      // Source MAC address

struct in_addr dst_ip;                 // Destination IP address
struct libnet_ether_addr dst_mac;      // Destination MAC address

struct in_addr atk_ip;                 // Attacker IP address
struct libnet_ether_addr atk_mac;      // Attacker MAC address

struct libnet_ether_addr bcast_mac;    // Broadcast MAC address

struct libnet_t *l;                    // Libnet handle
struct pcap_t *handle;                 // Pcap   handle


// ---------------------------------------------------------------------------------------------------------------------


/**
 * @brief Set the Global Data objects.
 * 
 * @param argc  Number of arguments.
 * @param argv  Arguments.
 *
 * @return int  0 if success, -1 if error.
 */
int setGlobalData(int argc, char *argv[]) {

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
    src_ip.s_addr = inet_addr(argv[1]);
    sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &src_mac.ether_addr_octet[0], &src_mac.ether_addr_octet[1], &src_mac.ether_addr_octet[2],
        &src_mac.ether_addr_octet[3], &src_mac.ether_addr_octet[4], &src_mac.ether_addr_octet[5]);

    // Destination IP and MAC addresses.
    dst_ip.s_addr = inet_addr(argv[3]);
    sscanf(argv[4], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &dst_mac.ether_addr_octet[0], &dst_mac.ether_addr_octet[1], &dst_mac.ether_addr_octet[2],
        &dst_mac.ether_addr_octet[3], &dst_mac.ether_addr_octet[4], &dst_mac.ether_addr_octet[5]);
    
    // Broadcast MAC address.
    memset(&bcast_mac, 0xff, sizeof(bcast_mac));
    
    return 0;
}


/**
 * @brief   Main function.
 * 
 * @param   argc Number of arguments.
 * @param   argv Arguments.
 * 
 * @return  0 if success, -1 if error.
 */
int main(int argc, char *argv[]) {
    // Set Global Data
    setGlobalData(argc, argv);

    // Print Global Data (test)
    printf("src IP  : %s\n", inet_ntoa(src_ip));
    printf("src MAC : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
        src_mac.ether_addr_octet[0], src_mac.ether_addr_octet[1], src_mac.ether_addr_octet[2],
        src_mac.ether_addr_octet[3], src_mac.ether_addr_octet[4], src_mac.ether_addr_octet[5]);

    printf("dst IP  : %s\n", inet_ntoa(dst_ip));
    printf("dst MAC : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
        dst_mac.ether_addr_octet[0], dst_mac.ether_addr_octet[1], dst_mac.ether_addr_octet[2],
        dst_mac.ether_addr_octet[3], dst_mac.ether_addr_octet[4], dst_mac.ether_addr_octet[5]);

    printf("atk IP  : %s\n", inet_ntoa(atk_ip));
    printf("atk MAC : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
        atk_mac.ether_addr_octet[0], atk_mac.ether_addr_octet[1], atk_mac.ether_addr_octet[2],
        atk_mac.ether_addr_octet[3], atk_mac.ether_addr_octet[4], atk_mac.ether_addr_octet[5]);

    printf("bdt MAC : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
        bcast_mac.ether_addr_octet[0], bcast_mac.ether_addr_octet[1], bcast_mac.ether_addr_octet[2],
        bcast_mac.ether_addr_octet[3], bcast_mac.ether_addr_octet[4], bcast_mac.ether_addr_octet[5]);

    printf("\n");

    return 0;
}
