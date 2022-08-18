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


int main(int argc, char *argv[]) {
    // TODO: start to code

    return 0;
}
