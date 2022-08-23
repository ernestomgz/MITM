#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>


#include <arpa/inet.h>
#include <libnet.h>


#include "packetManage.h"
#include "utils.h"



void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	//ARP packet creation and allocation
	ARP_packet *arp=malloc(sizeof(ARP_packet));
	
	//Trying to convert packet into ARP
	if(ARP_packet_construct(arp,header,packet)!=-1){
		printf("ARP packet detected\n");
		//do thing with arp object
		ARP_free(arp);
		return;
	}else
		ARP_free(arp);

	return; //TODO: delete 

	//TCP packet creation and allocation
	TCP_packet *tcp=malloc(sizeof(TCP_packet));

	//Trying to convert packet into TCP
	if(TCP_packet_construct(tcp,header,packet)!=-1){
		printf("TCP packet detected in port %d\n",ntohs(tcp->tcp_header_t->th_dport));
		//only processing TCP of port 20 or 21 because are the ports used by FTP
		if (ntohs(tcp->tcp_header_t->th_dport)==21||ntohs(tcp->tcp_header_t->th_dport)==20){
			//spoof packet
		}

		
		TCP_free(tcp);
		return;
	}else
		TCP_free(tcp);
	//printf("Error obtaining packet type\n");

}
