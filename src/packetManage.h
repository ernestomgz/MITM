#ifndef PKT_MNG 
#define PKT_MNG

void my_packet_handler(u_char*,const struct pcap_pkthdr*,const u_char*);
void print_packet_info(const u_char*,struct pcap_pkthdr);
#endif
