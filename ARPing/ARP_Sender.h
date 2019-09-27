#pragma once
#include <iostream>
#include "pcap.h"

class ARP_Sender
{
public:
	ARP_Sender();
	~ARP_Sender();
	//
	bool Init();
	bool SendPacket(unsigned char* to_mac,unsigned char* chunk_data,size_t len);
	void CaptureARPPacket();
	void Release();
	//
	static void Packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
private:
	bool GetAdapterMac();
private:
	pcap_t*		adapterHandler;
	pcap_if_t*	alldevs;
	pcap_if_t*	adapterDevice;
	char		errbuf[PCAP_ERRBUF_SIZE];
	char		packet_filter[PCAP_ERRBUF_SIZE];
	u_int		netmask;
	bpf_program fcode;
	//
	char		mac_addr[6];

};

