#pragma once
#include <iostream>
#include "pcap.h"

static struct timeval g_tv;
class ARP_Sender
{
public:
	ARP_Sender();
	~ARP_Sender();
	//
	bool Init();
	bool SeletAdapter(int idx);
	bool SendPacket(const unsigned char* chunk_data);
	bool CaptureARPPacket(const char* ip);
	void Release();
	//
	static void Packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
private:
	bool GetAdapterMac();
	bool GetAdapterIP();
	char*	iptos(u_long in);
	void MakeTimeStamp();
private:
	pcap_t*		adapterHandler;
	pcap_if_t*	alldevs;
	pcap_if_t*	adapterDevice;
	char		errbuf[PCAP_ERRBUF_SIZE];
	char		packet_filter[PCAP_ERRBUF_SIZE];
	u_int		netmask;
	bpf_program fcode;
	int			max_devs;
	//
	unsigned char mac_addr[6];
	unsigned char ip_addr[4];
public :
	inline const unsigned char* GetCurMacAddr() { return mac_addr; }
	inline const unsigned char* GetCurIPAddr() { return ip_addr; }
};

