#pragma once
#include<string>
#define FRAME_ARP_LEN (14+48)
#define FRAME_ARP_TYPE 0x0806
using namespace std;
class NetFrame
{
public:
	NetFrame();
	~NetFrame();
public:
	static void CreateARPFrame(const unsigned char* dest, const unsigned char* source, const unsigned char* arp_data, unsigned char* data);
protected:
};

