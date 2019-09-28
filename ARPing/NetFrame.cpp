#include "NetFrame.h"
#include <WinSock2.h>

NetFrame::NetFrame()
{
}


NetFrame::~NetFrame()
{
}

void NetFrame::CreateARPFrame(const unsigned char * dest, const unsigned char * source, const unsigned char * arp_data,unsigned char* data)
{
	unsigned char frame[FRAME_ARP_LEN];
	if (dest) {
		memcpy_s(frame, 6, dest, 6);
	}
	else {
		memset(frame,0xff,6);
	}
	memcpy_s(frame + 6, 6, source, 6);
	unsigned short t = htons(FRAME_ARP_TYPE);
	memcpy_s(frame + 12, 2, &t , 2);
	memcpy_s(frame + 14, 48, arp_data, 28);
	if (data) {
		memcpy_s(data, FRAME_ARP_LEN, frame, FRAME_ARP_LEN);
	}
}