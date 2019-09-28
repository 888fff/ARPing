// ARPing.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <string>
#include "pcap.h"
#include "ARP_Chunk.h"
#include "ARP_Sender.h"
using namespace std;
////
// 函数原型

//-----------
int main()
{
	std::cout << "****** Hello ARP! ******\n" << endl;
	//------------------------------------------------
	//		WinPcap Test Code hhh~~
	//------------------------------------------------
	ARP_Sender arp_sender;
	arp_sender.Init();
	int	inum;
	scanf_s("%d", &inum);	
	if (!arp_sender.SeletAdapter(inum)) {
		return -1;
	}
	printf("输入请求的ARP的IP:\n");
	char ip_str[18];
	scanf_s("%s", ip_str,18);
	//创建arp chunk
	ARP_Chunk chunk;
	chunk.SetHardwareType(1);
	chunk.SetProtocolType(ARP_PT_IP);
	chunk.SetHardwareAddressLength(6);
	chunk.SetProtocolAddressLength(4);
	chunk.SetOperationCode(ARP_OC_REQUEST);
	chunk.SetSourceHardwareAddress(arp_sender.GetCurMacAddr());
	chunk.SetSourceProtocolAddress(arp_sender.GetCurIPAddr());
	chunk.SetTargetHardwareAddressStr(0);
	chunk.SetTargetProtocolAddressStr(ip_str);
	//
	string tmp;
	chunk.GetTargetProtocolAddress(tmp);
	arp_sender.SetFilter(ip_str);
	printf("-----开始向%s发送ARP请求-----\n",tmp.c_str());
	//
	
	if (arp_sender.SendPacket(chunk.GetData())) {
		for (int counter = 1; counter < 4;counter++) {
			while (arp_sender.CaptureARPPacket()<=0){}
			arp_sender.SendPacket(chunk.GetData());
		}

	}
	return 0;

}

