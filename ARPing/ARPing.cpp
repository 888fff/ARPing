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
	std::cout << "Hello ARP!\n" << endl;
	ARP_Chunk chunk;
	chunk.SetHardwareType(1);
	chunk.SetProtocolType(ARP_PT_IP);
	chunk.SetHardwareAddressLength(6);
	chunk.SetProtocolAddressLength(4);
	chunk.SetOperationCode(ARP_OC_REQUEST);
	chunk.SetSourceHardwareAddressStr("00:a0:24:71:e4:44");
	chunk.SetSourceProtocolAddressStr("128.143.137.144");
	chunk.SetTargetHardwareAddressStr(0);
	chunk.SetTargetProtocolAddressStr("128.143.137.1");
	const BYTE* buffer = chunk.GetData();

	//------------------------------------------------
	//		WinPcap Test Code
	//------------------------------------------------
	ARP_Sender arp_sender;
	arp_sender.Init();
	arp_sender.CaptureARPPacket();

	return 0;

}

