#include "ARP_Chunk.h"
#include "Defined.h"
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <algorithm>
using namespace std;



ARP_Chunk::ARP_Chunk()
{
	memset(data,0, ARP_CHUNK_SIZE);
}


ARP_Chunk::~ARP_Chunk()
{
}

void ARP_Chunk::SetHardwareType(short t)
{
	*(data + ARP_HT_OFFSET) = t;
}

void ARP_Chunk::SetProtocolType(short t)
{
	*(data + ARP_PT_OFFSET) = t;
}

void ARP_Chunk::SetHardwareAddressLength(unsigned char len)
{
	*(data + ARP_HAL_OFFSET) = len;
}

void ARP_Chunk::SetProtocolAddressLength(unsigned char len)
{
	*(data + ARP_PAL_OFFSET) = len;
}

void ARP_Chunk::SetOperationCode(short c)
{
	*(data + ARP_OC_OFFSET) = c;
}

void ARP_Chunk::SetSourceHardwareAddress(const unsigned char * addr)
{
	memcpy(data + ARP_SHA_OFFSET, addr, ARP_HA_SIZE * (sizeof *addr) );
}

void ARP_Chunk::SetSourceHardwareAddressStr(const char * addr)
{
	//这里可以有一些参数的验证，算了不写了，哈哈
	string buff(addr);
	string trans;
	buff.erase(std::remove(buff.begin(), buff.end(), ':'), buff.end());
	long len = buff.length();
	for (long i = 0; i < len; i += 2)
	{
		string byte = buff.substr(i, 2);
		//字符串转整形
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
		trans.push_back(chr);
	}
	SetSourceHardwareAddress((BYTE)trans.c_str());
}

void ARP_Chunk::SetSourceProtocolAddress(const unsigned char * addr)
{
	memcpy(data + ARP_SPA_OFFSET, addr, ARP_PA_SIZE);
}

void ARP_Chunk::SetSourceProtocolAddressStr(const char * addr)
{
	string buff(addr);
	buff.push_back('.');
	string trans;
	string ip;
	string::size_type position;
	position = buff.find(".");
	while (position != buff.npos)
	{
		ip = buff.substr(0, position);
		buff = buff.substr(position + 1);
		char chr = (int)strtol(ip.c_str(), NULL, 10);
		trans.push_back(chr);
		position = buff.find(".");
	}
	SetSourceProtocolAddress((BYTE)trans.c_str());
}

void ARP_Chunk::SetTargetHardwareAddress(const unsigned char * addr)
{
	if (addr)
		memcpy(data + ARP_THA_OFFSET, addr, ARP_HA_SIZE);
	else
		memset(data + ARP_THA_OFFSET, 0, ARP_HA_SIZE);
}

void ARP_Chunk::SetTargetHardwareAddressStr(const char * addr)
{
}

void ARP_Chunk::SetTargetProtocolAddress(const unsigned char * addr)
{
	memcpy(data + ARP_TPA_OFFSET, addr, ARP_PA_SIZE);
}

void ARP_Chunk::SetTargetProtocolAddressStr(const char * addr)
{
}
