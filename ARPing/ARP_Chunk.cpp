#include "ARP_Chunk.h"
#include "Defined.h"
#include <string.h>
#include <sstream>
#include <iomanip>
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
	memcpy(data + ARP_HT_OFFSET, &t, sizeof t);
}

void ARP_Chunk::SetProtocolType(short t)
{
	memcpy(data + ARP_PT_OFFSET, &t, sizeof t);
}

void ARP_Chunk::SetHardwareAddressLength(unsigned char len)
{
	memcpy(data + ARP_HAL_OFFSET, &len, 1);
}

void ARP_Chunk::SetProtocolAddressLength(unsigned char len)
{
	memcpy(data + ARP_PAL_OFFSET, &len, 1);
}

void ARP_Chunk::SetOperationCode(short c)
{
	memcpy(data + ARP_OC_OFFSET, &c, sizeof c);

}

void ARP_Chunk::SetSourceHardwareAddress(const unsigned char * addr)
{
	memcpy(data + ARP_SHA_OFFSET, addr, ARP_HA_SIZE * (sizeof *addr) );
}

void ARP_Chunk::SetSourceHardwareAddressStr(const char * addr)
{
	//这里可以有一些参数的验证，算了不写了，哈哈
	string trans;
	setHardwareAddressStr(addr, trans);
	SetSourceHardwareAddress((BYTE*)trans.c_str());
}

void ARP_Chunk::SetSourceProtocolAddress(const unsigned char * addr)
{
	memcpy(data + ARP_SPA_OFFSET, addr, ARP_PA_SIZE);
}

void ARP_Chunk::SetSourceProtocolAddressStr(const char * addr)
{
	string trans;
	setProtocolAddressStr(addr, trans);
	SetSourceProtocolAddress((BYTE*)trans.c_str());
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
	if (addr == 0 || strlen(addr) == 0) {
		SetTargetHardwareAddress(0);
	}
	else {
		string trans;
		setHardwareAddressStr(addr, trans);
		SetTargetHardwareAddress((BYTE*)trans.c_str());
	}

}

void ARP_Chunk::SetTargetProtocolAddress(const unsigned char * addr)
{
	memcpy(data + ARP_TPA_OFFSET, addr, ARP_PA_SIZE);
}

void ARP_Chunk::SetTargetProtocolAddressStr(const char * addr)
{
	string trans;
	setProtocolAddressStr(addr, trans);
	SetTargetProtocolAddress((BYTE*)trans.c_str());
}

short ARP_Chunk::GetHardwareType(string& out)
{
	short ht = *(short*)(data + ARP_HT_OFFSET);
	stringstream ss;
	ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << ht;
	out = ss.str();
	ss.clear();
	return ht;
}

short ARP_Chunk::GetProtocolType(string& out)
{
	short ret = *(short*)(data + ARP_PT_OFFSET);
	stringstream ss;
	ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << ret;
	out = ss.str();
	ss.clear();
	return ret;
}

BYTE ARP_Chunk::GetHardwareAddressLength(string& out)
{
	unsigned int ret = static_cast<unsigned int>(*(data + ARP_HAL_OFFSET));
	stringstream ss;
	ss << std::dec << ret;
	out = ss.str();
	ss.clear();
	return ret;
}

BYTE ARP_Chunk::GetProtocolAddressLength(string& out)
{
	int ret = static_cast<unsigned int>(*(data + ARP_PAL_OFFSET));
	stringstream ss;
	ss << std::dec << ret;
	out = ss.str();
	ss.clear();

	return ret;
}

short ARP_Chunk::GetOperationCode(string& out)
{
	short ret = *(short*)(data + ARP_OC_OFFSET);
	stringstream ss;
	ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << ret;
	out = ss.str();
	ss.clear();

	return ret;
}

void ARP_Chunk::GetSourceProtocolAddress(std::string & out)
{
}

void ARP_Chunk::GetSourceHardwareAddress(std::string & out)
{
}

void ARP_Chunk::GetTargetProtocolAddress(std::string & out)
{
}

void ARP_Chunk::GetTargetHardwareAddress(std::string & out)
{
}

void ARP_Chunk::setHardwareAddressStr(const char* addr, string& out)
{
	string buff(addr);
	string trans;
	buff.erase(std::remove(buff.begin(), buff.end(), ':'), buff.end());
	size_t len = buff.length();
	for (long i = 0; i < len; i += 2)
	{
		string byte = buff.substr(i, 2);
		//字符串转整形
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
		trans.push_back(chr);
	}
	out =  trans;
}

void ARP_Chunk::setProtocolAddressStr(const char * addr, string& out)
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
	out = trans;
}
