#include "ARP_Chunk.h"
#include "Defined.h"
#include <string.h>
#include <sstream>
#include <iomanip>
#include <stdio.h>
#include <iostream>
#include <algorithm>
#include <WinSock2.h>
using namespace std;



ARP_Chunk::ARP_Chunk()
{
	memset(data,0, ARP_CHUNK_SIZE);
}

ARP_Chunk::ARP_Chunk(const void * packet, long len)
{
	if (packet) {
		memcpy(data, packet, len);
	}
	else {
		memset(data, 0, ARP_CHUNK_SIZE);
	}
}


ARP_Chunk::~ARP_Chunk()
{

}

void ARP_Chunk::SetHardwareType(short t)
{
	*(short*)(data + ARP_HT_OFFSET) = htons(t);
}

void ARP_Chunk::SetProtocolType(short t)
{
	*(short*)(data + ARP_PT_OFFSET) = htons(t);
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
	*(short*)(data + ARP_OC_OFFSET) = htons(c);
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
		memset(data + ARP_THA_OFFSET, 0xff, ARP_HA_SIZE);
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
	ht = ntohs(ht);
	stringstream ss;
	ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << ht;
	ss >> out;
	ss.clear();
	return ht;
}

short ARP_Chunk::GetProtocolType(string& out)
{
	short ret = *(short*)(data + ARP_PT_OFFSET);
	ret = ntohs(ret);
	stringstream ss;
	ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << ret;
	ss >> out;
	ss.clear();
	return ret;
}

BYTE ARP_Chunk::GetHardwareAddressLength(string& out)
{
	unsigned int ret = static_cast<unsigned int>(*(data + ARP_HAL_OFFSET));
	stringstream ss;
	ss << std::dec << ret;
	ss >> out;
	ss.clear();
	return ret;
}

BYTE ARP_Chunk::GetProtocolAddressLength(string& out)
{
	int ret = static_cast<unsigned int>(*(data + ARP_PAL_OFFSET));
	stringstream ss;
	ss << std::dec << ret;
	ss >> out;
	ss.clear();

	return ret;
}

short ARP_Chunk::GetOperationCode(string& out)
{
	short ret = *(short*)(data + ARP_OC_OFFSET);
	ret = ntohs(ret);
	stringstream ss;
	ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << ret;
	ss >> out;
	ss.clear();

	return ret;
}

void ARP_Chunk::GetSourceProtocolAddress(std::string & out)
{
	char remove;
	stringstream ss;
	for (int i = 0; i < ARP_PA_SIZE; ++i)
		ss << "." <<std::dec << static_cast<unsigned short>(*(data + ARP_SPA_OFFSET + i));
	ss >> remove;
	ss >> out;
	ss.clear();
}

void ARP_Chunk::GetSourceHardwareAddress(std::string & out)
{
	stringstream ss;
	char remove;
	for (int i = 0; i < ARP_HA_SIZE; ++i)
		ss << ":"<< setiosflags(ios::uppercase) << std::hex << std::setw(2)
		<< std::setfill('0') << static_cast<unsigned short>(*(data + ARP_SHA_OFFSET+i)) ;
	ss >> remove;
	ss >> out;
	ss.clear();
}

void ARP_Chunk::GetTargetProtocolAddress(std::string & out)
{
	char remove;
	stringstream ss;
	for (int i = 0; i < ARP_PA_SIZE; ++i)
		ss << "." << std::dec << static_cast<unsigned short>(*(data + ARP_TPA_OFFSET + i));
	ss >> remove;
	ss >> out;
	ss.clear();
}

void ARP_Chunk::GetTargetHardwareAddress(std::string & out)
{
	char remove;
	stringstream ss;
	for (int i = 0; i < ARP_HA_SIZE; ++i)
		ss << ":" <<setiosflags(ios::uppercase) << std::hex << std::setw(2)
		<< std::setfill('0') << static_cast<unsigned short>(*(data + ARP_THA_OFFSET + i));
	ss >> remove;
	ss >> out;
	ss.clear();
}

std::string ARP_Chunk::ToString()
{
	string ret; short t;
	string out;
	t = GetHardwareType(ret);
	out.append("HardwareType:").append(ret).append("\n");

	t = GetProtocolType(ret);
	out.append("ProtocolType:").append(ret).append("\n");

	t = GetHardwareAddressLength(ret);
	out.append("HardwareAddressLength:").append(ret).append("\n");

	t = GetProtocolAddressLength(ret);
	out.append("ProtocolAddressLength:").append(ret).append("\n");

	t = GetOperationCode(ret);
	out.append("OperationCode:").append(ret).append("\n");

	GetSourceHardwareAddress(ret);
	out.append("SourceHardwareAddress:	").append(ret).append("\n");

	GetSourceProtocolAddress(ret);
	out.append("SourceProtocolAddress:	").append(ret).append("\n");

	GetTargetHardwareAddress(ret);
	out.append("TargetHardwareAddress:	").append(ret).append("\n");

	GetTargetProtocolAddress(ret);
	out.append("TargetProtocolAddress:	").append(ret).append("\n");

	return out;
}

void ARP_Chunk::setHardwareAddressStr(const char* addr, string& out)
{
	string buff(addr);
	string trans;
	buff.erase(std::remove(buff.begin(), buff.end(), ':'), buff.end());
	size_t len = buff.length();
	for (size_t i = 0; i < len; i += 2)
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
