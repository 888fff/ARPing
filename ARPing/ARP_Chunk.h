#pragma once
#define ARP_CHUNK_SIZE 28
#define ARP_HA_SIZE 6
#define ARP_PA_SIZE 4

#define ARP_HT_OFFSET 0
#define ARP_PT_OFFSET 2
#define ARP_HAL_OFFSET 4
#define ARP_PAL_OFFSET 5
#define ARP_OC_OFFSET 6
#define ARP_SHA_OFFSET 8
#define ARP_SPA_OFFSET 14
#define ARP_THA_OFFSET 18
#define ARP_TPA_OFFSET 24
//
#define ARP_PT_IP 2048
#define ARP_OC_REQUEST 1
#define ARP_OC_RESPONSE 2


#include <string>
class ARP_Chunk
{
public:
	ARP_Chunk();
	~ARP_Chunk();
	//
	void SetHardwareType(short t);
	void SetProtocolType(short t);
	void SetHardwareAddressLength(unsigned char len = 6);
	void SetProtocolAddressLength(unsigned char len = 4);
	void SetOperationCode(short c);

	void SetSourceHardwareAddress(const unsigned char* addr);
	void SetSourceHardwareAddressStr(const char* addr);

	void SetSourceProtocolAddress(const unsigned char* addr);
	void SetSourceProtocolAddressStr(const char* addr);

	void SetTargetHardwareAddress(const unsigned char* addr = 0);
	void SetTargetHardwareAddressStr(const char* addr = 0);

	void SetTargetProtocolAddress(const unsigned char* addr);
	void SetTargetProtocolAddressStr(const char* addr);

	inline const unsigned char* GetData() { return data; }
public:
	short GetHardwareType(std::string& out);
	short GetProtocolType(std::string& out);
	unsigned char GetHardwareAddressLength(std::string& out);
	unsigned char GetProtocolAddressLength(std::string& out);
	short GetOperationCode(std::string& out);
	void GetSourceProtocolAddress(std::string& out);
	void GetSourceHardwareAddress(std::string& out);
	void GetTargetProtocolAddress(std::string& out);
	void GetTargetHardwareAddress(std::string& out);




private:
	unsigned char data[ARP_CHUNK_SIZE];
	void setHardwareAddressStr(const char* addr, std::string& out);
	void setProtocolAddressStr(const char* addr, std::string& out);


};

