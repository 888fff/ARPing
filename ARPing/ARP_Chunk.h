#pragma once
#define ARP_CHUNK_SIZE 28
#define ARP_HA_SIZE 6
#define ARP_PA_SIZE 4

#define ARP_HT_OFFSET 0
#define ARP_PT_OFFSET (ARP_HT_OFFSET+2)
#define ARP_HAL_OFFSET (ARP_PT_OFFSET+2)
#define ARP_PAL_OFFSET (ARP_HAL_OFFSET+1)
#define ARP_OC_OFFSET (ARP_PAL_OFFSET+1)
#define ARP_SHA_OFFSET (ARP_OC_OFFSET+2)
#define ARP_SPA_OFFSET (ARP_SHA_OFFSET+ ARP_HA_SIZE)
#define ARP_THA_OFFSET (ARP_SPA_OFFSET+ ARP_PA_SIZE)
#define ARP_TPA_OFFSET (ARP_THA_OFFSET+ ARP_HA_SIZE)

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
private:
	unsigned char data[ARP_CHUNK_SIZE];
};

