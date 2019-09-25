#pragma once
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
	void SetSourceProtocolAddress(const unsigned char* addr);
	void SetTargetHardwareAddress(const unsigned char* addr = 0);
	void SetTargetProtocolAddress(const unsigned char* addr);
	inline const unsigned char* GetData() { return data; }
private:
	unsigned char data[28];
};

