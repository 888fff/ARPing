#include "ARP_Chunk.h"
#include <string.h>
#include <stdio.h>


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
	memcpy(data + ARP_SHA_OFFSET, addr, ARP_HA_SIZE);
}

void ARP_Chunk::SetSourceHardwareAddressStr(const char * addr)
{
	char *ptr;
	char *p;
	char buff[128];
	strcpy_s(buff, sizeof buff,addr);
	ptr = strtok_s(buff, ":" ,&p);
	while (ptr != NULL) {
		//printf("%s:", ptr);
		ptr = strtok_s(NULL, ":",&p);

	}
}

void ARP_Chunk::SetSourceProtocolAddress(const unsigned char * addr)
{
	memcpy(data + ARP_SPA_OFFSET, addr, ARP_PA_SIZE);

}

void ARP_Chunk::SetSourceProtocolAddressStr(const char * addr)
{
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
