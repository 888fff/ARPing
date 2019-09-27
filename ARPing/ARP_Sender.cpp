#include "ARP_Sender.h"
#include "Packet32.h"
#include <NtDDNdis.h>
#include "ARP_Chunk.h"
using namespace std;

ARP_Sender::ARP_Sender()
{
	strcpy_s(packet_filter, PCAP_ERRBUF_SIZE ,"arp");
}


ARP_Sender::~ARP_Sender()
{
	Release();
}

bool ARP_Sender::Init()
{
	char source[] = PCAP_SRC_IF_STRING;
	if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == -1)
	{
		cout << errbuf << endl;
		return false;
	}
	if (alldevs == 0) {
		cout << "No interfaces found! Make sure WinPcap is installed." << endl;
		return false;
	}
	adapterDevice = alldevs;
	if ((adapterHandler = pcap_open(adapterDevice->name,  // 设备名
		65536,     // 要捕捉的数据包的部分 
				   // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
		1000,      // 读取超时时间
		NULL,      // 远程机器验证
		errbuf     // 错误缓冲池
	)) == NULL)
	{
		cout << "Unable to open the adapter." << adapterDevice->name <<" is not supported by WinPcap." << endl;
		Release();
		return false;
	}
	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adapterHandler) != DLT_EN10MB)
	{
		cout << "This program works only on Ethernet networks." <<endl;
		Release();
		return false;
	}
	if (adapterDevice->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(adapterDevice->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;

	//编译过滤器
	if (pcap_compile(adapterHandler, &fcode, packet_filter, 1, netmask) < 0)
	{
		cout << "Unable to compile the packet filter. Check the syntax" << endl;
		Release();
		return false;
	}

	//设置过滤器
	if (pcap_setfilter(adapterHandler, &fcode) < 0)
	{
		cout << "Error setting the filter" << endl;
		Release();
		return false;
	}
	//获取当前Adapter的Mac地址
	if (!GetAdapterMac()) {
		cout << "获取当前配适器mac地址失败" << endl;
	}
	//
	Release();
	return true;
}

bool ARP_Sender::SendPacket(unsigned char * to_mac, unsigned char * chunk_data, size_t len)
{
	if (pcap_sendpacket(adapterHandler, chunk_data, len /* size */) != 0)
	{
		cout << "Error sending the packet:" << pcap_geterr(adapterHandler) << endl;
		return false;
	}
	return true;
}

void ARP_Sender::CaptureARPPacket()
{
	pcap_handler callback = (pcap_handler)&ARP_Sender::Packet_handler;//强制转换

	pcap_loop(adapterHandler, 0, callback, NULL);
}

void ARP_Sender::Release()
{
	pcap_freealldevs(alldevs);
}

void ARP_Sender::Packet_handler(u_char * param, const pcap_pkthdr * header, const u_char * pkt_data)
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime,&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* 打印数据包的时间戳和长度 */
	printf("%s.%.6d len:%d \n", timestr, header->ts.tv_usec, header->len);

	ARP_Chunk chunk( pkt_data + 14 ,28);
	printf("%s\n ", chunk.ToString().c_str());


}

bool ARP_Sender::GetAdapterMac()
{
	LPADAPTER lpAdapter = PacketOpenAdapter(adapterDevice->name);
	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		return false;
	}

	PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	if (NULL == OidData)
	{
		PacketCloseAdapter(lpAdapter);
		return false;
	}

	OidData->Oid = OID_802_3_CURRENT_ADDRESS;

	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);

	BOOLEAN Status = PacketRequest(lpAdapter, FALSE, OidData);
	if (Status)
	{
		for (int i = 0; i < 6; ++i)
		{
			mac_addr[i] = (OidData->Data)[i];
		}
	}
	else
	{
		return false;
		free(OidData);
	}
	free(OidData);
	PacketCloseAdapter(lpAdapter);
	return true;
}
