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
	if ((adapterHandler = pcap_open(adapterDevice->name,  // �豸��
		65536,     // Ҫ��׽�����ݰ��Ĳ��� 
				   // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,         // ����ģʽ
		1000,      // ��ȡ��ʱʱ��
		NULL,      // Զ�̻�����֤
		errbuf     // ���󻺳��
	)) == NULL)
	{
		cout << "Unable to open the adapter." << adapterDevice->name <<" is not supported by WinPcap." << endl;
		Release();
		return false;
	}
	/* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
	if (pcap_datalink(adapterHandler) != DLT_EN10MB)
	{
		cout << "This program works only on Ethernet networks." <<endl;
		Release();
		return false;
	}
	if (adapterDevice->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(adapterDevice->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;

	//���������
	if (pcap_compile(adapterHandler, &fcode, packet_filter, 1, netmask) < 0)
	{
		cout << "Unable to compile the packet filter. Check the syntax" << endl;
		Release();
		return false;
	}

	//���ù�����
	if (pcap_setfilter(adapterHandler, &fcode) < 0)
	{
		cout << "Error setting the filter" << endl;
		Release();
		return false;
	}
	//��ȡ��ǰAdapter��Mac��ַ
	if (!GetAdapterMac()) {
		cout << "��ȡ��ǰ������mac��ַʧ��" << endl;
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
	pcap_handler callback = (pcap_handler)&ARP_Sender::Packet_handler;//ǿ��ת��

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

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime,&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* ��ӡ���ݰ���ʱ����ͳ��� */
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
