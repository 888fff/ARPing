#include "ARP_Sender.h"
#include "Packet32.h"
#include <NtDDNdis.h>
#include "ARP_Chunk.h"
#include "NetFrame.h"

using namespace std;

ARP_Sender::ARP_Sender()
{
	max_devs = 0;
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
	//��ʾ��ǰ�豸�б�
	for (adapterDevice = alldevs; adapterDevice; adapterDevice = adapterDevice->next)
	{
		printf("[%d] %s \n", ++max_devs, adapterDevice->name);
		if (adapterDevice->description)
			printf("����: (%s)\n", adapterDevice->description);
		else
			printf(" (No description available)\n");
	}

	if (max_devs == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return false;
	}
	printf("ѡ����Ҫʹ�õ�Adapter:\n");
	return true;
}

bool ARP_Sender::SeletAdapter(int idx)
{
	if (idx < 1 || idx > max_devs)
	{
	cout << "Interface number out of range." << endl;
	Release();
	return false;
	}

	/* ��ת��ѡ�е������� */
	adapterDevice = alldevs;
	for (int i = 0; i < idx - 1; adapterDevice = adapterDevice->next, i++);

	if ((adapterHandler = pcap_open(adapterDevice->name,  // �豸��
		65536,     // Ҫ��׽�����ݰ��Ĳ��� 
				   // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,         // ����ģʽ
		1,      // ��ȡ��ʱʱ��
		NULL,      // Զ�̻�����֤
		errbuf     // ���󻺳��
	)) == NULL)
	{
		cout << "Unable to open the adapter." << adapterDevice->name << " is not supported by WinPcap." << endl;
		Release();
		return false;
	}
	/* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
	if (pcap_datalink(adapterHandler) != DLT_EN10MB)
	{
		cout << "This program works only on Ethernet networks." << endl;
		Release();
		return false;
	}
	if (adapterDevice->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(adapterDevice->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;

	//��õ�ǰAdapter��IP��ַ
	if (!GetAdapterIP()) {
		cout << "��ȡ��ǰ������IP��ַʧ��" << endl;
		Release();
		return false;
	}
	//��ȡ��ǰAdapter��Mac��ַ
	if (!GetAdapterMac()) {
		cout << "��ȡ��ǰ������mac��ַʧ��" << endl;
		Release();
		return false;
	}
	//
	Release();
	return true;
}

bool ARP_Sender::SendPacket(const unsigned char * chunk_data)
{
	unsigned char data[FRAME_ARP_LEN];
	NetFrame::CreateARPFrame(0, mac_addr, chunk_data, data);

	if (pcap_sendpacket(adapterHandler, data, FRAME_ARP_LEN) != 0)
	{
		cout << "Error sending the packet:" << pcap_geterr(adapterHandler) << endl;
		return false;
	}
	//��¼һ��ʱ��
	MakeTimeStamp();
	return true;
}

bool ARP_Sender::SetFilter(const char * ip)
{
	char ip_str[18];
	strcpy_s(ip_str, iptos(*(long*)ip_addr));
	sprintf_s(packet_filter, "arp src host %s and dst host %s", ip, ip_str);

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

	return true;
}

int ARP_Sender::CaptureARPPacket()
{
	//pcap_handler callback = (pcap_handler)&ARP_Sender::Packet_handler;//ǿ��ת��
	//pcap_loop(adapterHandler, 0, callback, NULL);

	int					res;
	struct pcap_pkthdr  *header = 0;
	const u_char		*pkt_data = 0;

	if ((res = pcap_next_ex(adapterHandler, &header, &pkt_data)) >= 0){
		Packet_handler(0, header, pkt_data);
		return res;
	}

	return res;
}

void ARP_Sender::Release()
{
	if (alldevs) {
		pcap_freealldevs(alldevs);
		alldevs = 0;
	}
}

void ARP_Sender::Packet_handler(u_char * param, const pcap_pkthdr * header, const u_char * pkt_data)
{
	
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;
	//
	if (header == 0 || pkt_data == 0) return;

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime,&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
	float delay = (header->ts.tv_sec - m_tv.tv_sec) * 1000 + (header->ts.tv_usec - m_tv.tv_usec) * 0.001;
	/* ��ӡ���ݰ���ʱ����ͳ��� */
	printf("%s delay:%.6f ms len:%d \n", timestr, delay , header->len);
	ARP_Chunk chunk( pkt_data + 14 ,28);
	printf("%s\n ", chunk.ToString().c_str());
}

bool ARP_Sender::GetAdapterMac()
{
	LPADAPTER lpAdapter = PacketOpenAdapter(adapterDevice->name + 8);
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
		//
		char output[128];
		sprintf_s(output, "%02X:%02X:%02X:%02X:%02X:%02X", 
			mac_addr[0], 
			mac_addr[1], 
			mac_addr[2], 
			mac_addr[3],
			mac_addr[4],
			mac_addr[5]);
		printf("\tMac Address:%s\n\n", output);
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

bool ARP_Sender::GetAdapterIP()
{
	pcap_addr_t *a;

	/* IP addresses */
	for (a = adapterDevice->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr) {
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
				u_char *p;
				p = (u_char *)&((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
				for (size_t i = 0; i < 4; i++)
				{
					ip_addr[i] = p[i];
				}
			}
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;

		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	return true;
}

char * ARP_Sender::iptos(u_long in)
{
	const int IPTOSBUFFERS = 12;
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;
	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

void ARP_Sender::MakeTimeStamp()
{
	time_t clock;
	struct tm tm;
	SYSTEMTIME wtm;
	GetLocalTime(&wtm);
	tm.tm_year = wtm.wYear - 1900;
	tm.tm_mon = wtm.wMonth - 1;
	tm.tm_mday = wtm.wDay;
	tm.tm_hour = wtm.wHour;
	tm.tm_min = wtm.wMinute;
	tm.tm_sec = wtm.wSecond;
	tm.tm_isdst = -1;
	clock = mktime(&tm);
	m_tv.tv_sec = clock;
	m_tv.tv_usec = wtm.wMilliseconds*1000;
}
