﻿// ARPing.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <string>
#include "pcap.h"
#include "ARP_Chunk.h"
using namespace std;
int main()
{
    std::cout << "Hello World!\n"; 
	ARP_Chunk chunk;
	chunk.SetHardwareType(1);
	chunk.SetProtocolType(ARP_PT_IP);
	chunk.SetHardwareAddressLength(6);
	chunk.SetProtocolAddressLength(4);
	chunk.SetOperationCode(ARP_OC_REQUEST);
	chunk.SetSourceHardwareAddressStr("00:a0:24:71:e4:44");
	chunk.SetSourceProtocolAddressStr("128.143.137.144");
	const BYTE* buffer = chunk.GetData();
	string ret; short t;
	t = chunk.GetHardwareType(ret);
	t = chunk.GetProtocolType(ret);
	t = chunk.GetHardwareAddressLength(ret);
	t = chunk.GetProtocolAddressLength(ret);
	t = chunk.GetOperationCode(ret);


}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
