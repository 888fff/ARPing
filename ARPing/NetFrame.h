#pragma once
#include<string>
using namespace std;
class NetFrame
{
public:
	NetFrame();
	~NetFrame();
	//
	void FillFrame(unsigned char* data);
	void ToString();
	//
	string GetDestinationString();
	long   GetDestination();
	//
	string GetSourceSting();
	long	GetSource();
	//
	int		GetType();
	//
	const unsigned char* GetData();
protected:
	unsigned char data[1600];
};

