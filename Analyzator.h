
// Analyzator.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include <pcap.h>
#include <string.h>


typedef struct thread_param {
		int protocol;
		CDialog *pDlg;
	} THREAD_PARAM;

typedef enum {TCP, UDP} IP_PROT_TYPE;

// CAnalyzatorApp:
// See Analyzator.cpp for the implementation of this class
//

class CAnalyzatorApp : public CWinApp
{
public:
	CAnalyzatorApp();

// Overrides
public:
	virtual BOOL InitInstance();
	bool OpenPCAPfile(CStringA path);
	void ReOpenPCAPfile(void);
	static UINT AnalyzeFrames(void *pParam);
	static UINT AnalyzeCommunication(void *pParam);
	CString CheckProtocolFiles(void);

// Implementation

	DECLARE_MESSAGE_MAP()

private:
	static pcap_t *handle;
	static char pcap_errbuf[PCAP_ERRBUF_SIZE];
	static struct pcap_pkthdr pcap_header;
	static CStringA FilePath;
	FILE *f_eth2;
	FILE *f_ip;
	FILE *f_ports;
	FILE *f_icmp;
	unsigned int GetEth2ProtocolNum(char *Name);
	unsigned int GetIPProtocolNum(char *Name);
	IP_PROT_TYPE GetIPProtocolType(char *AppName);
	unsigned int GetPortNumber(char *AppName);
	CString GetICMPType(byte TypeNum);
	byte GetUpperByte(unsigned int number);
	byte GetLowerByte(unsigned int number);
	unsigned int MergeBytes(byte upper, byte lower);
};

extern CAnalyzatorApp theApp;