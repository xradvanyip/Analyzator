
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
	static UINT AnalyzeFrames(void *pParam);

// Implementation

	DECLARE_MESSAGE_MAP()

private:
	static pcap_t *handle;
	static char pcap_errbuf[PCAP_ERRBUF_SIZE];
	static struct pcap_pkthdr pcap_header;
	static CStringA FilePath;
public:
	static UINT AnalyzeCommunication(void *pParam);
};

extern CAnalyzatorApp theApp;