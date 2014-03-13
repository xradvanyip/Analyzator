
// Analyzator.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include <pcap.h>
#include <string.h>


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

// Implementation

	DECLARE_MESSAGE_MAP()

private:
	pcap_t *handle;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr pcap_header;
	
};

extern CAnalyzatorApp theApp;