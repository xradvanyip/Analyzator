
// Analyzator.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include <pcap.h>
#include <string.h>


#define ETH2_HDR_LEN 14

typedef struct ip_data {
	byte ip1, ip2, ip3, ip4;
	unsigned sent;
} IP_DATA;

typedef struct communication {
	byte src_ip[4], dst_ip[4];
	unsigned src_port, dst_port;
	unsigned start_frame_id, end_frame_id, frames_count;
	bool start_pre_verified, start_verified;
	bool end_init, end_pre_verified, end_verified, reversed_end;
} COMMUNICATION;

typedef struct frame_len_count {
	unsigned from, to, count;
} FRAME_LEN_COUNT;

typedef struct thread_param {
		int protocol;
		CDialog *pDlg;
	} THREAD_PARAM;

typedef struct arp {
	byte ip1[4], ip2[4];
	unsigned req_frame_id, rep_frame_id;
	bool reply_received;
} ARP;

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
	static bool IsACK(byte b);
	static bool HaveACK(byte b);
	static bool HaveRST(byte b);
	static bool IsSYN(byte b);
	static bool HaveSYN(byte b);
	static bool IsFIN(byte b);
	static bool HaveFIN(byte b);
	static bool IsSYNandACK(byte b);
	static bool IsFINandACK(byte b);
	bool CmpCommWithFrame(COMMUNICATION comm, const u_char *frame, bool reverse = false);
	bool CmpUDPCommWithFrame(COMMUNICATION comm, const u_char *frame);
	bool CmpARPCommWithFrame(ARP arp_comm, const u_char *frame, bool IsReply = false);
	void PrintFrame(const u_char *frame, CString *print, bool print_flags = false);

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
	static byte GetUpperByte(unsigned int number);
	static byte GetLowerByte(unsigned int number);
	static unsigned int MergeBytes(byte upper, byte lower);
};

extern CAnalyzatorApp theApp;