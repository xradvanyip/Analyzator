
// Analyzator.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include <afxtempl.h>
#include "Analyzator.h"
#include "AnalyzatorDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif



// CAnalyzatorApp

BEGIN_MESSAGE_MAP(CAnalyzatorApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CAnalyzatorApp construction

CAnalyzatorApp::CAnalyzatorApp()
	: f_eth2(NULL)
	, f_ip(NULL)
	, f_ports(NULL)
	, f_icmp(NULL)
{
	// support Restart Manager
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CAnalyzatorApp object

CAnalyzatorApp theApp;


// CAnalyzatorApp initialization

BOOL CAnalyzatorApp::InitInstance()
{
	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


	AfxEnableControlContainer();

	// Create the shell manager, in case the dialog contains
	// any shell tree view or shell list view controls.
	CShellManager *pShellManager = new CShellManager;

	// Activate "Windows Native" visual manager for enabling themes in MFC controls
	CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	SetRegistryKey(_T("Local AppWizard-Generated Applications"));
	
	f_eth2 = fopen("ethernet2_protocols.txt","r");
	f_ip = fopen("ip_protocols.txt","r");
	f_ports = fopen("ports.txt","r");
	f_icmp = fopen("icmp.txt","r");

	CAnalyzatorDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}
	else if (nResponse == -1)
	{
		TRACE(traceAppMsg, 0, "Warning: dialog creation failed, so application is terminating unexpectedly.\n");
		TRACE(traceAppMsg, 0, "Warning: if you are using MFC controls on the dialog, you cannot #define _AFX_NO_MFC_CONTROLS_IN_DIALOGS.\n");
	}

	// Delete the shell manager created above.
	if (pShellManager != NULL)
	{
		delete pShellManager;
	}

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}

CStringA CAnalyzatorApp::FilePath;
char CAnalyzatorApp::pcap_errbuf[PCAP_ERRBUF_SIZE];
pcap_t *CAnalyzatorApp::handle = NULL;
struct pcap_pkthdr CAnalyzatorApp::pcap_header;

bool CAnalyzatorApp::OpenPCAPfile(CStringA path)
{
	if (handle) pcap_close(handle);
	handle = pcap_open_offline(path,pcap_errbuf);
	if (!handle) return true;
	FilePath = path;
	return false;
}


UINT CAnalyzatorApp::AnalyzeFrames(void *pParam)
{
	CAnalyzatorDlg *pDlg = (CAnalyzatorDlg *) pParam;

	const u_char *frame;
	int frame_id = 0, i;
	int length_on_wire;
	CArray<IP_DATA, IP_DATA> ip;
	bool found;
	IP_DATA el;
	int ip_index;
	unsigned max_bytes_sent = 0;
	CString print;
	while ((frame = pcap_next(handle,&pcap_header)) != NULL)    // pre kazdy ramec
	{
		/* ramec ID */
		print.Format(_T("ramec %d\r\n"),++frame_id);
		
		/* vypis ramca */
		theApp.PrintFrame(frame,&print);
		
		/* prazdny riadok */
		print.AppendFormat(_T("\r\n"));
		
		pDlg->PrintToOutput(print);

		/* dlzka ramca prenasaneho po mediu */
		length_on_wire = pcap_header.len + 4;
		if (length_on_wire < 64) length_on_wire = 64;
		
		found = false;
		if ((frame[12] == 0x08) && (frame[13] == 0x00) && ((frame[14] & 0xF0) == 0x40)) {
			for (i=0;i < ip.GetCount();i++) {
				if ((ip[i].ip1 == frame[26]) && (ip[i].ip2 == frame[27]) && (ip[i].ip3 == frame[28]) && (ip[i].ip4 == frame[29])) {
					ip[i].sent += length_on_wire;
					found = true;
					break;
				}
			}
			if (!found) {
				el.ip1 = frame[26];
				el.ip2 = frame[27];
				el.ip3 = frame[28];
				el.ip4 = frame[29];
				el.sent = length_on_wire;
				ip.Add(el);
			}
		}
	}
	print.Format(_T("IP adresy vysielajucich uzlov:\r\n"));
	for (i=0;i < ip.GetCount();i++) {
		print.AppendFormat(_T("%d.%d.%d.%d\r\n"),ip[i].ip1,ip[i].ip2,ip[i].ip3,ip[i].ip4);
		if (max_bytes_sent < ip[i].sent) {
			max_bytes_sent = ip[i].sent;
			ip_index = i;
		}
	}
	print.AppendFormat(_T("\r\nAdresa uzla s najvacsim poctom odvysielanych bajtov:\r\n"));
	print.AppendFormat(_T("%d.%d.%d.%d    %u bajtov"),ip[ip_index].ip1,ip[ip_index].ip2,ip[ip_index].ip3,ip[ip_index].ip4,max_bytes_sent);
	pDlg->PrintToOutput(print);
	ip.RemoveAll();
	theApp.ReOpenPCAPfile();
	pDlg->PrintToOutput(_T("end_output"));
	return 0;
}


UINT CAnalyzatorApp::AnalyzeCommunication(void *pParam)
{
	THREAD_PARAM *parameters = (THREAD_PARAM *) pParam;
	CAnalyzatorDlg *pDlg = (CAnalyzatorDlg *) parameters->pDlg;
	int prot = parameters->protocol;

	char type[][15] = {"all", "http", "https", "telnet", "ssh", "ftp-control", "ftp-data", "tftp", "icmp", "arp"};
	bool run_all = false;
	const u_char *frame;
	int c_index, complete_c_id, uncomplete_c_id, i;
	unsigned IP_prot_code = theApp.GetEth2ProtocolNum("IP");
	unsigned ARP_prot_code = theApp.GetEth2ProtocolNum("ARP");
	int IP_header_length, flags_i;
	byte TCP_code = theApp.GetIPProtocolNum("TCP");
	byte UDP_code = theApp.GetIPProtocolNum("UDP");
	unsigned frame_id = 0, analyzed_port, curr_src_port, curr_dst_port;
	IP_PROT_TYPE analyzed_seg_type;
	COMMUNICATION current_communication;
	CArray<COMMUNICATION, COMMUNICATION> comm_list;
	int found;
	FRAME_LEN_COUNT fcount;
	CArray<FRAME_LEN_COUNT, FRAME_LEN_COUNT> lengths_list;
	ARP current_arp;
	CArray<ARP, ARP> arp_list;
	CString print;

	// ak budu analyzovane vsetky typy komunikacii
	if (prot == 0) {
		run_all = true;
		prot = 1;
	}
	
	while (TRUE)
	{	
		print.Empty();
		if (prot < 8)  //ak TCP alebo UDP
		{
			analyzed_port = theApp.GetPortNumber(type[prot]);    //nacitanie cisla portu zo suboru
			analyzed_seg_type = theApp.GetIPProtocolType(type[prot]);    //nacitanie typu segmentu zo suboru
			
			// pre komunikacie so spojenim
			if (analyzed_seg_type == TCP) {
				while ((frame = pcap_next(handle,&pcap_header)) != NULL)
				{
					frame_id++;
					// ak ide o IPv4 s TCP
					if ((frame[12] == GetUpperByte(IP_prot_code)) && (frame[13] == GetLowerByte(IP_prot_code))
						&& ((frame[14] & 0xF0) == 0x40) && (frame[23] == theApp.GetIPProtocolNum("TCP"))) {
						IP_header_length = (frame[14] & 0x0F) * 4;
						flags_i = ETH2_HDR_LEN+IP_header_length+13;
						curr_src_port = MergeBytes(frame[ETH2_HDR_LEN+IP_header_length],frame[ETH2_HDR_LEN+IP_header_length+1]);
						curr_dst_port = MergeBytes(frame[ETH2_HDR_LEN+IP_header_length+2],frame[ETH2_HDR_LEN+IP_header_length+3]);
						if ((curr_src_port != analyzed_port) && (curr_dst_port != analyzed_port)) continue;
						found = 0;

						// vyhladanie v zozname
						for (i=0;i < comm_list.GetCount();i++)
							// ak sa tam nachadza
							if (theApp.CmpCommWithFrame(comm_list[i],frame)) {
								found = 1;
								c_index = i;
								if (!comm_list[i].end_verified) {
									comm_list[i].frames_count++;
									comm_list[i].end_frame_id = frame_id;
								}
								break;
							}
							// ak sa tam nachadza s opacnymi adresami
							else if (theApp.CmpCommWithFrame(comm_list[i],frame,true)) {
								found = 2;
								c_index = i;
								if (!comm_list[i].end_verified) {
									comm_list[i].frames_count++;
									comm_list[i].end_frame_id = frame_id;
								}
								break;
							}
						
						/* ak SYN=1 a ACK=0 */
						if ((IsSYN(frame[flags_i])) && ((!found) || (!comm_list[c_index].end_verified))) {
							current_communication.src_ip[0] = frame[26];
							current_communication.src_ip[1] = frame[27];
							current_communication.src_ip[2] = frame[28];
							current_communication.src_ip[3] = frame[29];
							current_communication.dst_ip[0] = frame[30];
							current_communication.dst_ip[1] = frame[31];
							current_communication.dst_ip[2] = frame[32];
							current_communication.dst_ip[3] = frame[33];
							current_communication.src_port = curr_src_port;
							current_communication.dst_port = curr_dst_port;
							current_communication.frames_count = 1;
							current_communication.start_pre_verified = false;
							current_communication.start_verified = false;
							current_communication.end_init = false;
							current_communication.end_pre_verified = false;
							current_communication.end_verified = false;
							current_communication.reversed_end = false;
							current_communication.start_frame_id = frame_id;
							current_communication.end_frame_id = frame_id;
							if (!found) comm_list.Add(current_communication);
							else comm_list.SetAt(c_index,current_communication);
						}

						/* ak SYN=1 a ACK=1 */
						if (IsSYNandACK(frame[flags_i]) && (found == 2)) comm_list[c_index].start_pre_verified = true;

						/* ak SYN=0, FIN=0 a ACK=1 */
						if (IsACK(frame[flags_i]))
							if (found == 1) {
								if ((comm_list[c_index].end_pre_verified) && (!comm_list[c_index].reversed_end)) {
									comm_list[c_index].end_verified = true;
									comm_list[c_index].end_frame_id = frame_id;
								}
								else if (comm_list[c_index].start_pre_verified) comm_list[c_index].start_verified = true;
							}
							else if ((found == 2) && (comm_list[c_index].end_pre_verified) && (comm_list[c_index].reversed_end)) {
								comm_list[c_index].end_verified = true;
								comm_list[c_index].end_frame_id = frame_id;
							}

						/* ak FIN=1 a ACK=1 */
						if (IsFINandACK(frame[flags_i]))
							if (found == 1) {
								if (!comm_list[c_index].end_init) comm_list[c_index].end_init = true;
								else if (comm_list[c_index].reversed_end) comm_list[c_index].end_pre_verified = true;
							}
							else if (found == 2) {
								if (!comm_list[c_index].end_init) {
									comm_list[c_index].end_init = true;
									comm_list[c_index].reversed_end = true;
								}
								else if (!comm_list[c_index].reversed_end) comm_list[c_index].end_pre_verified = true;
							}

						/* ak RST=1 */
						if ((HaveRST(frame[flags_i])) && (found)) {
								comm_list[c_index].end_verified = true;
								comm_list[c_index].end_frame_id = frame_id;
						}
					}
				}
				theApp.ReOpenPCAPfile();
				frame_id = 0;
				
				// najdenie prvu kompletnu a prvu nekompletnu komunikaciu
				complete_c_id = -1;
				uncomplete_c_id = -1;
				for (i=0;i < comm_list.GetCount();i++) {
					if ((complete_c_id == -1) && (comm_list[i].start_verified) && (comm_list[i].end_verified)) complete_c_id = i;
					else if ((uncomplete_c_id == -1) && (comm_list[i].start_verified) && (!comm_list[i].end_verified)) uncomplete_c_id = i;
					if ((complete_c_id != -1) && (uncomplete_c_id != -1)) break;
				}

				// ak obsahuje aspon jednu kompletnu komunikaciu
				if (complete_c_id != -1)
				{
					print.Format(_T("Komunikacia kompletna\r\n"));
					if (comm_list[complete_c_id].dst_port == analyzed_port)
						print.AppendFormat(_T("Klient: %d.%d.%d.%d:%d  Server: %d.%d.%d.%d:%s (%d)"),
							comm_list[complete_c_id].src_ip[0],comm_list[complete_c_id].src_ip[1],
							comm_list[complete_c_id].src_ip[2],comm_list[complete_c_id].src_ip[3],comm_list[complete_c_id].src_port,
							comm_list[complete_c_id].dst_ip[0],comm_list[complete_c_id].dst_ip[1],
							comm_list[complete_c_id].dst_ip[2],comm_list[complete_c_id].dst_ip[3],CString(type[prot]),comm_list[complete_c_id].dst_port);
					else print.AppendFormat(_T("Klient: %d.%d.%d.%d:%d  Server: %d.%d.%d.%d:%s (%d)"),
							comm_list[complete_c_id].dst_ip[0],comm_list[complete_c_id].dst_ip[1],
							comm_list[complete_c_id].dst_ip[2],comm_list[complete_c_id].dst_ip[3],comm_list[complete_c_id].dst_port,
							comm_list[complete_c_id].src_ip[0],comm_list[complete_c_id].src_ip[1],
							comm_list[complete_c_id].src_ip[2],comm_list[complete_c_id].src_ip[3],CString(type[prot]),comm_list[complete_c_id].src_port);
					pDlg->PrintToOutput(print);
					c_index = 0;
					while ((frame = pcap_next(handle,&pcap_header)) != NULL)
					{
						frame_id++;
						// ak ide o IPv4 s TCP
						if ((frame[12] == GetUpperByte(IP_prot_code)) && (frame[13] == GetLowerByte(IP_prot_code))
							&& ((frame[14] & 0xF0) == 0x40) && (frame[23] == theApp.GetIPProtocolNum("TCP")))
						{
							if ((frame_id >= comm_list[complete_c_id].start_frame_id)
								&& ((theApp.CmpCommWithFrame(comm_list[complete_c_id], frame)) || (theApp.CmpCommWithFrame(comm_list[complete_c_id], frame, true)))) {
								c_index++;

								if ((c_index <= 10) || ((comm_list[complete_c_id].frames_count - c_index + 1) <= 10)) {
																		
									/* ramec ID */
									print.Format(_T("\r\nramec %d\r\n"), frame_id);

									/* vypis ramca */
									theApp.PrintFrame(frame, &print, true);

									if ((comm_list[complete_c_id].frames_count > 20) && (c_index == 10)) print.AppendFormat(_T("\r\n\r\n............"));

									pDlg->PrintToOutput(print);
								}

								/* statistika ramcov */
								found = 0;
								for (i = 0; i < lengths_list.GetCount(); i++)
									if (pcap_header.len <= lengths_list[i].to) {
										lengths_list[i].count++;
										found = 1;
										break;
									}
								if (!found) {
									do {
										if (lengths_list.GetCount() == 0) fcount.from = 0;
										else fcount.from = lengths_list[lengths_list.GetCount() - 1].to + 1;
										if (fcount.from == 0) fcount.to = 19;
										else fcount.to = 2 * fcount.from - 1;
										fcount.count = 0;
										lengths_list.Add(fcount);
									} while (pcap_header.len > fcount.to);
									lengths_list[lengths_list.GetCount() - 1].count++;
								}
							}
						}
						if (frame_id == comm_list[complete_c_id].end_frame_id) break;
					}
					// vypis statistiky ramcov
					print.Format(_T("\r\nStatistika dlzky ramcov v bajtoch:"));
					for (i=0;i < lengths_list.GetCount();i++) {
						if (lengths_list[i].from < 80) print.AppendFormat(_T("\r\n%d - %d\t\t%d"),lengths_list[i].from,lengths_list[i].to,lengths_list[i].count);
						else print.AppendFormat(_T("\r\n%d - %d\t%d"),lengths_list[i].from,lengths_list[i].to,lengths_list[i].count);
					}
					if (uncomplete_c_id != -1) print.AppendFormat(_T("\r\n\r\n"));
					pDlg->PrintToOutput(print);
					lengths_list.RemoveAll();
				}

				// ak obsahuje aspon jednu nekompletnu komunikaciu
				if (uncomplete_c_id != -1)
				{
					theApp.ReOpenPCAPfile();
					frame_id = 0;
					print.Format(_T("Komunikacia nekompletna\r\n"));
					if (comm_list[uncomplete_c_id].dst_port == analyzed_port)
						print.AppendFormat(_T("Klient: %d.%d.%d.%d:%d  Server: %d.%d.%d.%d:%s (%d)"),
							comm_list[uncomplete_c_id].src_ip[0],comm_list[uncomplete_c_id].src_ip[1],
							comm_list[uncomplete_c_id].src_ip[2],comm_list[uncomplete_c_id].src_ip[3],comm_list[uncomplete_c_id].src_port,
							comm_list[uncomplete_c_id].dst_ip[0],comm_list[uncomplete_c_id].dst_ip[1],
							comm_list[uncomplete_c_id].dst_ip[2],comm_list[uncomplete_c_id].dst_ip[3],CString(type[prot]),comm_list[uncomplete_c_id].dst_port);
					else print.AppendFormat(_T("Klient: %d.%d.%d.%d:%d  Server: %d.%d.%d.%d:%s (%d)"),
							comm_list[uncomplete_c_id].dst_ip[0],comm_list[uncomplete_c_id].dst_ip[1],
							comm_list[uncomplete_c_id].dst_ip[2],comm_list[uncomplete_c_id].dst_ip[3],comm_list[uncomplete_c_id].dst_port,
							comm_list[uncomplete_c_id].src_ip[0],comm_list[uncomplete_c_id].src_ip[1],
							comm_list[uncomplete_c_id].src_ip[2],comm_list[uncomplete_c_id].src_ip[3],CString(type[prot]),comm_list[uncomplete_c_id].src_port);
					pDlg->PrintToOutput(print);
					c_index = 0;
					while ((frame = pcap_next(handle,&pcap_header)) != NULL)
					{
						frame_id++;
						// ak ide o IPv4 s TCP
						if ((frame[12] == GetUpperByte(IP_prot_code)) && (frame[13] == GetLowerByte(IP_prot_code))
							&& ((frame[14] & 0xF0) == 0x40) && (frame[23] == theApp.GetIPProtocolNum("TCP")))
						{
							if ((frame_id >= comm_list[uncomplete_c_id].start_frame_id)
								&& ((theApp.CmpCommWithFrame(comm_list[uncomplete_c_id], frame)) || (theApp.CmpCommWithFrame(comm_list[uncomplete_c_id], frame, true)))) {
								c_index++;

								if ((c_index <= 10) || ((comm_list[uncomplete_c_id].frames_count - c_index + 1) <= 10)) {
									/* ramec ID */
									print.Format(_T("\r\nramec %d\r\n"), frame_id);

									/* vypis ramca */
									theApp.PrintFrame(frame, &print, true);

									if ((comm_list[uncomplete_c_id].frames_count > 20) && (c_index == 10)) print.AppendFormat(_T("\r\n\r\n............"));

									pDlg->PrintToOutput(print);
								}
							}
						}
						if (frame_id == comm_list[uncomplete_c_id].end_frame_id) break;
					}
				}
				comm_list.RemoveAll();
			}
			
			// pre komunikacie bez spojenim
			if (analyzed_seg_type == UDP) {
				while ((frame = pcap_next(handle,&pcap_header)) != NULL)
				{
					frame_id++;
					// ak ide o IPv4 s UDP
					if ((frame[12] == GetUpperByte(IP_prot_code)) && (frame[13] == GetLowerByte(IP_prot_code))
						&& ((frame[14] & 0xF0) == 0x40) && (frame[23] == theApp.GetIPProtocolNum("UDP"))) {
						IP_header_length = (frame[14] & 0x0F) * 4;
						curr_src_port = MergeBytes(frame[ETH2_HDR_LEN+IP_header_length],frame[ETH2_HDR_LEN+IP_header_length+1]);
						curr_dst_port = MergeBytes(frame[ETH2_HDR_LEN+IP_header_length+2],frame[ETH2_HDR_LEN+IP_header_length+3]);
						found = 0;

						// hladanie UDP komunikacii
						for (i=0;i < comm_list.GetCount();i++)
							if (theApp.CmpUDPCommWithFrame(comm_list[i],frame))
							{
								found = 1;	
								comm_list[i].frames_count++;
								comm_list[i].end_frame_id = frame_id;
								break;
							}
						
						if ((!found) && (curr_dst_port == analyzed_port))
						{
							current_communication.src_ip[0] = frame[26];
							current_communication.src_ip[1] = frame[27];
							current_communication.src_ip[2] = frame[28];
							current_communication.src_ip[3] = frame[29];
							current_communication.dst_ip[0] = frame[30];
							current_communication.dst_ip[1] = frame[31];
							current_communication.dst_ip[2] = frame[32];
							current_communication.dst_ip[3] = frame[33];
							current_communication.src_port = curr_src_port;
							current_communication.dst_port = curr_dst_port;
							current_communication.frames_count = 1;
							current_communication.start_frame_id = frame_id;
							current_communication.end_frame_id = frame_id;
							comm_list.Add(current_communication);
						}
					}
				}
				theApp.ReOpenPCAPfile();
				frame_id = 0;
				// vypis UDP komunikacii
				for (i = 0; i < comm_list.GetCount(); i++)
				{
					if (frame_id > comm_list[i].start_frame_id) {
						theApp.ReOpenPCAPfile();
						frame_id = 0;
					}
					print.Format(_T("Komunikacia bez spojenim\r\n"));
					print.AppendFormat(_T("Klient: %d.%d.%d.%d:%d  Server: %d.%d.%d.%d:%s (%d)"),
						comm_list[i].src_ip[0], comm_list[i].src_ip[1], comm_list[i].src_ip[2], comm_list[i].src_ip[3], comm_list[i].src_port,
						comm_list[i].dst_ip[0], comm_list[i].dst_ip[1], comm_list[i].dst_ip[2], comm_list[i].dst_ip[3], CString(type[prot]), comm_list[i].dst_port);
					pDlg->PrintToOutput(print);
					c_index = 0;
					while ((frame = pcap_next(handle, &pcap_header)) != NULL) {
						frame_id++;
						// ak ide o IPv4 s UDP
						if ((frame[12] == GetUpperByte(IP_prot_code)) && (frame[13] == GetLowerByte(IP_prot_code))
							&& ((frame[14] & 0xF0) == 0x40) && (frame[23] == theApp.GetIPProtocolNum("UDP")))
						{
							if ((frame_id >= comm_list[i].start_frame_id) && (theApp.CmpUDPCommWithFrame(comm_list[i], frame))) {
								c_index++;
								if ((c_index <= 10) || ((comm_list[i].frames_count - c_index + 1) <= 10)) {
									/* ramec ID */
									print.Format(_T("\r\nramec %d\r\n"), frame_id);

									/* vypis ramca */
									theApp.PrintFrame(frame, &print);

									if ((comm_list[i].frames_count > 20) && (c_index == 10)) print.AppendFormat(_T("\r\n\r\n............"));

									pDlg->PrintToOutput(print);
								}
							}
						}
						if (frame_id == comm_list[i].end_frame_id) break;
					}
					if (i < (comm_list.GetCount() - 1)) pDlg->PrintToOutput(_T("\r\n\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++\r\n\r\n"));
				}
				comm_list.RemoveAll();
			}
		}

		// vypis ICMP sprav
		if (prot == 8)
		{
			found = 0;
			while ((frame = pcap_next(handle,&pcap_header)) != NULL)
			{
				frame_id++;
				// ak ide o IPv4 s ICMP
				if ((frame[12] == GetUpperByte(IP_prot_code)) && (frame[13] == GetLowerByte(IP_prot_code))
					&& ((frame[14] & 0xF0) == 0x40) && (frame[23] == theApp.GetIPProtocolNum("ICMP")))
				{
					if (found) pDlg->PrintToOutput(_T("\r\n\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++\r\n\r\n"));
					found = 1;
					print.Format(_T("ICMP komunikacia\r\n"));

					IP_header_length = (frame[14] & 0x0F) * 4;
					
					/* vypis text spravy */
					print.AppendFormat(_T("Sprava: %s\r\n"),theApp.GetICMPType(frame[ETH2_HDR_LEN+IP_header_length]));
					
					/* vypis IP adries */
					print.AppendFormat(_T("Zdrojova IP: %d.%d.%d.%d,   Cielova IP: %d.%d.%d.%d\r\n"),frame[26],frame[27],frame[28],frame[29],
						frame[30],frame[31],frame[32],frame[33]);
					
					/* ramec ID */
					print.AppendFormat(_T("ramec %d\r\n"), frame_id);

					/* vypis ramca */
					theApp.PrintFrame(frame, &print);

					pDlg->PrintToOutput(print);
				}
			}
		}

		// analyza ARP komunikacii
		if (prot == 9)
		{
			// hladanie ARP dvojic
			while ((frame = pcap_next(handle,&pcap_header)) != NULL)
			{
				frame_id++;
				// ak ide o ARP s hw type Ethernet (size 6B) a prot. type IP (size 4B)
				if ((frame[12] == GetUpperByte(ARP_prot_code)) && (frame[13] == GetLowerByte(ARP_prot_code))
					&& (MergeBytes(frame[14],frame[15]) == 1) && (MergeBytes(frame[16],frame[17]) == IP_prot_code)
					&& (frame[18] == 6) && (frame[19] == 4))
				{
					// ak je to Request
					if (MergeBytes(frame[20],frame[21]) == 1)
					{
						found = 0;
						for (i=0;i < arp_list.GetCount();i++)
							if (theApp.CmpARPCommWithFrame(arp_list[i],frame))
							{
								found = 1;
								break;
							}
						if (!found)
						{
							current_arp.ip1[0] = frame[28];
							current_arp.ip1[1] = frame[29];
							current_arp.ip1[2] = frame[30];
							current_arp.ip1[3] = frame[31];
							current_arp.ip2[0] = frame[38];
							current_arp.ip2[1] = frame[39];
							current_arp.ip2[2] = frame[40];
							current_arp.ip2[3] = frame[41];
							current_arp.req_frame_id = frame_id;
							current_arp.reply_received = false;
							arp_list.Add(current_arp);
						}
					}

					// ak je to Reply
					if (MergeBytes(frame[20],frame[21]) == 2)
					{
						for (i=0;i < arp_list.GetCount();i++)
							if (theApp.CmpARPCommWithFrame(arp_list[i],frame,true))
							{
								arp_list[i].reply_received = true;
								arp_list[i].rep_frame_id = frame_id;
								break;
							}
					}
				}
			}
			theApp.ReOpenPCAPfile();
			frame_id = 0;
			// vypis ARP dvojic
			c_index = 0;
			found = 0;
			for (i = 0; i < arp_list.GetCount(); i++)
				if (arp_list[i].reply_received)
				{
					if (frame_id > arp_list[i].req_frame_id) {
						theApp.ReOpenPCAPfile();
						frame_id = 0;
					}
					c_index++;
					if (found) pDlg->PrintToOutput(_T("\r\n\r\n+++++++++++++++++++++++++++++++++++++++++++++++++++++\r\n\r\n"));
					found = 1;
					while ((frame = pcap_next(handle, &pcap_header)) != NULL)
					{
						frame_id++;
						// ak ide o ARP s hw type Ethernet (size 6B) a prot. type IP (size 4B)
						if ((frame[12] == GetUpperByte(ARP_prot_code)) && (frame[13] == GetLowerByte(ARP_prot_code))
							&& (MergeBytes(frame[14], frame[15]) == 1) && (MergeBytes(frame[16], frame[17]) == IP_prot_code)
							&& (frame[18] == 6) && (frame[19] == 4))
						{
							// ak je to Request
							if ((frame_id >= arp_list[i].req_frame_id) && (MergeBytes(frame[20], frame[21]) == 1))
							{
								/* vypis cisla komunikacie */
								print.Format(_T("Komunikacia c. %d\r\n"), c_index);

								/* vypis udajov o ARP */
								print.AppendFormat(_T("ARP-Request\r\nIP adresa: %d.%d.%d.%d,   MAC Adresa: ???\r\n"), frame[38], frame[39], frame[40], frame[41]);
								print.AppendFormat(_T("Zdrojova IP: %d.%d.%d.%d,   Cielova IP: %d.%d.%d.%d\r\n"),
									frame[28], frame[29], frame[30], frame[31], frame[38], frame[39], frame[40], frame[41]);

								/* ramec ID */
								print.AppendFormat(_T("ramec %d\r\n"), frame_id);

								/* vypis ramca */
								theApp.PrintFrame(frame, &print);
								print.AppendFormat(_T("\r\n"));

								pDlg->PrintToOutput(print);
							}
							// ak je to Reply
							if (frame_id == arp_list[i].rep_frame_id)
							{
								/* vypis cisla komunikacie */
								print.Format(_T("Komunikacia c. %d\r\n"), c_index);

								/* vypis udajov o ARP */
								print.AppendFormat(_T("ARP-Reply\r\nIP adresa: %d.%d.%d.%d,   MAC Adresa: %.2X %.2X %.2X %.2X %.2X %.2X\r\n"),
									frame[28], frame[29], frame[30], frame[31], frame[22], frame[23], frame[24], frame[25], frame[26], frame[27]);
								print.AppendFormat(_T("Zdrojova IP: %d.%d.%d.%d,   Cielova IP: %d.%d.%d.%d\r\n"),
									frame[28], frame[29], frame[30], frame[31], frame[38], frame[39], frame[40], frame[41]);

								/* ramec ID */
								print.AppendFormat(_T("ramec %d\r\n"), frame_id);

								/* vypis ramca */
								theApp.PrintFrame(frame, &print);

								pDlg->PrintToOutput(print);
								break;
							}
						}
					}
				}
				arp_list.RemoveAll();
		}
		theApp.ReOpenPCAPfile();
		frame_id = 0;
		if ((run_all) && (prot < 9)) {
			prot++;
			if (!print.IsEmpty()) pDlg->PrintToOutput(_T("\r\n---------------------------------------------------------------\r\n"));
		}
		else break;
	}
	pDlg->PrintToOutput(_T("end_output"));
	return 0;
}


CString CAnalyzatorApp::CheckProtocolFiles(void)
{
	CString error(_T("Chyba pri otvarani:"));

	if ((f_eth2) && (f_ip) && (f_ports) && (f_icmp)) return _T("");
	if (!f_eth2) error.AppendFormat(_T("\r\nethernet2_protocols.txt"));
	if (!f_ip) error.AppendFormat(_T("\r\nip_protocols.txt"));
	if (!f_ports) error.AppendFormat(_T("\r\nports.txt"));
	if (!f_icmp) error.AppendFormat(_T("\r\nicmp.txt"));

	return error;
}


unsigned int CAnalyzatorApp::GetEth2ProtocolNum(char *Name)
{
	unsigned int num;
	char tmp[100], scanstr[50];
	
	sprintf(scanstr,"%s\t%%X",Name);
	while (fgets(tmp,100,f_eth2) != NULL) if (strstr(tmp,Name) != NULL) {
		if (sscanf(tmp,scanstr,&num) > 0) break;
	}
	rewind(f_eth2);
	
	return num;
}


unsigned int CAnalyzatorApp::GetIPProtocolNum(char *Name)
{
	unsigned int num;
	char tmp[100], scanstr[50];
	
	sprintf(scanstr,"%s\t%%u",Name);
	while (fgets(tmp,100,f_ip) != NULL) if (strstr(tmp,Name) != NULL) {
		if (sscanf(tmp,scanstr,&num) > 0) break;
	}
	rewind(f_ip);
	
	return num;
}


IP_PROT_TYPE CAnalyzatorApp::GetIPProtocolType(char *AppName)
{
	IP_PROT_TYPE type;
	char typestr[5];
	char tmp[100], scanstr[50];
	
	sprintf(scanstr,"%s\t%%s",AppName);
	while (fgets(tmp,100,f_ports) != NULL) if (strstr(tmp,AppName) != NULL) {
		if (sscanf(tmp,scanstr,&typestr) > 0) break;
	}
	if (strcmp(typestr,"TCP") == 0) type = TCP;
	else type = UDP;
	rewind(f_ports);
	
	return type;
}


unsigned int CAnalyzatorApp::GetPortNumber(char *AppName)
{
	unsigned int num;
	char tmp[100], scanstr[50];
	
	sprintf(scanstr,"%s\t%%*3c\t%%u",AppName);
	while (fgets(tmp,100,f_ports) != NULL) if (strstr(tmp,AppName) != NULL) {
		if (sscanf(tmp,scanstr,&num) > 0) break;
	}
	rewind(f_ports);
	
	return num;
}


CString CAnalyzatorApp::GetICMPType(byte TypeNum)
{
	CStringA type;
	char tmp[100], scanstr[50];
	char typestr[50];
	
	sprintf(scanstr,"%u\t%%[^\n]s",TypeNum);
	while (fgets(tmp,100,f_icmp) != NULL) if (sscanf(tmp,scanstr,typestr) > 0) break;
	rewind(f_icmp);
	type.Format("%s",typestr);

	return CString(type);
}


byte CAnalyzatorApp::GetUpperByte(unsigned int number)
{
	return number >> 8;
}


byte CAnalyzatorApp::GetLowerByte(unsigned int number)
{
	return number & 0xFF;
}


unsigned int CAnalyzatorApp::MergeBytes(byte upper, byte lower)
{
	unsigned int num = upper << 8;
	num |= lower;
	return num;
}


void CAnalyzatorApp::ReOpenPCAPfile(void)
{
	if (handle) pcap_close(handle);
	handle = pcap_open_offline(FilePath,pcap_errbuf);
}


bool CAnalyzatorApp::IsACK(byte b)
{
	// ak ACK=1, SYN=0, FIN=0, RST=0
	if ((b & 0x17) == 0x10) return true;
	else return false;
}


bool CAnalyzatorApp::HaveACK(byte b)
{
	// ak ACK=1
	if (b & 0x10) return true;
	else return false;
}


bool CAnalyzatorApp::HaveRST(byte b)
{
	// ak RST=1
	if (b & 0x4) return true;
	else return false;
}


bool CAnalyzatorApp::IsSYN(byte b)
{
	// ak SYN=1, ACK=0, FIN=0, RST=0
	if ((b & 0x17) == 0x2) return true;
	else return false;
}


bool CAnalyzatorApp::HaveSYN(byte b)
{
	// ak SYN=1
	if (b & 0x2) return true;
	else return false;
}


bool CAnalyzatorApp::IsFIN(byte b)
{
	// ak FIN=1, ACK=0, SYN=0, RST=0
	if ((b & 0x17) == 0x1) return true;
	else return false;
}


bool CAnalyzatorApp::HaveFIN(byte b)
{
	// ak FIN=1
	if (b & 0x1) return true;
	else return false;
}


bool CAnalyzatorApp::IsSYNandACK(byte b)
{
	// ak SYN=1, ACK=1, FIN=0, RST=0
	if ((b & 0x17) == 0x12) return true;
	else return false;
}


bool CAnalyzatorApp::IsFINandACK(byte b)
{
	// ak FIN=1, ACK=1, SYN=0, RST=0
	if ((b & 0x17) == 0x11) return true;
	else return false;
}


bool CAnalyzatorApp::CmpCommWithFrame(COMMUNICATION comm, const u_char *frame, bool reverse)
{
	int IP_header_length = (frame[14] & 0x0F) * 4;
	unsigned curr_src_port = MergeBytes(frame[ETH2_HDR_LEN+IP_header_length],frame[ETH2_HDR_LEN+IP_header_length+1]);
	unsigned curr_dst_port = MergeBytes(frame[ETH2_HDR_LEN+IP_header_length+2],frame[ETH2_HDR_LEN+IP_header_length+3]);
	
	if (!reverse)
	{
		if ((comm.src_ip[0] == frame[26]) && (comm.src_ip[1] == frame[27]) && (comm.src_ip[2] == frame[28]) && (comm.src_ip[3] == frame[29])
			&& (comm.dst_ip[0] == frame[30]) && (comm.dst_ip[1] == frame[31]) && (comm.dst_ip[2] == frame[32]) && (comm.dst_ip[3] == frame[33])
			&& (comm.src_port == curr_src_port) && (comm.dst_port == curr_dst_port)) return true;  // ak ramec obsahuje rovnaku komunikaciu
		// ak v ramci je ina komunukacia
		else return false;
	}
	else
	{
		if ((comm.dst_ip[0] == frame[26]) && (comm.dst_ip[1] == frame[27]) && (comm.dst_ip[2] == frame[28]) && (comm.dst_ip[3] == frame[29])
			&& (comm.src_ip[0] == frame[30]) && (comm.src_ip[1] == frame[31]) && (comm.src_ip[2] == frame[32]) && (comm.src_ip[3] == frame[33])
			&& (comm.dst_port == curr_src_port) && (comm.src_port == curr_dst_port)) return true;  // ak ramec obsahuje rovnaku komunikaciu
		// ak v ramci je ina komunukacia
		else return false;
	}
}


bool CAnalyzatorApp::CmpUDPCommWithFrame(COMMUNICATION comm, const u_char *frame)
{
	int IP_header_length = (frame[14] & 0x0F) * 4;
	unsigned curr_src_port = MergeBytes(frame[ETH2_HDR_LEN + IP_header_length], frame[ETH2_HDR_LEN + IP_header_length + 1]);
	unsigned curr_dst_port = MergeBytes(frame[ETH2_HDR_LEN + IP_header_length + 2], frame[ETH2_HDR_LEN + IP_header_length + 3]);

	if (((comm.src_ip[0] == frame[26]) && (comm.src_ip[1] == frame[27]) && (comm.src_ip[2] == frame[28]) && (comm.src_ip[3] == frame[29])
		&& (comm.dst_ip[0] == frame[30]) && (comm.dst_ip[1] == frame[31]) && (comm.dst_ip[2] == frame[32]) && (comm.dst_ip[3] == frame[33])
		&& (comm.src_port == curr_src_port))
		|| ((comm.dst_ip[0] == frame[26]) && (comm.dst_ip[1] == frame[27]) && (comm.dst_ip[2] == frame[28]) && (comm.dst_ip[3] == frame[29])
		&& (comm.src_ip[0] == frame[30]) && (comm.src_ip[1] == frame[31]) && (comm.src_ip[2] == frame[32]) && (comm.src_ip[3] == frame[33])
		&& (comm.src_port == curr_dst_port))) return true;
	else return false;
}


bool CAnalyzatorApp::CmpARPCommWithFrame(ARP arp_comm, const u_char *frame, bool IsReply)
{
	if (!IsReply)
	{
		if ((arp_comm.ip1[0] == frame[28]) && (arp_comm.ip1[1] == frame[29]) && (arp_comm.ip1[2] == frame[30]) && (arp_comm.ip1[3] == frame[31])
			&& (arp_comm.ip2[0] == frame[38]) && (arp_comm.ip2[1] == frame[39]) && (arp_comm.ip2[2] == frame[40]) && (arp_comm.ip2[3] == frame[41]))
			return true;
		else return false;
	}
	else
	{
		if ((arp_comm.ip2[0] == frame[28]) && (arp_comm.ip2[1] == frame[29]) && (arp_comm.ip2[2] == frame[30]) && (arp_comm.ip2[3] == frame[31])
			&& (arp_comm.ip1[0] == frame[38]) && (arp_comm.ip1[1] == frame[39]) && (arp_comm.ip1[2] == frame[40]) && (arp_comm.ip1[3] == frame[41]))
			return true;
		else return false;
	}
}


void CAnalyzatorApp::PrintFrame(const u_char *frame, CString *print, bool print_flags)
{
	int length_on_wire, i;
	int IP_header_length = (frame[14] & 0x0F) * 4;
	int flags_i = ETH2_HDR_LEN+IP_header_length+13;
	
	/* dlzka ramca poskytnuta paketovym drajverom */
	print->AppendFormat(_T("dlzka ramca poskytnuta paketovym drajverom – %d B\r\n"),pcap_header.len);
	
	/* dlzka ramca prenasaneho po mediu */
	length_on_wire = pcap_header.len + 4;
	if (length_on_wire < 64) length_on_wire = 64;
	print->AppendFormat(_T("dlzka ramca prenasaneho po mediu – %d B\r\n"),length_on_wire);
	
	/* typ ramca */
	if (frame[12] >= 0x06) print->AppendFormat(_T("Ethernet II\r\n"));
	else if ((frame[14] == 0xFF) && (frame[15] == 0xFF)) print->AppendFormat(_T("IEEE 802.3 - RAW\r\n"));
	else if ((frame[14] == 0xAA) && (frame[15] == 0xAA) && (frame[16] == 0x03)) print->AppendFormat(_T("IEEE 802.3 - LLC - SNAP\r\n"));
	else print->AppendFormat(_T("IEEE 802.3 - LLC\r\n"));

	/* zdrojova MAC adresa */
	print->AppendFormat(_T("Zdrojova MAC adresa: "));
	for (i=6;i < 12;i++) print->AppendFormat(_T("%.2X "),frame[i]);
	print->Delete(print->GetLength()-1);
	
	/* cielova MAC adresa */
	print->AppendFormat(_T("\r\nCielova MAC adresa: "));
	for (i=0;i < 6;i++) print->AppendFormat(_T("%.2X "),frame[i]);
	print->Delete(print->GetLength()-1);
	
	/* vypis priznakov */
	if (print_flags) {
		print->AppendFormat(_T("\r\nPriznaky:"));
		if (HaveSYN(frame[flags_i])) print->AppendFormat(_T(" SYN"));
		if (HaveFIN(frame[flags_i])) print->AppendFormat(_T(" FIN"));
		if (HaveRST(frame[flags_i])) print->AppendFormat(_T(" RST"));
		if (HaveACK(frame[flags_i])) print->AppendFormat(_T(" ACK"));
	}
	
	/* vypis bajtov ramca */
	print->AppendFormat(_T("\r\n"));
	for (i=0;i < pcap_header.len;i++) {
		print->AppendFormat(_T("%.2X"),frame[i]);
		if (!((i+1) % 8) && ((i+1) % 16) && ((i+1) != pcap_header.len)) print->AppendFormat(_T("   "));
		else if (!((i+1) % 16) && ((i+1) != pcap_header.len)) print->AppendFormat(_T("\r\n"));
		else if ((i+1) != pcap_header.len) print->AppendChar(' ');
	}
}
