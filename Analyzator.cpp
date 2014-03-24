
// Analyzator.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include <afxtempl.h>
#include "Analyzator.h"
#include "AnalyzatorDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

typedef struct ip_data {
	byte ip1, ip2, ip3, ip4;
	unsigned sent;
} IP_DATA;


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
		/* rámec ID */
		print.Format(_T("rámec %d\r\n"),++frame_id);
		
		/* dåžka rámca poskytnutá paketovým drajverom */
		print.AppendFormat(_T("dåžka rámca poskytnutá paketovým drajverom – %d B\r\n"),pcap_header.len);
		
		/* dåžka rámca prenášaného po médiu */
		length_on_wire = pcap_header.len + 4;
		if (length_on_wire < 64) length_on_wire = 64;
		print.AppendFormat(_T("dåžka rámca prenášaného po médiu – %d B\r\n"),length_on_wire);
		
		/* typ ramca */
		if (frame[12] >= 0x06) print.AppendFormat(_T("Ethernet II\r\n"));
		else if ((frame[14] == 0xFF) && (frame[15] == 0xFF)) print.AppendFormat(_T("IEEE 802.3 - RAW\r\n"));
		else if ((frame[14] == 0xAA) && (frame[15] == 0xAA) && (frame[16] == 0x03)) print.AppendFormat(_T("IEEE 802.3 - LLC - SNAP\r\n"));
		else print.AppendFormat(_T("IEEE 802.3 - LLC\r\n"));

		/* zdrojová MAC adresa */
		print.AppendFormat(_T("Zdrojová MAC adresa: "));
		for (i=6;i < 12;i++) print.AppendFormat(_T("%.2X "),frame[i]);
		print.Delete(print.GetLength()-1);
		
		/* cie¾ová MAC adresa */
		print.AppendFormat(_T("\r\nCie¾ová MAC adresa: "));
		for (i=0;i < 6;i++) print.AppendFormat(_T("%.2X "),frame[i]);
		print.Delete(print.GetLength()-1);
		
		/* vypis bajtov ramca */
		print.AppendFormat(_T("\r\n"));
		for (i=0;i < pcap_header.len;i++) {
			print.AppendFormat(_T("%.2X"),frame[i]);
			if (!((i+1) % 8) && ((i+1) % 16) && ((i+1) != pcap_header.len)) print.AppendFormat(_T("   "));
			else if (!((i+1) % 16) && ((i+1) != pcap_header.len)) print.AppendFormat(_T("\r\n"));
			else if ((i+1) != pcap_header.len) print.AppendChar(' ');
		}
		
		/* prazdny riadok */
		print.AppendFormat(_T("\r\n"));
		
		pDlg->PrintToOutput(print);

		found = false;
		if ((frame[12] == 0x08) && (frame[13] == 0x00) && ((frame[14] & 0xF0) == 0x40)) {
			for (i=0;i < ip.GetCount();i++) {
				if ((ip[i].ip1 == frame[26]) && (ip[i].ip2 == frame[27]) && (ip[i].ip3 == frame[28]) && (ip[i].ip4 == frame[29])) {
					ip[i].sent += pcap_header.len;
					found = true;
					break;
				}
			}
			if (!found) {
				el.ip1 = frame[26];
				el.ip2 = frame[27];
				el.ip3 = frame[28];
				el.ip4 = frame[29];
				el.sent = pcap_header.len;
				ip.Add(el);
			}
		}
	}
	print.Format(_T("IP adresy vysielajúcich uzlov:\r\n"));
	for (i=0;i < ip.GetCount();i++) {
		print.AppendFormat(_T("%d.%d.%d.%d\r\n"),ip[i].ip1,ip[i].ip2,ip[i].ip3,ip[i].ip4);
		if (max_bytes_sent < ip[i].sent) {
			max_bytes_sent = ip[i].sent;
			ip_index = i;
		}
	}
	print.AppendFormat(_T("\r\nAdresa uzla s najväèším poètom odvysielaných bajtov:\r\n"));
	print.AppendFormat(_T("%d.%d.%d.%d    %u bajtov"),ip[ip_index].ip1,ip[ip_index].ip2,ip[ip_index].ip3,ip[ip_index].ip4,max_bytes_sent);
	pDlg->PrintToOutput(print);
	ip.RemoveAll();
	pcap_close(handle);
	handle = pcap_open_offline(FilePath,pcap_errbuf);
	pDlg->PrintToOutput(_T("end_output"));
	return 0;
}


UINT CAnalyzatorApp::AnalyzeCommunication(void *pParam)
{
	THREAD_PARAM *parameters = (THREAD_PARAM *) pParam;
	CAnalyzatorDlg *pDlg = (CAnalyzatorDlg *) parameters->pDlg;
	int prot = parameters->protocol;

	bool run_all = FALSE;
	const u_char *frame;
	int frame_id = 0, i;
	CString print;

	if (prot == 0) {
		run_all = TRUE;
		prot = 1;
	}
	
	while (TRUE)
	{
		while ((frame = pcap_next(handle,&pcap_header)) != NULL)
		{
			pDlg->PrintToOutput(_T("http"));
		}
		pcap_close(handle);
		handle = pcap_open_offline(FilePath,pcap_errbuf);
		if ((run_all) && (prot < 9)) prot++;
		else break;
	}
	pDlg->PrintToOutput(_T("end_output"));
	return 0;
}


CString CAnalyzatorApp::CheckProtocolFiles(void)
{
	CString error(_T("Chyba pri otváraní:"));

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
	char *typestr;
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
