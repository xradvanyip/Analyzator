
// AnalyzatorDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Analyzator.h"
#include "AnalyzatorDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAnalyzatorDlg dialog

THREAD_PARAM p1;



CAnalyzatorDlg::CAnalyzatorDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CAnalyzatorDlg::IDD, pParent)
	, filedialog(NULL)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

}

void CAnalyzatorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_FILENAME, m_filename);
	DDX_Control(pDX, IDC_OUTPUT, m_output);
	DDX_Control(pDX, IDC_PROTOCOLS, m_protocols);
	DDX_Control(pDX, IDC_FRAMESBUTTON, m_fbutton);
	DDX_Control(pDX, IDC_COMMBUTTON, m_commbutton);
}

BEGIN_MESSAGE_MAP(CAnalyzatorDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_OPENBUTTON, &CAnalyzatorDlg::OnBnClickedOpenbutton)
	ON_BN_CLICKED(IDC_FRAMESBUTTON, &CAnalyzatorDlg::OnBnClickedFramesbutton)
	ON_BN_CLICKED(IDC_COMMBUTTON, &CAnalyzatorDlg::OnBnClickedCommbutton)
	ON_MESSAGE(WM_THREAD_MESSAGE, &CAnalyzatorDlg::OnThreadMessage)
END_MESSAGE_MAP()


// CAnalyzatorDlg message handlers

BOOL CAnalyzatorDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	m_output.GetFont()->GetLogFont(&OutputLogFont);
	wcscpy(OutputLogFont.lfFaceName,_T("Courier New"));
	OutputLogFont.lfHeight = -12;
	OutputFont.CreateFontIndirectW(&OutputLogFont);
	m_output.SetFont(&OutputFont);
	
	filedialog = new CFileDialog(TRUE,_T("pcap"),NULL,NULL,_T("Tcpdump/libpcap files (*.pcap)|*.pcap|All Files|*||"));
	m_protocols.SetCurSel(0);
	m_output.LimitText();
	EnableControls(FALSE);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CAnalyzatorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CAnalyzatorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CAnalyzatorDlg::OnOK(void)
{
}


void CAnalyzatorDlg::OnBnClickedOpenbutton()
{
	filedialog->DoModal();
	this->SetMenu(this->GetMenu());
	CStringA path(filedialog->GetPathName());
	if (path.IsEmpty()) return;
	if (theApp.OpenPCAPfile(path)) AfxMessageBox(_T("Chyba pri otvoreni!"),MB_ICONERROR);
	else
	{
		EnableControls(TRUE);
		m_output.SetWindowTextW(_T(""));
		m_filename.SetWindowTextW(filedialog->GetFileName());
	}
}


void CAnalyzatorDlg::OnBnClickedFramesbutton()
{
	m_output.SetWindowTextW(_T(""));
	EnableControls(FALSE);
	AfxBeginThread(CAnalyzatorApp::AnalyzeFrames,this);
}


void CAnalyzatorDlg::OnBnClickedCommbutton()
{
	m_output.SetWindowTextW(_T(""));
	EnableControls(FALSE);
	p1.protocol = m_protocols.GetCurSel();
	p1.pDlg = this;
	
	CString error = theApp.CheckProtocolFiles();
		
	if (error.IsEmpty() == FALSE) {
		AfxMessageBox(error,MB_ICONERROR);
		EnableControls(TRUE);
	}
	else AfxBeginThread(CAnalyzatorApp::AnalyzeCommunication,&p1);
}


void CAnalyzatorDlg::EnableControls(bool enabled)
{
	if (enabled) {
		m_fbutton.EnableWindow(TRUE);
		m_commbutton.EnableWindow(TRUE);
		m_protocols.EnableWindow(TRUE);
	}
	else {
		m_fbutton.EnableWindow(FALSE);
		m_commbutton.EnableWindow(FALSE);
		m_protocols.EnableWindow(FALSE);
	}
}


afx_msg LRESULT CAnalyzatorDlg::OnThreadMessage(WPARAM wParam, LPARAM lParam)
{
	CString *line = (CString *)lParam;
	CString line_to_print;
	int length = m_output.GetWindowTextLengthW();
	if (*line == "end_output") EnableControls(TRUE);
	else {
		line_to_print.Format(_T("%s\r\n"),*line);
		m_output.SetSel(length,length);
		m_output.ReplaceSel(line_to_print);
	}
	delete line;
	
	return 0;
}


void CAnalyzatorDlg::PrintToOutput(CString text)
{
	CString *textptr = new CString(text);
	SendMessage(WM_THREAD_MESSAGE,0,(LPARAM)textptr);
}
