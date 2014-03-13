
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



CAnalyzatorDlg::CAnalyzatorDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CAnalyzatorDlg::IDD, pParent)
	, filedialog(NULL)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	filedialog = new CFileDialog(TRUE,NULL,NULL,NULL,_T("Tcpdump/libpcap files (*.pcap)|*.pcap|All Files|*||"));
}

void CAnalyzatorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_FILENAME, m_filename);
}

BEGIN_MESSAGE_MAP(CAnalyzatorDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_OPENBUTTON, &CAnalyzatorDlg::OnBnClickedOpenbutton)
END_MESSAGE_MAP()


// CAnalyzatorDlg message handlers

BOOL CAnalyzatorDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

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
		CDialogEx::OnPaint();
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
	CStringA path(filedialog->GetPathName());
	if (theApp.OpenPCAPfile(path)) AfxMessageBox(_T("Chyba pri otvoreni!"),MB_ICONERROR);
	else
	{
		m_filename.SetWindowTextW(filedialog->GetFileName());
	}
}
