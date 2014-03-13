
// AnalyzatorDlg.h : header file
//

#pragma once
#include "analyzator.h"
#include "afxwin.h"


// CAnalyzatorDlg dialog
class CAnalyzatorDlg : public CDialogEx
{
// Construction
public:
	CAnalyzatorDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_ANALYZATOR_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

	virtual void OnOK(void);
public:
	afx_msg void OnBnClickedOpenbutton();
private:
	CFileDialog *filedialog;
	CEdit m_filename;
};
