
// AnalyzatorDlg.h : header file
//

#pragma once
#include "analyzator.h"
#include "afxwin.h"

#define WM_THREAD_MESSAGE WM_APP+100

// CAnalyzatorDlg dialog
class CAnalyzatorDlg : public CDialog
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
	CFont OutputFont;
	LOGFONT OutputLogFont;
	CFileDialog *filedialog;
	CEdit m_filename;
	CEdit m_output;
	CComboBox m_protocols;
	CButton m_fbutton;
	CButton m_commbutton;
public:
	afx_msg void OnBnClickedFramesbutton();
	afx_msg void OnBnClickedCommbutton();
	void EnableControls(bool enabled);
protected:
	afx_msg LRESULT OnThreadMessage(WPARAM wParam, LPARAM lParam);
public:
	void PrintToOutput(CString text);
};
