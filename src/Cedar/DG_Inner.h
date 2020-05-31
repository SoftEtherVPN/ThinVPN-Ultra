// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// DG_Inner.h
// DG.c の内部ヘッダ

// 定数
#define DG_MAIN_DLG_TIMER_INTERVAL		(250)

// 構造体宣言
typedef struct DG
{
	CEDAR *Cedar;		// Cedar
	RPC *Rpc;			// RPC
	char CurrentPcid[MAX_PATH];	// 現在の PCID
	bool NoAuthWarningFlag;
	bool ChangingPcid;
	bool AuthDlgFirstNoAuth;
	bool Password2Clicked;
	UINT DsCaps;
	bool BluetoothDirFlag;
	UINT64 MainDlgStartTick;
	bool Hello;
	ONCEMSG_DLG *MsgForServerDlg;
	ONCEMSG_DLG *MsgForServerDlg2;
	bool IsAdminOrSystem_Cache;
} DG;

// パスワードダイアログデータ
typedef struct DG_PASSWORD
{
	char Password[MAX_PATH];
} DG_PASSWORD;


// 関数プロトタイプ
void DgMain(DG *dg);
bool DgProxyDlg(HWND hWnd, INTERNET_SETTING *setting);
UINT DgProxyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DgProxyDlgInit(HWND hWnd, INTERNET_SETTING *t);
void DgProxyDlgSet(HWND hWnd, INTERNET_SETTING *t);
void DgProxyDlgUpdate(HWND hWnd);
void DgProxyDlgUseForIE(HWND hWnd);
void DgProxyDlgOnOk(HWND hWnd, INTERNET_SETTING *t);
bool DgLoginDlg(HWND hWnd, char *password, UINT password_size);
UINT DgLoginDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DgLoginDlgUpdate(HWND hWnd);
void DgMainDlg(DG *dg);
UINT DgMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DgMainDlgInit(HWND hWnd, DG *dg);
void DgMainDlgOnKillFocusPcid(HWND hWnd, DG *dg);
void DgMainDlgOnOk(HWND hWnd, DG *dg);
void DgMainDlgOnTimer(HWND hWnd, DG *dg);
void DgMainDlgRefresh(HWND hWnd, DG *dg, bool startup);
void DgMainDlgUpdate(HWND hWnd, DG *dg);
bool DgMainDlgProxy(HWND hWnd, DG *dg);
bool DgAuthDlg(HWND hWnd, DG *dg);
UINT DgAuthDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DgAuthDlgInit(HWND hWnd, DG *dg);
void DgAuthDlgUpdate(HWND hWnd);
void DgAuthDlgOnOk(HWND hWnd, DG *dg);
bool DgOptionDlg(HWND hWnd, DG *dg);
UINT DgOptionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DgOptionDlgInit(HWND hWnd, DG *dg);
void DgOptionDlgOnOk(HWND hWnd, DG *dg);
void DgOptionDlgUpdate(HWND hWnd, DG *dg);
void DgOptionDlgUrdpConfig(HWND hWnd, DG *dg);
bool DgPasswordDlg(HWND hWnd, DG *dg);
UINT DgPasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DgPasswordDlgInit(HWND hWnd, DG *dg);
void DgPasswordDlgUpdate(HWND hWnd);
void DgPasswordDlgOnOk(HWND hWnd, DG *dg);
void DgPassword1Dlg(HWND hWnd, DG *dg);
UINT DgPassword1DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool DgPassword2Dlg(HWND hWnd, DG *dg);
UINT DgPassword2DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DgHashDlgInit(HWND hWnd, DG *dg);
UINT DgHashDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DgHashDlg(HWND hWnd, DG *dg);
void DgSelectBluetoothDir(HWND hWnd, DG *dg);
void DgInitSmServerAndSmHub(SM_SERVER **ppserver, SM_HUB **pphub, DG *dg);
void DgFreeSmServerAndSmHub(SM_SERVER *s, SM_HUB *h);

bool DgOtpDlg(HWND hWnd, DG *dg);
UINT DgOtpDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DgOptDlgInit(HWND hWnd, DG *dg);
void DgOptDlgUpdate(HWND hWnd, DG *dg);
void DgOptDlgOnOk(HWND hWnd, DG *dg);


bool DgMacDlg(HWND hWnd, DG *dg);
UINT DgMacDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);

bool DgWoLDlg(HWND hWnd, DG *dg);
UINT DgWoLDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);



