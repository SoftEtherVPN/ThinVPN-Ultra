// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// DU_Inner.h
// DU.c の内部ヘッダ

// 定数
#define DU_CANDIDATE_MAX				12		// 接続先候補の最大数
#define DU_BANNER_SWITCH_INTERVAL		(30 * 1000)	// バナースイッチ間隔
#define	DU_LOCALCONFIG_FILENAME			"@uselocalconfig"	// ローカルに設定データを保存する

// データ構造宣言
typedef struct DU
{
	CEDAR *Cedar;		// Cedar
	DC *Dc;				// DC
	char AutoConnectPcid[MAX_PATH];		// 自動で接続する PCID
} DU;

// メインウインドウ
typedef struct DU_MAIN
{
	DU *Du;
	HWND hWnd;
	HWND hWndConnect;
	char Pcid[MAX_PATH];
} DU_MAIN;

// オプションダイアログ
typedef struct DU_OPTION
{
	DU_MAIN *Main;
	DU *Du;
	INTERNET_SETTING InternetSetting;
} DU_OPTION;

// ダウンロードダイアログ
typedef struct DU_DOWNLOAD
{
	DU_MAIN *Main;
	DU *Du;
	DC *Dc;
	bool Halt;
	HWND hWnd;
	HWND hWndConnect;
	UINT64 LastTick;
} DU_DOWNLOAD;

// パスワードダイアログデータ
typedef struct DU_PASSWORD
{
	char Password[MAX_PATH];
	char Hostname[MAX_PATH];
} DU_PASSWORD;

// ユーザー認証ダイアログデータ
typedef struct DU_AUTH
{
	DU *Du;
	DC *Dc;
	char Pcid[MAX_PATH];		// PCID
	DC_AUTH Auth;				// 認証データ
} DU_AUTH;

// URDP に関するメッセージ
typedef struct DU_URDPMSG
{
	HWND hWnd;
	THREAD *Thread;
	bool DontShow;
} DU_URDPMSG;

// バージョン情報ダイアログ
typedef struct DU_ABOUT
{
	char *SoftName;
	UINT Icon;
	char *BuildInfo;
} DU_ABOUT;

// 関数プロトタイプ宣言
void DuMain(DU *du);
UINT DuMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuMainDlgInit(HWND hWnd, DU_MAIN *t);
void DuMainBanner(HWND hWnd, DU_MAIN *t);
void DuMainDlgUpdate(HWND hWnd, DU_MAIN *t, bool forceEnable);
void DuMainDlgOnOk(HWND hWnd, DU_MAIN *t);
void DuMainDlgOnClose(HWND hWnd, DU_MAIN *t);
void DuMainDlgSetControlEnabled(HWND hWnd, bool b);
void DuConnectMain(HWND hWnd, DU_MAIN *t, char *pcid);
void DuSelectBluetoothDir(HWND hWnd, DU_MAIN *t);

void DuOptionDlg(HWND hWnd, DU_MAIN *t);
UINT DuOptionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuOptionDlgUpdate(HWND hWnd, DU_OPTION *t);
void DuOptionDlgInit(HWND hWnd, DU_OPTION *t);
void DuOptionDlgInitProxyStr(HWND hWnd, DU_OPTION *t);
void DuOptionDlgOnOk(HWND hWnd, DU_OPTION *t);

bool DuDownloadMstsc(HWND hWnd, DU_MAIN *t);
bool DuDownloadCallback(void *param, UINT total_size, UINT current_size, BUF *recv_buf);
UINT DuDownloadDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuDownloadDlgInit(HWND hWnd, DU_DOWNLOAD *t);
void DuDownloadDlgOnCancel(HWND hWnd, DU_DOWNLOAD *t);
void DuDownloadDlgOnTimer(HWND hWnd, DU_DOWNLOAD *t);
void DuDownloadDlgPrintStatus(HWND hWnd, UINT current, UINT total);

bool DuPasswordCallback(DC_SESSION *s, char *password, UINT password_max_size);
bool DuAdvAuthCallback(DC_SESSION *s, DC_AUTH *auth);
bool DuEventCallback(DC_SESSION *s, UINT event_type, void *event_param);

bool DuPasswordDlg(HWND hWnd, char *password, UINT password_size, char *hostname);
UINT DuPasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuPasswordDlgUpdate(HWND hWnd);

void DuConnectDlg(HWND hWnd, DU_MAIN *t);
UINT DuConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuConnectDlgInit(HWND hWnd, DU_MAIN *t);
void DuConnectDlgOnTimer(HWND hWnd, DU_MAIN *t);

DU_URDPMSG *DuUrdpMsgStart(DU_MAIN *m);
void DuUrdpMsgStop(DU_MAIN *m, DU_URDPMSG *t);
UINT DuUrdpMsgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuUrdpMsgThread(THREAD *thread, void *param);

void DuAboutDlg(HWND hWnd, UINT icon, char *softname, char *buildinfo);
UINT DuAboutDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);

void DuShareDlg(HWND hWnd, DU_MAIN *m);
UINT DuShareDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuShareDlgUpdate(HWND hWnd);

bool DuAuthDlg(HWND hWnd, DU_MAIN *t, char *pcid, DC_AUTH *auth);
UINT DuAuthDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuAuthDlgInit(HWND hWnd, DU_AUTH *a);
void DuAuthDlgUpdate(HWND hWnd, DU_AUTH *a);
void DuAuthDlgOnOk(HWND hWnd, DU_AUTH *a);
void DuAuthDlgSetCertPath(HWND hWnd, wchar_t *path);

void DuTheEndDlg(HWND hWnd);
UINT DuTheEndDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);

bool DuDialupDlg(HWND hWnd);
UINT DuDialupDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);


