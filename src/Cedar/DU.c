// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// DU.c
// PacketiX Desktop VPN Client GUI

// Build 8600

#include <GlobalConst.h>

#ifdef	WIN32

#define	SM_C
#define	CM_C
#define	NM_C
#define	DG_C
#define DU_C

#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include <Cedar/CMInner.h>
#include <Cedar/SMInner.h>
#include <Cedar/NMInner.h>
#include <Cedar/EMInner.h>
#include <Cedar/Wt.h>
#include <Cedar/Desk.h>
#include "DG_Inner.h"
#include "DU_Inner.h"
#include "../PenCore/resource.h"

bool MsAppendMenu(HMENU hMenu, UINT flags, UINT_PTR id, wchar_t *str);


// 業務完了 Dlg Proc
UINT DuTheEndDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_THINCLIENT);
		if (MsIsVista())
		{
			SetFont(hWnd, IDCANCEL, GetMeiryoFontEx2(11, true));
		}
		else
		{
			DlgFont(hWnd, IDCANCEL, 11, true);
		}

		Top(hWnd);

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			if (IsChecked(hWnd, C_NOMORE))
			{
				MsRegWriteInt(REG_CURRENT_USER, DU_REGKEY, DU_SHOW_THEEND_KEY_NAME, 0);
			}

			Close(hWnd);
			break;
		}

		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// 業務完了
void DuTheEndDlg(HWND hWnd)
{
	Dialog(hWnd, D_DU_THEEND, DuTheEndDlgProc, NULL);
}

bool DuDialupDlg(HWND hWnd)
{
	return DialogEx2(hWnd, D_DU_DIALUP, DuDialupDlgProc, NULL, false, false);
}

static HINSTANCE hWinMM = NULL;
static BOOL (WINAPI *_PlaySoundW)(LPCWSTR, HMODULE, DWORD) = NULL;

UINT DuDialupDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	wchar_t tmp[MAX_PATH];
	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_VB6);
		if (hWinMM == NULL)
		{
			hWinMM = LoadLibraryA("winmm.dll");
		}
		if (_PlaySoundW == NULL)
		{
			if (hWinMM != NULL)
			{
				_PlaySoundW = (UINT (__stdcall *)(LPCWSTR,HMODULE,DWORD))GetProcAddress(hWinMM, "PlaySoundW");
			}
		}
		CombinePathW(tmp, sizeof(tmp), MsGetMyTempDirW(), L"dial.wav");
		if (IsFileExistsW(tmp) == false)
		{
			FileCopyW(L"|dial.wav", tmp);
		}
		if (_PlaySoundW != NULL)
		{
			_PlaySoundW(tmp, NULL, SND_FILENAME | SND_ASYNC | SND_NOWAIT);
		}
		SetFont(hWnd, S_STATIC, GetFont(_SS("DASAI_FONT"), 9, false, false, false, false));
		SetFont(hWnd, IDCANCEL, GetFont(_SS("DASAI_FONT"), 9, false, false, false, false));
		SetTimer(hWnd, 1, 24 * 1000, NULL);
		Top(hWnd);
		Center(hWnd);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			SetText(hWnd, S_STATIC, _UU("DU_DIALUP_CONNECTING"));
			SetTimer(hWnd, 2, Rand32() % 1500 + 1000, NULL);
			break;

		case 2:
			KillTimer(hWnd, 2);
			EndDialog(hWnd, 1);
			PlaySoundW(NULL, NULL, SND_ASYNC);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		PlaySoundW(NULL, NULL, SND_ASYNC);
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// コントロール更新
void DuShareDlgUpdate(HWND hWnd)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SetEnable(hWnd, S_INFO, IsChecked(hWnd, C_SHARE_DISK) || IsChecked(hWnd, C_SHARE_CLIPBOARD));
	SetEnable(hWnd, B_USAGE, IsChecked(hWnd, C_SHARE_DISK) || IsChecked(hWnd, C_SHARE_CLIPBOARD));
}

// 共有ダイアログプロシージャ
UINT DuShareDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_MAIN *m = (DU_MAIN *)param;
	DC *dc = m->Du->Dc;

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_SHARE);
		DlgFont(hWnd, C_USE, 0, true);
		DlgFont(hWnd, C_SHARE_CLIPBOARD, 0, true);
		DlgFont(hWnd, C_SHARE_DISK, 0, true);
		DlgFont(hWnd, C_SHARE_PRINTER, 0, true);
		DlgFont(hWnd, C_SHARE_COMPORT, 0, true);

		Check(hWnd, C_SHARE_CLIPBOARD, dc->MstscUseShareClipboard);
		Check(hWnd, C_SHARE_DISK, dc->MstscUseShareDisk);
		Check(hWnd, C_SHARE_PRINTER, dc->MstscUseSharePrinter);
		Check(hWnd, C_SHARE_COMPORT, dc->MstscUseShareComPort);

		SetEnable(hWnd, C_SHARE_CLIPBOARD, DcGetCurrentMstscVersion(dc) == DC_MSTSC_VER_VISTA);
		if (IsEnable(hWnd, C_SHARE_CLIPBOARD) == false)
		{
			Check(hWnd, C_SHARE_CLIPBOARD, true);
		}

		DuShareDlgUpdate(hWnd);

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case C_SHARE_CLIPBOARD:
		case C_SHARE_DISK:
		case C_SHARE_PRINTER:
		case C_SHARE_COMPORT:
			DuShareDlgUpdate(hWnd);
			break;

		case IDOK:
			dc = m->Du->Dc;
			if (IsEnable(hWnd, C_SHARE_CLIPBOARD))
			{
				dc->MstscUseShareClipboard = IsChecked(hWnd, C_SHARE_CLIPBOARD);
			}

			dc->MstscUseShareDisk = IsChecked(hWnd, C_SHARE_DISK);
			dc->MstscUseSharePrinter = IsChecked(hWnd, C_SHARE_PRINTER);
			dc->MstscUseShareComPort = IsChecked(hWnd, C_SHARE_COMPORT);

			EndDialog(hWnd, 1);

			break;

		case B_USAGE:
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("DU_DISK_SHARE_HELP"));
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// 共有ダイアログ
void DuShareDlg(HWND hWnd, DU_MAIN *m)
{
	// 引数チェック
	if (m == NULL)
	{
		return;
	}

	Dialog(hWnd, D_DU_SHARE, DuShareDlgProc, m);
}

// バージョン情報プロシージャ
UINT DuAboutDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_ABOUT *t = (DU_ABOUT *)param;
	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, t->Icon);
		SetIcon(hWnd, S_ICON, t->Icon);
		SetTextA(hWnd, S_TITLE, t->SoftName);
		FormatText(hWnd, S_VERSION,
			DESK_VERSION / 100, DESK_VERSION % 100,
			DESK_BUILD);
		SetTextA(hWnd, S_BUILDINFO, t->BuildInfo);
		DlgFont(hWnd, S_TITLE, 13, true);
		DlgFont(hWnd, S_VERSION, 0, true);
		DlgFont(hWnd, S_BETA, 0, true);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			EndDialog(hWnd, 1);
			break;

		case B_WEB:
			MsExecute(_SS("DESKTOPVPN_URL"), NULL);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// バージョン情報ダイアログ
void DuAboutDlg(HWND hWnd, UINT icon, char *softname, char *buildinfo)
{
	DU_ABOUT t;
	// 引数チェック
	if (softname == NULL || buildinfo == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.Icon = icon;
	t.SoftName = softname;
	t.BuildInfo = buildinfo;

	Dialog(hWnd, D_DU_ABOUT, DuAboutDlgProc, &t);
}

// URDP メッセージプロシージャ
UINT DuUrdpMsgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_URDPMSG *t = (DU_URDPMSG *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		t->hWnd = hWnd;
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		t->DontShow = IsChecked(hWnd, B_NOAGAIN);
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// URDP メッセージスレッド
void DuUrdpMsgThread(THREAD *thread, void *param)
{
	DU_URDPMSG *t;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	t = (DU_URDPMSG *)param;

	Dialog(NULL, D_DU_URDPMSG, DuUrdpMsgProc, t);
}

// URDP メッセージの停止
void DuUrdpMsgStop(DU_MAIN *m, DU_URDPMSG *t)
{
	DC *dc;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	if (m == NULL || t == NULL)
	{
		return;
	}


	dc = m->Du->Dc;

	PostMessage(t->hWnd, WM_CLOSE, 0, 0);

	WaitThread(t->Thread, INFINITE);
	ReleaseThread(t->Thread);

	dc->DontShowFullScreenMessage = t->DontShow;
	DcSaveConfig(dc);

	Free(t);
}

// URDP メッセージの開始
DU_URDPMSG *DuUrdpMsgStart(DU_MAIN *m)
{
	DC *dc;
	DU_URDPMSG *t;
	// 引数チェック
	if (m == NULL)
	{
		return NULL;
	}

	dc = m->Du->Dc;

	if (dc->DontShowFullScreenMessage)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(DU_URDPMSG));
	t->Thread = NewThread(DuUrdpMsgThread, t);

	while (t->hWnd == NULL)
	{
		SleepThread(100);
	}

	return t;
}

// ダイアログ初期化
void DuConnectDlgInit(HWND hWnd, DU_MAIN *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	DisableClose(hWnd);

	SetIcon(hWnd, 0, ICO_LICENSE);

	t->hWndConnect = hWnd;

	FormatText(hWnd, S_INFO, t->Pcid);
	DlgFont(hWnd, S_INFO, 0, true);

	SetTimer(hWnd, 1, 100, NULL);
}

// 接続処理の開始
void DuConnectDlgOnTimer(HWND hWnd, DU_MAIN *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	KillTimer(hWnd, 1);

	DuConnectMain(hWnd, t, t->Pcid);

	EndDialog(hWnd, 1);

	t->hWndConnect = NULL;
}

// 接続ダイアログプロシージャ
UINT DuConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_MAIN *t = (DU_MAIN *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DuConnectDlgInit(hWnd, t);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			DuConnectDlgOnTimer(hWnd, t);
			break;
		}
		break;

	case WM_CLOSE:
		return 1;
	}

	return 0;
}

// 接続ダイアログを開く
void DuConnectDlg(HWND hWnd, DU_MAIN *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Dialog(hWnd, D_DU_CONNECT, DuConnectDlgProc, t);
}

// コントロール更新
void DuPasswordDlgUpdate(HWND hWnd)
{
	char pass[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_PASSWORD, pass, sizeof(pass));

	SetEnable(hWnd, IDOK, StrLen(pass) == 0 ? false : true);
}

// パスワードダイアログプロシージャ
UINT DuPasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_PASSWORD *t = (DU_PASSWORD *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_KEY);
		FormatText(hWnd, S_TITLE, t->Hostname);
		Focus(hWnd, E_PASSWORD);
		DuPasswordDlgUpdate(hWnd);
		break;

	case WM_COMMAND:
		DuPasswordDlgUpdate(hWnd);

		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_PASSWORD, t->Password, sizeof(t->Password));
			EndDialog(hWnd, 1);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// パスワードダイアログ
bool DuPasswordDlg(HWND hWnd, char *password, UINT password_size, char *hostname)
{
	DU_PASSWORD t;
	UINT ret;
	// 引数チェック
	if (password == NULL)
	{
		return false;
	}
	if (hostname == NULL)
	{
		hostname = "";
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Hostname, sizeof(t.Hostname), hostname);

	ret = Dialog(hWnd, D_DU_PASSWORD, DuPasswordDlgProc, &t);

	if (ret == 0)
	{
		return false;
	}

	StrCpy(password, password_size, t.Password);

	return true;
}

// イベントコールバック
bool DuEventCallback(DC_SESSION *s, UINT event_type, void *event_param)
{
	char *url;
	DU_MAIN *t;
	HINSTANCE ret;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	t = (DU_MAIN *)s->Param;

	switch (event_type)
	{
	case DC_EVENT_URL_RECVED:
		// URL を受信
		url = (char *)event_param;
		ret = ShellExecuteA(t->hWnd, "open", url, NULL, NULL, SW_SHOW);
		if ((DWORD)ret <= 32)
		{
			// 失敗したのでメッセージを表示する
			MsgBoxEx(t->hWndConnect, MB_ICONINFORMATION, _UU("DU_URL_ERROR"),
				url);
		}
		break;

	case DC_EVENT_MSG_RECVED:
		// メッセージを受信した。表示する
		{
			wchar_t *msg = (wchar_t *)event_param;

			OnceMsgEx(t->hWndConnect, _UU("DU_SERVER_MSG"), msg, false, ICO_VB6, NULL);
		}
		break;
	}

	return true;
}

// パスワードコールバック
bool DuPasswordCallback(DC_SESSION *s, char *password, UINT password_max_size)
{
	DU_MAIN *t;
	HWND hWnd;
	// 引数チェック
	if (s == NULL || password == NULL)
	{
		return false;
	}

	t = (DU_MAIN *)s->Param;

	hWnd = t->hWnd;

	if (DuPasswordDlg(hWnd, password, password_max_size, s->Pcid) == false)
	{
		return false;
	}

	return true;
}

// 認証ダイアログ初期化
void DuAuthDlgInit(HWND hWnd, DU_AUTH *a)
{
	DC_ADVAUTH *aa;
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	FormatText(hWnd, S_TITLE, a->Pcid);

	aa = DcGetAdvAuth(a->Dc, a->Pcid);
	if (aa != NULL)
	{
		SetTextA(hWnd, E_USERNAME, aa->Username);

		if (aa->AuthType != DESK_AUTH_CERT)
		{
			Check(hWnd, C_PASSWORD, true);
			Check(hWnd, C_CERT, false);

			DuAuthDlgUpdate(hWnd, a);

			if (IsEmpty(hWnd, E_USERNAME) == false)
			{
				FocusEx(hWnd, E_PASSWORD);
			}
			else
			{
				FocusEx(hWnd, E_USERNAME);
			}
		}
		else
		{
			Check(hWnd, C_CERT, true);
			Check(hWnd, C_PASSWORD, false);

			DuAuthDlgUpdate(hWnd, a);

			DuAuthDlgSetCertPath(hWnd, aa->CertPath);

			if (IsEmpty(hWnd, E_USERNAME) == false)
			{
				if (IsEmpty(hWnd, E_CERTPATH))
				{
					Focus(hWnd, B_BROWSE);
				}
				else
				{
					Focus(hWnd, IDOK);
				}
			}
			else
			{
				FocusEx(hWnd, E_USERNAME);
			}
		}
	}
	else
	{
		Check(hWnd, C_PASSWORD, true);
		Check(hWnd, C_CERT, false);

		FocusEx(hWnd, E_USERNAME);
	}

	// コントロール更新
	DuAuthDlgUpdate(hWnd, a);
}

// 認証ダイアログ更新
void DuAuthDlgUpdate(HWND hWnd, DU_AUTH *a)
{
	bool b = true, b1 = true, b2 = true;
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	if (IsChecked(hWnd, C_CERT))
	{
		b1 = false;

		if (IsEmpty(hWnd, E_CERTPATH))
		{
			b = false;
		}
	}
	else
	{
		b2 = false;
	}

	if (IsEmpty(hWnd, E_USERNAME))
	{
		b = false;
	}

	SetEnable(hWnd, S_S1, b1);
	SetEnable(hWnd, S_S2, b1);
	SetEnable(hWnd, E_PASSWORD, b1);

	SetEnable(hWnd, S_S4, b2);
	SetEnable(hWnd, E_CERTPATH, b2);
	SetEnable(hWnd, B_BROWSE, b2);

	SetEnable(hWnd, IDOK, b);
}

// 証明書パスを指定する
void DuAuthDlgSetCertPath(HWND hWnd, wchar_t *path)
{
	// 引数チェック
	if (hWnd == NULL || path == NULL)
	{
		return;
	}

	SetText(hWnd, E_CERTPATH, path);

	FocusEx(hWnd, IDOK);
}

// OK ボタンをクリックした
void DuAuthDlgOnOk(HWND hWnd, DU_AUTH *a)
{
	wchar_t tmp[MAX_PATH];
	DC_AUTH aa;
	DC_ADVAUTH ad;
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	Zero(&aa, sizeof(aa));

	aa.UseAdvancedSecurity = true;

	GetTxtA(hWnd, E_USERNAME, aa.RetUsername, sizeof(aa.RetUsername));

	if (IsChecked(hWnd, C_CERT))
	{
		X *x;
		K *k;
		BUF *buf_x, *buf_k;

		// 証明書認証
		aa.AuthType = DESK_AUTH_CERT;

		GetTxt(hWnd, E_CERTPATH, tmp, sizeof(tmp));

		// 証明書と秘密鍵を読み込む
		if (CmLoadXAndKEx(hWnd, &x, &k, tmp, NULL, true) == false)
		{
			FocusEx(hWnd, E_CERTPATH);
			return;
		}

		buf_x = XToBuf(x, false);
		buf_k = KToBuf(k, false, NULL);
		FreeX(x);
		FreeK(k);

		aa.RetCertSize = MIN(buf_x->Size, sizeof(aa.RetCertData));
		Copy(aa.RetCertData, buf_x->Buf, aa.RetCertSize);

		aa.RetKeySize = MIN(buf_k->Size, sizeof(aa.RetKeyData));
		Copy(aa.RetKeyData, buf_k->Buf, aa.RetKeySize);

		FreeBuf(buf_x);
		FreeBuf(buf_k);
	}
	else
	{
		// パスワード認証
		aa.AuthType = DESK_AUTH_USERPASSWORD;
		GetTxtA(hWnd, E_PASSWORD, aa.RetPassword, sizeof(aa.RetPassword));
	}

	Zero(&ad, sizeof(ad));
	StrCpy(ad.Pcid, sizeof(ad.Pcid), a->Pcid);
	ad.AuthType = aa.AuthType;

	if (IsChecked(hWnd, C_CERT))
	{
		UniStrCpy(ad.CertPath, sizeof(ad.CertPath), tmp);
	}
	
	StrCpy(ad.Username, sizeof(ad.Username), aa.RetUsername);

	DcSetAdvAuth(a->Dc, &ad);

	Copy(&a->Auth, &aa, sizeof(DC_AUTH));

	EndDialog(hWnd, true);
}

// 認証ダイアログプロシージャ
UINT DuAuthDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_AUTH *a = (DU_AUTH *)param;
	wchar_t *s;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		DuAuthDlgInit(hWnd, a);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_USERNAME:
		case E_PASSWORD:
		case E_CERTPATH:
			DuAuthDlgUpdate(hWnd, a);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			DuAuthDlgOnOk(hWnd, a);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_BROWSE:
			s = OpenDlg(hWnd, _UU("DLG_PKCS12_ONLY_FILTER"), _UU("DLG_OPEN_CERT_P12"));
			if (s != NULL)
			{
				DuAuthDlgSetCertPath(hWnd, s);

				Free(s);
				DuAuthDlgUpdate(hWnd, a);
			}
			break;

		case C_PASSWORD:
			DuAuthDlgUpdate(hWnd, a);

			if (IsChecked(hWnd, C_PASSWORD))
			{
				if (IsEmpty(hWnd, E_USERNAME) == false)
				{
					FocusEx(hWnd, E_PASSWORD);
				}
				else
				{
					FocusEx(hWnd, E_USERNAME);
				}
			}
			break;

		case C_CERT:
			DuAuthDlgUpdate(hWnd, a);

			if (IsChecked(hWnd, C_CERT))
			{
				if (IsEmpty(hWnd, E_USERNAME) == false)
				{
					FocusEx(hWnd, B_BROWSE);
				}
				else
				{
					FocusEx(hWnd, E_USERNAME);
				}
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// 認証ダイアログ
bool DuAuthDlg(HWND hWnd, DU_MAIN *t, char *pcid, DC_AUTH *auth)
{
	UINT ret;
	DU_AUTH a;
	// 引数チェック
	if (t == NULL || pcid == NULL || auth == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));

	a.Du = t->Du;
	a.Dc = a.Du->Dc;

	StrCpy(a.Pcid, sizeof(a.Pcid), pcid);

	ret = Dialog(hWnd, D_DU_AUTH, DuAuthDlgProc, &a);

	if (ret == 0)
	{
		return false;
	}

	Copy(auth, &a.Auth, sizeof(DC_AUTH));

	return true;
}

// 新しい認証方法のコールバック
bool DuAdvAuthCallback(DC_SESSION *s, DC_AUTH *auth)
{
	DU_MAIN *t;
	HWND hWnd;
	// 引数チェック
	if (s == NULL || auth == NULL)
	{
		return false;
	}

	t = (DU_MAIN *)s->Param;

	hWnd = t->hWnd;

	if (DuAuthDlg(hWnd, t, s->Pcid, auth) == false)
	{
		return false;
	}

	return true;
}

// 接続処理メイン
void DuConnectMain(HWND hWnd, DU_MAIN *t, char *pcid)
{
	wchar_t mstsc[MAX_PATH];
	bool need_download = false;
	DC_SESSION *s;
	DC *dc;
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || t == NULL || pcid == NULL)
	{
		return;
	}

	dc = t->Du->Dc;

	if (DcGetMstscPath(dc, mstsc, sizeof(mstsc), &need_download) == false)
	{
		// mstsc の設定が不十分
		if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO, _UU("DU_NO_MSTSC_CONFIG")) == IDYES)
		{
			DuOptionDlg(hWnd, t);
		}
		return;
	}

	if (need_download)
	{
		// ダウンロードを実施する
		if (DuDownloadMstsc(hWnd, t) == false)
		{
			return;
		}
	}

	// セッション接続
	ret = NewDcSession(dc, pcid, DuPasswordCallback, DuAdvAuthCallback, DuEventCallback, t, &s);
	if (ret != ERR_NO_ERROR)
	{
		MsgBox(hWnd, MB_ICONEXCLAMATION, _E(ret));
		return;
	}

	ret = DcSessionConnect(s);
	if (ret != ERR_NO_ERROR)
	{
		if (ret != ERR_RECV_URL && ret != ERR_RECV_MSG)
		{
			MsgBox(hWnd, MB_ICONEXCLAMATION, _E(ret));
		}
	}
	else
	{
		bool dialup_ok = true;

		wchar_t exe[MAX_PATH];
		char arg[MAX_PATH];
		UINT ret = ERR_NO_ERROR;
		void *process = NULL;
		DU_URDPMSG *msg = NULL;
		ONCEMSG_DLG *once = NULL;
		UINT process_id = 0;
		bool rdp_file_write_failed = false;
		UINT urdp_version = 0;

		if (MsRegReadInt(REG_CURRENT_USER, DU_REGKEY, DU_ENABLE_RELAX_KEY_NAME))
		{
			Hide(t->hWnd, 0);
			Hide(t->hWndConnect, 0);
			dialup_ok = DuDialupDlg(NULL);
			Show(t->hWndConnect, 0);
			Show(t->hWnd, 0);
		}

		if (dialup_ok == false)
		{
		}
		else
		{
			if (s->ServiceType == DESK_SERVICE_RDP)
			{
				// リモートデスクトップクライアントの実行
				// RDP
				UniStrCpy(exe, sizeof(exe), mstsc);

				ret = DcGetMstscArguments(s, exe, arg, sizeof(arg));

				if (ret == ERR_NO_ERROR)
				{
					process = DcRunMstsc(dc, exe, arg, s->Hostname, s->IsShareDisabled, &process_id, &rdp_file_write_failed);
				}
			}
			else
			{
				if (s->DsCaps & DS_CAPS_SUPPORT_URDP2)
				{
					urdp_version = 2;
				}

				// URDP
				ret = DcGetUrdpClientArguments(s, arg, sizeof(arg), s->IsShareDisabled, urdp_version);

				if (ret == ERR_NO_ERROR)
				{
					process = DcRunUrdpClient(arg, &process_id, urdp_version);

					if (process != NULL)
					{
						wchar_t *once_msg = NULL;
						wchar_t tmp[MAX_SIZE];

						if (urdp_version <= 1)
						{
							// URDP1 の使い方のメッセージ
							msg = DuUrdpMsgStart(t);
						}

						// URDP の場合必ず表示する Once Msg
						if (s->DsCaps & DS_CAPS_RUDP_VERY_LIMITED)
						{
							once_msg = _UU("DU_ONCEMSG_1");
						}
						else
						{
							if (s->DsCaps & DS_CAPS_WIN_RDP_ENABLED)
							{
								once_msg = _UU("DU_ONCEMSG_3");
							}
							else
							{
								once_msg = _UU("DU_ONCEMSG_2");
							}
						}

						UniFormat(tmp, sizeof(tmp), _UU("DU_ONCEMSG_TITLE"), s->Pcid);

						once = StartAsyncOnceMsg(tmp, once_msg, true, ICO_INFORMATION, true);
					}
				}
			}

			if (ret == ERR_NO_ERROR)
			{
				if (process == NULL)
				{
					// プロセス起動失敗
					ret = ERR_DESK_PROCESS_EXEC_FAILED;

					if (s->IsShareDisabled && rdp_file_write_failed)
					{
						// .rdp ファイルに書き込めない
						ret = ERR_DESK_RDP_FILE_WRITE_ERROR;
					}
				}
				else
				{
					s->ProcessIdOfClient = process_id;

					// プロセス起動成功
					Hide(hWnd, 0);
					Hide(t->hWnd, 0);

					DcWaitForProcessExit(process);

					if (msg != NULL)
					{
						DuUrdpMsgStop(t, msg);
					}

					if (once != NULL)
					{
						StopAsyncOnceMsg(once);
					}

					// お疲れ様でした
					if (MsRegReadInt(REG_CURRENT_USER, DU_REGKEY, DU_SHOW_THEEND_KEY_NAME))
					{
						DuTheEndDlg(NULL);
					}

					Show(t->hWnd, 0);
				}
			}

			if (ret != ERR_NO_ERROR)
			{
				if (ret != ERR_RECV_URL && ret != ERR_RECV_MSG)
				{
					MsgBox(hWnd, MB_ICONEXCLAMATION, _E(ret));
				}
			}
		}
	}

	ReleaseDcSession(s);
}

// 初期化
void DuDownloadDlgInit(HWND hWnd, DU_DOWNLOAD *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	t->hWnd = hWnd;

	SetRange(hWnd, P_PROGRESS, 0, 100);
	DuDownloadDlgPrintStatus(hWnd, 0, 0);

	SetTimer(hWnd, 1, 100, NULL);
}

// キャンセル
void DuDownloadDlgOnCancel(HWND hWnd, DU_DOWNLOAD *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	t->Halt = true;
}

// ダウンロードメイン処理
void DuDownloadDlgOnTimer(HWND hWnd, DU_DOWNLOAD *t)
{
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	KillTimer(hWnd, 1);

	// ダウンロード開始
	ret = DcDownloadMstsc(t->Dc, DuDownloadCallback, t);

	if (ret == ERR_NO_ERROR)
	{
		// ダウンロードと展開が完了した
		EndDialog(hWnd, 1);
	}
	else
	{
		// エラー発生
		MsgBox(hWnd, MB_ICONEXCLAMATION, _E(ret));

		EndDialog(hWnd, 0);
	}
}

// ダウンロードコールバック
bool DuDownloadCallback(void *param, UINT total_size, UINT current_size, BUF *recv_buf)
{
	DU_DOWNLOAD *t = (DU_DOWNLOAD *)param;
	HWND hWnd;
	UINT64 now;
	// 引数チェック
	if (t == NULL)
	{
		return false;
	}

	now = Tick64();

	hWnd = t->hWnd;

	if (t->LastTick == 0 || (total_size == current_size) ||
		now > (t->LastTick + 125))
	{
		if (current_size != 0)
		{
			t->LastTick = now;
		}
		DuDownloadDlgPrintStatus(hWnd, current_size, total_size);
	}

	DoEvents(hWnd);

	return t->Halt ? false : true;
}

// ダウンロード状況の表示
void DuDownloadDlgPrintStatus(HWND hWnd, UINT current, UINT total)
{
	wchar_t tmp[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (total == 0)
	{
		UniStrCpy(tmp, sizeof(tmp), _UU("DU_DOWNLOAD_INIT"));
		SetPos(hWnd, P_PROGRESS, 0);
		Show(hWnd, P_PROGRESS);
	}
	else
	{
		if (current != total)
		{
			UINT percent = (UINT)((UINT64)current * 100ULL / (UINT64)total);
			char s1[MAX_PATH];
			char s2[MAX_PATH];

			ToStrByte(s1, sizeof(s1), (UINT64)total);
			ToStrByte(s2, sizeof(s2), (UINT64)current);

			UniFormat(tmp, sizeof(tmp), _UU("DU_DOWNLOAD_STATUS"), percent,
				s1, s2);

			SetPos(hWnd, P_PROGRESS, percent);
			Show(hWnd, P_PROGRESS);
		}
		else
		{
			Hide(hWnd, P_PROGRESS);
			UniStrCpy(tmp, sizeof(tmp), _UU("DU_DOWNLOAD_FINISH"));
		}
	}

	SetText(hWnd, S_STATUS, tmp);
}

// ダウンロードダイアログプロシージャ
UINT DuDownloadDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_DOWNLOAD *t = (DU_DOWNLOAD *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DuDownloadDlgInit(hWnd, t);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			DuDownloadDlgOnTimer(hWnd, t);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		DuDownloadDlgOnCancel(hWnd, t);
		return 1;
	}

	return 0;
}

// mstsc のダウンロード
bool DuDownloadMstsc(HWND hWnd, DU_MAIN *t)
{
	DC *dc;
	DU_DOWNLOAD d;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return false;
	}

	dc = t->Du->Dc;

	Zero(&d, sizeof(d));
	d.Main = t;
	d.Du = t->Du;
	d.Dc = dc;

	if (Dialog(hWnd, D_DU_DOWNLOAD, DuDownloadDlgProc, &d) == false)
	{
		return false;
	}

	return true;
}

// 初期化
void DuOptionDlgInit(HWND hWnd, DU_OPTION *t)
{
	DC *dc;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	dc = t->Du->Dc;

	DcGetInternetSetting(dc, &t->InternetSetting);

	DlgFont(hWnd, S_PROXY_CONFIG, 0, true);

	SetEnable(hWnd, C_SYSTEM32, DcIsMstscInstalledOnSystem32());

	Check(hWnd, C_SYSTEM32, dc->MstscLocation == DC_MSTSC_SYSTEM32);
	Check(hWnd, C_DOWNLOAD, dc->MstscLocation == DC_MSTSC_DOWNLOAD);
	Check(hWnd, C_USERPATH, dc->MstscLocation == DC_MSTSC_USERPATH);
	SetText(hWnd, E_PATH, dc->MstscUserPath);

	if (IsEmptyStr(dc->MstscParams) == false)
	{
		SetTextA(hWnd, E_PARAM, dc->MstscParams);
		Check(hWnd, C_ADDPARAM, true);
	}
	else
	{
		Check(hWnd, C_ADDPARAM, false);
	}

	Check(hWnd, C_PUBLIC, dc->MstscUsePublicSwitchForVer6);

	Check(hWnd, C_CHECK_CERT, WideGetDontCheckCert(dc->Wide) ? false : true);

	Check(hWnd, C_VER2, dc->EnableVersion2);

	Check(hWnd, C_SHOW_THEEND, MsRegReadInt(REG_CURRENT_USER, DU_REGKEY, DU_SHOW_THEEND_KEY_NAME));
	Check(hWnd, C_ENABLE_RELAX, MsRegReadInt(REG_CURRENT_USER, DU_REGKEY, DU_ENABLE_RELAX_KEY_NAME));

	Check(hWnd, C_MULTIDISPLAY, !dc->DisableMultiDisplay);

	DuOptionDlgInitProxyStr(hWnd, t);

	DuOptionDlgUpdate(hWnd, t);
}

// プロキシ文字列初期化
void DuOptionDlgInitProxyStr(HWND hWnd, DU_OPTION *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	SetText(hWnd, S_PROXY_CONFIG, GetProxyTypeStr(t->InternetSetting.ProxyType));
}

// コントロール更新
void DuOptionDlgUpdate(HWND hWnd, DU_OPTION *t)
{
	bool b = true;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	SetEnable(hWnd, S_CHECK_CERT, IsChecked(hWnd, C_CHECK_CERT));

	SetEnable(hWnd, E_PATH, IsChecked(hWnd, C_USERPATH));
	SetEnable(hWnd, S_PATH, IsChecked(hWnd, C_USERPATH));
	SetEnable(hWnd, B_BROWSE, IsChecked(hWnd, C_USERPATH));

	SetEnable(hWnd, E_PARAM, IsChecked(hWnd, C_ADDPARAM));
	SetEnable(hWnd, S_PARAMS, IsChecked(hWnd, C_ADDPARAM));

	if (IsChecked(hWnd, C_USERPATH))
	{
		wchar_t tmp[MAX_PATH];

		GetTxt(hWnd, E_PATH, tmp, sizeof(tmp));

		if (UniIsEmptyStr(tmp))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, C_ADDPARAM))
	{
		wchar_t tmp[MAX_PATH];

		GetTxt(hWnd, E_PARAM, tmp, sizeof(tmp));

		if (UniIsEmptyStr(tmp))
		{
			b = false;
		}
	}

	SetEnable(hWnd, IDOK, b);
}

// OK ボタン
void DuOptionDlgOnOk(HWND hWnd, DU_OPTION *t)
{
	wchar_t tmp[MAX_PATH];
	DC *dc;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	dc = t->Du->Dc;

	// パラメータ検査
	if (IsChecked(hWnd, C_USERPATH))
	{
		GetTxt(hWnd, E_PATH, tmp, sizeof(tmp));
		UniTrim(tmp);

		if (IsFileExistsW(tmp) == false)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("DU_MSTSC_NOT_FOUND"), tmp);
			FocusEx(hWnd, E_PATH);
			return;
		}

		if (DcGetMstscVersion(tmp) == 0)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("DU_MSTSC_INVALID"), tmp);
			FocusEx(hWnd, E_PATH);
			return;
		}
	}

	// プロキシ設定
	DcSetInternetSetting(dc, &t->InternetSetting);

	// SSL 設定
	WideSetDontCheckCert(dc->Wide, IsChecked(hWnd, C_CHECK_CERT) ? false : true);

	// mstsc の場所
	if (IsChecked(hWnd, C_DOWNLOAD))
	{
		dc->MstscLocation = DC_MSTSC_DOWNLOAD;
	}
	else if (IsChecked(hWnd, C_USERPATH))
	{
		dc->MstscLocation = DC_MSTSC_USERPATH;
	}
	else
	{
		dc->MstscLocation = DC_MSTSC_SYSTEM32;
	}

	dc->EnableVersion2 = IsChecked(hWnd, C_VER2);

	GetTxt(hWnd, E_PATH, dc->MstscUserPath, sizeof(dc->MstscUserPath));
	UniTrim(dc->MstscUserPath);

	// パラメータ
	if (IsChecked(hWnd, C_ADDPARAM))
	{
		GetTxtA(hWnd, E_PARAM, dc->MstscParams, sizeof(dc->MstscParams));
		Trim(dc->MstscParams);
	}
	else
	{
		StrCpy(dc->MstscParams, sizeof(dc->MstscParams), "");
	}

	dc->MstscUsePublicSwitchForVer6 = IsChecked(hWnd, C_PUBLIC);

	dc->DisableMultiDisplay = !IsChecked(hWnd, C_MULTIDISPLAY);

	DcSaveConfig(dc);

	// お疲れ様でした
	MsRegWriteInt(REG_CURRENT_USER, DU_REGKEY, DU_SHOW_THEEND_KEY_NAME, IsChecked(hWnd, C_SHOW_THEEND));

	// リラックスモード
	MsRegWriteInt(REG_CURRENT_USER, DU_REGKEY, DU_ENABLE_RELAX_KEY_NAME, IsChecked(hWnd, C_ENABLE_RELAX));

	EndDialog(hWnd, 1);
}

// オプションダイアログプロシージャ
UINT DuOptionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_OPTION *t = (DU_OPTION *)param;
	wchar_t *ret;

	switch (msg)
	{
	case WM_INITDIALOG:
		DuOptionDlgInit(hWnd, t);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PATH:
		case E_PARAM:
			DuOptionDlgUpdate(hWnd, t);
			break;
		}

		switch (wParam)
		{
		case B_PROXY:
			// プロキシ
			if (DgProxyDlg(hWnd, &t->InternetSetting))
			{
				DuOptionDlgInitProxyStr(hWnd, t);
			}
			break;

		case C_CHECK_CERT:
			// SSL
			DuOptionDlgUpdate(hWnd, t);
			break;

		case C_SYSTEM32:
		case C_DOWNLOAD:
		case C_USERPATH:
			DuOptionDlgUpdate(hWnd, t);

			if (IsChecked(hWnd, C_USERPATH))
			{
				FocusEx(hWnd, E_PATH);
			}
			break;

		case C_ADDPARAM:
			DuOptionDlgUpdate(hWnd, t);

			if (IsChecked(hWnd, C_ADDPARAM))
			{
				FocusEx(hWnd, E_PARAM);
			}
			break;

		case B_BROWSE:
			ret = OpenDlg(hWnd, _UU("DLG_EXE_FILES"), _UU("DU_MSTSC_OPEN_TITLE"));
			if (ret != NULL)
			{
				UniTrim(ret);
				SetText(hWnd, E_PATH, ret);
				FocusEx(hWnd, E_PATH);
				Free(ret);
			}
			break;

		case IDOK:
			DuOptionDlgOnOk(hWnd, t);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// オプションダイアログ
void DuOptionDlg(HWND hWnd, DU_MAIN *t)
{
	DU_OPTION o;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	Zero(&o, sizeof(o));
	o.Du = t->Du;
	o.Main = t;

	Dialog(hWnd, D_DU_OPTION, DuOptionDlgProc, &o);
}

// 初期化
void DuMainDlgInit(HWND hWnd, DU_MAIN *t)
{
	UINT i;
	LIST *c;
	HFONT h;
	HMENU hMenu;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	c = t->Du->Dc->Candidate;

	t->hWnd = hWnd;

	hMenu = GetSystemMenu(hWnd, false);
	if (hMenu != NULL)
	{
		MsAppendMenu(hMenu, MF_ENABLED | MF_STRING, CMD_ABOUT, _UU("DU_MENU_ABOUT"));

		if (t->Du->Dc->SupportBluetooth)
		{
			MsAppendMenu(hMenu, MF_ENABLED | MF_STRING, CMD_OPTION, _UU("DU_MENU_BLUETOOTH"));
		}

		DrawMenuBar(hWnd);
	}

	if (t->Du->Dc->SupportBluetooth)
	{
		wchar_t tmp[MAX_PATH];
		wchar_t tmp2[MAX_PATH];

		GetTxt(hWnd, 0, tmp, sizeof(tmp));

		UniFormat(tmp2, sizeof(tmp2), _UU("DU_MAIN_DLG_CAPTION"), tmp);

		SetText(hWnd, 0, tmp2);
	}

	FormatText(hWnd, 0,
		DESK_VERSION / 100, DESK_VERSION % 100,
		DESK_BUILD);

	Center2(hWnd);

	SetIcon(hWnd, 0, ICO_THINCLIENT);

	h = GetFont("Arial", 10, false, false, false, false);
	SetFont(hWnd, C_PCID, h);

	for (i = 0;i < LIST_NUM(c);i++)
	{
		CANDIDATE *item = LIST_DATA(c, i);

		if (UniIsEmptyStr(item->Str) == false)
		{
			CbAddStr(hWnd, C_PCID, item->Str, 0);
		}
	}

	CbSetHeight(hWnd, C_PCID, 20);

	DuMainDlgUpdate(hWnd, t, false);

	// バナー初期化
	if (Rand32() % 2)
	{
		Show(hWnd, S_BANNER1);
		Hide(hWnd, S_BANNER2);
	}
	else
	{
		Show(hWnd, S_BANNER2);
		Hide(hWnd, S_BANNER1);
	}

	SetTimer(hWnd, 1, 100, NULL);
	SetTimer(hWnd, 2, DU_BANNER_SWITCH_INTERVAL, NULL);
}

// コントロール更新
void DuMainDlgUpdate(HWND hWnd, DU_MAIN *t, bool forceEnable)
{
	bool b = true;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	if (IsEmpty(hWnd, C_PCID) && forceEnable == false)
	{
		b = false;
	}

	SetEnable(hWnd, IDOK, b);
}

// OK ボタン
void DuMainDlgOnOk(HWND hWnd, DU_MAIN *t)
{
	char pcid[MAX_PATH];
	wchar_t tmp[MAX_PATH];
	UINT i;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	GetTxtA(hWnd, C_PCID, pcid, sizeof(pcid));
	Trim(pcid);

	StrToUni(tmp, sizeof(tmp), pcid);

	AddCandidate(t->Du->Dc->Candidate, tmp, DU_CANDIDATE_MAX);

	DcSaveConfig(t->Du->Dc);

	i = CbFindStr(hWnd, C_PCID, tmp);
	if (i != INFINITE)
	{
		SendMsg(hWnd, C_PCID, CB_DELETESTRING, i, 0);
	}

	CbInsertStr(hWnd, C_PCID, 0, tmp, 0);

	CbSelect(hWnd, C_PCID, 0);

	StrCpy(t->Pcid, sizeof(t->Pcid), pcid);

	DuMainDlgSetControlEnabled(hWnd, false);

	DuConnectDlg(hWnd, t);

	DuMainDlgSetControlEnabled(hWnd, true);

	FocusEx(hWnd, C_PCID);
}

// コントロールの有効 / 無効の設定
void DuMainDlgSetControlEnabled(HWND hWnd, bool b)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SetEnable(hWnd, C_PCID, b);
	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, IDCANCEL, b);
	SetEnable(hWnd, B_OPTION, b);

	if (b)
	{
		EnableClose(hWnd);
	}
	else
	{
		DisableClose(hWnd);
	}
	DoEvents(hWnd);
}

// 閉じる
void DuMainDlgOnClose(HWND hWnd, DU_MAIN *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	DcSaveConfig(t->Du->Dc);
	EndDialog(hWnd, 0);
}

// バナー切り替え
void DuMainBanner(HWND hWnd, DU_MAIN *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	if (IsShow(hWnd, S_BANNER1))
	{
		Show(hWnd, S_BANNER2);
		Hide(hWnd, S_BANNER1);
	}
	else
	{
		Show(hWnd, S_BANNER1);
		Hide(hWnd, S_BANNER2);
	}
}

// メインダイアログプロシージャ
UINT DuMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_MAIN *t = (DU_MAIN *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DuMainDlgInit(hWnd, t);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case C_PCID:
			// 空欄状態から上下矢印を入力したときにOKが無効になるのを防止
			DuMainDlgUpdate(hWnd, t, HIWORD(wParam)==CBN_SELCHANGE);
			break;

		case S_BANNER1:
		case S_BANNER2:
			switch (HIWORD(wParam))
			{
			case STN_CLICKED:
				MsExecute(_SS("SE_BANNER_URL"), NULL);
				break;
			}
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// 接続
			if (IsEnable(hWnd, IDOK))
			{
				DuMainDlgOnOk(hWnd, t);
			}
			break;

		case IDCANCEL:
			// キャンセル
			Close(hWnd);
			break;

		case B_OPTION:
			// オプション
			DuOptionDlg(hWnd, t);
			break;

		case B_SHARE:
			// 共有
			DuShareDlg(hWnd, t);
			break;

		case B_ERASE:
			// 履歴の消去
			if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("DU_ERASE")) == IDYES)
			{
				DcEraseCandidate(t->Du->Dc);
				DcClearAdvAuthList(t->Du->Dc);

				DcSaveConfig(t->Du->Dc);

				CbReset(hWnd, C_PCID);
				SetTextA(hWnd, C_PCID, "");

				Focus(hWnd, C_PCID);
			}
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			if (t->Du->Dc->SupportBluetooth && t->Du->Dc->BluetoothDirInited)
			{
				DuSelectBluetoothDir(hWnd, t);
			}
			if (IsEmptyStr(t->Du->AutoConnectPcid) == false)
			{
				// 自動接続
				SetTextA(hWnd, C_PCID, t->Du->AutoConnectPcid);
				SendMsg(hWnd, 0, WM_COMMAND, IDOK, 0);
			}
			break;

		case 2:
			DuMainBanner(hWnd, t);
			break;
		}
		break;

	case WM_SYSCOMMAND:
		switch (LOWORD(wParam))
		{
		case CMD_ABOUT:
			// バージョン情報
			About(hWnd, t->Du->Cedar, _UU("PRODUCT_NAME_DESKCLIENT"));
			break;

		case CMD_OPTION:
			// Bluetooth のディレクトリを指定してもらう
			DuSelectBluetoothDir(hWnd, t);
			break;
		}
		break;

	case WM_CLOSE:
		DuMainDlgOnClose(hWnd, t);
		return 1;
	}

	return 0;
}

// メイン
void DuMain(DU *du)
{
	DU_MAIN t;
	// 引数チェック
	if (du == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.Du = du;

	Dialog(NULL, D_DU_MAIN, DuMainDlgProc, &t);
}

// Bluetooth のディレクトリを指定してもらうダイアログ
void DuSelectBluetoothDir(HWND hWnd, DU_MAIN *t)
{
	DC *dc;
	wchar_t *ret;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	dc = t->Du->Dc;

	ret = FolderDlgW(hWnd, _UU("DU_BLUETOOTH_SELFOL_MSG"), dc->BluetoothDir);

	if (ret != NULL)
	{
		if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
			_UU("DU_BLUETOOTH_CONFIRM_MSG"), ret) == IDYES)
		{
			UniStrCpy(dc->BluetoothDir, sizeof(dc->BluetoothDir), ret);

			Free(ret);

			DcSaveConfig(dc);
		}
	}
}

// GUI の実行
void DUExec()
{
	DU *du = ZeroMalloc(sizeof(DU));
	char *s,*s2;
	bool localconfig = false;

	InitWinUi(_UU("DU_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	du->Cedar = NewCedar(NULL, NULL);

	s = s2 = GetCommandLineStr();

	// /local オプションで設定ファイルを実行ファイルのディレクトリに保存
	if (StrCmpi(s,"/local") == 0 || StartWith(s,"/local "))
	{
		localconfig = true;
		s+=6;
	}

	if (IsFileExists(DU_LOCALCONFIG_FILENAME))
	{
		localconfig = true;
	}

	if (IsEmptyStr(s) == false)
	{
		Trim(s);
		StrCpy(du->AutoConnectPcid, sizeof(du->AutoConnectPcid), s);
	}

	Free(s2);
	
	du->Dc = NewDc(localconfig);

	// メイン
	DuMain(du);

	FreeDc(du->Dc);
	ReleaseCedar(du->Cedar);

	FreeWinUi();

	Free(du);
}

#endif	// WIN32
