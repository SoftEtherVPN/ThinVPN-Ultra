// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// DG.c
// PacketiX Desktop VPN Server 設定ツール

// Build 8600

#include <GlobalConst.h>

#ifdef	WIN32

#define	SM_C
#define	CM_C
#define	NM_C
#define	DG_C

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


// MAC 登録ダイアログプロシージャ
UINT DgMacDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	RPC_DS_CONFIG t;
	DG *dg = (DG *)param;
	bool ok = false;
	Zero(&t, sizeof(t));

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_NIC_ONLINE);

		if (CALL(hWnd, DtcGetConfig(dg->Rpc, &t)) == false)
		{
			EndDialog(hWnd, 0);
			return 0;
		}

		SetFont(hWnd, E_TEXT, GetFont(MsIsWindows7() ? "Consolas" : "Arial", 12, false, false, false, false));

		SetTextA(hWnd, E_TEXT, t.MacAddressList);

		Focus(hWnd, E_TEXT);

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			{
				char *s = GetTextA(hWnd, E_TEXT);

				if (CALL(hWnd, DtcGetConfig(dg->Rpc, &t)))
				{
					StrCpy(t.MacAddressList, sizeof(t.MacAddressList), s);

					if (CALL(hWnd, DtcSetConfig(dg->Rpc, &t)))
					{
						ok = true;
					}
				}

				Free(s);

				if (ok)
				{
					EndDialog(hWnd, 1);
				}
				break;
			}

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

// MAC 登録ダイアログ
bool DgMacDlg(HWND hWnd, DG *dg)
{
	if (dg == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_DG_MAC, DgMacDlgProc, dg);
}

// OTP ダイアログ
bool DgOtpDlg(HWND hWnd, DG *dg)
{
	if (dg == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_DG_OTP, DgOtpDlgProc, dg);
}

// OTP ダイアログ
UINT DgOtpDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DG *dg = (DG *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DgOptDlgInit(hWnd, dg);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case B_OTP_ENABLE:
		case E_MAIL:
			DgOptDlgUpdate(hWnd, dg);
			break;
		}

		switch (wParam)
		{
		case B_OTP_ENABLE:
			if (IsChecked(hWnd, B_OTP_ENABLE))
			{
				FocusEx(hWnd, E_MAIL);
			}
			break;

		case B_NEW_EMERGENCY:
			{
				char new_otp[128];

				DsGenerateNewOtp(new_otp, sizeof(new_otp), DS_EMERGENCY_OTP_LENGTH);

				SetTextA(hWnd, E_EMERGENCY, new_otp);

				MsgBox(hWnd, MB_ICONINFORMATION, _UU("DG_EMERGENCY_OTP_GENERATED"));

				FocusEx(hWnd, E_EMERGENCY);
			}
			break;

		case IDOK:
			DgOptDlgOnOk(hWnd, dg);
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

// OTP ダイアログ 初期化
void DgOptDlgInit(HWND hWnd, DG *dg)
{
	RPC_DS_CONFIG t;
	RPC_DS_STATUS st;
	if (dg == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	Zero(&st, sizeof(st));

	SetIcon(hWnd, 0, ICO_IPSEC);

	if (CALL(hWnd, DtcGetConfig(dg->Rpc, &t)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	Check(hWnd, B_OTP_ENABLE, t.EnableOtp);

	SetTextA(hWnd, E_MAIL, t.OtpEmail);

	if (t.EnableOtp == false)
	{
		Focus(hWnd, B_OTP_ENABLE);
	}
	else
	{
		FocusEx(hWnd, E_MAIL);
	}

	DlgFont(hWnd, B_OTP_ENABLE, 10, true);
	DlgFont(hWnd, S_1, 0, true);
	DlgFont(hWnd, S_2, 0, true);

	if (DtcGetStatus(dg->Rpc, &st) == ERR_NO_ERROR)
	{
		if (IsEmptyStr(st.OtpEndWith) == false)
		{
			wchar_t tmp[MAX_PATH];

			UniFormat(tmp, sizeof(tmp), _UU("DG_OTP_ENDWITH"), st.OtpEndWith);

			SetText(hWnd, S_2, tmp);
		}
	}

	SetFont(hWnd, E_MAIL, GetFont("Arial", 12, false, false, false, false));

	DlgFont(hWnd, S_18, 0, true);

	SetFont(hWnd, E_EMERGENCY, GetFont(MsIsWindows7() ? "Consolas" : "Arial", 11, false, false, false, false));

	SetTextA(hWnd, E_EMERGENCY, t.EmergencyOtp);

	DgOptDlgUpdate(hWnd, dg);
}

// OTP ダイアログ コントロール更新
void DgOptDlgUpdate(HWND hWnd, DG *dg)
{
	char email[MAX_PATH];
	bool ok = true;
	bool enabled = false;
	if (dg == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_MAIL, email, sizeof(email));

	enabled = IsChecked(hWnd, B_OTP_ENABLE);

	SetEnable(hWnd, S_1, enabled);
	SetEnable(hWnd, S_2, enabled);
	SetEnable(hWnd, S_3, enabled);
	SetEnable(hWnd, S_5, enabled);
	SetEnable(hWnd, E_MAIL, enabled);

	SetEnable(hWnd, S_18, enabled);
	SetEnable(hWnd, E_EMERGENCY, enabled);
	SetEnable(hWnd, B_NEW_EMERGENCY, enabled);

	if (enabled)
	{
		if (!(InStr(email, "@") && InStr(email, ".")))
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// OTP ダイアログ OK ボタン
void DgOptDlgOnOk(HWND hWnd, DG *dg)
{
	RPC_DS_CONFIG t;
	RPC_DS_STATUS st;
	char tmp[MAX_PATH];
	if (dg == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	Zero(&st, sizeof(st));

	if (DtcGetStatus(dg->Rpc, &st) == ERR_NO_ERROR)
	{
		if (IsChecked(hWnd, B_OTP_ENABLE))
		{
			if (IsEmptyStr(st.OtpEndWith) == false)
			{
				GetTxtA(hWnd, E_MAIL, tmp, sizeof(tmp));

				if (EndWith(tmp, st.OtpEndWith) == false)
				{
					MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("DG_OTP_ENDWITH_ERROR"), st.OtpEndWith);

					FocusEx(hWnd, E_MAIL);

					return;
				}
			}
		}
	}

	if (CALL(hWnd, DtcGetConfig(dg->Rpc, &t)) == false)
	{
		return;
	}

	t.EnableOtp = IsChecked(hWnd, B_OTP_ENABLE);

	GetTxtA(hWnd, E_MAIL, t.OtpEmail, sizeof(t.OtpEmail));

	GetTxtA(hWnd, E_EMERGENCY, t.EmergencyOtp, sizeof(t.EmergencyOtp));

	CALL(hWnd, DtcSetConfig(dg->Rpc, &t));

	EndDialog(hWnd, 1);
}

// Bluetooth ディレクトリの指定
void DgSelectBluetoothDir(HWND hWnd, DG *dg)
{
	RPC_DS_CONFIG t;
	wchar_t default_dir[MAX_PATH];
	wchar_t *ret;
	// 引数チェック
	if (dg == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	if (DtcGetConfig(dg->Rpc, &t) != ERR_NO_ERROR)
	{
		return;
	}

	if (UniIsEmptyStr(t.BluetoothDir) == false)
	{
		// 保存されているディレクトリの値
		UniStrCpy(default_dir, sizeof(default_dir), t.BluetoothDir);
	}
	else
	{
		// デフォルトで現在のユーザーの My Documents の下
		UniFormat(default_dir, sizeof(default_dir), _UU("DESK_BLUETOOTH_FOLDER_NAME"),
			MsGetMyDocumentsDirW());
	}

	// ダイアログを表示
	ret = FolderDlgW(hWnd, _UU("DG_BLUETOOTH_SELFOL_MSG"), default_dir);

	if (ret == NULL)
	{
		return;
	}

	UniStrCpy(t.BluetoothDir, sizeof(t.BluetoothDir), ret);

	CALL(hWnd, DtcSetConfig(dg->Rpc, &t));

	Free(ret);
}

// ダイアログプロシージャ
UINT DgPassword2DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DG *dg = (DG *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		if (MsIsVista())
		{
			SetFont(hWnd, S_1, GetMeiryoFontEx2(14, true));
			SetFont(hWnd, S_2, GetMeiryoFontEx2(11, false));
		}
		else
		{
			DlgFont(hWnd, S_1, (_GETLANG() == 0 ? 18 : 14), true);
			DlgFont(hWnd, S_2, 11, false);
		}

		dg->Password2Clicked = false;
		SetIcon(hWnd, 0, ICO_KEY);
		//DlgFont(hWnd, S_1, (_GETLANG() == 0 ? 18 : 14), true);
		DlgFont(hWnd, IDOK, 0, true);

		SetShow(hWnd, S_LANG_JP, _GETLANG() == 0);
		SetShow(hWnd, S_LANG_EN, _GETLANG() != 0);

		MessageBeep(MB_ICONASTERISK);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			dg->Password2Clicked = true;
			EndDialog(hWnd, 1);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case C_DONTSHOW:
			if (IsChecked(hWnd, C_DONTSHOW))
			{
				Disable(hWnd, IDOK);
			}
			else
			{
				Enable(hWnd, IDOK);
			}
			break;
		}
		break;

	case WM_CLOSE:
		if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
			_UU("DG_PASSWORD2_MSG")) == IDYES)
		{
			if (IsChecked(hWnd, C_DONTSHOW))
			{
				MsRegWriteInt(REG_CURRENT_USER, DG_REGKEY, "DontShowPasswordWarning", 1);
			}

			EndDialog(hWnd, 0);
		}
		return 1;
	}

	return 0;
}

// パスワード警告ダイアログ 2
bool DgPassword2Dlg(HWND hWnd, DG *dg)
{
	// 引数チェック
	if (dg == NULL)
	{
		return false;
	}

	if (MsRegReadInt(REG_CURRENT_USER, DG_REGKEY, "DontShowPasswordWarning") != 0)
	{
		return false;
	}

	if (Dialog(hWnd, D_DG_PASSWORD2, DgPassword2DlgProc, dg) == 0)
	{
		return false;
	}

	return true;
}

// ダイアログプロシージャ
UINT DgPassword1DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		if (MsIsVista())
		{
			SetFont(hWnd, S_1, GetMeiryoFontEx2(14, true));
			SetFont(hWnd, S_2, GetMeiryoFontEx2(11, false));
		}
		else
		{
			DlgFont(hWnd, S_1, (_GETLANG() == 0 ? 18 : 14), true);
			DlgFont(hWnd, S_2, 11, false);
		}

		SetIcon(hWnd, 0, ICO_KEY);
		//DlgFont(hWnd, S_1, (_GETLANG() == 0 ? 18 : 14), true);
		//DlgFont(hWnd, S_2, 11, false);

		SetShow(hWnd, S_LANG_JP, _GETLANG() == 0);
		SetShow(hWnd, S_LANG_EN, _GETLANG() != 0);

		MessageBeep(MB_ICONQUESTION);
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
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// パスワード警告ダイアログ 1
void DgPassword1Dlg(HWND hWnd, DG *dg)
{
	// 引数チェック
	if (dg == NULL)
	{
		return;
	}

	Dialog(hWnd, D_DG_PASSWORD1, DgPassword1DlgProc, dg);
}

// OK クリック
void DgPasswordDlgOnOk(HWND hWnd, DG *dg)
{
	RPC_DS_CONFIG c;
	wchar_t *username;
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	username = MsGetUserNameW();

	Zero(&c, sizeof(c));
	if (CALL(hWnd, DtcGetConfig(dg->Rpc, &c)) == false)
	{
		return;
	}

	if (IsChecked(hWnd, R_USE_PASSWORD) == false)
	{
		Zero(c.HashedPassword, sizeof(c.HashedPassword));
	}
	else
	{
		char pass[MAX_PATH];

		GetTxtA(hWnd, E_PASSWORD1, pass, sizeof(pass));

		if (StrCmp(pass, HIDDEN_PASSWORD) != 0)
		{
			HashSha1(c.HashedPassword, pass, StrLen(pass));
		}
	}

	if (IsChecked(hWnd, R_USER))
	{
		UniStrCpy(c.AdminUsername, sizeof(c.AdminUsername), username);
	}
	else
	{
		UniStrCpy(c.AdminUsername, sizeof(c.AdminUsername), L"");
	}

	if (CALL(hWnd, DtcSetConfig(dg->Rpc, &c)) == false)
	{
		return;
	}

	EndDialog(hWnd, 1);
}

// ダイアログ初期化
void DgPasswordDlgInit(HWND hWnd, DG *dg)
{
	RPC_DS_CONFIG c;
	wchar_t *username;
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	username = MsGetUserNameW();

	Zero(&c, sizeof(c));
	if (CALL(hWnd, DtcGetConfig(dg->Rpc, &c)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	if (IsZero(c.HashedPassword, sizeof(c.HashedPassword)) == false)
	{
		Check(hWnd, R_USE_PASSWORD, true);
		SetTextA(hWnd, E_PASSWORD1, HIDDEN_PASSWORD);
		SetTextA(hWnd, E_PASSWORD2, HIDDEN_PASSWORD);
		FocusEx(hWnd, E_PASSWORD1);
	}

	FormatText(hWnd, S_INFO, username);
	FormatText(hWnd, R_USER, username);

	Check(hWnd, R_USER, (UniIsEmptyStr(c.AdminUsername) == false));

	DgPasswordDlgUpdate(hWnd);
}

// コントロール更新
void DgPasswordDlgUpdate(HWND hWnd)
{
	char pass1[MAX_PATH];
	char pass2[MAX_PATH];
	bool b = true;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_PASSWORD1, pass1, sizeof(pass1));
	GetTxtA(hWnd, E_PASSWORD2, pass2, sizeof(pass2));

	if (IsChecked(hWnd, R_USE_PASSWORD))
	{
		if (StrCmp(pass1, pass2) != 0)
		{
			b = false;
		}
		if (StrLen(pass1) == 0)
		{
			b = false;
		}
	}

	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, E_PASSWORD1, IsChecked(hWnd, R_USE_PASSWORD));
	SetEnable(hWnd, E_PASSWORD2, IsChecked(hWnd, R_USE_PASSWORD));
	SetEnable(hWnd, IDC_STATIC1, IsChecked(hWnd, R_USE_PASSWORD));
	SetEnable(hWnd, IDC_STATIC2, IsChecked(hWnd, R_USE_PASSWORD));
}

// パスワード設定プロシージャ
UINT DgPasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DG *dg = (DG *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DgPasswordDlgInit(hWnd, dg);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PASSWORD1:
		case E_PASSWORD2:
			DgPasswordDlgUpdate(hWnd);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			DgPasswordDlgOnOk(hWnd, dg);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case R_USE_PASSWORD:
			DgPasswordDlgUpdate(hWnd);

			if (IsChecked(hWnd, R_USE_PASSWORD))
			{
				FocusEx(hWnd, E_PASSWORD1);
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

// パスワード設定ダイアログ
bool DgPasswordDlg(HWND hWnd, DG *dg)
{
	// 引数チェック
	if (dg == NULL)
	{
		return false;
	}

	if (Dialog(hWnd, D_DG_PASSWORD, DgPasswordDlgProc, dg) == 0)
	{
		return false;
	}

	return true;
}

// OK ボタンが押された
void DgOptionDlgOnOk(HWND hWnd, DG *dg)
{
	RPC_DS_CONFIG c;
	bool check_rdp = false;
	SYSLOG_SETTING sys;
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	Zero(&c, sizeof(c));

	if (CALL(hWnd, DtcGetConfig(dg->Rpc, &c)) == false)
	{
		return;
	}

	Zero(&sys, sizeof(sys));
	if (CALL(hWnd, ScGetSysLog(dg->Rpc, &sys)) == false)
	{
		return;
	}

	c.Active = IsChecked(hWnd, B_ACTIVE);
	c.PowerKeep = IsChecked(hWnd, B_POWERKEEP);
	c.SaveLogFile = IsChecked(hWnd, C_LOG);
#ifndef	DESK_DISABLE_NEW_FEATURE
	c.SaveEventLog = IsChecked(hWnd, C_EVENTLOG);
#else	// DESK_DISABLE_NEW_FEATURE
	c.SaveEventLog = false;
#endif	// DESK_DISABLE_NEW_FEATURE
	c.DisableShare = IsChecked(hWnd, C_DISABLESHARE);
	sys.SaveType = 0;

#ifndef	DESK_DISABLE_NEW_FEATURE
	if (IsChecked(hWnd, C_SYSLOG))
	{
		sys.SaveType = 1;
		GetTxtA(hWnd, E_SYSLOG_HOSTNAME, sys.Hostname, sizeof(sys.Hostname));
		sys.Port = GetInt(hWnd, E_SYSLOG_PORT);
	}
	else
	{
		sys.SaveType = 0;
	}
#else	// DESK_DISABLE_NEW_FEATURE
	sys.SaveType = 0;
#endif	// DESK_DISABLE_NEW_FEATURE

	if (IsChecked(hWnd, B_URDP))
	{
		c.ServiceType = DESK_SERVICE_VNC;
	}
	else
	{
		if (c.ServiceType != DESK_SERVICE_RDP)
		{
			check_rdp = true;
		}

		c.ServiceType = DESK_SERVICE_RDP;
	}

	c.RdpEnableGroupKeeper = IsChecked(hWnd, B_ADDGROUP);
	GetTxt(hWnd, E_USERNAME, c.RdpGroupKeepUserName, sizeof(c.RdpGroupKeepUserName));
	c.RdpEnableOptimizer = IsChecked(hWnd, B_RDP_OPTIMIZE);
	GetTxtA(hWnd, E_STOPSVC, c.RdpStopServicesList, sizeof(c.RdpStopServicesList));

	if (CALL(hWnd, DtcSetConfig(dg->Rpc, &c)) == false)
	{
		return;
	}

	if (CALL(hWnd, ScSetSysLog(dg->Rpc, &sys)) == false)
	{
		return;
	}

	if (check_rdp)
	{
		if (MsIsRemoteDesktopEnabled() == false)
		{
			wchar_t *msg = _UU("DESK_ENABLE_RDP_XP");
			if (MsIsVista())
			{
				msg = _UU("DESK_ENABLE_RDP_VISTA");
			}
			if (MsIsWin2000())
			{
				msg = _UU("DESK_ENABLE_RDP_2000");
			}

			MsgBox(hWnd, MB_ICONINFORMATION, msg);
		}
	}

	EndDialog(hWnd, 1);
}

// ダイアログ初期化
void DgOptionDlgInit(HWND hWnd, DG *dg)
{
	RPC_DS_CONFIG c;
	RPC_DS_STATUS s;
	SYSLOG_SETTING sys;
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	Zero(&c, sizeof(c));

	if (CALL(hWnd, DtcGetConfig(dg->Rpc, &c)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	Zero(&s, sizeof(s));

	if (CALL(hWnd, DtcGetStatus(dg->Rpc, &s)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	DlgFont(hWnd, B_ACTIVE, 10, true);

	Check(hWnd, B_ACTIVE, c.Active);
	Check(hWnd, B_POWERKEEP, c.PowerKeep);
	Check(hWnd, B_RDP, c.ServiceType == DESK_SERVICE_RDP);
	Check(hWnd, B_URDP, c.ServiceType == DESK_SERVICE_VNC);
	Check(hWnd, C_LOG, c.SaveLogFile);
	Check(hWnd, C_EVENTLOG, c.SaveEventLog);

	Zero(&sys, sizeof(sys));

	if (CALL(hWnd, ScGetSysLog(dg->Rpc, &sys)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	Check(hWnd, C_SYSLOG, sys.SaveType != 0);
	SetTextA(hWnd, E_SYSLOG_HOSTNAME, sys.Hostname);
	SetIntEx(hWnd, E_SYSLOG_PORT, sys.Port);

	if (MsIsRemoteDesktopAvailable() == false)
	{
		// リモートデスクトップ利用不可
		Disable(hWnd, B_RDP);
		Check(hWnd, B_RDP, false);
		Check(hWnd, B_URDP, true);
		SetText(hWnd, S_INFO, _UU("DG_OPTION_URDP_ONLY"));
	}
	else if (s.IsUserMode == false)
	{
		// URDP 利用不可
		Disable(hWnd, B_URDP);
		Check(hWnd, B_URDP, false);
		Check(hWnd, B_RDP, true);
		SetText(hWnd, S_INFO, _UU("DG_OPTION_RDP_ONLY"));
	}

	// 共有機能関係
	if (s.ForceDisableShare)
	{
		Disable(hWnd, C_DISABLESHARE);
		Check(hWnd, C_DISABLESHARE, true);

		SetText(hWnd, S_STATIC1, _UU("DG_FORCE_DISABLE_SHARE"));
	}
	else
	{
		Check(hWnd, C_DISABLESHARE, c.DisableShare);
	}

	SetEnable(hWnd, C_EVENTLOG, s.SupportEventLog);

#ifdef	DESK_DISABLE_NEW_FEATURE
	Hide(hWnd, C_EVENTLOG);
	Hide(hWnd, C_SYSLOG);
	Hide(hWnd, S_01);
	Hide(hWnd, E_SYSLOG_HOSTNAME);
	Hide(hWnd, S_02);
	Hide(hWnd, E_SYSLOG_PORT);
#endif	// DESK_DISABLE_NEW_FEATURE

	Check(hWnd, B_ADDGROUP, c.RdpEnableGroupKeeper);
	SetText(hWnd, E_USERNAME, c.RdpGroupKeepUserName);
	Check(hWnd, B_RDP_OPTIMIZE, c.RdpEnableOptimizer);
	SetTextA(hWnd, E_STOPSVC, c.RdpStopServicesList);

	dg->IsAdminOrSystem_Cache = s.IsAdminOrSystem;

	DgOptionDlgUpdate(hWnd, dg);
}

// URDP の設定画面
void DgOptionDlgUrdpConfig(HWND hWnd, DG *dg)
{
	char tmp[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	if (MsgBox(hWnd, MB_YESNO | MB_ICONEXCLAMATION | MB_DEFBUTTON2, _UU("DG_OPTION_URDP_MSG")) == IDYES)
	{
		DeskInitUrdpFiles(NULL, false, false);
		ConbinePath(tmp, sizeof(tmp), MsGetMyTempDir(), "urdpconfig.exe");

		Run(tmp, NULL, false, false);
	}
}

// コントロール更新
void DgOptionDlgUpdate(HWND hWnd, DG *dg)
{
	bool b = true;
	bool b2 = false;
	bool show_disable_share = true;
	bool is_rdp = false;
	bool add_group = false;
	UINT port;
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	port = GetInt(hWnd, E_PORT);

	SetEnable(hWnd, B_URDPCONFIG, IsChecked(hWnd, B_URDP));

	if (IsChecked(hWnd, B_RDP))
	{
		Enable(hWnd, S_PORT);
		Enable(hWnd, E_PORT);

		//if (port == DS_RDP_PORT)
		//{
		//	Disable(hWnd, B_DEFAULT);
		//}
		//else
		//{
		//	Enable(hWnd, B_DEFAULT);
		//}

		//if (port == 0 || port >= 65536)
		//{
		//	b = false;
		//}

		is_rdp = true;
	}
	else
	{
		Disable(hWnd, S_PORT);
		Disable(hWnd, E_PORT);
		//Disable(hWnd, B_DEFAULT);
	}

	add_group = IsChecked(hWnd, B_ADDGROUP);

	SetEnable(hWnd, B_ADDGROUP, is_rdp && dg->IsAdminOrSystem_Cache);
	SetEnable(hWnd, S_1, is_rdp && dg->IsAdminOrSystem_Cache && add_group);
	SetEnable(hWnd, E_USERNAME, is_rdp && dg->IsAdminOrSystem_Cache && add_group);
	SetEnable(hWnd, B_CURRENTUSER, is_rdp && dg->IsAdminOrSystem_Cache && add_group);
	SetEnable(hWnd, B_RDP_OPTIMIZE, is_rdp && dg->IsAdminOrSystem_Cache);
	SetEnable(hWnd, S_18, is_rdp && dg->IsAdminOrSystem_Cache);
	SetEnable(hWnd, E_STOPSVC, is_rdp && dg->IsAdminOrSystem_Cache);

	if (IsChecked(hWnd, C_SYSLOG))
	{
		if (IsEmpty(hWnd, E_SYSLOG_HOSTNAME))
		{
			b = false;
		}

		if (GetInt(hWnd, E_SYSLOG_PORT) == 0)
		{
			b = false;
		}

		b2 = true;
	}

	// 共有機能に関する説明画面のテキストを現在の動作モードにあわせて変更する
	if (IsChecked(hWnd, B_RDP))
	{
		// RDP
		SetText(hWnd, S_STATIC1, _UU("DG_OPTION_DISABLESHARE_1"));
	}
	else
	{
		// URDP
		SetText(hWnd, S_STATIC1, _UU("DG_OPTION_DISABLESHARE_2"));

		show_disable_share = false;
	}

	SetShow(hWnd, S_STATIC2, show_disable_share);
	SetShow(hWnd, S_ICON1, show_disable_share);
	SetShow(hWnd, S_STATIC1, show_disable_share);
	SetShow(hWnd, C_DISABLESHARE, show_disable_share);

	SetEnable(hWnd, S_01, b2);
	SetEnable(hWnd, S_02, b2);
	SetEnable(hWnd, E_SYSLOG_HOSTNAME, b2);
	SetEnable(hWnd, E_SYSLOG_PORT, b2);

	SetEnable(hWnd, IDOK, b);
}

// オプションダイアログプロシージャ
UINT DgOptionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DG *dg = (DG *)param;
	switch (msg)
	{
	case WM_INITDIALOG:
		DgOptionDlgInit(hWnd, dg);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case S_01:
		case S_02:
		case E_SYSLOG_HOSTNAME:
		case E_SYSLOG_PORT:
		case B_ADDGROUP:
			DgOptionDlgUpdate(hWnd, dg);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			DgOptionDlgOnOk(hWnd, dg);
			break;

		case B_URDPCONFIG:
			DgOptionDlgUrdpConfig(hWnd, dg);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_RDP:
		case B_URDP:
		case C_EVENTLOG:
		case B_ADDGROUP:
			DgOptionDlgUpdate(hWnd, dg);
			break;

		case C_SYSLOG:
			DgOptionDlgUpdate(hWnd, dg);
			if (IsChecked(hWnd, C_SYSLOG))
			{
				FocusEx(hWnd, E_SYSLOG_HOSTNAME);
			}
			break;

		//case B_DEFAULT:
		//	SetInt(hWnd, E_PORT, DS_RDP_PORT);
		//	DgOptionDlgUpdate(hWnd);
		//	FocusEx(hWnd, E_PORT);
		//	break;

		case B_LOG:
			if (true)
			{
				RPC_DS_STATUS t;

				Zero(&t, sizeof(t));

				if (DtcGetStatus(dg->Rpc, &t) == ERR_NO_ERROR)
				{
					wchar_t tmp[MAX_PATH];
					
					ConbinePathW(tmp, sizeof(tmp), t.ExeDirW, L"server_log");

					MsExecuteW(tmp, L"");
				}
			}
			break;

		case B_CURRENTUSER:
			SetText(hWnd, E_USERNAME, MsGetUserNameExW());
			FocusEx(hWnd, E_USERNAME);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// オプションダイアログ
bool DgOptionDlg(HWND hWnd, DG *dg)
{
	// 引数チェック
	if (dg == NULL)
	{
		return false;
	}

	if (Dialog(hWnd, D_DG_OPTION, DgOptionDlgProc, dg) == 0)
	{
		return false;
	}

	return true;
}

// ダイアログ初期化
void DgAuthDlgInit(HWND hWnd, DG *dg)
{
	RPC_DS_CONFIG t;
	RPC_DS_STATUS st;
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	Zero(&st, sizeof(st));

	if (CALL(hWnd, DtcGetConfig(dg->Rpc, &t)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	if (CALL(hWnd, DtcGetStatus(dg->Rpc, &st)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	Check(hWnd, C_USE_AUTH, t.AuthType == DESK_AUTH_PASSWORD);
	if (t.AuthType == DESK_AUTH_PASSWORD)
	{
		SetTextA(hWnd, E_PASSWORD1, HIDDEN_PASSWORD);
		SetTextA(hWnd, E_PASSWORD2, HIDDEN_PASSWORD);
	}

	Check(hWnd, C_CHECK_CERT, t.DontCheckCert ? false : true);

	Check(hWnd, C_USE_ADVANCED, t.UseAdvancedSecurity);

	dg->AuthDlgFirstNoAuth = (t.AuthType == DESK_AUTH_NONE);

	if (dg->Password2Clicked)
	{
		Check(hWnd, C_USE_AUTH, true);
		FocusEx(hWnd, E_PASSWORD1);
	}

	DlgFont(hWnd, S_PASSWORD2, 0, true);
	DlgFont(hWnd, S_PASSWORD3, 0, true);
	DlgFont(hWnd, C_USE_AUTH, 10, true);
	DlgFont(hWnd, C_USE_ADVANCED, 10, true);

#ifdef	DESK_DISABLE_NEW_FEATURE
	Hide(hWnd, S_S10);
	Hide(hWnd, S_S11);
	Hide(hWnd, C_USE_ADVANCED);
	Hide(hWnd, B_USER);
	Hide(hWnd, B_CA);
	Hide(hWnd, B_RADIUS);
	Hide(hWnd, B_CRL);
#endif	// DESK_DISABLE_NEW_FEATURE

	Check(hWnd, C_INSPECTION, t.EnableInspection);
	Check(hWnd, C_CHECKMAC, t.EnableMacCheck);

	SetEnable(hWnd, C_INSPECTION, !st.EnforceInspection);
	SetEnable(hWnd, C_CHECKMAC, !st.EnforceMacCheck);

	DgAuthDlgUpdate(hWnd);
}

// ダイアログコントロール更新
void DgAuthDlgUpdate(HWND hWnd)
{
	bool b = true;
	bool b2;
	bool b3;
	bool b4;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	b3 = true;
	b4 = false;

	if (IsChecked(hWnd, C_USE_ADVANCED))
	{
		b3 = false;
		b4 = true;
	}

	if (IsChecked(hWnd, C_USE_AUTH))
	{
		char pass1[MAX_PATH];
		char pass2[MAX_PATH];

		GetTxtA(hWnd, E_PASSWORD1, pass1, sizeof(pass1));
		GetTxtA(hWnd, E_PASSWORD2, pass2, sizeof(pass2));

		if (IsChecked(hWnd, C_USE_ADVANCED) == false)
		{
			if (StrCmp(pass1, pass2) != 0)
			{
				b = false;
			}

			if (StrLen(pass1) == 0)
			{
				b = false;
			}
		}
	}

	SetEnable(hWnd, IDOK, b);

	b2 = IsChecked(hWnd, C_USE_AUTH);
	SetEnable(hWnd, S_PASSWORD2, b2 && b3);
	SetEnable(hWnd, S_PASSWORD3, b2 && b3);
	SetEnable(hWnd, E_PASSWORD1, b2 && b3);
	SetEnable(hWnd, E_PASSWORD2, b2 && b3);
	SetEnable(hWnd, S_S3, b3);
	SetEnable(hWnd, S_PASSWORD1, b3);
	SetEnable(hWnd, S_S2, b3);
	SetEnable(hWnd, C_USE_AUTH, b3);

	SetEnable(hWnd, S_S10, b4);
	SetEnable(hWnd, B_USER, b4);
	SetEnable(hWnd, B_CA, b4);
	SetEnable(hWnd, B_RADIUS, b4);
	SetEnable(hWnd, B_CRL, b4);

	SetEnable(hWnd, S_CHECK_CERT, IsChecked(hWnd, C_CHECK_CERT));

	SetEnable(hWnd, B_MAC, IsChecked(hWnd, C_CHECKMAC));
}

// セキュリティ設定 OK ボタン
void DgAuthDlgOnOk(HWND hWnd, DG *dg)
{
	RPC_DS_CONFIG t;
	RPC_DS_STATUS st;
	bool b = false;
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	Zero(&st, sizeof(st));

	if (CALL(hWnd, DtcGetStatus(dg->Rpc, &st)) == false)
	{
		return;
	}

	if (st.NumAdvancedUsers == 0)
	{
		if (IsChecked(hWnd, C_USE_ADVANCED))
		{
			if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
				_UU("DG_ZERO_USERS")) == IDNO)
			{
				return;
			}
		}
	}

	if (CALL(hWnd, DtcGetConfig(dg->Rpc, &t)) == false)
	{
		return;
	}

	if (IsChecked(hWnd, C_USE_AUTH))
	{
		char pass[MAX_PATH];
		char pass2[MAX_PATH];

		GetTxtA(hWnd, E_PASSWORD1, pass, sizeof(pass));
		GetTxtA(hWnd, E_PASSWORD2, pass2, sizeof(pass2));

		if (StrCmp(pass, pass2) != 0 || StrLen(pass) == 0)
		{
			t.AuthType = DESK_AUTH_NONE;
		}
		else
		{
			if (StrCmp(pass, HIDDEN_PASSWORD) != 0)
			{
				if (CheckPasswordComplexity(pass) == false && MsRegReadInt(REG_CURRENT_USER, DG_REGKEY, "DisableCheckPasswordComplexity") == 0)
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("DG_PASSWORD_POLICY_ERROR"));
					FocusEx(hWnd, E_PASSWORD1);
					return;
				}

				HashSha1(t.AuthPassword, pass, StrLen(pass));

				t.AuthType = DESK_AUTH_PASSWORD;

				b = true;
			}
		}
	}
	else
	{
		t.AuthType = DESK_AUTH_NONE;
	}

	t.DontCheckCert = IsChecked(hWnd, C_CHECK_CERT) ? false : true;

#ifndef	DESK_DISABLE_NEW_FEATURE
	t.UseAdvancedSecurity = IsChecked(hWnd, C_USE_ADVANCED);
#else	// DESK_DISABLE_NEW_FEATURE
	t.UseAdvancedSecurity = false;
#endif	// DESK_DISABLE_NEW_FEATURE

	if (t.UseAdvancedSecurity == false && t.AuthType == DESK_AUTH_NONE)
	{
		if (MsgBox(hWnd, MB_YESNO | MB_ICONEXCLAMATION, _UU("DG_AUTH_NO_PASSWORD")) == IDYES)
		{
			Check(hWnd, C_USE_AUTH, true);
			SetTextA(hWnd, E_PASSWORD2, "");
			SetTextA(hWnd, E_PASSWORD1, "");
			FocusEx(hWnd, E_PASSWORD1);
			return;
		}
	}

	t.EnableInspection = IsChecked(hWnd, C_INSPECTION);
	t.EnableMacCheck = IsChecked(hWnd, C_CHECKMAC);

	if (CALL(hWnd, DtcSetConfig(dg->Rpc, &t)) == false)
	{
		return;
	}

	if (b)
	{
		if (dg->Password2Clicked)
		{
			dg->Password2Clicked = false;
			DgPassword1Dlg(hWnd, dg);
		}
	}

	EndDialog(hWnd, 1);
}

// SM_SERVER と SM_HUB の準備
void DgInitSmServerAndSmHub(SM_SERVER **ppserver, SM_HUB **pphub, DG *dg)
{
	SM_SERVER *s;
	SM_HUB *h;
	// 引数チェック
	if (ppserver == NULL || pphub == NULL || dg == NULL)
	{
		return;
	}

	s = ZeroMalloc(sizeof(SM_SERVER));

	s->Rpc = dg->Rpc;
	StrCpy(s->ServerName, sizeof(s->ServerName), "localhost");
	s->ServerAdminMode = true;
	s->ServerType = SERVER_TYPE_STANDALONE;
	s->Bridge = false;
	s->CapsList = ScGetCapsEx(dg->Rpc);
	//s->EmptyPassword = false;
	s->CurrentSetting = NULL;

	h = ZeroMalloc(sizeof(SM_HUB));
	StrCpy(h->HubName, sizeof(h->HubName), CEDAR_DESKVPN_HUBNAME);
	h->p = s;
	h->Rpc = s->Rpc;

	*ppserver = s;
	*pphub = h;
}

// SM_SERVER と SM_HUB の解放
void DgFreeSmServerAndSmHub(SM_SERVER *s, SM_HUB *h)
{
	// 引数チェック
	if (s == NULL || h == NULL)
	{
		return;
	}

	FreeCapsList(s->CapsList);

	Free(s);
	Free(h);
}

// セキュリティダイアログプロシージャ
UINT DgAuthDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DG *dg = (DG *)param;
	SM_SERVER *s;
	SM_HUB *h;

	switch (msg)
	{
	case WM_INITDIALOG:
		DgAuthDlgInit(hWnd, dg);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PASSWORD1:
		case E_PASSWORD2:
			DgAuthDlgUpdate(hWnd);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			DgAuthDlgOnOk(hWnd, dg);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case C_USE_AUTH:
			DgAuthDlgUpdate(hWnd);

			if (IsChecked(hWnd, C_USE_AUTH))
			{
				FocusEx(hWnd, E_PASSWORD1);
			}
			break;

		case C_USE_ADVANCED:
			DgAuthDlgUpdate(hWnd);

			if (IsChecked(hWnd, C_USE_ADVANCED))
			{
				Focus(hWnd, B_USER);
			}
			break;

		case C_CHECK_CERT:
		case C_INSPECTION:
		case C_CHECKMAC:
			DgAuthDlgUpdate(hWnd);
			break;

		case B_HASH:
			// 固有 ID の表示
			DgHashDlg(hWnd, dg);
			break;

		case B_USER:
			// ユーザーの管理
			DgInitSmServerAndSmHub(&s, &h, dg);
			{
				SmUserListDlg(hWnd, h);
			}
			DgFreeSmServerAndSmHub(s, h);
			break;

		case B_CA:
			// CA の管理
			DgInitSmServerAndSmHub(&s, &h, dg);
			{
				SmCaDlg(hWnd, h);
			}
			DgFreeSmServerAndSmHub(s, h);
			break;

		case B_RADIUS:
			// 外部認証サーバーの設定
			DgInitSmServerAndSmHub(&s, &h, dg);
			{
				SmRadiusDlg(hWnd, h);
			}
			DgFreeSmServerAndSmHub(s, h);
			break;

		case B_CRL:
			// 無効な証明書の設定
			DgInitSmServerAndSmHub(&s, &h, dg);
			{
				Dialog(hWnd, D_SM_CRL, SmCrlDlgProc, h);
			}
			DgFreeSmServerAndSmHub(s, h);
			break;

		case B_ACL:
			// IP アクセス制御リストの設定
			DgInitSmServerAndSmHub(&s, &h, dg);
			{
				SM_EDIT_HUB eh;

				Zero(&eh, sizeof(eh));

				eh.EditMode = true;
				StrCpy(eh.HubName, sizeof(eh.HubName), h->HubName);
				eh.p = s;

				SmHubAc(hWnd, &eh);
			}
			DgFreeSmServerAndSmHub(s, h);
			break;

		case B_OTP:
			// OTP
			DgOtpDlg(hWnd, dg);
			break;

		case B_MAC:
			// MAC
			DgMacDlg(hWnd,dg);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// セキュリティダイアログ
bool DgAuthDlg(HWND hWnd, DG *dg)
{
	// 引数チェック
	if (dg == NULL)
	{
		return false;
	}

	if (Dialog(hWnd, D_DG_AUTH, DgAuthDlgProc, dg) == 0)
	{
		return false;
	}

	return true;
}

// 固有 ID ダイアログの初期化
void DgHashDlgInit(HWND hWnd, DG *dg)
{
	HFONT h;
	RPC_DS_STATUS t;
	// 引数チェック
	if (dg == NULL)
	{
		return;
	}

	h = GetFont("Arial", 12, false, false, false, false);
	SetFont(hWnd, E_HASH, h);

	h = GetFont("Arial", 10, false, false, false, false);
	SetFont(hWnd, E_IP, h);

	Zero(&t, sizeof(t));

	if (DtcGetStatus(dg->Rpc, &t) == ERR_NO_ERROR)
	{
		BUF *buf;

		buf = StrToBin(t.Hash);

		if (buf != NULL && buf->Size == SHA1_SIZE)
		{
			char tmp[MAX_SIZE];

			BinToStrEx(tmp, sizeof(tmp), buf->Buf, buf->Size);

			SetTextA(hWnd, E_HASH, tmp);
		}

		FreeBuf(buf);

		if (IsEmptyStr(t.GateIP) == false)
		{
			SetTextA(hWnd, E_IP, t.GateIP);
		}
		else
		{
			Hide(hWnd, S_INFO2);
			Hide(hWnd, E_IP);
		}
	}
}

// 固有 ID ダイアログプロシージャ
UINT DgHashDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DG *dg = (DG *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DgHashDlgInit(hWnd, dg);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
		case IDCANCEL2:
			Close(hWnd);
			break;

		case B_RESET:
			if (MsgBox(hWnd, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2, _UU("DG_RESET_CERT_MSG")) == IDYES)
			{
				RPC_TEST t;

				Zero(&t, sizeof(t));

				if (CALL(hWnd, DtcResetCertOnNextBoot(dg->Rpc, &t)))
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("DG_RESET_CERT_DONE"));
					Close(hWnd);
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

// 固有 ID ダイアログ
void DgHashDlg(HWND hWnd, DG *dg)
{
	// 引数チェック
	if (dg == NULL)
	{
		return;
	}

	Dialog(hWnd, D_DG_HASH, DgHashDlgProc, dg);
}

// ウインドウ内の文字列をフォーマットする
void DgFormatText(HWND hWnd, UINT id, ...)
{
	va_list args;
	wchar_t *buf;
	UINT size;
	wchar_t *str;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	str = GetText(hWnd, id);
	if (str == NULL)
	{
		return;
	}

	if (true)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t *caption = str;

		UniFormat(tmp, sizeof(tmp), L"DgFormatText(): Current Caption = \"%s\"", caption);

		WinUiDebug(tmp);
	}

	size = MAX(UniStrSize(str) * 10, MAX_SIZE * 10);
	buf = Malloc(size);

	va_start(args, id);
	UniFormatArgs(buf, size, str, args);

	if (true)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t *caption = str;

		UniFormat(tmp, sizeof(tmp), L"DgFormatText(): buf = \"%s\"", buf);

		WinUiDebug(tmp);
	}

	SetText(hWnd, id, buf);

	if (true)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t *caption = str;

		UniFormat(tmp, sizeof(tmp), L"DuFormatText(): Current Caption = \"%s\"", caption);

		WinUiDebug(tmp);
	}

	Free(buf);

	Free(str);
	va_end(args);
}

// 初期化
void DgMainDlgInit(HWND hWnd, DG *dg)
{
	HFONT h;
	HMENU hMenu;
	bool debug = true;
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	if (debug)
	{
		wchar_t tmp[MAX_SIZE];

		UniFormat(tmp, sizeof(tmp), L"DgMainDlgInit(): _UU(\"D_DG_MAIN@CAPTION\") = \"%s\"", _UU("D_DG_MAIN@CAPTION"));

		WinUiDebug(tmp);
	}

	if (debug)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t *caption = GetText(hWnd, 0);

		UniFormat(tmp, sizeof(tmp), L"DgMainDlgInit(): Current Caption = \"%s\"", caption);

		Free(caption);

		WinUiDebug(tmp);
	}

	DgFormatText(hWnd, 0,
		DESK_VERSION / 100, DESK_VERSION % 100,
		DESK_BUILD);

	if (debug)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t *caption = GetText(hWnd, 0);

		UniFormat(tmp, sizeof(tmp), L"DgMainDlgInit(): Current Caption = \"%s\"", caption);

		Free(caption);

		WinUiDebug(tmp);
	}

	hMenu = GetSystemMenu(hWnd, false);
	if (hMenu != NULL)
	{
		MsAppendMenu(hMenu, MF_ENABLED | MF_STRING, CMD_ABOUT, _UU("DU_MENU_ABOUT"));
		MsAppendMenu(hMenu, MF_ENABLED | MF_STRING, D_DG_HASH, _UU("DG_MENU_HASH_ID"));

		if (dg->DsCaps & DS_CAPS_SUPPORT_BLUETOOTH)
		{
			MsAppendMenu(hMenu, MF_ENABLED | MF_STRING, CMD_OPTION, _UU("DG_MENU_BLUETOOTH"));
		}

		DrawMenuBar(hWnd);
	}

	if (dg->DsCaps & DS_CAPS_SUPPORT_BLUETOOTH)
	{
		wchar_t tmp[MAX_SIZE], tmp2[MAX_SIZE];

		GetTxt(hWnd, 0, tmp, sizeof(tmp));

		UniFormat(tmp2, sizeof(tmp2), _UU("DG_MAIN_DLG_CAPTION"), tmp);

		SetText(hWnd, 0, tmp2);
	}

	SetIcon(hWnd, 0, ICO_USER_ADMIN);

	DlgFont(hWnd, S_PROXY_CONFIG, 0, true);

	h = GetFont("Arial", 12, true, false, false, false);
	SetFont(hWnd, E_PCID, h);

	Zero(dg->CurrentPcid, sizeof(dg->CurrentPcid));
	dg->NoAuthWarningFlag = false;

	DgMainDlgRefresh(hWnd, dg, true);

	SetTimer(hWnd, 1, DG_MAIN_DLG_TIMER_INTERVAL, NULL);
}

// コントロールの更新
void DgMainDlgUpdate(HWND hWnd, DG *dg)
{
	char pcid[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_PCID, pcid, sizeof(pcid));
	Trim(pcid);

	if (StrCmpi(pcid, dg->CurrentPcid) == 0 || StrLen(pcid) == 0)
	{
		Disable(hWnd, IDOK);
		Disable(hWnd, B_RESTORE);
	}
	else
	{
		Enable(hWnd, IDOK);
		Enable(hWnd, B_RESTORE);
	}
}

// 表示内容の更新
void DgMainDlgRefresh(HWND hWnd, DG *dg, bool startup)
{
	RPC_DS_STATUS t;
	RPC_DS_CONFIG c;
	INTERNET_SETTING s;
	UINT ret;
	wchar_t *proxy_string;
	wchar_t status_string[MAX_PATH * 4];
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	if (dg->MainDlgStartTick == 0)
	{
		dg->MainDlgStartTick = Tick64();
	}

	// 設定の取得
	Zero(&c, sizeof(c));
	ret = DtcGetConfig(dg->Rpc, &c);
	if  (ret != ERR_NO_ERROR)
	{
		MsTerminateProcess();
	}

	// 状態の取得
	Zero(&t, sizeof(t));
	ret = DtcGetStatus(dg->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		MsTerminateProcess();
	}

	if (t.LastError != ERR_NO_ERROR)
	{
		Hide(hWnd, IDOK);
		Hide(hWnd, B_RESTORE);
		Hide(hWnd, E_PCID);
		Hide(hWnd, S_PCID);
		Hide(hWnd, S_PCID_2);
		Hide(hWnd, S_PCID_3);
		Hide(hWnd, S_PCID_4);

		Disable(hWnd, S_ACCEPT);
		Disable(hWnd, B_ACCEPT);
		Disable(hWnd, B_DENY);
	}
	else
	{
		Show(hWnd, IDOK);
		Show(hWnd, B_RESTORE);
		Show(hWnd, E_PCID);
		Show(hWnd, S_PCID);
		Show(hWnd, S_PCID_2);
		Show(hWnd, S_PCID_3);
		Show(hWnd, S_PCID_4);

		Enable(hWnd, S_ACCEPT);
		SetEnable(hWnd, B_ACCEPT, t.Active == false);
		SetEnable(hWnd, B_DENY, t.Active);

		if (StrCmpi(dg->CurrentPcid, t.Pcid) != 0)
		{
			StrCpy(dg->CurrentPcid, sizeof(dg->CurrentPcid), t.Pcid);
			SetTextA(hWnd, E_PCID, t.Pcid);
		}
	}

	if (t.LastError == ERR_NO_ERROR)
	{
		bool has_error_msg = false;

		if (t.Active)
		{
			UniFormat(status_string, sizeof(status_string), _UU("DG_INTERNET_CONNECT_OK_1"),
				t.Pcid);
		}
		else
		{
			UniFormat(status_string, sizeof(status_string), _UU("DG_INTERNET_CONNECT_OK_2"));
		}

		if (t.MsgForServerArrived && t.MsgForServerOnce == false && UniIsEmptyStr(t.MsgForServer) == false)
		{
			// サーバーからエラーメッセージが届いている
			has_error_msg = true;
			UniStrCpy(status_string, sizeof(status_string), t.MsgForServer);
		}

		SetText(hWnd, S_STATUS, status_string);
		SetText(hWnd, S_CURRENT, _UU("DG_CURRENT_OK"));

		Hide(hWnd, S_WARNING);

		if (t.Active && has_error_msg == false)
		{
			Hide(hWnd, S_DENY);
			Show(hWnd, S_LOCK);
		}
		else
		{
			Show(hWnd, S_DENY);
			Hide(hWnd, S_LOCK);
		}
	}
	else
	{
		Show(hWnd, S_WARNING);
		Hide(hWnd, S_DENY);
		Hide(hWnd, S_LOCK);

		SetText(hWnd, S_CURRENT, _UU("DG_CURRENT_ERROR"));

		SetText(hWnd, S_STATUS, _E(t.LastError));

	}

	if (t.IsConfigured == false)
	{
		// 最初の起動時にプロキシサーバーの設定をシステムからインポートする
		Zero(&s, sizeof(s));
		GetSystemInternetSetting(&s);
		DtcSetInternetSetting(dg->Rpc, &s);
	}

	Zero(&s, sizeof(s));
	ret = DtcGetInternetSetting(dg->Rpc, &s);
	if (ret != ERR_NO_ERROR)
	{
		MsTerminateProcess();
	}

	proxy_string = GetProtocolName(s.ProxyType);
	SetText(hWnd, S_PROXY_CONFIG, proxy_string);

	if ((dg->MainDlgStartTick + 666ULL) <= Tick64())
	{
		if (dg->Hello == false)
		{
			dg->Hello = true;

			if (t.NumConfigures == 1)
			{
				// 2012.10.18 これはもういらん!
				// SGI による不要な要求!!

				// このユーザー以外で設定ツールを開けないようにするかどうか聞く
/*				wchar_t *username = MsGetUserNameW();

				if (UniIsEmptyStr(c.AdminUsername))
				{
					if (MsgBoxEx(hWnd, MB_YESNO	| MB_DEFBUTTON2 | MB_ICONQUESTION,
						_UU("DG_ADMINUSERNAME_MSG"), username, username) == IDYES)
					{
						RPC_DS_CONFIG t;

						Zero(&t, sizeof(t));

						// そのように設定する
						if (DtcGetConfig(dg->Rpc, &t) == ERR_NO_ERROR)
						{
							UniStrCpy(t.AdminUsername, sizeof(t.AdminUsername), username);

							DtcSetConfig(dg->Rpc, &t);

							MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("DG_ADMINUSERNAME_MSG2"), username);
						}
					}
				}*/
			}
		}

		if (startup == false)
		{
			if (t.LastError == ERR_NO_ERROR)
			{
				if (c.UseAdvancedSecurity == false && c.AuthType == DESK_AUTH_NONE)
				{
					if (dg->NoAuthWarningFlag == false)
					{
						dg->NoAuthWarningFlag = true;

						// パスワードが設定されていない場合の警告の表示
						if (DgPassword2Dlg(hWnd, dg))
						{
							DgAuthDlg(hWnd, dg);
						}
					}
				}
			}
		}

		if (dg->DsCaps & DS_CAPS_SUPPORT_BLUETOOTH)
		{
			if (dg->BluetoothDirFlag == false)
			{
				RPC_DS_CONFIG cfg;

				dg->BluetoothDirFlag = true;

				Zero(&cfg, sizeof(cfg));

				if (DtcGetConfig(dg->Rpc, &cfg) == ERR_NO_ERROR)
				{
					if (UniIsEmptyStr(cfg.BluetoothDir))
					{
						// Bluetooth ディレクトリが指定されていないのでダイアログを
						// 表示して指定してもらう
						DgSelectBluetoothDir(hWnd, dg);
					}
				}
			}
		}
	}

	if (t.MsgForServerArrived && UniIsEmptyStr(t.MsgForServer) == false)
	{
		// 新しいメッセージが届いている
		// 画面に表示する
		if (dg->MsgForServerDlg == NULL) // 既に過去にメッセージが表示されたことがある場合は新たに表示しない
		{
			dg->MsgForServerDlg = StartAsyncOnceMsg(_UU("DU_SERVER_MSG2"), t.MsgForServer, t.MsgForServerOnce,
				ICO_VB6, true);
		}
	}

	if (UniIsEmptyStr(t.MsgForServer2) == false)
	{
		// ポリシー関係のメッセージが届いている
		// 画面に表示する
		if (dg->MsgForServerDlg2 == NULL) // 既に過去にメッセージが表示されたことがある場合は新たに表示しない
		{
			dg->MsgForServerDlg2 = StartAsyncOnceMsg(_UU("DS_POLICY_MESSAGE_TITLE"), t.MsgForServer2, true,
				ICO_INFORMATION, true);
		}
	}

	// Init user name
	if (UniIsEmptyStr(c.RdpGroupKeepUserName))
	{
		UniStrCpy(c.RdpGroupKeepUserName, sizeof(c.RdpGroupKeepUserName), MsGetUserNameExW());
		DtcSetConfig(dg->Rpc, &c);
	}

	// コントロールの更新
	DgMainDlgUpdate(hWnd, dg);
}

// タイマー呼び出し
void DgMainDlgOnTimer(HWND hWnd, DG *dg)
{
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	KillTimer(hWnd, 1);

	DgMainDlgRefresh(hWnd, dg, false);

	SetTimer(hWnd, 1, DG_MAIN_DLG_TIMER_INTERVAL, NULL);
}

// プロキシサーバーの設定
bool DgMainDlgProxy(HWND hWnd, DG *dg)
{
	INTERNET_SETTING s;
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return false;
	}

	Zero(&s, sizeof(s));

	if (CALL(hWnd, DtcGetInternetSetting(dg->Rpc, &s)) == false)
	{
		return false;
	}

	if (DgProxyDlg(hWnd, &s) == false)
	{
		return false;
	}

	if (CALL(hWnd, DtcSetInternetSetting(dg->Rpc, &s)) == false)
	{
		return false;
	}

	return true;
}

// PCID のフォーカスが解除された場合
void DgMainDlgOnKillFocusPcid(HWND hWnd, DG *dg)
{
	char pcid[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	if (dg->ChangingPcid)
	{
		return;
	}
	dg->ChangingPcid = true;

	GetTxtA(hWnd, E_PCID, pcid, sizeof(pcid));

	Trim(pcid);

	if (IsEmptyStr(pcid) == false)
	{
		if (IsEnable(hWnd, IDOK))
		{
			if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("DG_PCID_KILLFOCUS"), pcid) == IDYES)
			{
				DgMainDlgOnOk(hWnd, dg);
			}
		}
	}

	dg->ChangingPcid = false;
}

// PCID の変更
void DgMainDlgOnOk(HWND hWnd, DG *dg)
{
	// 引数チェック
	if (hWnd == NULL || dg == NULL)
	{
		return;
	}

	if (IsShow(hWnd, IDOK) && IsEnable(hWnd, IDOK))
	{
		RPC_PCID t;
		char pcid[MAX_PATH];
		wchar_t tmp[MAX_PATH];

		GetTxtA(hWnd, E_PCID, pcid, sizeof(pcid));
		Trim(pcid);

		Zero(&t, sizeof(t));
		StrCpy(t.Pcid, sizeof(t.Pcid), pcid);

		if (CALL(hWnd, DtcChangePcid(dg->Rpc, &t)))
		{
			UniFormat(tmp, sizeof(tmp), _UU("DG_CHANGE_PCID_OK"), pcid);
			MsgBox(hWnd, MB_ICONINFORMATION, tmp);

			DgMainDlgRefresh(hWnd, dg, false);

			FocusEx(hWnd, E_PCID);
		}
	}
}

// メインダイアログプロシージャ
UINT DgMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DG *dg = (DG *)param;
	RPC_DS_CONFIG t;

	switch (msg)
	{
	case WM_INITDIALOG:
		DgMainDlgInit(hWnd, dg);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PCID:
			DgMainDlgUpdate(hWnd, dg);

			switch (HIWORD(wParam))
			{
			case EN_KILLFOCUS:
				if (IsFocus(hWnd, B_RESTORE) == false && IsFocus(hWnd, IDCANCEL) == false)
				{
					DgMainDlgOnKillFocusPcid(hWnd, dg);
				}
				break;
			}
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// PCID の変更
			if (dg->ChangingPcid)
			{
				break;
			}
			dg->ChangingPcid = true;
			DgMainDlgOnOk(hWnd, dg);
			dg->ChangingPcid = false;
			break;

		case B_RESTORE:
			// PCID を元に戻す
			if (IsShow(hWnd, B_RESTORE) && IsEnable(hWnd, B_RESTORE))
			{
				SetTextA(hWnd, E_PCID, dg->CurrentPcid);
				FocusEx(hWnd, E_PCID);
				DgMainDlgUpdate(hWnd, dg);
			}
			break;

		case B_PROXY:
			// Proxy 設定
			if (DgMainDlgProxy(hWnd, dg))
			{
				DgMainDlgRefresh(hWnd, dg, false);
			}
			break;

		case B_AUTH:
			// セキュリティ設定
			if (DgAuthDlg(hWnd, dg))
			{
				DgMainDlgRefresh(hWnd, dg, false);
			}
			break;

		case B_OPTION:
			// 動作設定
			if (DgOptionDlg(hWnd, dg))
			{
				DgMainDlgRefresh(hWnd, dg, false);
			}
			break;

		case B_PASSWORD:
			// パスワード設定
			if (DgPasswordDlg(hWnd, dg))
			{
				DgMainDlgRefresh(hWnd, dg, false);
			}
			break;

		case B_ABOUT:
			// バージョン情報
			if (true)
			{
				RPC_DS_STATUS s;

				Zero(&s, sizeof(s));

				if (CALL(hWnd, DtcGetStatus(dg->Rpc, &s)))
				{
					/*DuAboutDlg(hWnd, ICO_DESKSERVER,
						((s.ForceDisableShare == false) ? _SS("PRODUCT_NAME_DESKSERVER") : _SS("PRODUCT_NAME_DESKSERVER2")),
						dg->Cedar->BuildInfo);*/

					About(hWnd, dg->Cedar, (s.ForceDisableShare == false) ? _UU("PRODUCT_NAME_DESKSERVER") : _UU("PRODUCT_NAME_DESKSERVER2"));
				}
			}
			break;

		case B_SHOWID:
			// バージョン情報
			DgHashDlg(hWnd, dg);
			break;

		case B_ACCEPT:
		case B_DENY:
			// 接続の許可 / 禁止
			Zero(&t, sizeof(t));
			if (CALL(hWnd, DtcGetConfig(dg->Rpc, &t)))
			{
				t.Active = (wParam == B_ACCEPT);

				if (CALL(hWnd, DtcSetConfig(dg->Rpc, &t)))
				{
					DgMainDlgRefresh(hWnd, dg, false);
				}
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_SYSCOMMAND:
		switch (LOWORD(wParam))
		{
		case CMD_ABOUT:
			SendMsg(hWnd, 0, WM_COMMAND, B_ABOUT, 0);
			break;

		case D_DG_HASH:
			DgHashDlg(hWnd, dg);
			break;

		case CMD_OPTION:
			DgSelectBluetoothDir(hWnd, dg);
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			DgMainDlgOnTimer(hWnd, dg);
			break;
		}
		break;

	case WM_CLOSE:
		DgMainDlgOnKillFocusPcid(hWnd, dg);
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// メインダイアログ
void DgMainDlg(DG *dg)
{
	// 引数チェック
	if (dg == NULL)
	{
		return;
	}

	Dialog(NULL, D_DG_MAIN, DgMainDlgProc, dg);
}

// ダイアログ初期化
void DgProxyDlgInit(HWND hWnd, INTERNET_SETTING *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	DgProxyDlgSet(hWnd, t);
}

// 現在の設定を設定
void DgProxyDlgSet(HWND hWnd, INTERNET_SETTING *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	Check(hWnd, C_DIRECT, t->ProxyType == PROXY_DIRECT);
	Check(hWnd, C_HTTP, t->ProxyType == PROXY_HTTP);
	Check(hWnd, C_SOCKS, t->ProxyType == PROXY_SOCKS);

	SetTextA(hWnd, E_ADDRESS, t->ProxyHostName);
	SetIntEx(hWnd, E_PORT, t->ProxyPort);
	SetTextA(hWnd, E_USERNAME, t->ProxyUsername);
	SetTextA(hWnd, E_PASSWORD, t->ProxyPassword);
	SetTextA(hWnd, E_USERAGENT, t->ProxyUserAgent);

	DgProxyDlgUpdate(hWnd);
}

// ダイアログ状態のアップデート
void DgProxyDlgUpdate(HWND hWnd)
{
	UINT type;
	bool b = true;
	bool b2 = false;
	bool b3 = false;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	type = PROXY_DIRECT;
	if (IsChecked(hWnd, C_HTTP))
	{
		type = PROXY_HTTP;
	}
	else if (IsChecked(hWnd, C_SOCKS))
	{
		type = PROXY_SOCKS;
	}

	if (type != PROXY_DIRECT)
	{
		if (IsEmpty(hWnd, E_ADDRESS))
		{
			b = false;
		}
		if (GetInt(hWnd, E_PORT) == 0)
		{
			b = false;
		}

		b2 = true;

		if (type == PROXY_HTTP)
		{
			b3 = true;
		}
	}

	SetEnable(hWnd, IDOK, b);

	SetEnable(hWnd, S_ADDRESS, b2);
	SetEnable(hWnd, E_ADDRESS, b2);
	SetEnable(hWnd, S_PORT, b2);
	SetEnable(hWnd, E_PORT, b2);

	SetEnable(hWnd, S_USERNAME, b3);
	SetEnable(hWnd, E_USERNAME, b3);
	SetEnable(hWnd, S_OPTION1, b3);
	SetEnable(hWnd, S_PASSWORD, b3);
	SetEnable(hWnd, E_PASSWORD, b3);
	SetEnable(hWnd, S_OPTION2, b3);

	SetEnable(hWnd, E_USERAGENT, b3);
	SetEnable(hWnd, S_USERAGENT, b3);
	SetEnable(hWnd, S_USERAGENT2, b3);
}

// IE の設定を使用する
void DgProxyDlgUseForIE(HWND hWnd)
{
	INTERNET_SETTING s;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	Zero(&s, sizeof(s));
	GetSystemInternetSetting(&s);

	StrCpy(s.ProxyUserAgent, sizeof(s.ProxyUserAgent), DEFAULT_PROXY_USER_AGENT_IE);

	DgProxyDlgSet(hWnd, &s);

	MsgBox(hWnd, MB_ICONINFORMATION, _UU("DG_PROXY_FROM_IE"));
}

// OK
void DgProxyDlgOnOk(HWND hWnd, INTERNET_SETTING *t)
{
	UINT type;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	Zero(t, sizeof(t));

	type = PROXY_DIRECT;
	if (IsChecked(hWnd, C_HTTP))
	{
		type = PROXY_HTTP;
	}
	else if (IsChecked(hWnd, C_SOCKS))
	{
		type = PROXY_SOCKS;
	}

	t->ProxyType = type;
	GetTxtA(hWnd, E_ADDRESS, t->ProxyHostName, sizeof(t->ProxyHostName));
	t->ProxyPort = GetInt(hWnd, E_PORT);
	GetTxtA(hWnd, E_USERNAME, t->ProxyUsername, sizeof(t->ProxyUsername));
	GetTxtA(hWnd, E_PASSWORD, t->ProxyPassword, sizeof(t->ProxyPassword));
	GetTxtA(hWnd, E_USERAGENT, t->ProxyUserAgent, sizeof(t->ProxyUserAgent));

	EndDialog(hWnd, 1);
}

// プロキシサーバー設定ダイアログ
UINT DgProxyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	INTERNET_SETTING *t = (INTERNET_SETTING *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DgProxyDlgInit(hWnd, t);
		break;

	case WM_COMMAND:
		DgProxyDlgUpdate(hWnd);

		switch (wParam)
		{
		case IDOK:
			DgProxyDlgOnOk(hWnd, t);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_IE:
			DgProxyDlgUseForIE(hWnd);
			break;

		case C_HTTP:
		case C_SOCKS:
			FocusEx(hWnd, E_ADDRESS);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// プロキシサーバー設定
bool DgProxyDlg(HWND hWnd, INTERNET_SETTING *setting)
{
	UINT ret;
	// 引数チェック
	if (setting == NULL)
	{
		return false;
	}

	ret = Dialog(hWnd, D_DG_PROXY, DgProxyDlgProc, setting);

	return ret == 0 ? false : true;
}

// コントロール更新
void DgLoginDlgUpdate(HWND hWnd)
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

// ログインダイアログプロシージャ
UINT DgLoginDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DG_PASSWORD *t = (DG_PASSWORD *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_DESKSERVER);
		DgLoginDlgUpdate(hWnd);
		break;

	case WM_COMMAND:
		DgLoginDlgUpdate(hWnd);

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

// ログインダイアログ
bool DgLoginDlg(HWND hWnd, char *password, UINT password_size)
{
	DG_PASSWORD t;
	UINT ret;
	// 引数チェック
	if (password == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));

	ret = Dialog(hWnd, D_DG_LOGIN, DgLoginDlgProc, &t);

	if (ret == 0)
	{
		return false;
	}

	StrCpy(password, password_size, t.Password);

	return true;
}

// DG メイン
void DgMain(DG *dg)
{
	RPC *rpc;
	UINT ret;
	char password[MAX_PATH];
	bool b = false;
	// 引数チェック
	if (dg == NULL)
	{
		return;
	}

	Zero(password, sizeof(password));

	while (true)
	{
		ret = DtcConnect(password, &rpc);

		if (ret == ERR_ACCESS_DENIED)
		{
			if (DgLoginDlg(NULL, password, sizeof(password)) == false)
			{
				break;
			}
		}
		else
		{
			if (ret == ERR_NO_ERROR)
			{
				b = true;
				break;
			}
			else
			{
				MsgBox(NULL, MB_ICONEXCLAMATION, _E(ret));
				break;
			}
		}
	}

	if (b == false)
	{
		return;
	}

	dg->Rpc = rpc;

	if (true)
	{
		RPC_DS_STATUS t;

		Zero(&t, sizeof(t));

		DtcGetStatus(rpc, &t);

		dg->DsCaps = t.DsCaps;
	}

	DgMainDlg(dg);

	if (dg->MsgForServerDlg != NULL)
	{
		// メッセージ画面が表示されたままの場合は閉じる
		StopAsyncOnceMsg(dg->MsgForServerDlg);
		dg->MsgForServerDlg = NULL;
	}

	if (dg->MsgForServerDlg2 != NULL)
	{
		// メッセージ画面 2 が表示されたままの場合は閉じる
		StopAsyncOnceMsg(dg->MsgForServerDlg2);
		dg->MsgForServerDlg2 = NULL;
	}

	EndRpc(rpc);
}

// DG の実行
void DGExec()
{
	DG *dg = ZeroMalloc(sizeof(DG));

	InitWinUi(_UU("DG_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	dg->Cedar = NewCedar(NULL, NULL);

	// メイン
	DgMain(dg);

	ReleaseCedar(dg->Cedar);

	FreeWinUi();

	Free(dg);
}


#endif	// WIN32
