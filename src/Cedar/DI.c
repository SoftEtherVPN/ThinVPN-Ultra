// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// DI.c
// PacketiX Desktop VPN Setup GUI

// Build 8600

#include <GlobalConst.h>

#ifdef	WIN32

#define	SM_C
#define	CM_C
#define	NM_C
#define	DG_C
#define DU_C
#define DI_C

#define	_WIN32_WINNT		0x0600
#define	WINVER				0x0600
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
#include "DI_Inner.h"
#include "../PenCore/resource.h"

static wchar_t debug_cmdline[MAX_PATH] = {0};

// インストーラメイン処理
void DiMain(DI *di)
{
	DI_STARTUP startup;
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	// コマンドライン解釈
	Zero(&startup, sizeof(startup));
	DiParseCommandLine(&startup);

	if (startup.Uninstall)
	{
		// アンインストールモード
		di->UninstallMode = true;
		UniStrCpy(di->InstallDir, sizeof(di->InstallDir), startup.Path);
		di->Product = startup.Product;
		di->IsUserMode = startup.Usermode;
	}
	else
	{
		if (di->IsHelper)
		{
			if (startup.CalledFromSetup == false)
			{
				// DeskHelper.exe が単体で起動された
				MsgBox(NULL, MB_ICONINFORMATION, _UU("DI_HELPER_NOT_CALLED"));
				return;
			}
		}
	}

	if (di->IsHelper && startup.InstallUrpd)
	{
		// RUDP インストールモード
		DiInstallRudpMain(di);
		return;
	}

	if (di->IsHelper && di->IsAdmin == false)
	{
		// DeskHelper.exe が Admin 以外のユーザーによって起動された
		MsgBox(NULL, MB_ICONEXCLAMATION, _UU("DI_HELPER_NOT_ADMIN"));
		return;
	}

	di->CanSelectSystem = di->CanSelectUser = true;

	if (di->UninstallMode == false)
	{
		// インストールメイン
		DiInstallMain(di);
	}
	else
	{
		// アンインストールメイン
		DiUninstallMain(di);
	}
}

// RUDP インストール処理
void DiInstallRudpMain(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	DeskInstallRudpServerToProgramFilesDir();

	if (DeskIsUacSettingStrict())
	{
		DeskMitigateUacSetting();
	}
}

// アンインストールのメイン処理
bool DiUninstallProcessMain(HWND hWnd, DI *di)
{
	UINT i;
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return false;
	}

	// 確認メッセージ
	if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("DIU_CONFIRM_MSG"),
		di->Title, di->Title, di->InstallDir, di->Title) == IDNO)
	{
		return false;
	}

	// サービスの停止とアンインストール
	if (di->Product == DI_PRODUCT_SERVER)
	{
		if (DiUninstallServerService(hWnd, di) == false)
		{
			MsgBox(hWnd, MB_ICONSTOP, _UU("DIU_UNINSTALL_SVC_FAILED"));
			return false;
		}
	}

	// ファイルのロック解除を待機
	if (DiWaitForUnlockFile(hWnd, di) == false)
	{
		return false;
	}

	// ファイルを削除
	for (i = 0;i < LIST_NUM(di->FilesList);i++)
	{
		DI_FILE *f = LIST_DATA(di->FilesList, i);
		wchar_t dst[MAX_PATH];

LABEL_RETRY:

		if (DiIsFileSpecialForInstaller(di, f) == false)
		{
			ConbinePathW(dst, sizeof(dst), di->InstallDir, f->FileName);

			if (IsFileExistsW(dst))
			{
				if (FileDeleteW(dst) == false)
				{
					// ファイル削除失敗
					UINT ret = MsgBoxEx(hWnd, MB_ABORTRETRYIGNORE, _UU("DIU_DELETE_FAILED"), dst);

					if (ret == IDABORT)
					{
						// 中止
						return false;
					}
					else if (ret == IDRETRY)
					{
						// 再試行
						goto LABEL_RETRY;
					}
				}
			}
		}
	}

	// ショートカットを削除
	DiDeleteShortcuts(hWnd, di);

	if (di->IsUserMode == false)
	{
		// レジストリからアンインストール情報を削除
		DiDeleteUninstallInfo(di->ProductSimpleName);
	}

	// システム更新通知
	MsUpdateSystem();

	// 完了
	MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("DIU_FINISH_MSG"),
		di->Title, di->InstallDir, di->Title);

	return true;
}

// アンインストール処理実施
void DiUninstallDlgOnTimer(HWND hWnd, DI *di)
{
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	if (DiUninstallProcessMain(hWnd, di) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	EndDialog(hWnd, 1);
}

// ダイアログの初期化
void DiUninstallDlgInit(HWND hWnd, DI *di)
{
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	DisableClose(hWnd);
	SetIcon(hWnd, 0, ICO_SETUP);
	FormatText(hWnd, 0, di->Title);
	FormatText(hWnd, S_INFO, di->Title);

	SetTimer(hWnd, 1, 250, NULL);
}

// アンインストールダイアログプロシージャ
UINT DiUninstallDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DI *di = (DI *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DiUninstallDlgInit(hWnd, di);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			DiUninstallDlgOnTimer(hWnd, di);
			break;
		}
		break;

	case WM_CLOSE:
		return 1;
	}

	return 0;
}

// アンインストールダイアログ
void DiUninstallDlg(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	Dialog(di->hWndParent, D_DI_UNINSTALL, DiUninstallDlgProc, di);
}

// アンインストールメイン
void DiUninstallMain(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	DiInitProductSimpleName(di);

	if (di->IsUserMode == false && di->IsAdmin == false)
	{
		// Admin 以外でシステムモードのアンインストールはできない
		MsgBoxEx(NULL, MB_ICONSTOP, _UU("DI_MSG_UNINSTALL_NOT_ADMIN"));
		return;
	}

	// 製品のファイル情報を適用する
	DiApplyProductFileList(di);

	// アンインストールダイアログ
	DiUninstallDlg(di);
}

// インストールメイン
void DiInstallMain(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	// インストール処理メイン
	if (di->IsVista)
	{
		// Windows Vista の場合の権限関係の処理
		if (di->IsHelper)
		{
			di->CanSelectSystem = true;
			di->CanSelectUser = false;
			di->WhyCanNotSelectUser = _UU("DI_WHY_CANT_SELECT_USER_1");
		}
		else
		{
			// 選択画面を表示する
			di->CanSelectSystem = false;
			di->WhyCanNotSelectSystem = _UU("DI_WHY_CANT_SELECT_SYSTEM_2");
			di->CanSelectUser = true;

			if (MsIsRemoteDesktopAvailable() == false)
			{
				// リモートデスクトップが無効なエディションではユーザーモードを
				// 強制する
				di->CanSelectSystem = false;
				di->WhyCanNotSelectSystem = _UU("DI_WHY_CANT_SELECT_SYSTEM_3");
				di->CanSelectUser = true;
			}
			else
			{
				bool b = true;

				// システムモードかユーザーモードかを選択させる
				if (DiShowVistaSelect(di, &b) == false)
				{
					// キャンセル
					return;
				}

				if (b == false)
				{
					// システムモードのインストーラが起動したのでこのプロセスは終了する
					return;
				}
			}
		}
	}
	else
	{
		// Windows Vista 以外の場合は現在のユーザー権限でインストール可能
		// なオプションが決定される
		di->CanSelectUser = true;
		di->CanSelectSystem = di->IsAdmin;
		if (di->CanSelectSystem == false)
		{
			// 権限が不足しているのでシステムモードではインストールできない
			di->WhyCanNotSelectSystem = _UU("DI_WHY_CANT_SELECT_SYSTEM_1");
		}
	}

	// ini ファイルの存在をチェック
	if (DiCheckSetupIni(di) == false)
	{
		MsgBox(di->hWndParent, MB_ICONEXCLAMATION, _UU("DI_BAD_STARTUP"));
		return;
	}

	// インストールする製品の選択
	if (DiSelectProduct(di) == false)
	{
		return;
	}

	DiInitProductSimpleName(di);

	if (di->Product == DI_PRODUCT_SERVER)
	{
		if (MsIsRemoteDesktopAvailable() == false)
		{
			// リモートデスクトップが無効な OS では Server を
			// システムモードでインストールできない
			di->CanSelectSystem = false;
			di->WhyCanNotSelectSystem = _UU("DI_WHY_CANT_SELECT_SYSTEM_3");
		}
	}

	// 製品のファイル情報を適用する
	DiApplyProductFileList(di);

	// デフォルトインストール先を決定する
	DiGenerateDefaultInstallDir(di);

#if 0
	// 情報の表示
	DiThanksDlg(di);
#endif

#if	0
	// 警告の表示
	if (di->Product == DI_PRODUCT_SERVER)
	{
		if (DiNoticeDlg(di) == false)
		{
			return;
		}
	}
#endif

	// 使用許諾契約書
	if (DiEulaDlg(di) == false)
	{
		return;
	}

	if (di->Product == DI_PRODUCT_SERVER)
	{
		// DeskServer の現在の状態を取得
		if (DiCheckServerStatus(di) == false)
		{
			return;
		}
	}

	if (di->FixedInstallDir == false)
	{
		if (di->IsUserMode == false)
		{
			UNINSTALL_INFO info;

			if (DiReadUninstallInfo(di->ProductSimpleName, &info))
			{
				// 既に登録されているレジストリ情報を読み込めた
				UniStrCpy(di->DefaultInstallDirSystem, sizeof(di->DefaultInstallDirSystem), info.InstallLocation);
			}
		}
	}

	// セットアップ種類の選択
	if (DiSelectTypeDlg(di) == false)
	{
		return;
	}

	if (di->IsTypical == false)
	{
		// メインダイアログ
		if (DiMainDlg(di) == false)
		{
			return;
		}
	}
	else
	{
		// 標準インストールの準備
		if (DiPrepareTypicalInstall(di) == false)
		{
			return;
		}
	}

	// インストール処理ダイアログ
	if (DiProcessDlg(di) == false)
	{
		return;
	}
}

// 製品シンプル名を初期化
void DiInitProductSimpleName(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	if (di->Product == DI_PRODUCT_SERVER)
	{
		di->ProductSimpleName = DI_PRODUCT_SERVER_NAME;
	}
	else
	{
		di->ProductSimpleName = DI_PRODUCT_CLIENT_NAME;
	}	
}

// アンインストール情報の削除
bool DiDeleteUninstallInfo(char *name)
{
	char key[MAX_PATH];
	// 引数チェック
	if (name == NULL)
	{
		return false;
	}

	Format(key, sizeof(key), "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s",
		name);

	if (MsRegDeleteKey(REG_LOCAL_MACHINE, key) == false)
	{
		return false;
	}

	return true;
}

// アンインストール情報の読み込み
bool DiReadUninstallInfo(char *name, UNINSTALL_INFO *info)
{
	char key[MAX_PATH];
	wchar_t *DisplayIcon, *InstallLocation, *DisplayName, *UninstallString;
	bool ret = false;
	// 引数チェック
	if (name == NULL || info == NULL)
	{
		return false;
	}

	Zero(info, sizeof(UNINSTALL_INFO));

	Format(key, sizeof(key), "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s",
		name);

	DisplayIcon = MsRegReadStrW(REG_LOCAL_MACHINE, key, "DisplayIcon");
	InstallLocation = MsRegReadStrW(REG_LOCAL_MACHINE, key, "InstallLocation");
	DisplayName = MsRegReadStrW(REG_LOCAL_MACHINE, key, "DisplayName");
	UninstallString = MsRegReadStrW(REG_LOCAL_MACHINE, key, "UninstallString");

	if (DisplayIcon && InstallLocation && DisplayName && UninstallString)
	{
		ret = true;

		UniStrCpy(info->DisplayIcon, sizeof(info->DisplayIcon), DisplayIcon);
		UniStrCpy(info->InstallLocation, sizeof(info->InstallLocation), InstallLocation);
		UniStrCpy(info->DisplayName, sizeof(info->DisplayName), DisplayName);
		UniStrCpy(info->UninstallString, sizeof(info->UninstallString), UninstallString);
	}

	Free(DisplayIcon);
	Free(InstallLocation);
	Free(DisplayName);
	Free(UninstallString);

	return ret;
}

// アンインストール情報の登録
bool DiWriteUninstallInfo(char *name, UNINSTALL_INFO *info)
{
	char key[MAX_PATH];
	// 引数チェック
	if (info == NULL || name == NULL)
	{
		return false;
	}

	Format(key, sizeof(key), "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s",
		name);

	if (MsRegWriteStrW(REG_LOCAL_MACHINE, key, "DisplayIcon", info->DisplayIcon) == false)
	{
		return false;
	}

	MsRegWriteStrW(REG_LOCAL_MACHINE, key, "InstallLocation", info->InstallLocation);
	MsRegWriteStrW(REG_LOCAL_MACHINE, key, "DisplayName", info->DisplayName);
	MsRegWriteStrW(REG_LOCAL_MACHINE, key, "UninstallString", info->UninstallString);

	return true;
}

// メインインストール処理
void DiProcessDlgOnTimer(HWND hWnd, DI *di)
{
	bool b;
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	b = DiProcessDlgOnMain(hWnd, di);

	if (b == false)
	{
		// インストール中断
		MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DI_INSTALL_ABORTED"), di->Title);
		EndDialog(hWnd, 0);
	}
	else
	{
		// インストール完了
		EndDialog(hWnd, 1);
	}
}
bool DiProcessDlgOnMain(HWND hWnd, DI *di)
{
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return false;
	}

	if (di->Product == DI_PRODUCT_SERVER)
	{
		// サービスを停止させる
		DiProcessDlgSetStatus(hWnd, _UU("DI_PROCESS_STOP_SVC"), INFINITE);

		if (DiStopServerService(hWnd, di) == false)
		{
			// サービス停止失敗
			return false;
		}
	}

	// ファイルのロック解除を待つ
	DiProcessDlgSetStatus(hWnd, _UU("DI_PROCESS_UNLOCK"), INFINITE);

	if (DiWaitForUnlockFile(hWnd, di) == false)
	{
		// ロックされたままであった
		return false;
	}
	else
	{
		UINT i;
		UINT total, current;

		// 合計ファイルサイズを取得
		total = 0;
		current = 0;
		for (i = 0;i < LIST_NUM(di->FilesList);i++)
		{
			DI_FILE *f = LIST_DATA(di->FilesList, i);

			total += f->FileSize;
		}

		// ファイルコピー開始
		for (i = 0;i < LIST_NUM(di->FilesList);i++)
		{
			DI_FILE *f = LIST_DATA(di->FilesList, i);
			wchar_t src[MAX_PATH];
			wchar_t dst[MAX_PATH];
			wchar_t msg[MAX_PATH * 2];
			UINT current_pos;
			UINT percent;

LABEL_RETRY:
			current_pos = current + f->FileSize / 2;
			percent = (UINT)((UINT64)current_pos * 100ULL / (UINT64)total);
			ConbinePathW(src, sizeof(src), MsGetExeDirNameW(), f->FileName);
			ConbinePathW(dst, sizeof(dst), di->InstallDir, f->FileName);

			UniFormat(msg, sizeof(msg), _UU("DI_PROCESS_FILECOPY"), dst);

			DiProcessDlgSetStatus(hWnd, msg, percent);

			// コピー実行
			if (FileCopyW(src, dst) == false)
			{
				// ファイルコピー失敗
				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_RETRYCANCEL,
					_UU("DI_FILE_COPY_ERROR"), dst) == IDCANCEL)
				{
					return false;
				}

				goto LABEL_RETRY;
			}

			current += f->FileSize;
		}

		DiProcessDlgSetStatus(hWnd, NULL, 100);

		if (di->Product == DI_PRODUCT_SERVER)
		{
			// Server サービスのインストール
			DiProcessDlgSetStatus(hWnd, _UU("DI_PROCESS_SERVICE"), INFINITE);

			if (DiInstallServerService(hWnd, di) == false)
			{
				return false;
			}

			DeskWaitReadyForDeskServerRpc(hWnd);
		}

		if (di->Product == DI_PRODUCT_SERVER)
		{
			if (di->IsUserMode == false)
			{
				// RDP ログオン画面の有効化 / 無効化
				MsSetRdpAllowLoginScreen(di->EnableRdpLogonScreen);

				MsRegWriteInt(REG_LOCAL_MACHINE, DI_REGKEY, "RDP1", 1);
			}
		}

		if (di->Product == DI_PRODUCT_SERVER)
		{
			if (di->IsUserMode)
			{
				bool old_strict = false;

LABEL_RETRY_EXEC:
				old_strict = DeskIsUacSettingStrict();

				// RUDP を Program Files 配下にインストールする
				if (DiInstallUrdpToProgramFiles(hWnd, di) == false)
				{
					// ヘルパーの起動に失敗した場合は再試行するか確認する
					if (MsgBox(hWnd, MB_ICONQUESTION | MB_RETRYCANCEL,
						_UU("DI_INSTALL_RUDP_ERROR")) == IDRETRY)
					{
						// 再試行
						goto LABEL_RETRY_EXEC;
					}
				}
				else
				{
					bool new_strict = DeskIsUacSettingStrict();

					if (old_strict && (new_strict == false))
					{
						// UAC の暗転設定が解除されたことを情報表示
						MsgBox(hWnd, MB_ICONINFORMATION, _UU("DI_INSTALL_RUDP_UAC_MITIGATE"));
					}
				}
			}
		}

		// ショートカットの作成
		DiProcessDlgSetStatus(hWnd, _UU("DI_PROCESS_LINK"), 0);
		DiCreateShortcuts(hWnd, di);

		if (di->IsUserMode == false)
		{
			// アンインストール情報の登録
			DiRegistUninstallInfo(hWnd, di);
		}

		// システム更新通知
		MsUpdateSystem();

		if (di->IsUserMode == false && di->Product == DI_PRODUCT_SERVER)
		{
			wchar_t username[MAX_PATH];

			StrToUni(username, sizeof(username), MsGetUserName());

			if (MsIsPasswordEmpty(username))
			{
				if (MsIsUseWelcomeLogin())
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("DI_EMPTY_PASSWORD_WARNING_1"));
				}
				else
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("DI_EMPTY_PASSWORD_WARNING_2"));
				}
			}
		}

		// プログラムの起動
		DiProcessDlgSetStatus(hWnd, _UU("DI_PROCESS_FINISH"), 0);
		DiExecuteProgram(hWnd, di);
	}

	return true;
}

// アンインストール情報の登録
void DiRegistUninstallInfo(HWND hWnd, DI *di)
{
	UNINSTALL_INFO info;
	wchar_t exe[MAX_PATH];
	wchar_t arg[MAX_PATH * 2];
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	Zero(&info, sizeof(info));

	if (di->Product == DI_PRODUCT_SERVER)
	{
		// Server
		ConbinePathW(info.DisplayIcon, sizeof(info.DisplayIcon),
			di->InstallDir, DI_FILENAME_DESKCONFIG);

		UniStrCpy(info.DisplayName, sizeof(info.DisplayName), _UU("DI_LINK_SERVER_DIRNAME"));
	}
	else
	{
		// Client
		ConbinePathW(info.DisplayIcon, sizeof(info.DisplayIcon),
			di->InstallDir, DI_FILENAME_DESKCLIENT);

		UniStrCpy(info.DisplayName, sizeof(info.DisplayName), _UU("DI_LINK_CLIENT_FILENAME"));
	}

	UniStrCpy(info.InstallLocation, sizeof(info.InstallLocation), di->InstallDir);

	DiGetUninstallExeAndArgs(di, exe, sizeof(exe), arg, sizeof(arg));

	UniFormat(info.UninstallString, sizeof(info.UninstallString),
		L"\"%s\" %s", exe, arg);

	if (DiWriteUninstallInfo(di->ProductSimpleName, &info) == false)
	{
		MsgBox(hWnd, MB_ICONSTOP, _UU("DI_REGIST_UNINSTALL_INFO_FAILED"));
	}
}

// プログラムの起動
void DiExecuteProgram(HWND hWnd, DI *di)
{
	wchar_t exe[MAX_PATH];
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	if (di->Product == DI_PRODUCT_SERVER)
	{
		// DeskConfig.exe の起動
		MsgBox(hWnd, MB_ICONINFORMATION, _UU("DI_MSG_EXEC_SERVER_CONFIG"));

		ConbinePathW(exe, sizeof(exe), di->InstallDir, DI_FILENAME_DESKCONFIG);

		if (MsExecuteW(exe, L"") == false)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DI_EXEC_FAILED"), exe);
		}
	}
	else
	{
		// DeskClient.exe の起動
		if (MsgBox(hWnd, MB_ICONINFORMATION | MB_YESNO, _UU("DI_MSG_EXEC_CLIENT_CONFIG")) == IDNO)
		{
			return;
		}

		ConbinePathW(exe, sizeof(exe), di->InstallDir, DI_FILENAME_DESKCLIENT);

		if (MsExecuteW(exe, L"") == false)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DI_EXEC_FAILED"), exe);
		}
	}
}

// アンインストール時に呼び出すべきプログラムを取得
void DiGetUninstallExeAndArgs(DI *di, wchar_t *exe, UINT exe_size, wchar_t *args, UINT args_size)
{
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	if (exe != NULL)
	{
		ConbinePathW(exe, exe_size, di->InstallDir,
			di->IsHelper ? DI_FILENAME_DESKHELPER : DI_FILENAME_DESKSETUP);
	}

	if (args != NULL)
	{
		UniFormat(args, args_size, L"/UNINSTALL:1 /PRODUCT:%u /USERMODE:%u /PATH:\"%s\"",
			di->Product, di->IsUserMode, di->InstallDir);
	}
}

// ショートカットの削除
void DiDeleteShortcuts(HWND hWnd, DI *di)
{
	wchar_t dir_name[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	DiGetShortcutDirName(di, dir_name, sizeof(dir_name));

	if (di->Product == DI_PRODUCT_SERVER)
	{
		// Server
		DiDeleteShortcut(di, 
			DI_DIR_PROGRAMS, dir_name,
			_UU("DI_LINK_SERVER_FILENAME"));

		// Server
		DiDeleteShortcut(di, 
			DI_DIR_STARTMENU, L"",
			_UU("DI_LINK_SERVER_FILENAME"));

		// Server
		DiDeleteShortcut(di, 
			DI_DIR_DESKTOP, L"",
			_UU("DI_LINK_SERVER_FILENAME"));

		// Server アンインストーラ
		DiDeleteShortcut(di,
			DI_DIR_PROGRAMS, dir_name,
			_UU("DI_LINK_SERVER_UNINSTALL_FILENAME"));
	}
	else
	{
		// Client
		DiDeleteShortcut(di,
			DI_DIR_PROGRAMS, dir_name,
			_UU("DI_LINK_CLIENT_FILENAME"));

		DiDeleteShortcut(di,
			DI_DIR_STARTMENU, L"",
			_UU("DI_LINK_CLIENT_FILENAME"));

		DiDeleteShortcut(di,
			DI_DIR_DESKTOP, L"",
			_UU("DI_LINK_CLIENT_FILENAME"));

		// Client アンインストーラ
		DiDeleteShortcut(di,
			DI_DIR_PROGRAMS, dir_name,
			_UU("DI_LINK_CLIENT_UNINSTALL_FILENAME"));
	}
}

// ショートカットの作成
void DiCreateShortcuts(HWND hWnd, DI *di)
{
	wchar_t dir_name[MAX_PATH];
	wchar_t *uninstaller_exe = DI_FILENAME_DESKSETUP;
	wchar_t uninst_args[MAX_PATH * 2];
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	if (di->IsHelper)
	{
		uninstaller_exe = DI_FILENAME_DESKHELPER;
	}

	DiGetShortcutDirName(di, dir_name, sizeof(dir_name));

	DiGetUninstallExeAndArgs(di, NULL, 0, uninst_args, sizeof(uninst_args));

	if (di->Product == DI_PRODUCT_SERVER)
	{
		// Server
		DiCreateShortcut(di, DI_FILENAME_DESKCONFIG, NULL,
			DI_DIR_PROGRAMS, dir_name,
			_UU("DI_LINK_SERVER_FILENAME"), _UU("DI_LINK_SERVER_COMMENT"));

#if	0
		DiCreateShortcut(di, DI_FILENAME_DESKCONFIG, NULL,
			DI_DIR_STARTMENU, L"",
			_UU("DI_LINK_SERVER_FILENAME"), _UU("DI_LINK_SERVER_COMMENT"));

		DiCreateShortcut(di, DI_FILENAME_DESKCONFIG, NULL,
			DI_DIR_DESKTOP, L"",
			_UU("DI_LINK_SERVER_FILENAME"), _UU("DI_LINK_SERVER_COMMENT"));
#endif

		// Server アンインストーラ
		DiCreateShortcut(di, uninstaller_exe, uninst_args,
			DI_DIR_PROGRAMS, dir_name,
			_UU("DI_LINK_SERVER_UNINSTALL_FILENAME"), _UU("DI_LINK_SERVER_UNINSTALL_COMMENT"));
	}
	else
	{
		// Client
		DiCreateShortcut(di, DI_FILENAME_DESKCLIENT, NULL,
			DI_DIR_PROGRAMS, dir_name,
			_UU("DI_LINK_CLIENT_FILENAME"), _UU("DI_LINK_CLIENT_COMMENT"));

		DiCreateShortcut(di, DI_FILENAME_DESKCLIENT, NULL,
			DI_DIR_STARTMENU, L"",
			_UU("DI_LINK_CLIENT_FILENAME"), _UU("DI_LINK_CLIENT_COMMENT"));

		DiCreateShortcut(di, DI_FILENAME_DESKCLIENT, NULL,
			DI_DIR_DESKTOP, L"",
			_UU("DI_LINK_CLIENT_FILENAME"), _UU("DI_LINK_CLIENT_COMMENT"));

		// Client アンインストーラ
		UniFormat(uninst_args, sizeof(uninst_args), L"/UNINSTALL:YES /PRODUCT:%u /USERMODE:%u /PATH:\"%s\"",
			di->Product, di->IsUserMode, di->InstallDir);
		DiCreateShortcut(di, uninstaller_exe, uninst_args,
			DI_DIR_PROGRAMS, dir_name,
			_UU("DI_LINK_CLIENT_UNINSTALL_FILENAME"), _UU("DI_LINK_CLIENT_UNINSTALL_COMMENT"));
	}
}

// ショートカットを作成するディレクトリ名を取得
void DiGetShortcutDirName(DI *di, wchar_t *dir_name, UINT dir_name_size)
{
	// 引数チェック
	if (di == NULL || dir_name == NULL)
	{
		return;
	}

	if (di->Product == DI_PRODUCT_SERVER)
	{
		UniStrCpy(dir_name, dir_name_size, _UU("DI_LINK_SERVER_DIRNAME"));
	}
	else
	{
		UniStrCpy(dir_name, dir_name_size, _UU("DI_LINK_CLIENT_DIRNAME"));
	}

	if (di->IsUserMode)
	{
		UniStrCat(dir_name, dir_name_size, _UU("DI_SHORTCUT_DIR_TAG_FOR_USER"));
	}
}

// ショートカット用ディレクトリ名の正規化
wchar_t *DiNormalizeShortcutDirName(DI *di, wchar_t *name)
{
	// 引数チェック
	if (di == NULL || name == NULL)
	{
		return NULL;
	}

	if (name == DI_DIR_STARTMENU)
	{
		if (di->IsUserMode)
		{
			return MsGetPersonalStartMenuDirW();
		}
		else
		{
			return MsGetCommonStartMenuDirW();
		}
	}
	else if (name == DI_DIR_PROGRAMS)
	{
		if (di->IsUserMode)
		{
			return MsGetPersonalProgramsDirW();
		}
		else
		{
			return MsGetCommonProgramsDirW();
		}
	}
	else if (name == DI_DIR_DESKTOP)
	{
		if (di->IsUserMode)
		{
			return MsGetPersonalDesktopDirW();
		}
		else
		{
			return MsGetCommonDesktopDirW();
		}
	}
	else
	{
		return name;
	}
}

// ショートカットファイルの削除
void DiDeleteShortcut(DI *di, wchar_t *parent_dir, wchar_t *dir_name, wchar_t *shortcut_name)
{
	wchar_t filename[MAX_PATH];
	wchar_t dirname[MAX_PATH];
	// 引数チェック
	if (di == NULL || parent_dir == NULL || shortcut_name == NULL)
	{
		return;
	}
	if (dir_name == NULL)
	{
		dir_name = L"";
	}

	parent_dir = DiNormalizeShortcutDirName(di, parent_dir);

	UniFormat(dirname, sizeof(dirname), L"%s\\%s", parent_dir, dir_name);
	if (MsUniIsDirectory(dirname) == false)
	{
		return;
	}

	UniFormat(filename, sizeof(filename), L"%s\\%s.lnk", dirname, shortcut_name);

	MsUniFileDelete(filename);

	if (UniIsEmptyStr(dir_name) == false)
	{
		MsUniDirectoryDelete(dirname);
	}
}

// ショートカットファイルの作成
bool DiCreateShortcut(DI *di, wchar_t *exe, wchar_t *args, wchar_t *parent_dir, wchar_t *dir_name, wchar_t *shortcut_name, wchar_t *description)
{
	wchar_t w_filename[MAX_PATH];
	wchar_t w_target[MAX_PATH];
	wchar_t w_args[MAX_PATH];
	wchar_t w_workdir[MAX_PATH];
	wchar_t dirname[MAX_PATH];
	wchar_t exe_fullpath[MAX_PATH];
	// 引数チェック
	if (di == NULL || exe == NULL || parent_dir == NULL || shortcut_name == NULL)
	{
		return false;
	}
	if (dir_name == NULL)
	{
		dir_name = L"";
	}
	if (args == NULL)
	{
		args = L"";
	}
	if (description == NULL)
	{
		description = L"";
	}

	parent_dir = DiNormalizeShortcutDirName(di, parent_dir);

	UniFormat(dirname, sizeof(dirname), L"%s\\%s", parent_dir, dir_name);
	MsUniMakeDirEx(dirname);
	if (MsUniIsDirectory(dirname) == false)
	{
		return false;
	}

	UniFormat(w_filename, sizeof(w_filename), L"%s\\%s.lnk", dirname, shortcut_name);

	ConbinePathW(exe_fullpath, sizeof(exe_fullpath), di->InstallDir, exe);
	UniStrCpy(w_target, sizeof(w_target), exe_fullpath);
	UniStrCpy(w_args, sizeof(w_args), args);
	UniStrCpy(w_workdir, sizeof(w_workdir), di->InstallDir);

	if (CreateLink(w_filename, w_target, w_workdir, w_args,
		description, w_target, 0) == false)
	{
		return false;
	}

	return true;
}

// インストール先ファイルのロックが解除されるのを待つ
bool DiWaitForUnlockFile(HWND hWnd, DI *di)
{
	UINT64 start_time;
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	while (true)
	{
		bool b = true;
		wchar_t list[MAX_PATH * 10];

		start_time = 0;

		while (start_time == 0 || ((start_time + (UINT64)DI_FILE_UNLOCK_TIMEOUT) > Tick64()))
		{
			if (start_time == 0)
			{
				start_time = Tick64();
			}

			if (DiIsAnyFileLocked(di, list, sizeof(list)) == false)
			{
				b = false;
				break;
			}

			DoEvents(hWnd);
			SleepThread(256);
		}

		if (b == false)
		{
			return true;
		}

		if (MsgBoxEx(hWnd, MB_ICONINFORMATION | MB_RETRYCANCEL, _UU("DI_FILE_LOCKED"), list) == IDCANCEL)
		{
			return false;
		}
	}
}

// 指定されたファイルがインストーラのための特別なファイルかどうか取得する
bool DiIsFileSpecialForInstaller(DI *di, DI_FILE *f)
{
	// 引数チェック
	if (di == NULL || f == NULL)
	{
		return false;
	}

	if (UniStrCmpi(f->FileName, DI_FILENAME_DESKSETUP) == 0 ||
		UniStrCmpi(f->FileName, DI_FILENAME_DESKHELPER) == 0 ||
		UniStrCmpi(f->FileName, DI_FILENAME_HAMCORE) == 0)
	{
		return true;
	}

	return false;
}

// 1 つ以上のインストール先のファイルがロックされているかどうか調べる
bool DiIsAnyFileLocked(DI *di, wchar_t *locked_list, UINT locked_list_size)
{
	UINT i;
	bool ret = false;
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	UniStrCpy(locked_list, locked_list_size, L"");

	for (i = 0;i < LIST_NUM(di->FilesList);i++)
	{
		DI_FILE *f = LIST_DATA(di->FilesList, i);
		wchar_t tmp[MAX_PATH];

		ConbinePathW(tmp, sizeof(tmp), di->InstallDir, f->FileName);

		if (IsFileExistsW(tmp))
		{
			if (MsIsFileLockedW(tmp))
			{
				if (di->UninstallMode == false || DiIsFileSpecialForInstaller(di, f) == false)
				{
					ret = true;

					UniStrCat(locked_list, locked_list_size, tmp);
					UniStrCat(locked_list, locked_list_size, L"\r\n");
				}
			}
		}
	}

	return ret;
}

// Server サービスのアンインストール
bool DiUninstallServerService(HWND hWnd, DI *di)
{
	UINT i;
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	if (di->IsUserMode)
	{
		// ユーザーモードサービスが動作していれば停止させる
		DsStopUsermodeService();
		SleepThread(512);
	}

	for (i = 0;i < LIST_NUM(di->FilesList);i++)
	{
		DI_FILE *f = LIST_DATA(di->FilesList, i);

		if (f->RegistAsService)
		{
			if (di->IsUserMode == false)
			{
				// システムサービスのアンインストール
				if (DiUninstallFileAsSystemService(hWnd, di, f) == false)
				{
					// アンインストール失敗
					return false;
				}
			}
			else
			{
				// ユーザーサービスのアンインストール
				if (DiUninstallFileAsUserService(hWnd, di, f) == false)
				{
					// アンインストール失敗
					return false;
				}
			}
		}
	}

	return true;
}

// Server サービスのインストール
bool DiInstallServerService(HWND hWnd, DI *di)
{
	UINT i;
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(di->FilesList);i++)
	{
		DI_FILE *f = LIST_DATA(di->FilesList, i);

		if (f->RegistAsService)
		{
			if (di->IsUserMode == false)
			{
				// システムサービスとしてインストール
				if (DiInstallFileAsSystemService(hWnd, di, f) == false)
				{
					return false;
				}
			}
			else
			{
				// ユーザーサービスとしてインストール
				if (DiInstallFileAsUserService(hWnd, di, f) == false)
				{
					return false;
				}
			}
		}
	}

	return true;
}

// ファイルをユーザーサービスとしてアンインストールする
bool DiUninstallFileAsUserService(HWND hWnd, DI *di, DI_FILE *f)
{
	wchar_t dst[MAX_PATH];
	char svc_title[MAX_PATH];
	char svc_descript[MAX_PATH];
	wchar_t filename[MAX_PATH];
	LIST *o;
	UINT i;
	// 引数チェック
	if (di == NULL || f == NULL)
	{
		return false;
	}

	ConbinePathW(dst, sizeof(dst), di->InstallDir, f->FileName);

	Format(svc_title, sizeof(svc_title), SVC_TITLE, f->ServiceName);
	Format(svc_descript, sizeof(svc_descript), SVC_DESCRIPT, f->ServiceName);

	ConbinePathW(filename, sizeof(filename), MsGetPersonalStartupDirW(), _UU(svc_title));
	UniStrCat(filename, sizeof(filename), L".lnk");

	// プロセスを強制終了
	o = MsGetProcessList();
	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);

		if (UniStrCmpi(p->ExeFilenameW, dst) == 0)
		{
			MsKillProcess(p->ProcessId);
		}
	}
	MsFreeProcessList(o);

	// ショートカットを削除
	if (IsFileExistsW(filename) == false)
	{
		return true;
	}

	if (FileDeleteW(filename) == false)
	{
		return false;
	}

	return true;
}

// ファイルをユーザーサービスとしてインストールする
bool DiInstallFileAsUserService(HWND hWnd, DI *di, DI_FILE *f)
{
	wchar_t dst[MAX_PATH];
	char svc_title[MAX_PATH];
	char svc_descript[MAX_PATH];
	wchar_t filename[MAX_PATH];
	wchar_t w_filename[MAX_PATH];
	wchar_t w_target[MAX_PATH];
	wchar_t w_workdir[MAX_PATH];
	// 引数チェック
	if (di == NULL || f == NULL)
	{
		return false;
	}

	ConbinePathW(dst, sizeof(dst), di->InstallDir, f->FileName);

	Format(svc_title, sizeof(svc_title), SVC_TITLE, f->ServiceName);
	Format(svc_descript, sizeof(svc_descript), SVC_DESCRIPT, f->ServiceName);

	ConbinePathW(filename, sizeof(filename), MsGetPersonalStartupDirW(), _UU(svc_title));
	UniStrCat(filename, sizeof(filename), L".lnk");

	MakeDirEx(MsGetPersonalStartupDir());

	// ショートカットを作成
	UniStrCpy(w_filename, sizeof(w_filename), filename);
	UniStrCpy(w_target, sizeof(w_target), dst);
	UniStrCpy(w_workdir, sizeof(w_workdir), di->InstallDir);

	if (CreateLink(w_filename, w_target, w_workdir, L"/usermode", _UU(svc_descript),
		w_target, 0) == false)
	{
		MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DI_SVC_INSTALL_USERMODE_FAILED"),
			f->ServiceName, filename);
		return false;
	}

	// サービスを起動
	if (MsExecuteW(dst, L"/usermode") == false)
	{
		MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DI_EXEC_FAILED"), dst);
		return false;
	}

	return true;
}

// ファイルをシステムサービスとしてアンインストールする
bool DiUninstallFileAsSystemService(HWND hWnd, DI *di, DI_FILE *f)
{
	wchar_t dst[MAX_PATH];
	// 引数チェック
	if (di == NULL || f == NULL)
	{
		return false;
	}

	ConbinePathW(dst, sizeof(dst), di->InstallDir, f->FileName);

	if (MsIsServiceInstalled(f->ServiceName) == false)
	{
		return true;
	}

	MsStopService(f->ServiceName);

	if (MsUninstallService(f->ServiceName) == false)
	{
		return false;
	}

	return true;
}

// ファイルをシステムサービスとしてインストールする
bool DiInstallFileAsSystemService(HWND hWnd, DI *di, DI_FILE *f)
{
	wchar_t dst[MAX_PATH];
	char svc_title[MAX_PATH];
	char svc_descript[MAX_PATH];
	wchar_t cmdline[MAX_PATH * 2];
	UINT error_code;
	// 引数チェック
	if (di == NULL || f == NULL)
	{
		return false;
	}

	ConbinePathW(dst, sizeof(dst), di->InstallDir, f->FileName);

	if (MsIsServiceInstalled(f->ServiceName))
	{
		MsStopService(f->ServiceName);

		if (MsUninstallService(f->ServiceName) == false)
		{
			// すでにサービスがインストールされていてアンインストールに失敗した
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DI_ALREADY_SVC_UNINSTALL_FAILED"), f->ServiceName);
			return false;
		}
	}

	Format(svc_title, sizeof(svc_title), SVC_TITLE, f->ServiceName);
	Format(svc_descript, sizeof(svc_descript), SVC_DESCRIPT, f->ServiceName);

	UniFormat(cmdline, sizeof(cmdline), L"\"%s\" /service", dst);

	// サービスをインストールする
	if (MsInstallServiceExW(f->ServiceName, _UU(svc_title), _UU(svc_descript), cmdline, &error_code) == false)
	{
		// サービスのインストールに失敗した
		MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DI_SVC_INSTALL_FAILED"), f->ServiceName, error_code);
		return false;
	}

	// サービスを起動する
	if (MsStartServiceEx(f->ServiceName, &error_code) == false)
	{
		// サービスの起動に失敗した
		MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DI_SVC_START_FAILED"), f->ServiceName, error_code);
		return false;
	}

	return true;
}

// Server サービスの停止
bool DiStopServerService(HWND hWnd, DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	if (di->IsUserMode)
	{
		DsStopUsermodeService();
	}
	else
	{
		UINT i;

		for (i = 0;i < LIST_NUM(di->FilesList);i++)
		{
			DI_FILE *f = LIST_DATA(di->FilesList, i);

			if (f->RegistAsService)
			{
				if (MsIsServiceInstalled(f->ServiceName) && MsIsServiceRunning(f->ServiceName))
				{
					if (MsStopService(f->ServiceName) == false)
					{
						MsgBox(hWnd, MB_ICONSTOP, _UU("DI_STOP_SVC_ERROR"));
						return false;
					}
				}
			}
		}
	}

	return true;
}

// 初期化
void DiProcessDlgInit(HWND hWnd, DI *di)
{
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	SetRange(hWnd, S_STATUS, 0, 100);
	DiProcessDlgSetStatus(hWnd, _UU("DI_PROCESS_INIT"), 0);

	SetIcon(hWnd, 0, ICO_SETUP);
	SetIcon(hWnd, S_ICON, di->Icon);
	FormatText(hWnd, 0, di->Title);
	FormatText(hWnd, S_INFO, di->Title);
	DisableClose(hWnd);

	SetTimer(hWnd, 1, 512, NULL);
}

// ステータスの表示
void DiProcessDlgSetStatus(HWND hWnd, wchar_t *str, UINT pos)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (str != NULL)
	{
		SetText(hWnd, S_STATUS, str);
	}

	if (pos != INFINITE)
	{
		SetPos(hWnd, P_PROGRESS, pos);
	}

	Refresh(DlgItem(hWnd, S_STATUS));
	Refresh(DlgItem(hWnd, P_PROGRESS));
}

// インストール処理ダイアログプロシージャ
UINT DiProcessDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DI *di = (DI *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DiProcessDlgInit(hWnd, di);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			DiProcessDlgOnTimer(hWnd, di);
			break;
		}
		break;

	case WM_CLOSE:
		return 1;
	}

	return 0;
}

// インストール処理ダイアログ
bool DiProcessDlg(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	if (Dialog(di->hWndParent, D_DI_PROCESS, DiProcessDlgProc, di) == 0)
	{
		return false;
	}

	return true;
}

// 標準インストールの準備
bool DiPrepareTypicalInstall(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	if (di->CanSelectSystem)
	{
		di->IsUserMode = false;
		UniStrCpy(di->InstallDir, sizeof(di->InstallDir), di->DefaultInstallDirSystem);
	}
	else
	{
		di->IsUserMode = true;
		UniStrCpy(di->InstallDir, sizeof(di->InstallDir), di->DefaultInstallDirUser);
	}

	MakeDirExW(di->InstallDir);

	if (MsIsDirectoryW(di->InstallDir) == false)
	{
		// ディレクトリ作成失敗
		MsgBoxEx(di->hWndParent, MB_ICONEXCLAMATION, _UU("DI_MAKEDIR_FAILED"), di->InstallDir);
		return false;
	}

	return true;
}

// ダイアログプロシージャ
UINT DiSelectTypeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DI *di = (DI *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, S_INFO, di->Title);
		DlgFont(hWnd, C_TYPICAL, 0, true);
		Check(hWnd, C_TYPICAL, true);
		SetIcon(hWnd, 0, ICO_SETUP);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			di->IsTypical = IsChecked(hWnd, C_TYPICAL);
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

// 種類選択ダイアログ
bool DiSelectTypeDlg(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	if (Dialog(di->hWndParent, D_DI_SELECT_TYPE, DiSelectTypeDlgProc, di) == 0)
	{
		return false;
	}

	return true;
}

// 初期化
void DiMainDlgInit(HWND hWnd, DI *di)
{
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SETUP);
	SetIcon(hWnd, S_ICON, di->Icon);
	FormatText(hWnd, 0, di->Title);
	FormatText(hWnd, S_INFO, di->Title);

	if (di->CanSelectSystem)
	{
		DlgFont(hWnd, C_SYSTEM, 0, true);
		FormatText(hWnd, C_SYSTEM, di->Title, _UU("DI_RECOMMEND"));
		FormatText(hWnd, C_USER, di->Title, L"");

		Check(hWnd, C_SYSTEM, true);
		Check(hWnd, C_USER, false);
	}
	else
	{
		DlgFont(hWnd, C_USER, 0, true);
		DlgFont(hWnd, C_USER, 0, true);
		FormatText(hWnd, C_USER, di->Title, _UU("DI_RECOMMEND"));
		FormatText(hWnd, C_SYSTEM, di->Title, L"");

		Check(hWnd, C_SYSTEM, false);
		Check(hWnd, C_USER, true);
	}

	if (di->Product == DI_PRODUCT_SERVER)
	{
		SetText(hWnd, S_SYSTEM, _UU("DI_SYSTEM_SERVER"));
		SetText(hWnd, S_USER, _UU("DI_USER_SERVER"));
	}
	else
	{
		SetText(hWnd, S_SYSTEM, _UU("DI_SYSTEM_CLIENT"));
		SetText(hWnd, S_USER, _UU("DI_USER_CLIENT"));
	}

	FormatText(hWnd, S_USER, MsGetUserNameW());

	if (di->FixedInstallDir)
	{
		// インストール先固定
		Disable(hWnd, E_DIR);
		Disable(hWnd, B_RESTORE);
		SetText(hWnd, S_DIR, _UU("DI_FIXED_DIR"));
	}

	FormatText(hWnd, S_DIR, di->Title);

	SetShow(hWnd, C_SECURITY, di->Product == DI_PRODUCT_SERVER);

	Check(hWnd, C_SECURITY, di->EnableRdpLogonScreen);

	DiMainDlgUpdate(hWnd, di, true);
}

// コントロール更新
void DiMainDlgUpdate(HWND hWnd, DI *di, bool select_clicked)
{
	bool b = true;
	wchar_t tmp[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	if (di->CanSelectSystem == false)
	{
		if (IsChecked(hWnd, C_SYSTEM))
		{
			MsgBox(hWnd, MB_ICONEXCLAMATION, di->WhyCanNotSelectSystem);

			Check(hWnd, C_USER, true);
			Check(hWnd, C_SYSTEM, false);
			Focus(hWnd, C_USER);
		}
	}
	if (di->CanSelectUser == false)
	{
		if (IsChecked(hWnd, C_USER))
		{
			MsgBox(hWnd, MB_ICONEXCLAMATION, di->WhyCanNotSelectUser);
	
			Check(hWnd, C_SYSTEM, true);
			Check(hWnd, C_USER, false);
			Focus(hWnd, C_SYSTEM);
		}
	}

	SetEnable(hWnd, C_SECURITY, IsChecked(hWnd, C_SYSTEM) && di->Product == DI_PRODUCT_SERVER);

	GetTxt(hWnd, E_DIR, tmp, sizeof(tmp));
	DiNormalizeDirName(tmp, sizeof(tmp), tmp);
	if (UniIsEmptyStr(tmp))
	{
		b = false;
	}

	SetEnable(hWnd, IDOK, b);

	if (select_clicked)
	{
		DiMainDlgOnRestore(hWnd, di);
	}
}

// OK ボタン
void DiMainDlgOnOk(HWND hWnd, DI *di)
{
	wchar_t tmp[MAX_PATH];
	bool is_usermode;
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	is_usermode = IsChecked(hWnd, C_USER);

	di->EnableRdpLogonScreen = IsChecked(hWnd, C_SECURITY);

	GetTxt(hWnd, E_DIR, tmp, sizeof(tmp));
	DiNormalizeDirName(tmp, sizeof(tmp), tmp);

	if (di->FixedInstallDir)
	{
		if (is_usermode == false)
		{
			UniStrCpy(tmp, sizeof(tmp), di->DefaultInstallDirSystem);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), di->DefaultInstallDirUser);
		}
	}

	if (UniIsEmptyStr(tmp))
	{
		return;
	}

	if (is_usermode == false)
	{
		if (MsIsLocalDriveW(tmp) == false)
		{
			// ローカルドライブでない
			MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("DI_MUST_LOCAL_DRIVE"));

			FocusEx(hWnd, E_DIR);
			return;
		}
	}

	// ディリレクトリの作成
	MakeDirExW(tmp);
	if (MsIsDirectoryW(tmp) == false)
	{
		// ディレクトリ作成失敗
		MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("DI_MAKEDIR_FAILED"), tmp);

		FocusEx(hWnd, E_DIR);
		return;
	}

	di->IsUserMode = is_usermode;
	UniStrCpy(di->InstallDir, sizeof(di->InstallDir), tmp);

	EndDialog(hWnd, 1);
}

// 戻す
void DiMainDlgOnRestore(HWND hWnd, DI *di)
{
	wchar_t *dir = NULL;
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	if (IsChecked(hWnd, C_SYSTEM))
	{
		dir = di->DefaultInstallDirSystem;
	}
	else
	{
		dir = di->DefaultInstallDirUser;
	}

	SetText(hWnd, E_DIR, dir);
}

// ダイアログプロシージャ
UINT DiMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DI *di = (DI *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DiMainDlgInit(hWnd, di);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_DIR:
			if (HIWORD(wParam) == EN_KILLFOCUS)
			{
				wchar_t tmp[MAX_PATH];

				GetTxt(hWnd, E_DIR, tmp, sizeof(tmp));
				DiNormalizeDirName(tmp, sizeof(tmp), tmp);
				SetText(hWnd, E_DIR, tmp);
			}

			DiMainDlgUpdate(hWnd, di, false);
			break;
		}

		switch (wParam)
		{
		case C_SYSTEM:
		case C_USER:
			if (di->CanSelectSystem && (wParam == C_USER))
			{
				if (di->Product == DI_PRODUCT_SERVER)
				{
					// 警告は一回しか表示しないようにする カーソルで項目選択したときメッセージがたくさん届く対策 2007.08.27 sugiyama
					static bool warning_not_shown = true;
					if(warning_not_shown)
					{
						warning_not_shown = false;
						if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("DI_CUSTOM_SELECT_WARNING")) == IDNO)
						{
							Check(hWnd, C_SYSTEM, true);
							Check(hWnd, C_USER, false);
							Focus(hWnd, C_SYSTEM);
						}
					}
				}
			}
			DiMainDlgUpdate(hWnd, di, true);
			break;

		case B_RESTORE:
			DiMainDlgOnRestore(hWnd, di);
			FocusEx(hWnd, E_DIR);
			break;

		case IDOK:
			DiMainDlgOnOk(hWnd, di);
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

// メインダイアログ
bool DiMainDlg(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	if (Dialog(di->hWndParent, D_DI_MAIN, DiMainDlgProc, di) == 0)
	{
		return false;
	}

	return true;
}

// ディレクトリ名を正規化する
void DiNormalizeDirName(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t tmp[MAX_PATH];

	NormalizePathW(tmp, sizeof(tmp), src);

	if (UniStartWith(tmp, L"\""))
	{
		UniStrCpy(dst, size, tmp + 1);
	}
	else
	{
		UniStrCpy(dst, size, tmp);
	}

	if (UniEndWith(dst, L"\""))
	{
		dst[UniStrLen(dst) - 1] = 0;
	}

	UniTrim(dst);
}

// DeskServer の現在の状態を取得
bool DiCheckServerStatus(DI *di)
{
	DS_INFO info;
	UINT ret;
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

LABEL_RETRY:
	ret = DsGetServiceInfo(&info);
	if (ret == ERR_NO_ERROR)
	{
		// 接続が完了してしまった
		if (info.Build > DESK_BUILD)
		{
			// より新しいバージョンがすでに動作している
			MsgBox(di->hWndParent, MB_ICONINFORMATION, _UU("DI_SERVER_MORE_NEWER_INSTALLED"));
			return false;
		}

		if ((!(!(info.ForceDisableShare))) != (!(!(di->ForceShareDisabled))))
		{
			// インストールされている共有モード版が異なる
			if (di->ForceShareDisabled)
			{
				if (MsgBox(di->hWndParent, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("DI_SERVER_DIFF_FORCE_SHARE_1")) == IDNO)
				{
					return false;
				}
			}
			else
			{
				MsgBox(di->hWndParent, MB_ICONERROR, _UU("DI_SERVER_DIFF_FORCE_SHARE_2"));
				return false;
			}
		}

		if (info.IsUserMode)
		{
			// ユーザーモードで動作している場合
			if (di->CanSelectUser == false)
			{
				// システムモードでインストーラを起動している
				MsgBox(di->hWndParent, MB_ICONINFORMATION, _UU("DI_WHY_CANT_SELECT_SYSTEM_4"));
				return false;
			}
			// 上書きインストール時はユーザーモードのみ選択可能にする
			di->CanSelectSystem = false;
			di->WhyCanNotSelectSystem = _UU("DI_WHY_CANT_SELECT_SYSTEM_4");
			if (StrCmpi(info.UserName, MsGetUserNameEx()) != 0)
			{
				// ユーザーモードで起動しており現在のユーザーと異なる
				MsgBoxEx(di->hWndParent, MB_ICONINFORMATION, _UU("DI_SERVER_USERMODE_DIFF_USER"), info.UserNameW);
				return false;
			}

			UniStrCpy(di->DefaultInstallDirUser, sizeof(di->DefaultInstallDirUser),
				info.ExeDirW);

			di->FixedInstallDir = true;
		}
		else
		{
			// システムモードで動作している場合
			if (di->CanSelectSystem == false)
			{
				MsgBox(di->hWndParent, MB_ICONINFORMATION, _UU("DI_SERVER_IS_SYSTEM_MODE"));
				return false;
			}
			// システムモードのみ選択可能にする
			di->CanSelectUser = false;
			di->WhyCanNotSelectUser = _UU("DI_WHY_CANT_SELECT_USER_2");

			UniStrCpy(di->DefaultInstallDirSystem, sizeof(di->DefaultInstallDirSystem),
				info.ExeDirW);

			di->FixedInstallDir = true;
		}

		return true;
	}
	else if (ret == ERR_DESK_RPC_PROTOCOL_ERROR)
	{
		// ポート 9823 が不正である
		if (MsgBox(di->hWndParent, MB_ICONEXCLAMATION | MB_RETRYCANCEL, _UU("DI_SERVER_9823_ERROR")) == IDCANCEL)
		{
			return false;
		}

		goto LABEL_RETRY;
	}
	else
	{
		// その他のエラーが発生した場合は正常である
		return true;
	}
}

// ダイアログ初期化
void DiEulaDlgInit(HWND hWnd, DI *di)
{
	BUF *b;
	char c;
	UINT size;
	wchar_t *str;
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return;
	}

	b = ReadDump("|Eula.txt");
	if (b == NULL)
	{
		MsTerminateProcess();
	}

	SeekBuf(b, b->Size, 0);
	c = 0;
	WriteBuf(b, &c, 1);

	size = CalcUtf8ToUni(b->Buf, b->Size - 1);
	str = ZeroMalloc(size);
	Utf8ToUni(str, size, b->Buf, b->Size - 1);

	SetText(hWnd, E_EULA, str);

	Free(str);
	FreeBuf(b);

	FormatText(hWnd, 0, di->Title);
	FormatText(hWnd, S_INFO, di->Title);

	Focus(hWnd, E_EULA);
	SendMsg(hWnd, E_EULA, EM_SETSEL, 0, 0);

	SetIcon(hWnd, 0, ICO_SETUP);
}

// プロシージャ
UINT DiEulaDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DI *di = (DI *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DiEulaDlgInit(hWnd, di);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			EndDialog(hWnd, 1);
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

// 使用許諾契約書
bool DiEulaDlg(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	if (Dialog(di->hWndParent, D_DI_EULA, DiEulaDlgProc, di) == 0)
	{
		return false;
	}

	return true;
}

// 謝辞ダイアログ
void DiThanksDlg(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	if (_GETLANG() == 0)
	{
		Dialog(di->hWndParent, D_DI_THANKS, DiThanksDlgProc, di);
	}
	else
	{
		Dialog(di->hWndParent, D_DI_THANKS_EN, DiThanksDlgProc, di);
	}
}

// 謝辞ダイアログプロシージャ
UINT DiThanksDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DI *di = (DI *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_INFORMATION);
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

// 注意書きダイアログ
bool DiNoticeDlg(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	if (Dialog(di->hWndParent, D_DI_NOTICE, DiNoticeDlgProc, di) == 0)
	{
		return false;
	}

	return true;
}

// 注意書きダイアログプロシージャ
UINT DiNoticeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DI *di = (DI *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_LOG);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			EndDialog(hWnd, 1);
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

// デフォルトインストール先を決定する
void DiGenerateDefaultInstallDir(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	if (di->Product == DI_PRODUCT_SERVER)
	{
		// システムの場合: Program Files
		ConbinePathW(di->DefaultInstallDirSystem, sizeof(di->DefaultInstallDirSystem),
			MsGetProgramFilesDirW(), L"Desktop VPN Server");

		// ユーザーの場合: Application Data
		ConbinePathW(di->DefaultInstallDirUser, sizeof(di->DefaultInstallDirUser),
			MsGetPersonalAppDataDirW(), L"Desktop VPN Server");
	}
	else
	{
		// システムの場合: Program Files
		ConbinePathW(di->DefaultInstallDirSystem, sizeof(di->DefaultInstallDirSystem),
			MsGetProgramFilesDirW(), L"Desktop VPN Client");

		// ユーザーの場合: Application Data
		ConbinePathW(di->DefaultInstallDirUser, sizeof(di->DefaultInstallDirUser),
			MsGetPersonalAppDataDirW(), L"Desktop VPN Client");
	}
}

// 製品のファイルリストを適用する
void DiApplyProductFileList(DI *di)
{
	UINT i;
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	di->FilesList = NewListFast(NULL);

	if (di->Product == DI_PRODUCT_SERVER)
	{
		// ThinSvr.exe の種類
		wchar_t exe[MAX_PATH];

		CombinePathW(exe, sizeof(exe), MsGetExeDirNameW(), L"thinsvr.exe");
		di->ForceShareDisabled = DsCheckShareDisableSignature(exe);

		// Server
		for (i = 0;i < num_di_files_for_desk_server;i++)
		{
			DI_FILE *f = &di_files_for_desk_server[i];

			Add(di->FilesList, f);
		}

		// タイトル
		di->Title = _UU("DI_TITLE_SERVER");

		if (di->ForceShareDisabled)
		{
			// 共有機能無効版
			di->Title = _UU("DI_TITLE_SERVER2");
		}

		// アイコン
		di->Icon = ICO_DESKSERVER;
	}
	else
	{
		// Client
		for (i = 0;i < num_di_files_for_desk_client;i++)
		{
			DI_FILE *f = &di_files_for_desk_client[i];

			Add(di->FilesList, f);
		}

		// タイトル
		di->Title = _UU("DI_TITLE_CLIENT");

		// アイコン
		di->Icon = ICO_THINCLIENT;
	}
}

// ファイルリストを解放する
void DiFreeProductFileList(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return;
	}

	if (di->FilesList != NULL)
	{
		ReleaseList(di->FilesList);
		di->FilesList = NULL;
	}
}

// ini ファイルが存在するかどうかチェックする
bool DiCheckSetupIni(DI *di)
{
	LIST *o;
	BUF *b;
	bool ret;
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	b = ReadDumpW(DI_FILENAME_SETUPINI);
	if (b == NULL)
	{
		return false;
	}

	o = ReadIni(b);

	ret = IniIntValue(o, "IsSetupSource") == 0 ? false : true;

	FreeIni(o);

	FreeBuf(b);

	return ret;
}

// インストールする製品の選択
bool DiSelectProduct(DI *di)
{
	bool has_server = false;
	bool has_client = false;
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	has_server = DiCheckFilesExists(di_files_for_desk_server, num_di_files_for_desk_server);
	has_client = DiCheckFilesExists(di_files_for_desk_client, num_di_files_for_desk_client);

	if (has_server && has_client)
	{
		// 両方の製品のファイルがあるのでインストールする製品を選択する
		if (DiSelectProductDlg(di) == false)
		{
			return false;
		}
	}
	else
	{
		if (has_server)
		{
			// Server
			di->Product = DI_PRODUCT_SERVER;
		}

		if (has_client)
		{
			// Client
			di->Product = DI_PRODUCT_CLIENT;
		}
	}

	if (di->Product == 0)
	{
		// 製品が不明
		MsgBox(di->hWndParent, MB_ICONEXCLAMATION, _UU("DI_BAD_STARTUP"));
		return false;
	}

	return true;
}

// コントロール更新
void DiSelectProductDlgUpdate(HWND hWnd)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SetEnable(hWnd, IDOK, IsChecked(hWnd, C_SERVER) || IsChecked(hWnd, C_CLIENT));
}

// ダイアログプロシージャ
UINT DiSelectProductDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DI *di = (DI *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_SETUP);
		DlgFont(hWnd, C_SERVER, 0, true);
		DlgFont(hWnd, C_CLIENT, 0, true);
		DiSelectProductDlgUpdate(hWnd);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case C_SERVER:
		case C_CLIENT:
			DiSelectProductDlgUpdate(hWnd);
			break;

		case IDOK:
			if (IsChecked(hWnd, C_CLIENT))
			{
				di->Product = DI_PRODUCT_CLIENT;
			}
			else
			{
				di->Product = DI_PRODUCT_SERVER;
			}

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

// 製品選択ダイアログ
bool DiSelectProductDlg(DI *di)
{
	// 引数チェック
	if (di == NULL)
	{
		return false;
	}

	if (Dialog(di->hWndParent, D_DI_SELECT_PRODUCT, DiSelectProductDlgProc, di) == 0)
	{
		return false;
	}

	return true;
}

// ファイルの存在をチェックする
bool DiCheckFilesExists(DI_FILE *files, UINT num)
{
	UINT i;
	// 引数チェック
	if (files == NULL)
	{
		return false;
	}

	for (i = 0;i < num;i++)
	{
		DI_FILE *f = &files[i];
		wchar_t tmp[MAX_PATH];
		IO *io;

		ConbinePathW(tmp, sizeof(tmp), MsGetExeDirNameW(), f->FileName);

		if (IsFileExistsW(tmp) == false)
		{
			return false;
		}

		io = FileOpenW(tmp, false);
		if (io == NULL)
		{
			return false;
		}

		f->FileSize = FileSize(io);

		FileClose(io);
	}

	return true;
}

// ダイアログ初期化
void DiVistaSelectDlgInit(HWND hWnd, DI_VISTA_SELECT *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SETUP);

	FormatText(hWnd, S_SYSTEM, MsGetUserNameW());
	FormatText(hWnd, S_USER, MsGetUserNameW());

	DlgFont(hWnd, C_SYSTEM, 0, true);
	DlgFont(hWnd, C_USER, 0, true);

	Check(hWnd, C_SYSTEM, true);
	Check(hWnd, C_USER, false);

	DiVistaSelectDlgUpdate(hWnd);
}

// コントロール更新
void DiVistaSelectDlgUpdate(HWND hWnd)
{
	bool b = false;
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (IsChecked(hWnd, C_SYSTEM))
	{
		b = true;
	}

	if (IsChecked(hWnd, C_USER))
	{
		b = true;
	}

	SetEnable(hWnd, IDOK, b);
}

// ヘルパーの起動 (URDP を Program Files 下にインストールする)
bool DiInstallUrdpToProgramFiles(HWND hWnd, DI *di)
{
	wchar_t exe[MAX_PATH];
	wchar_t tmp[MAX_PATH];
	bool ret;
	void *h;
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return false;
	}

	ConbinePathW(exe, sizeof(exe), MsGetExeDirNameW(), DI_FILENAME_DESKHELPER);

	ret = false;

	UniStrCpy(tmp, sizeof(tmp), L"/CALLEDFROMSETUP:TRUE /INSTALLURDP:TRUE");
	ret = MsExecuteEx3W(exe, tmp, &h, false, false);

	if (ret == false)
	{
		return false;
	}

	Hide(hWnd, 0);

	MsWaitProcessExit(h);

	return true;
}

// ヘルパーの起動
bool DiVistaSelectDlgCallHelper(HWND hWnd, DI *di)
{
	wchar_t exe[MAX_PATH];
	wchar_t tmp[MAX_PATH];
	bool ret;
	void *h;
	// 引数チェック
	if (hWnd == NULL || di == NULL)
	{
		return false;
	}

	ConbinePathW(exe, sizeof(exe), MsGetExeDirNameW(), DI_FILENAME_DESKHELPER);

	ret = false;

	UniStrCpy(tmp, sizeof(tmp), L"/CALLEDFROMSETUP:TRUE");
	ret = MsExecuteEx3W(exe, tmp, &h, false, false);

	if (ret == false)
	{
		return false;
	}

	Hide(hWnd, 0);

	MsWaitProcessExit(h);

	return true;
}

// 選択画面
UINT DiVistaSelectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DI_VISTA_SELECT *t = (DI_VISTA_SELECT *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DiVistaSelectDlgInit(hWnd, t);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case C_SYSTEM:
		case C_USER:
			if (wParam == C_USER)
			{
				if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("DI_CUSTOM_SELECT_WARNING")) == IDNO)
				{
					Check(hWnd, C_SYSTEM, true);
					Check(hWnd, C_USER, false);
					Focus(hWnd, C_SYSTEM);
				}
			}
			DiVistaSelectDlgUpdate(hWnd);
			break;

		case IDOK:
			Disable(hWnd, IDOK);
			Disable(hWnd, IDCANCEL);
			Disable(hWnd, C_SYSTEM);
			Disable(hWnd, C_USER);
			DisableClose(hWnd);
			if (IsChecked(hWnd, C_USER))
			{
				t->UserMode = true;
			}
			else
			{
				t->UserMode = false;

				if (DiVistaSelectDlgCallHelper(hWnd, t->Di) == false)
				{
					Enable(hWnd, IDOK);
					Enable(hWnd, IDCANCEL);
					Enable(hWnd, C_SYSTEM);
					Enable(hWnd, C_USER);
					EnableClose(hWnd);
					// 起動に失敗
					MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("DI_HELPER_CALL_FAILED"));
					break;
				}
			}

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

// 選択画面を表示
bool DiShowVistaSelect(DI *di, bool *user_mode)
{
	DI_VISTA_SELECT t;
	// 引数チェック
	if (di == NULL || user_mode == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	t.Di = di;

	if (Dialog(di->hWndParent, D_DI_VISTA_SELECT, DiVistaSelectDlgProc, &t) == 0)
	{
		return false;
	}

	*user_mode = t.UserMode;

	return true;
}

// デバッグ用コマンドラインの設定
void DiDebugWithCommandLine(char *cmdline)
{
	// 引数チェック
	if (cmdline == NULL)
	{
		return;
	}

	StrToUni(debug_cmdline, sizeof(debug_cmdline), cmdline);
}

// コマンドラインの解釈
void DiParseCommandLine(DI_STARTUP *st)
{
	CONSOLE *c;
	wchar_t *cmdline;
	LIST *o;
	PARAM args[] =
	{
		{"PATH", NULL, NULL, NULL, NULL, },
		{"UNINSTALL", NULL, NULL, NULL, NULL, },
		{"PRODUCT", NULL, NULL, NULL, NULL, },
		{"CALLEDFROMSETUP", NULL, NULL, NULL, NULL, },
		{"USERMODE", NULL, NULL, NULL, NULL, },
		{"INSTALLURDP", NULL, NULL, NULL, NULL, },
	};
	// 引数チェック
	if (st == NULL)
	{
		return;
	}

	Zero(st, sizeof(DI_STARTUP));

	c = NewLocalConsole(NULL, NULL);
	if (c == NULL)
	{
		return;
	}

	if (UniIsEmptyStr(debug_cmdline))
	{
		cmdline = GetCommandLineUniStr();
	}
	else
	{
		cmdline = UniCopyStr(debug_cmdline);
	}

	if (UniIsEmptyStr(cmdline) == false)
	{
		o = ParseCommandList(c, "setup", cmdline, args, sizeof(args) / sizeof(args[0]));

		if (o != NULL)
		{
			wchar_t *path = GetParamUniStr(o, "PATH");
			bool uninstall = GetParamYes(o, "UNINSTALL");
			UINT product_type = GetParamInt(o, "PRODUCT");
			bool usermode = GetParamYes(o, "USERMODE");
			bool install_rudp = GetParamYes(o, "INSTALLURDP");

			if (product_type != DI_PRODUCT_SERVER &&
				product_type != DI_PRODUCT_CLIENT)
			{
				product_type = 0;
			}

			if (uninstall && UniIsEmptyStr(path) == false && product_type != 0)
			{
				UniStrCpy(st->Path, sizeof(st->Path), path);
				st->Uninstall = true;
				st->Product = product_type;
				st->Usermode = usermode;
			}

			st->CalledFromSetup = GetParamYes(o, "CALLEDFROMSETUP");
			st->InstallUrpd = install_rudp;

			FreeParamValueList(o);
		}
	}

	Free(cmdline);

	c->Free(c);
}

// インストーラの実行
void DIExec(bool helper)
{
	INSTANCE *single;
	DI *di = ZeroMalloc(sizeof(DI));

	// 初期データの初期化
	di->IsHelper = helper;
	di->IsAdmin = MsIsAdmin();
	di->IsVista = MsIsVista();
	if (di->IsVista)
	{
		di->IsUacEnable = true;
		if (di->IsHelper == false && (di->IsAdmin))
		{
			// ヘルパーでないにもかかわらず Admin 権限がある場合は UAC は無効という
			// ことになる
			di->IsUacEnable = false;
		}
	}

	di->EnableRdpLogonScreen = MsIsRdpAllowLoginScreen();

	if (MsRegReadInt(REG_LOCAL_MACHINE, DI_REGKEY, "RDP1") == 0)
	{
		di->EnableRdpLogonScreen = true;
	}

	// GUI の初期化
	InitWinUi(_UU("DI_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	di->Cedar = NewCedar(NULL, NULL);

	single = NewSingleInstance(NULL);
	if (single != NULL)
	{
		// メイン処理
		DiMain(di);

		FreeSingleInstance(single);
	}
	else
	{
		MsgBox(NULL, MB_ICONINFORMATION, _UU("DI_ALREADY_RUNNING"));
	}

	DiFreeProductFileList(di);

	ReleaseCedar(di->Cedar);

	FreeWinUi();

	Free(di);
}

#endif	// WIN32


