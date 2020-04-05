// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// DI_Inner.h
// DI.c の内部ヘッダ

// 定数


// インストールする製品の種類
#define DI_PRODUCT_SERVER		1	// Desktop VPN Server のインストール
#define DI_PRODUCT_CLIENT		2	// Desktop VPN Client のインストール

//ディレクトリ
#define	DI_DIR_STARTMENU		((wchar_t *)1)		// スタートメニュー
#define DI_DIR_PROGRAMS			((wchar_t *)2)		// プログラム
#define DI_DIR_DESKTOP			((wchar_t *)3)		// デスクトップ

// ファイルロック解除タイムアウト
#define	DI_FILE_UNLOCK_TIMEOUT	(5 * 1000)

// インストールするファイル名
#define DI_FILENAME_DESKCLIENT		L"DeskClient.exe"
#define DI_FILENAME_DESKCONFIG		L"DeskConfig.exe"
#define DI_FILENAME_DESKSERVER		L"DeskServer.exe"
#define DI_FILENAME_DESKSETUP		L"DeskSetup.exe"
#define	DI_FILENAME_DESKHELPER		L"DeskHelper.exe"
#define DI_FILENAME_HAMCORE			L"hamcore.se2"

// 関係するファイル名
#define DI_FILENAME_SETUPINI		L"@DeskSetup.ini"

// インストールするファイル
typedef struct DI_FILE
{
	wchar_t *FileName;			// ファイル名
	bool RegistAsService;		// サービスとして登録するかどうか
	char *ServiceName;			// サービス名
	UINT FileSize;				// ファイルサイズ
} DI_FILE;

// Desktop VPN Server 用インストールファイル一覧
static DI_FILE di_files_for_desk_server[] =
{
	{DI_FILENAME_DESKSERVER,	true,	"DESKSERVER", },
	{DI_FILENAME_DESKCONFIG,	false,	NULL, },
	{DI_FILENAME_DESKSETUP,		false,	NULL, },
	{DI_FILENAME_DESKHELPER,	false,	NULL, },
	{DI_FILENAME_HAMCORE,		false,	NULL, },
};
static UINT num_di_files_for_desk_server = sizeof(di_files_for_desk_server) / sizeof(DI_FILE);

// Desktop VPN Client 用インストールファイル一覧
static DI_FILE di_files_for_desk_client[] =
{
	{DI_FILENAME_DESKCLIENT,	false,	NULL, },
	{DI_FILENAME_DESKSETUP,		false,	NULL, },
	{DI_FILENAME_DESKHELPER,	false,	NULL, },
	{DI_FILENAME_HAMCORE,		false,	NULL, },
};
static UINT num_di_files_for_desk_client = sizeof(di_files_for_desk_client) / sizeof(DI_FILE);

// アンインストールパラメータ
typedef struct UNINSTALL_INFO
{
	wchar_t DisplayIcon[MAX_PATH];		// アイコン
	wchar_t InstallLocation[MAX_PATH];	// インストール場所
	wchar_t DisplayName[MAX_PATH];		// 表示名
	wchar_t UninstallString[MAX_PATH];	// EXE ファイル名
} UNINSTALL_INFO;

// 起動パラメータ
typedef struct DI_STARTUP
{
	bool Uninstall;				// アンインストール
	UINT Product;				// アンインストールする製品
	wchar_t Path[MAX_PATH];		// パス
	bool CalledFromSetup;		// Setup から呼び出された
	bool Usermode;				// ユーザーモードかどうか
	bool InstallUrpd;			// URDP インストールモードかどうか
} DI_STARTUP;

// 構造体宣言
typedef struct DI
{
	CEDAR *Cedar;

	// 初期データ
	bool IsAdmin;				// Admin かどうか
	bool IsVista;				// Windows Vista かどうか
	HWND hWndParent;			// 親ウインドウ
	bool IsHelper;				// Helper かどうか
	bool IsUacEnable;			// UAC が有効かどうか

	// インストーラデータ
	UINT Product;				// インストールの種類
	char *ProductSimpleName;	// 製品シンプル名
	bool UninstallMode;			// アンインストールモード
	bool CanSelectSystem;		// System モードが選択可能かどうか
	bool CanSelectUser;			// User モードが選択可能かどうか
	bool IsUserMode;			// ユーザーモードかどうか
	wchar_t *WhyCanNotSelectSystem;	// System モードが選択できない理由
	wchar_t *WhyCanNotSelectUser;	// User モードが選択できない理由
	LIST *FilesList;			// ファイルリスト
	wchar_t *Title;				// ソフトウェアタイトル
	UINT Icon;					// ソフトウェアアイコン
	wchar_t DefaultInstallDirSystem[MAX_PATH];	// システムモードでのデフォルトインストール先
	wchar_t DefaultInstallDirUser[MAX_PATH];	// ユーザーモードでのデフォルトインストール先
	bool FixedInstallDir;		// インストール先ディレクトリをユーザーが変更不能にする
	wchar_t InstallDir[MAX_PATH];	// インストール先ディレクトリ名
	bool IsTypical;				// 標準インストールモード
	bool ForceShareDisabled;	// 共有機能無効版かどうか
	bool EnableRdpLogonScreen;	// RDP ログオン画面を有効にするかどうか
} DI;

// Vista 用選択ダイアログ
typedef struct DI_VISTA_SELECT
{
	DI *Di;
	bool UserMode;
} DI_VISTA_SELECT;

// 関数プロトタイプ
void DiMain(DI *di);
void DiParseCommandLine(DI_STARTUP *st);
bool DiShowVistaSelect(DI *di, bool *user_mode);
void DiInstallRudpMain(DI *di);
UINT DiVistaSelectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DiVistaSelectDlgInit(HWND hWnd, DI_VISTA_SELECT *t);
void DiVistaSelectDlgUpdate(HWND hWnd);
bool DiVistaSelectDlgCallHelper(HWND hWnd, DI *di);
bool DiInstallUrdpToProgramFiles(HWND hWnd, DI *di);
bool DiCheckFilesExists(DI_FILE *files, UINT num);
bool DiSelectProductDlg(DI *di);
UINT DiSelectProductDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DiSelectProductDlgUpdate(HWND hWnd);
bool DiSelectProduct(DI *di);
bool DiCheckSetupIni(DI *di);
void DiApplyProductFileList(DI *di);
void DiFreeProductFileList(DI *di);
void DiGenerateDefaultInstallDir(DI *di);
bool DiNoticeDlg(DI *di);
UINT DiNoticeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DiThanksDlg(DI *di);
UINT DiThanksDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool DiEulaDlg(DI *di);
UINT DiEulaDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DiEulaDlgInit(HWND hWnd, DI *di);
bool DiCheckServerStatus(DI *di);
bool DiPrepareTypicalInstall(DI *di);
bool DiMainDlg(DI *di);
UINT DiMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DiNormalizeDirName(wchar_t *dst, UINT size, wchar_t *src);
void DiMainDlgInit(HWND hWnd, DI *di);
void DiMainDlgUpdate(HWND hWnd, DI *di, bool select_clicked);
void DiMainDlgOnOk(HWND hWnd, DI *di);
void DiMainDlgOnRestore(HWND hWnd, DI *di);
bool DiSelectTypeDlg(DI *di);
UINT DiSelectTypeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool DiProcessDlg(DI *di);
UINT DiProcessDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DiProcessDlgInit(HWND hWnd, DI *di);
void DiProcessDlgSetStatus(HWND hWnd, wchar_t *str, UINT pos);
void DiProcessDlgOnTimer(HWND hWnd, DI *di);
bool DiProcessDlgOnMain(HWND hWnd, DI *di);
bool DiStopServerService(HWND hWnd, DI *di);
bool DiInstallServerService(HWND hWnd, DI *di);
bool DiUninstallServerService(HWND hWnd, DI *di);
bool DiWaitForUnlockFile(HWND hWnd, DI *di);
bool DiIsAnyFileLocked(DI *di, wchar_t *locked_list, UINT locked_list_size);
bool DiIsFileSpecialForInstaller(DI *di, DI_FILE *f);
bool DiInstallFileAsSystemService(HWND hWnd, DI *di, DI_FILE *f);
bool DiInstallFileAsUserService(HWND hWnd, DI *di, DI_FILE *f);
bool DiUninstallFileAsUserService(HWND hWnd, DI *di, DI_FILE *f);
bool DiUninstallFileAsSystemService(HWND hWnd, DI *di, DI_FILE *f);
void DiCreateShortcuts(HWND hWnd, DI *di);
void DiDeleteShortcuts(HWND hWnd, DI *di);
void DiGetUninstallExeAndArgs(DI *di, wchar_t *exe, UINT exe_size, wchar_t *args, UINT args_size);
void DiGetShortcutDirName(DI *di, wchar_t *dir_name, UINT dir_name_size);
bool DiCreateShortcut(DI *di, wchar_t *exe, wchar_t *args, wchar_t *parent_dir, wchar_t *dir_name, wchar_t *shortcut_name, wchar_t *description);
void DiDeleteShortcut(DI *di, wchar_t *parent_dir, wchar_t *dir_name, wchar_t *shortcut_name);
wchar_t *DiNormalizeShortcutDirName(DI *di, wchar_t *name);
void DiExecuteProgram(HWND hWnd, DI *di);
void DiInstallMain(DI *di);
void DiInitProductSimpleName(DI *di);
void DiUninstallMain(DI *di);
void DiRegistUninstallInfo(HWND hWnd, DI *di);
bool DiWriteUninstallInfo(char *name, UNINSTALL_INFO *info);
bool DiReadUninstallInfo(char *name, UNINSTALL_INFO *info);
bool DiDeleteUninstallInfo(char *name);
void DiUninstallDlg(DI *di);
UINT DiUninstallDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DiUninstallDlgInit(HWND hWnd, DI *di);
void DiUninstallDlgOnTimer(HWND hWnd, DI *di);
bool DiUninstallProcessMain(HWND hWnd, DI *di);



