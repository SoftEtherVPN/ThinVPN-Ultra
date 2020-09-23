// IPA-DN-Ultra Library Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on IPA-DN-Ultra Library and SoftEther VPN Project in GitHub.
// 
// All Rights Reserved.
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (IPA CYBERLAB, SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI
// OR OTHER SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY
// KIND OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE IPA CYBERLAB HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// daiyuu.securityreport [at] dnobori.jp
// 
// Thank you for your cooperation.


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
	{DI_FILENAME_DESKSERVER,	true,	DESK_SERVER_SVC_NAME, },
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



