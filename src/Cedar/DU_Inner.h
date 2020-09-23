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
	WINUI_UPDATE *Update;
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

// OTP ダイアログデータ
typedef struct DU_OTP
{
	char Otp[MAX_PATH];
	char Hostname[MAX_PATH];
} DU_OTP;

// ユーザー認証ダイアログデータ
typedef struct DU_AUTH
{
	DU *Du;
	DC *Dc;
	char Pcid[MAX_PATH];		// PCID
	DC_AUTH Auth;				// 認証データ

	UINT SecureDeviceId;				// スマートカードデバイス ID
	char SecureCertName[MAX_PATH];		// スマートカード証明書名
	char SecureKeyName[MAX_PATH];		// スマートカード秘密鍵名
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
void DuMainDlgInitPcidCandidate(HWND hWnd, DU_MAIN *t);
void DuMainBanner(HWND hWnd, DU_MAIN *t);
void DuMainDlgUpdate(HWND hWnd, DU_MAIN *t, bool forceEnable);
void DuMainDlgOnOk(HWND hWnd, DU_MAIN *t);
void DuMainDlgOnClose(HWND hWnd, DU_MAIN *t);
void DuMainDlgSetControlEnabled(HWND hWnd, bool b);
void DuConnectMain(HWND hWnd, DU_MAIN *t, char *pcid);

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
bool DuInspectionCallback(DC *dc, DC_INSPECT *ins, DC_SESSION *dcs);

bool DuPasswordDlg(HWND hWnd, char *password, UINT password_size, char *hostname);
UINT DuPasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuPasswordDlgUpdate(HWND hWnd);

bool DuOtpDlg(HWND hWnd, char *otp, UINT otp_size, char *hostname);
UINT DuOtpDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuOtpDlgUpdate(HWND hWnd);

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

bool DuInspectionDlg(HWND hWnd, DC_INSPECT *ins);
UINT DuInspectionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);

bool DuInitWfpApi();
void DuWfpTest();
void DuWfpAddIpAcl(HANDLE hEngine, bool is_in, IP *ip, IP *mask, UINT index, bool permit);
void DuWfpAddPortAcl(HANDLE hEngine, bool is_in, bool ipv6, UCHAR protocol, UINT port, UINT index, bool permit);

void *DuStartApplyWhiteListRules();
void DuStopApplyWhiteListRules(void *handle);

bool DuWoLDlg(HWND hWnd, DU_MAIN *m);
UINT DuWoLDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuWoLDlgInit(HWND hWnd, DU_MAIN *m);
void DuWoLSetControlEnable(HWND hWnd, bool b);
bool DuWoLDlgOnOk(HWND hWnd, DU_MAIN *m);

UINT DuGovFw2DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void DuGovFw2Main();

UINT DuGovFw1DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool DuGovFw1Main(bool mandate);



