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



