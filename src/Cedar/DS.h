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


// DS.h
// DS.c のヘッダ

#ifndef	DS_H
#define DS_H

// 履歴
#define	DS_HISTORY_EXPIRES			(60 * 1000)		// 履歴の有効期限
#define	DS_HISTORY_THRESHOLD		5				// エラーを発生させるまでの回数

// ログの種類
#define	DS_LOG_INFO					0	// 情報
#define	DS_LOG_WARNING				1	// 警告
#define	DS_LOG_ERROR				2	// エラー

// 定数
#define DS_PASSWORD_ENCRYPT_KEY		"pass_key"
#define DS_SEND_ERROR_AND_WAIT_SPAN	(3 * 1000)
#define DS_LOG_DIRNAME				"@server_log"
#define	DS_BLUETOOTH_FILE_SAVE_INTERVAL	(3 * 1000)

#define	DS_CFG_SECURITY_SETTINGS	"AdvancedSecurity"

#define DS_SESSION_INC_DEC_THRESHOLD	(5 * 60 * 1000)

// OTP 有効期限
#define DS_OTP_EXPIRES				(5 * 60 * 1000)

// OTP 長さ
#define	DS_OTP_LENGTH				6

// 非常用 OTP 長さ
#define DS_EMERGENCY_OTP_LENGTH		30

// OTP が変化せず試せる回数
#define DS_OTP_NUM_TRY				20

// ポリシークライアント更新間隔
#define DS_POLICY_CLIENT_UPDATE_INTERVAL	(5 * 60 * 1000)

// 受信ポリシーの有効期限
#define	DS_POLICY_EXPIRES					(DS_POLICY_CLIENT_UPDATE_INTERVAL * 2)

// ポリシークライアント最大ファイルサイズ
#define DS_POLICY_CLIENT_MAX_FILESIZE		(32 * 1024)

// SERVER_ALLOWED_MAC_LIST_URL への接続タイムアウト
#define DS_POLICY_SERVER_ALLOWED_MAC_LIST_URL_TIMEOUT	(5 * 1000)

// CLIENT_ALLOWED_MAC_LIST_URL への接続タイムアウト
#define DS_POLICY_CLIENT_ALLOWED_MAC_LIST_URL_TIMEOUT	(5 * 1000)

// SERVER_ALLOWED_MAC_LIST_URL のファイルサイズ最大
#define DS_POLICY_SERVER_ALLOWED_MAC_LIST_URL_MAX_SIZE	(1024 * 1024)


// ポリシーサーバー関係定数
#define DS_POLICY_INDOMAIN_SERVER_NAME	"thin-telework-policy-server"
#define DS_POLICY_IP_SERVER_NAME		"10.255.255.127"

// caps
//#define DS_CAPS_SUPPORT_BLUETOOTH	1			// Bluetooth サポート
#define	DS_CAPS_SUPPORT_URDP2		2			// URDP2 サポート
#define DS_CAPS_RUDP_VERY_LIMITED	4			// URDP かつ大変制限が厳しい
#define DS_CAPS_WIN_RDP_ENABLED		8			// Windows RDP も一応有効である


// Radius キャッシュ
struct DS_RADIUS_CACHE
{
	UCHAR ClientID[SHA1_SIZE];			// クライアント ID
	char UserName[MAX_SIZE];			// ユーザー名
	char Password[MAX_SIZE];			// パスワード
};

// 接続しているクライアント
struct DS_CLIENT
{
	UINT64 ConnectedTick;				// 接続日時
	IP Ip;								// IP アドレス
	char HostName[MAX_PATH];			// ホスト名
	UINT Port;							// ポート番号
	UCHAR ClientID[SHA1_SIZE];			// クライアント ID
	UINT TunnelID;						// トンネル ID
	UINT SeqNo;							// シーケンス番号
};

struct DS_WIN32_RDP_POLICY
{
	bool HasValidValue;
	UINT fDisableCdm;
	UINT fDisableClip;
};

struct DS
{
	WIDE *Wide;							// WideServer
	CEDAR *Cedar;						// Cedar
	LISTENER *RpcListener;				// RPC リスナ
	LIST *SockThreadList;				// ソケットスレッドリスト
	CFG_RW *CfgRw;						// 設定 R/W
	LOCK *PowerKeepLock;				// 電源維持機能に関するロック
	void *PowerKeepHandle;				// 電源維持機能ハンドル
	bool IsUserMode;					// ユーザーモードかどうか
	URDP_SERVER *UrdpServer;			// URDP Server
	bool IsConfigured;					// 設定が行われたかどうか
	LOG *Log;							// ログ
	LIST *ClientList;					// クライアント一覧
	UINT LastClientSeqNo;				// 最後のクライアントシーケンス番号
	bool SupportBluetooth;				// Bluetooth サポート
	SERVER *Server;						// Server オブジェクト (ユーザー認証用)
	bool ForceDisableShare;				// 強制的に共有機能が無効になっているかどうか
	void *EventLog;						// イベントログ
	bool SupportEventLog;				// イベントログをサポートしているかどうか
	LIST *History;						// 接続受付履歴
	LIST *RadiusCacheList;				// Radius キャッシュリスト

	COUNTER* CurrentNumSessions;		// 現在接続されているセッション数
	UINT64 LastSessionDisconnectedTick;	// 最後のセッションが切断された時刻
	LOCK* SessionIncDecLock;			// セッションが増えたり減ったりする際のロック

	COUNTER* CurrentNumRDPSessions;		// Current RDP sessions
	LOCK* RDPSessionIncDecLock;

	DS_WIN32_RDP_POLICY Win32RdpPolicy;

#ifdef OS_WIN32
	MS_ISLOCKED *IsLocked;				// ロックされているかどうかの状態管理
	MS_PROCESS_WATCHER* ProcessWatcher;	// プロセスウォッチャー
#endif // OS_WIN32

	// 設定データ
	bool PowerKeep;						// 電源維持機能を使用するかどうか
	bool Active;						// 接続を受け付けるかどうか
	UCHAR HashedPassword[SHA1_SIZE];	// 設定パスワード
	UINT AuthType;						// ユーザー認証の方式
	UCHAR AuthPassword[SHA1_SIZE];		// パスワード認証
	UINT ServiceType;					// サービスの種類
	UINT RdpPort;						// RDP ポート番号
	bool SaveLogFile;					// ログファイルを保存するかどうか
	bool SaveEventLog;					// イベントログを保存するかどうか
	wchar_t BluetoothDir[MAX_PATH];		// Bluetooth ディレクトリ
	bool UseAdvancedSecurity;			// 高度なセキュリティ機能を使用するかどうか
	bool DisableShare;					// 共有機能を禁止するかどうか
	wchar_t AdminUsername[MAX_PATH];	// 管理者のユーザー名
	UINT NumConfigures;					// 設定接続回数
	bool EnableOtp;						// OTP 有効
	char OtpEmail[MAX_PATH];			// OTP 送付先メールアドレス
	char EmergencyOtp[128];

	char OtpTicket[MAX_PATH];			// OTP チケット。2 回目以降の認証時に利用可能
	char InspectionTicket[MAX_PATH];	// 検疫チケット。2 回目以降の認証時に利用可能

	char LastOtp[MAX_PATH];				// 最後に発行された OTP
	UINT64 LastOtpExpires;				// 最後に発行された OTP の有効期限
	UINT OtpNumTry;						// OTP が試された回数

	UCHAR SmartCardTicket[SHA1_SIZE];	// スマートカード認証済みトークン

	bool EnableInspection;
	bool EnableMacCheck;
	char MacAddressList[1024];

	bool RdpEnableGroupKeeper;
	wchar_t RdpGroupKeepUserName[MAX_PATH];
	bool RdpEnableOptimizer;
	char RdpStopServicesList[MAX_PATH];

	bool ShowWatermark;
	wchar_t WatermarkStr[MAX_PATH];

	DS_POLICY_CLIENT *PolicyClient;		// ポリシークライアント

	bool EnableWoLTarget;
	bool EnableWoLTrigger;

	LOCK* ConfigLock;
};

struct DS_INFO
{
	char ExeDir[MAX_PATH];
	wchar_t ExeDirW[MAX_PATH];
	char ExePath[MAX_PATH];
	wchar_t ExePathW[MAX_PATH];
	char UserName[MAX_PATH];
	wchar_t UserNameW[MAX_PATH];
	UINT Version;
	UINT Build;
	bool IsUserMode;
	bool ForceDisableShare;
};

struct DS_HISTORY
{
	UINT64 Expires;
	IP Ip;
};

struct DS_POLICY_THREAD_CTX
{
	DS_POLICY_CLIENT *Client;
	char Url[MAX_PATH];
	bool ReplaceSuffix;
	EVENT *HaltEvent;
};

struct DS_POLICY_BODY
{
	char SrcUrl[MAX_PATH];
	wchar_t ServerMessage[MAX_SIZE];

	bool EnforceOtp;
	bool DisableOtp;

	bool DisableShare;

	bool EnforceInspection;
	bool DisableInspection;

	bool EnforceMacCheck;
	bool DisableMacCheck;

	char EnforceOtpEndWith[64];

	bool EnforceWatermark;
	bool DisableWatermark;

	bool EnforceProcessWatcher;
	bool EnforceProcessWatcherAlways;

	wchar_t WatermarkMessage[MAX_SIZE];
	char SyslogHostname[MAX_PATH];
	UINT SyslogPort;
	char ServerAllowedMacListUrl[MAX_PATH];
	char ClientAllowedMacListUrl[MAX_PATH];
	bool NoLocalMacAddressList;
};

struct DS_POLICY_CLIENT
{
	bool Halt;
	EVENT *HaltEvent;
	LIST *ThreadList;
	UINT64 PolicyExpires;
	DS_POLICY_BODY Policy;
	char ServerHash[128];
	LIST *HaltEventList;
	UINT NumThreads;
	UINT NumTryCompleted;
};

DS *NewDs(bool is_user_mode, bool force_share_disable);
UINT64 DsCalcMask(DS *ds);
void FreeDs(DS *ds);
void DsRpcListenerThread(THREAD *thread, void *param);
void DsRpcMain(DS *ds, SOCK *s);
void DsAcceptProc(THREAD *thread, SOCKIO *sock, void *param);
bool DsCheckServiceRpcPort();
bool DsCheckServiceRpcPortEx(bool *bad_protocol);
bool DsReadSecureCertAndKey(X **cert, K **key);
void DsWriteSecureCertAndKey(X *cert, K *key);
void DsInitConfig(DS *ds);
void DsFreeConfig(DS *ds);
bool DsLoadConfig(DS *ds);
bool DsLoadConfigMain(DS *ds, FOLDER *root);
void DsInitDefaultConfig(DS *ds);
void DsSaveConfig(DS *ds);
void DsNormalizeConfig(DS *ds, bool change_rdp_status);
FOLDER *DsSaveConfigMain(DS *ds);
PACK *DsRpcServer(RPC *r, char *name, PACK *p);
void DsUpdatePowerKeepSetting(DS *ds);
UINT DsGetServiceInfo(DS_INFO *info);
void DsStopUsermodeService();
void DsSaveConfigCommSetting(FOLDER *f);
void DsSaveInternetSetting(FOLDER *f, INTERNET_SETTING *setting);
void DsLoadInternetSetting(FOLDER *f, INTERNET_SETTING *setting);
BUF *DsEncryptPassword(char *password);
void DsDecryptPassword(BUF *b, char *str, UINT str_size);
UINT DtcConnect(char *password, RPC **rpc);
void DsServerMain(DS *ds, SOCKIO *sock);
void DsSendError(SOCKIO *sock, UINT error_code);
void DsSendErrorEx(SOCKIO *sock, UINT error_code, char *add_value_name, UCHAR *add_value_data, UINT data_size);
SOCK *DsConnectToLocalHostService(UINT svc_type, UINT rdp_port);
UINT DsGetRdpPortFromRegistry();
void DsLog(DS *ds, char *name, ...);
void DsLogEx(DS *ds, UINT ds_log_type, char *name, ...);
void DsLogMain(DS *ds, UINT ds_log_type, char *name, va_list args);
void DsSendSyslog(SERVER *s, wchar_t *message);
wchar_t *DsGetLogTypeStr(UINT ds_log_type);
void DsUpdateTaskIcon(DS *ds);
void DsResetCertProc(WIDE *wide, void *param);
void DsResetCertOnNextBoot();
UINT DsGetCaps(DS *ds);
void DsBluetoothMain(DS *ds, SOCKIO *sock);
bool DsIsShareDisabled(DS *ds);
bool DsCheckShareDisableSignature(wchar_t *exe);
void DsLockHistory(DS *ds);
void DsUnlockHistory(DS *ds);
void DsAddHistory(DS *ds, IP *ip);
void DsFlushHistory(DS *ds);
UINT DsGetHistoryCount(DS *ds, IP *ip);
void DsReportAuthFailed(DS *ds, UINT tunnel_id, IP *ip, char *hostname);
//bool IsIPPrivate(IP *ip);
bool DsAuthUserByPlainPassword(DS *ds, UCHAR *client_id, HUB *hub, char *username, char *password, bool ast);
void DsInitRadiusCacheList(DS *ds);
void DsFreeRadiusCacheList(DS *ds);
bool DsTryRadiusCache(DS *ds, UCHAR *client_id, char *username, char *password);
void DsAddRadiusCache(DS *ds, UCHAR *client_id, char *username, char *password);
void DsCleanAllRadiusCache(DS *ds);
void DsGenerateNewOtp(char *dst, UINT size, UINT len);

#ifdef	OS_WIN32
void DsWin32ProcessWatcherCallback(bool start, MS_PROCESS* process, void* param);
#endif //OS_WIN32


DS_POLICY_CLIENT *DsNewPolicyClient(char *server_hash);
void DsFreePolicyClient(DS_POLICY_CLIENT *c);
bool DsParsePolicyFile(DS_POLICY_BODY *b, BUF *buf);
void DsPolicyClientThread(THREAD *thread, void *param);
bool DsPolicyClientGetPolicy(DS_POLICY_CLIENT *c, DS_POLICY_BODY *pol);

bool DsGetPolicy(DS *ds, DS_POLICY_BODY *pol);
bool DsIsTryCompleted(DS *ds);
void DsPreparePolicyMessage(wchar_t *str, UINT str_size, DS_POLICY_BODY *pol);

void DsWin32GetRdpPolicy(DS_WIN32_RDP_POLICY* pol);
bool DsWin32SetRdpPolicy(DS_WIN32_RDP_POLICY* pol);

// RPC Procedures (Server Side)
UINT DtGetInternetSetting(DS *ds, INTERNET_SETTING *t);
UINT DtSetInternetSetting(DS *ds, INTERNET_SETTING *t);
UINT DtGetStatus(DS *ds, RPC_DS_STATUS *t);
UINT DtRegistMachine(DS *ds, RPC_PCID *t);
UINT DtChangePcid(DS *ds, RPC_PCID *t);
UINT DtSetConfig(DS *ds, RPC_DS_CONFIG *t);
UINT DtGetConfig(DS *ds, RPC_DS_CONFIG *t);
UINT DtGetPcidCandidate(DS *ds, RPC_PCID *t);
UINT DtResetCertOnNextBoot(DS *ds, RPC_TEST *t);

// RPC Procedures (Client Side)
UINT DtcGetInternetSetting(RPC *r, INTERNET_SETTING *t);
UINT DtcSetInternetSetting(RPC *r, INTERNET_SETTING *t);
UINT DtcGetStatus(RPC *r, RPC_DS_STATUS *t);
UINT DtcRegistMachine(RPC *r, RPC_PCID *t);
UINT DtcChangePcid(RPC *r, RPC_PCID *t);
UINT DtcSetConfig(RPC *r, RPC_DS_CONFIG *t);
UINT DtcGetConfig(RPC *r, RPC_DS_CONFIG *t);
UINT DtcGetPcidCandidate(RPC *r, RPC_PCID *t);
UINT DtcResetCertOnNextBoot(RPC *r, RPC_TEST *t);



#endif	// DS_H

