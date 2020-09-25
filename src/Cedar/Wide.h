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


// Wide.h
// Wide.c のヘッダ

#ifndef	WIDE_H
#define WIDE_H

// エラーレベル
#define DESK_ERRORLEVEL_NETWORK			0		// ネットワークエラー
#define DESK_ERRORLEVEL_SERVER_SIDE		1		// サーバー側エラー
#define DESK_ERRORLEVEL_CLIENT_SIDE		2		// クライアント側エラー

// SECURE_PACK_FOLDER の場所
#define SECURE_PACK_FOLDER_TYPE_DISK			0
#define SECURE_PACK_FOLDER_TYPE_LOCAL_MACHINE	1
#define SECURE_PACK_FOLDER_TYPE_CURRENT_USER	2
#define SECURE_PACK_EXE_FOLDER					3

// SECURE_PACK_FOLDER
struct SECURE_PACK_FOLDER
{
	UINT Type;
	bool ByMachineOnly;
	wchar_t FolderName[MAX_PATH];
};

// ログイン情報
struct WIDE_LOGIN_INFO
{
	UINT MachineId;
	char SvcName[MAX_PATH];
	char Msid[MAX_PATH];
	char Pcid[MAX_PATH];
	UINT64 CreateDate;
	UINT64 UpdateDate;
	UINT64 LastServerDate;
	UINT64 LastClientDate;
	UINT NumServer;
	UINT NumClient;
};

// CONNECT_MAIN_THREAD_PARAM
struct CONNECT_MAIN_THREAD_PARAM
{
	WIDE *Wide;
	bool Halt;
	EVENT *HaltEvent;
};

// マシン識別子
struct WT_MACHINE_ID
{
	UCHAR ProductIdHash[SHA1_SIZE];
	UCHAR MachineNameHash[SHA1_SIZE];
	UCHAR IpAddressHash[SHA1_SIZE];
	UCHAR MacAddressHash[SHA1_SIZE];
	UCHAR RamSizeHash[SHA1_SIZE];
};

// セッション ID とクライアント ID の対応表
struct SESSION_AND_CLIENT
{
	UCHAR SessionId[WT_SESSION_ID_SIZE];
	UCHAR ClientId[SHA1_SIZE];
};

// 前回セッション追加報告を送信してから何ミリ秒以内であれば次の報告を送信せずに
// 待機すべきか
#define WIDE_REPORT_FAST_SEND_INTERVAL	200

// その場合次のセッションリスト報告を送信するまでの間の遅延
//#define	WIDE_REPORT_FAST_SEND_DELAY		4000


// WIDE オブジェクトの種類
#define WIDE_TYPE_GATE			0		// WideGate
#define WIDE_TYPE_SERVER		1		// WideServer
#define WIDE_TYPE_CLIENT		2		// WideClient

// セッション接続情報キャッシュ
struct SESSION_INFO_CACHE
{
	char Pcid[MAX_PATH];						// PCID
	char HostName[MAX_HOST_NAME_LEN + 1];		// ホスト名
	char HostNameForProxy[MAX_HOST_NAME_LEN + 1];		// ホスト名 プロキシ用
	UINT Port;									// ポート番号
	UCHAR SessionId[WT_SESSION_ID_SIZE];		// 接続先セッション ID
	UINT64 ServerMask64;						// ServerMask64
	UINT64 Expires;								// 有効期限
};

// ACCEPT キュー エントリ
struct ACCEPT_QUEUE_ENTRY
{
	SOCKIO *sockio;
	EVENT *EndEvent;
};

// ACCEPT キュー
struct ACCEPT_QUEUE
{
	bool Halt;
	QUEUE *Queue;
	EVENT *Event;
};

// WIDE オブジェクト
struct WIDE
{
	// 共通
	WT *wt;
	UINT Type;
	LOCK *SettingLock;
	bool DontCheckCert;
	char SvcName[32];
	UINT SeLang;
	UCHAR ClientId[SHA1_SIZE];

	// WideClient
	char RecvUrl[MAX_PATH];
	wchar_t RecvMsg[MAX_SIZE];
	UINT64 SessionInfoCacheExpires;
	LIST *SessionInfoCache;

	// WideGate
	bool GateHalt;
	X *GateCert;
	K *GateKey;
	THREAD *ReportThread;
	EVENT *ReportThreadHaltEvent;
	LOCK *LockReport;
	LOCK *ReportIntervalLock;
	UINT64 NextReportTick;
	UINT64 NextReportTick2;
	UINT64 LastReportTick;
	LOCK *SecretKeyLock;
	char ControllerGateSecretKey[64];
	char GateKeyStr[64];


	// 2020/4/15 追加 アグレッシブタイムアウト機能
	LOCK *AggressiveTimeoutLock;
	UINT GateTunnelTimeout;
	UINT GateTunnelKeepAlive;
	bool GateTunnelUseAggressiveTimeout;

	UINT64 GateTunnelTimeoutLastLoadTick;
	// WideServer
	LOCK *ReconnectLock;
	X *ServerX;
	K *ServerK;
	THREAD *ConnectThread;
	bool HaltReconnectThread;
	EVENT *HaltReconnectThreadEvent;
	UINT ServerErrorCode;
	bool FirstFlag;
	WT_ACCEPT_PROC *ServerAcceptProc;
	void *ServerAcceptParam;
	bool IsConnected;
	char Pcid[MAX_PATH];
	bool SuppressReconnect;
	bool IsSuppressedReconnect;
	WIDE_RESET_CERT_PROC *ResetCertProc;
	void *ResetCertProcParam;
	UINT64 ServerMask64;
	bool SendMacList;
	ACCEPT_QUEUE *AcceptQueue;

	bool MsgForServerArrived;			// 新しいメッセージが WideController から届いている
	wchar_t MsgForServer[MAX_SIZE];		// 届いているメッセージ
	bool MsgForServerOnce;				// 次回から表示しない を許可

	// Server が Wide Controller からもらってきた Lifetime
	UINT64 SessionLifeTime;
	wchar_t SessionLifeTimeMsg[MAX_PATH];

	wchar_t MsgForServer2[MAX_SIZE * 2];		// ポリシー関係
};

// 関数プロトタイプ
///////////////////////////////////////////////


// 共通
void WideFreeIni(LIST *o);
void WideGetInternetSetting(WIDE *w, INTERNET_SETTING *setting);
void WideSetInternetSetting(WIDE *w, INTERNET_SETTING *setting);
void WideGetWindowsProductId(char *id, UINT size);
void WideGetWindowsProductIdMain(char *id, UINT size);
PACK *WideReadSecurePack(char *name);
void WideWriteSecurePack(char *name, PACK *p);
void WideWriteSecurePackEx(char *name, PACK *p, UINT64 timestamp);
void WideCleanSecurePack(char *name);
PACK *WideReadSecurePack(char *name);
void WideWriteSecurePackMain(UINT type, wchar_t *foldername, char *name, PACK *p, bool by_machine_only);
void WideWriteSecurePackEntry(UINT type, wchar_t *foldername, wchar_t *filename, PACK *p);
PACK *WideReadSecurePackMain(UINT type, wchar_t *foldername, char *name, bool for_user);
PACK *WideReadSecurePackEntry(UINT type, wchar_t *foldername, wchar_t *filename);
BUF *WideWriteSecurePackConvertToBuf(wchar_t *filename, PACK *p);
PACK *WideReadSecurePackConvertFromBuf(wchar_t *filename, BUF *src);
LIST *WideNewSecurePackFolderList();
void WideFreeSecurePackFolderList(LIST *o);
void WideGenerateSecurePackFileName(UINT type, wchar_t *filename, UINT size, wchar_t *foldername, char *name, bool for_user);
PACK *WideCall(WIDE *wide, char *function_name, PACK *pack, bool global_ip_only, bool try_secondary);
void WideSetDontCheckCert(WIDE *w, bool dont_check_cert);
bool WideGetDontCheckCert(WIDE *w);
UINT WideGetErrorLevel(UINT code);
bool WideIsProxyError(UINT code);
UINT WideGetEnvStr(WIDE *w, char *name, char *ret_str, UINT ret_size);
void WideGetCurrentMachineId(WT_MACHINE_ID *d);
void WideGetCurrentMachineIdMain(WT_MACHINE_ID *d);
bool WideCompareMachineId(WT_MACHINE_ID *d1, WT_MACHINE_ID *d2);
void WideSessionInfoCacheDeleteExpires(LIST *o);
SESSION_INFO_CACHE *WideSessionInfoCacheGet(LIST *o, char *pcid, UINT64 expire_span);
void WideSessionInfoCacheAdd(LIST *o, char *pcid, char *hostname, char *hostname_for_proxy, UINT port,
							 UCHAR *session_id, UINT64 expire_span, UINT64 servermask64);
void WideSessionInfoCacheDel(LIST *o, char *pcid);
LIST *WideInitSessionInfoCache();
void WideFreeSessionInfoCache(LIST *o);

void WideLoadEntryPoint(X** cert, char* url, UINT url_size, LIST* secondary_str_list, char* mode, UINT mode_size, char* system, UINT system_size);

bool WideVerifyNewEntryPointAndSignature(X *master_x, BUF *ep, BUF *sign);
BUF *WideTryDownloadAndVerifyNewEntryPoint(X *master_x, INTERNET_SETTING *setting, char *base_url, bool *cancel, WT *wt);
bool WideTryUpdateNewEntryPoint(wchar_t *dirname, X *master_x, INTERNET_SETTING *setting, bool *cancel, WT *wt);
bool WideTryUpdateNewEntryPointModest(wchar_t *dirname, X *master_x, INTERNET_SETTING *setting, bool *cancel, WT *wt, UINT interval);
bool WideTryUpdateNewEntryPointModestStandard(WT *wt, bool *cancel);


// WideClient
WIDE *WideClientStart(char *svc_name, UINT se_lang);
WIDE *WideClientStartEx(char *svc_name, UINT se_lang, X *master_cert, char *fixed_entrance_url);
void WideClientStop(WIDE *w);
UINT WideClientConnect(WIDE *w, char *pc_id, UINT ver, UINT build, SOCKIO **sockio, UINT client_options, bool no_cache);
UINT WideClientConnectInner(WIDE *w, WT_CONNECT *c, char *pcid, UINT ver, UINT build, UINT client_options, bool no_cache);
void WideClientGenerateClientId(UCHAR *id);
UINT WideClientGetWoLMacList(WIDE *w, char *pcid, UINT ver, UINT build, char *mac_list, UINT mac_list_size);

// WideServer
WIDE *WideServerStart(char *svc_name, WT_ACCEPT_PROC *accept_proc, void *accept_param, UINT se_lang);
WIDE *WideServerStartEx(char *svc_name, WT_ACCEPT_PROC *accept_proc, void *accept_param, UINT se_lang,
					    WIDE_RESET_CERT_PROC *reset_cert_proc, void *reset_cert_proc_param);
WIDE *WideServerStartEx2(char *svc_name, WT_ACCEPT_PROC *accept_proc, void *accept_param, UINT se_lang,
						WIDE_RESET_CERT_PROC *reset_cert_proc, void *reset_cert_proc_param,
						X *master_cert, char *fixed_entrance_url);
void WideServerStop(WIDE *w);
void WideServerReconnect(WIDE *w);
void WideServerReconnectEx(WIDE *w, bool stop);
void WideServerConnectThread(THREAD *thread, void *param);
void WideServerStartConnectThread(WIDE *w);
void WideServerStopConnectThread(WIDE *w);
void WideServerSetCertAndKey(WIDE *w, X *cert, K *key);
void WideServerSetCertAndKeyEx(WIDE *w, X *cert, K *key, bool no_reconnect);
bool WideServerGetCertAndKey(WIDE *w, X **cert, K **key);
UINT WideServerGetErrorCode(WIDE *w);
void WideServerGenerateCertAndKey(X **cert, K **key);
UINT WideServerGetLoginInfo(WIDE *w, WIDE_LOGIN_INFO *info);
UINT WideServerGetPcidCandidate(WIDE *w, char *name, UINT size, char *current_username);
UINT WideServerRegistMachine(WIDE *w, char *pcid, X *cert, K *key);
UINT WideServerRenameMachine(WIDE *w, char *new_name);
UINT WideServerSendOtpEmail(WIDE *w, char *otp, char *email, char *ip, char *fqdn);
UINT WideServerConnect(WIDE *w, WT_CONNECT *c);
void WideServerConnectMainThread(THREAD *thread, void *param);
bool WideServerIsConnected(WIDE *w);
bool WideServerGetPcid(WIDE *w, char *pcid, UINT size);
void WideServerGetHash(WIDE *w, char *hash, UINT size);
void WideServerGetSystem(WIDE* w, char* system, UINT size);
void WideServerSuppressAutoReconnect(WIDE *w, bool suppress);
bool WideServerTryAutoReconnect(WIDE *w);
BUF *WideServerSaveLocalKeyToBuffer(K *k, X *x);
bool WideServerLoadLocalKeyFromBuffer(BUF *buf, K **k, X **x);
CRYPT *WideServerLocalKeyFileEncrypt();

// WideServer - AcceptQueue
WIDE *WideServerStartForAcceptQueue(char *svc_name, X *master_cert, char *entrance);
ACCEPT_QUEUE *NewAcceptQueue();
void FreeAcceptQueue(ACCEPT_QUEUE *aq);
void AcceptQueueAcceptProc(THREAD *thread, SOCKIO *sock, void *param);
ACCEPT_QUEUE_ENTRY *AcceptQueueGetNext(WIDE *w);


// WideGate
WIDE *WideGateStart();
void WideGateStop(WIDE *wide);
LIST *WideGateLoadIni();
void WideGateLoadCertKey(X **cert, K **key);
UINT WideGateGetIniEntry(char *name);
void WideGatePackSessionList(PACK *p, WT *wt, LIST *sc_list);
void WideGatePackSession(PACK *p, TSESSION *s, UINT i, UINT num, LIST *sc_list);
void WideGatePackGateInfo(PACK *p, WT *wt);
void WideGateReportThread(THREAD *thread, void *param);
void WideGateReportSessionList(WIDE *wide);
void WideGateReportSessionAdd(WIDE *wide, TSESSION *s);
void WideGateReportSessionDel(WIDE *wide, UCHAR *session_id);
void WideGateSetControllerGateSecretKey(WIDE *wide, char *key);
bool WideGateGetControllerGateSecretKey(WIDE *wide, char *key, UINT key_size);
void WideGateSetControllerGateSecretKeyFromPack(WIDE *wide, PACK *p);
void WideGenerateRandomDummyDomain(char *str, UINT size);

void WideGateLoadAggressiveTimeoutSettings(WIDE *wide);
void WideGateLoadAggressiveTimeoutSettingsWithInterval(WIDE *wide);

#endif	// WIDE_H

