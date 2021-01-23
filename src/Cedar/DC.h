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

// DC.h
// DC.c のヘッダ

#ifndef	DC_H
#define DC_H

// 定数
#define DC_BLUETOOTH_FLAG_FILENAME		"@bluetooth.dat"
#define DC_BLUETOOTH_MAX_FILESIZE		(10 * 1024 * 1024)
#define DC_BLUETOOTH_POLLING_INTERVAL	10
#define	DC_BLUETOOTH_SOCK_RETRY_INTERVAL	1000
#define	DC_BLUETOOTH_FILE_SEND_FAIL_INTERVAL	(10 * 1000)
#define	DC_MAX_SIZE_CERT				4096


// DC 認証
struct DC_AUTH
{
	bool UseAdvancedSecurity;			// 高度なセキュリティ
	UINT AuthType;						// 認証の種類
	char RetPassword[MAX_SIZE];			// 返却パスワード
	char RetUsername[MAX_SIZE];			// 返却ユーザー名
	UCHAR RetCertData[DC_MAX_SIZE_CERT];	// 返却証明書データ
	UINT RetCertSize;					// 返却証明書サイズ
	UCHAR RetKeyData[DC_MAX_SIZE_CERT];	// 返却秘密鍵データ
	UINT RetKeySize;					// 返却秘密鍵サイズ

	UCHAR InRand[SHA1_SIZE];
	UCHAR RetSignedData[4096 / 8];
	UINT RetSignedDataSize;

	UCHAR SmartCardTicket[SHA1_SIZE];	// スマートカード認証済みチケット
};

// スレッド用パラメータ
struct DC_LISTENED_SOCK_THREAD_PARAM
{
	DC_SESSION *Session;
	SOCK *Sock;
};

// Bluetooth
struct DC_BLUE
{
	DC *Dc;								// DC
	UCHAR ClientId[SHA1_SIZE];			// クライアント ID
	THREAD *Thread;						// スレッド
	EVENT *HaltEvent;					// 停止イベント
	bool Halt;							// 停止フラグ
	SOCKIO *sockio;						// 停止するために切断すべき SOCKIO
	LOCK *Lock;							// ロック
	DC_SESSION *Session;				// セッション
	WIDE *Wide;							// WIDE
};

// DC セッション
struct DC_SESSION
{
	REF *Ref;							// 参照カウンタ
	void *Param;						// パラメータ
	UINT ListenPort;					// Listen しているポート番号
	SOCK *Listener;						// リスナー
	DC_PASSWORD_CALLBACK *PasswordCallback;	// パスワードコールバック
	DC_OTP_CALLBACK *OtpCallback;		// OTP コールバック
	DC_INSPECT_CALLBACK *InspectionCallback;	// 検疫コールバック
	DC_ADVAUTH_CALLBACK *AdvAuthCallback;	// 新しい認証方法のコールバック
	DC_EVENT_CALLBACK *EventCallback;	// イベントコールバック
	char Hostname[MAX_PATH];			// 接続先ホスト名
	char Pcid[WT_PCID_SIZE];			// PCID
	DC *Dc;								// DC
	UINT ServiceType;					// サービスタイプ
	char CachedPassword[MAX_SIZE];		// キャッシュされたパスワード
	DC_AUTH CachedAuthData;				// キャッシュされた拡張認証データ
	THREAD *ListenThread;				// Listen スレッド
	bool HaltListenThread;				// 停止フラグ
	THREAD *ConnectThread;				// Connect スレッド
	bool HaltConnectThread;				// Connect スレッドの停止
	EVENT *EventForListenThread;		// Listen スレッドのためのイベント
	EVENT *EventForConnectThread;		// Connect スレッドのためのイベント
	QUEUE *SockIoQueue;					// SOCKIO キュー
	LIST *SockThreadList;				// スレッドリスト
	UINT DsCaps;						// サーバーの Caps
	bool IsShareDisabled;				// 共有が無効化されているかどうか
	UINT ProcessIdOfClient;				// クライアントソフトウェアのプロセス ID
	char OtpTicket[MAX_PATH];			// OTP チケット
	UCHAR SmartCardTicket[SHA1_SIZE];	// スマートカード認証済みチケット
	char InspectionTicket[64];			// インスペクション済みチケット
	UINT64 LifeTime;					// 有効期限
	wchar_t LifeTimeMsg[MAX_PATH];		// 有効期限満了時のメッセージ
	bool IsLimitedMode;					// サーバーが行政システム適応モードかどうか
	bool IsEnspectionEnabled;			// 検疫有効
	bool IsLimitedFirewallMandated;		// 完全閉域化 FW を強制有効
	UINT64 IdleTimeout;					// アイドルタイムアウト
	wchar_t WatermarkStr1[MAX_SIZE];
	wchar_t WatermarkStr2[MAX_SIZE];
};

// 拡張認証データ
struct DC_ADVAUTH
{
	char Pcid[WT_PCID_SIZE];			// PCID
	UINT AuthType;						// 認証方法
	char Username[MAX_SIZE];			// ユーザー名
	wchar_t CertPath[MAX_PATH];			// 証明書のパス

	UINT SecureDeviceId;				// スマートカードデバイス ID
	char SecureCertName[MAX_PATH];		// スマートカード証明書名
	char SecureKeyName[MAX_PATH];		// スマートカード秘密鍵名
};

// 検疫結果
struct DC_INSPECT
{
	bool AntiVirusOk;
	bool WindowsUpdateOk;
	char MacAddressList[1024];
	char Ticket[64];
};

#define MAX_NWDETECT_URLS	4

#define	NWDETECT_TIMEOUT	(2 * 1000)
#define NWDETECT_DEFAULT_NUMTRY		2

// ネットワーク種類検出設定
struct DC_NWDETECT_SETTINGS
{
	UINT NumTry;
	UINT TimeoutMsecs;
	char NwDetectUrls[MAX_NWDETECT_URLS][64];
	char NwDetectExpectStrs[MAX_NWDETECT_URLS][64];
	DC_NWDETECT_CALLBACK* Callback;
	void* Param;
};

// ネットワーク種類検出結果
struct DC_NWDETECT_RESULT
{
	bool IsDetectedByUrl;
	bool IsFinished;
};

// ネットワーク種類検出
struct DC_NWDETECT
{
	DC_NWDETECT_SETTINGS Settings;

	THREAD* Thread;
	volatile bool Halt;
	volatile bool IsDetectedByUrl;
	volatile bool IsFinished;
};

// DC
struct DC
{
	WIDE *Wide;							// WideClient
	wchar_t ConfigFilename[MAX_PATH];	// Config ファイル名

	// 設定データ
	UINT MstscLocation;					// mstsc の場所
	wchar_t MstscUserPath[MAX_PATH];	// ユーザーが指定した mstsc
	char MstscParams[MAX_PATH];			// mstsc の追加引数
	bool MstscUsePublicSwitchForVer6;	// /public スイッチを使用する
	bool MstscUseShareClipboard;		// クリップボードの共有機能を使用する
	bool MstscUseShareDisk;				// ディスクの共有機能を使用する
	bool MstscUseSharePrinter;			// プリンタの共有機能を使用する
	bool MstscUseShareComPort;			// COM ポートの共有機能を使用する
	bool MstscUseShareAudioRec;			// マイク共用を使用する
	bool MstscUseShareCamera;			// カメラ共有を使用する
	bool DontShowFullScreenMessage;		// フルスクリーンメッセージを表示しない
	LIST *Candidate;					// 候補
	LIST *CandidateWoL;					// 候補 2 (WoL トリガー)
	wchar_t BluetoothDir[MAX_PATH];		// Bluetooth ディレクトリ
	bool BluetoothDirInited;			// Bluetooth ディレクトリが初期化された
	LIST *AdvAuthList;					// 拡張認証データリスト
	bool EnableVersion2;				// URDP2 を有効にする
	bool DisableMultiDisplay;			// マルチディスプレイ機能を無効にする
	bool DisableLimitedFw;				// 完全閉域化ファイアウォールを無効にする
};

// 関数プロトタイプ宣言
DC *NewDc(bool localconfig);
void FreeDc(DC *dc);
void DcGetInternetSetting(DC *dc, INTERNET_SETTING *setting);
void DcSetInternetSetting(DC *dc, INTERNET_SETTING *setting);
UINT DcConnectEx(DC *dc, DC_SESSION *dcs, char *pcid, DC_AUTH_CALLBACK *auth_callback, void *callback_param, char *ret_url, UINT ret_url_size, bool check_port,
				 SOCKIO **sockio, bool first_connection, wchar_t *ret_msg, UINT ret_msg_size, DC_OTP_CALLBACK *otp_callback, DC_SESSION *otp_callback_param,
				 DC_INSPECT_CALLBACK *ins_callback, DC_SESSION *ins_callback_param);
UINT DcConnectMain(DC *dc, DC_SESSION *dcs, SOCKIO *sock, char *pcid, DC_AUTH_CALLBACK *auth_callback, void *callback_param, bool check_port, bool first_connection, DC_OTP_CALLBACK *otp_callback, DC_SESSION *otp_callback_param, DC_INSPECT_CALLBACK *ins_callback, DC_SESSION *ins_callback_param);
UINT DcTriggerWoL(DC *dc, char *target_pcid, char *trigger_pcid);
void DcSetDebugFlag(bool allow);
bool DcGetDebugFlag();
UINT NewDcSession(DC *dc, char *pcid, DC_PASSWORD_CALLBACK *password_callback, DC_OTP_CALLBACK *otp_callback, DC_ADVAUTH_CALLBACK *advauth_callback, DC_EVENT_CALLBACK *event_callback, DC_INSPECT_CALLBACK *inspect_callback,
				  void *param, DC_SESSION **session);
UINT DcSessionConnect(DC_SESSION *s);
void ReleaseDcSession(DC_SESSION *s);
void CleanupDcSession(DC_SESSION *s);
SOCK *DcListen();
void DcGenerateHostname(char *hostname, UINT hostname_size, char *pcid);
void DcGetBestHostnameForPcid(char *hostname, UINT hostname_size, char *pcid);
bool DcSessionConnectAuthCallback1(DC *dc, DC_AUTH *auth, void *param);
bool DcSessionConnectAuthCallback2(DC *dc, DC_AUTH *auth, void *param);
bool DcSessionConnectOtpCallback1(DC *dc, char *otp, UINT otp_max_size, void *param);
bool DcSessionConnectOtpCallback2(DC *dc, char *otp, UINT otp_max_size, void *param);
bool DcSessionConnectInspectionCallback1(DC *dc, DC_INSPECT *ins, void *param);
bool DcSessionConnectInspectionCallback2(DC *dc, DC_INSPECT *ins, void *param);
void DcListenThread(THREAD *thread, void *param);
void DcListenedSockThread(THREAD *thread, void *param);
void DcConnectThread(THREAD *thread, void *param);
void DcGetDownloadMstscDir(wchar_t *name, UINT name_size);
void DcGetDownloadMstscPath(wchar_t *name, UINT name_size);
void DcInitConfig(DC *dc, bool localconfig);
void DcInitDefaultConfig(DC *dc);
int DcCompareAdvAuth(void *p1, void *p2);
void DcLoadConfig(DC *dc, FOLDER *root);
void DcSaveConfig(DC *dc);
void DcNormalizeConfig(DC *dc);
bool DcIsMstscInstalledOnSystem32();
bool DcIsMstscInstalledOnSystem32Inner();
bool DcIsMstscInstalledOnDownloadDir();
void DcGetMstscPathOnSystem32(wchar_t *name, UINT size);
UINT DcGetMstscVersion(wchar_t *name);
UINT DcGetMstscVersionInner(wchar_t *name);
UINT DcGetCurrentMstscVersion(DC *dc);
UINT DcGetCurrentMstscVersionInner(DC *dc);
UINT DcGetEnvStr(DC *dc, char *name, char *str, UINT str_size);
UINT DcDownloadMstscExe(DC *dc, wchar_t *name, UINT name_size, wchar_t *tmp_dir_name, UINT tmp_dir_name_size, WPC_RECV_CALLBACK *callback, void *callback_param);
UINT DcDownloadMstsc(DC *dc, WPC_RECV_CALLBACK *callback, void *callback_param);
bool DcGetMstscPath(DC *dc, wchar_t *name, UINT size, bool *download_required);
UINT DcGetMstscArguments(DC_SESSION *s, wchar_t *mstsc_exe, char *arg, UINT arg_size);
UINT DcGetUrdpClientArguments(DC_SESSION *s, char *arg, UINT arg_size, bool disable_share, UINT version);
void *DcRunMstsc(DC *dc, wchar_t *mstsc_exe, char *arg, char *target, bool disable_share, UINT *process_id, bool *rdp_file_write_failed);
void *DcRunUrdpClient(char *arg, UINT *process_id, UINT version);
bool DcWaitForProcessExit(void *h, UINT timeout, bool watch_gov_fw_exit, UINT64 idle_timeout, UINT *exit_code);
void DcInitMstscRdpFile();
bool DcSetMstscRdpFileInt(char *key_name, UINT value);
bool DcSetMstscRdpFileStr(char *key_name, char *value);
wchar_t *DcReadRdpFile(wchar_t *name, bool *is_empty);
bool DcWriteRdpFile(wchar_t *name, wchar_t *s);
void DcEraseCandidate(DC *dc);
void DcEraseCandidateWoL(DC *dc);
BUF *DcGetNextFileFromDir(wchar_t *dirname, wchar_t *filename, UINT filename_size, LIST *ignore_list);
DC_ADVAUTH *DcGetAdvAuth(DC *dc, char *pcid);
void DcSetAdvAuth(DC *dc, DC_ADVAUTH *advauth);
void DcClearAdvAuthList(DC *dc);
bool DcIsMstscParamsContainsRdpFile(char *cmdline);
DC_NWDETECT* DcNewNwDetectAuto(DC_NWDETECT_SETTINGS* settings);
DC_NWDETECT* DcNewNwDetect(DC_NWDETECT_SETTINGS* settings);
void DcNwDetectThread(THREAD* thread, void* param);
bool DcNwDetectProcessOneUrl(DC_NWDETECT* t, char* url, char* expect);
void DcFreeNwDetect(DC_NWDETECT* t, DC_NWDETECT_RESULT *result);


#endif	// DC_H

