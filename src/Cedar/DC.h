// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

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
	DC_BLUE *Blue;						// Bluetooth セッション
	bool IsShareDisabled;				// 共有が無効化されているかどうか
	UINT ProcessIdOfClient;				// クライアントソフトウェアのプロセス ID
	char OtpTicket[MAX_PATH];			// OTP チケット
	UCHAR SmartCardTicket[SHA1_SIZE];	// スマートカード認証済みチケット
	char InspectionTicket[64];			// インスペクション済みチケット
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

// DC
struct DC
{
	WIDE *Wide;							// WideClient
	wchar_t ConfigFilename[MAX_PATH];	// Config ファイル名
	bool SupportBluetooth;				// Bluetooth をサポート

	// 設定データ
	UINT MstscLocation;					// mstsc の場所
	wchar_t MstscUserPath[MAX_PATH];	// ユーザーが指定した mstsc
	char MstscParams[MAX_PATH];			// mstsc の追加引数
	bool MstscUsePublicSwitchForVer6;	// /public スイッチを使用する
	bool MstscUseShareClipboard;		// クリップボードの共有機能を使用する
	bool MstscUseShareDisk;				// ディスクの共有機能を使用する
	bool MstscUseSharePrinter;			// プリンタの共有機能を使用する
	bool MstscUseShareComPort;			// COM ポートの共有機能を使用する
	bool DontShowFullScreenMessage;		// フルスクリーンメッセージを表示しない
	LIST *Candidate;					// 候補
	wchar_t BluetoothDir[MAX_PATH];		// Bluetooth ディレクトリ
	bool BluetoothDirInited;			// Bluetooth ディレクトリが初期化された
	LIST *AdvAuthList;					// 拡張認証データリスト
	bool EnableVersion2;				// URDP2 を有効にする
	bool DisableMultiDisplay;			// マルチディスプレイ機能を無効にする
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
void DcSetLocalHostAllowFlag(bool allow);
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
void DcWaitForProcessExit(void *h);
void DcInitMstscRdpFile();
bool DcSetMstscRdpFileInt(char *key_name, UINT value);
bool DcSetMstscRdpFileStr(char *key_name, char *value);
wchar_t *DcReadRdpFile(wchar_t *name, bool *is_empty);
bool DcWriteRdpFile(wchar_t *name, wchar_t *s);
void DcEraseCandidate(DC *dc);
BUF *DcGetNextFileFromDir(wchar_t *dirname, wchar_t *filename, UINT filename_size, LIST *ignore_list);
DC_ADVAUTH *DcGetAdvAuth(DC *dc, char *pcid);
void DcSetAdvAuth(DC *dc, DC_ADVAUTH *advauth);
void DcClearAdvAuthList(DC *dc);
bool DcIsMstscParamsContainsRdpFile(char *cmdline);

#endif	// DC_H

