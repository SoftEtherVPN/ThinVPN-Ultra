// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

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

// caps
#define DS_CAPS_SUPPORT_BLUETOOTH	1			// Bluetooth サポート
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
	bool SupportBluetooth;				// Bluetooth サポート
	SERVER *Server;						// Server オブジェクト (ユーザー認証用)
	bool ForceDisableShare;				// 強制的に共有機能が無効になっているかどうか
	void *EventLog;						// イベントログ
	bool SupportEventLog;				// イベントログをサポートしているかどうか
	LIST *History;						// 接続受付履歴
	LIST *RadiusCacheList;				// Radius キャッシュリスト

#ifdef OS_WIN32
	MS_ISLOCKED *IsLocked;				// ロックされているかどうかの状態管理
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
void DsNormalizeConfig(DS *ds);
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
SOCK *DsConnectToLocalHostService(UINT svc_type, UINT rdp_port);
UINT DsGetRdpPortFromRegistry();
void DsLog(DS *ds, char *name, ...);
void DsLogEx(DS *ds, UINT ds_log_type, char *name, ...);
void DsLogMain(DS *ds, UINT ds_log_type, char *name, va_list args);
void DsSendSyslog(SERVER *s, wchar_t *message);
wchar_t *DsGetLogTypeStr(UINT ds_log_type);
void DsUpdateTaskIcon(DS *ds);
void DsResetCertProc(WIDE *wide, void *param);
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


// RPC Procedures (Server Side)
UINT DtGetInternetSetting(DS *ds, INTERNET_SETTING *t);
UINT DtSetInternetSetting(DS *ds, INTERNET_SETTING *t);
UINT DtGetStatus(DS *ds, RPC_DS_STATUS *t);
UINT DtRegistMachine(DS *ds, RPC_PCID *t);
UINT DtChangePcid(DS *ds, RPC_PCID *t);
UINT DtSetConfig(DS *ds, RPC_DS_CONFIG *t);
UINT DtGetConfig(DS *ds, RPC_DS_CONFIG *t);
UINT DtGetPcidCandidate(DS *ds, RPC_PCID *t);

// RPC Procedures (Client Side)
UINT DtcGetInternetSetting(RPC *r, INTERNET_SETTING *t);
UINT DtcSetInternetSetting(RPC *r, INTERNET_SETTING *t);
UINT DtcGetStatus(RPC *r, RPC_DS_STATUS *t);
UINT DtcRegistMachine(RPC *r, RPC_PCID *t);
UINT DtcChangePcid(RPC *r, RPC_PCID *t);
UINT DtcSetConfig(RPC *r, RPC_DS_CONFIG *t);
UINT DtcGetConfig(RPC *r, RPC_DS_CONFIG *t);
UINT DtcGetPcidCandidate(RPC *r, RPC_PCID *t);



#endif	// DS_H

