// WideTunnel Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// WtWpc.h
// WtWpc.c のヘッダ

#ifndef	WTWPC_H
#define WTWPC_H

// 定数
#define WPC_HTTP_POST_NAME			"POST"		// POST
#define WPC_HTTP_GET_NAME			"GET"		// GET
#define WPC_USER_AGENT				DEFAULT_USER_AGENT	// User Agent
#define WPC_TIMEOUT					(15 * 1000)	// タイムアウト
#define WPC_RECV_BUF_SIZE			64000		// 受信バッファサイズ
#define WPC_DATA_ENTRY_SIZE			4			// データエントリサイズ
#define WPC_MAX_HTTP_DATASIZE		(134217728)	// 最大の HTTP データサイズ
//
//// インターネット接続設定
//struct INTERNET_SETTING
//{
//	UINT ProxyType;								// プロキシサーバーの種類
//	char ProxyHostName[MAX_HOST_NAME_LEN + 1];	// プロキシサーバーホスト名
//	UINT ProxyPort;								// プロキシサーバーポート番号
//	char ProxyUsername[MAX_USERNAME_LEN + 1];	// プロキシサーバーユーザー名
//	char ProxyPassword[MAX_USERNAME_LEN + 1];	// プロキシサーバーパスワード
//};
//
//// URL
//struct URL_DATA
//{
//	bool Secure;							// HTTPS かどうか
//	char HostName[MAX_HOST_NAME_LEN + 1];	// ホスト名
//	UINT Port;								// ポート番号
//	char HeaderHostName[MAX_HOST_NAME_LEN + 16];	// ヘッダ上でのホスト名
//	char Method[32];						// メソッド
//	char Target[MAX_SIZE * 3];				// ターゲット
//	char Referer[MAX_SIZE * 3];				// Referer
//};
//
//// WPC エントリ
//struct WPC_ENTRY
//{
//	char EntryName[WPC_DATA_ENTRY_SIZE];		// エントリ名
//	void *Data;									// データ
//	UINT Size;									// データサイズ
//};
//
//// WPC パケット
//struct WPC_PACKET
//{
//	PACK *Pack;								// Pack (データ本体)
//	UCHAR Hash[SHA1_SIZE];					// データハッシュ
//	X *Cert;								// 証明書
//	UCHAR Sign[128];						// 電子署名
//};

//// 受信コールバック
//typedef bool (WPC_RECV_CALLBACK)(void *param, UINT total_size, UINT current_size, BUF *recv_buf);

// 関数プロトタイプ
//void EncodeSafe64(char *dst, void *src, UINT src_size);
//UINT DecodeSafe64(void *dst, char *src, UINT src_strlen);
//void Base64ToSafe64(char *str);
//void Safe64ToBase64(char *str);
//bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer);
//void CreateUrl(char *url, UINT url_size, URL_DATA *data);
//void GetSystemInternetSetting(INTERNET_SETTING *setting);
//bool GetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type);
//BUF *HttpRequest(WT *wt, URL_DATA *data, INTERNET_SETTING *setting,
//				UINT *error_code, bool check_ssl_trust, char *post_data,
//				WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param);
//INTERNET_SETTING *GetNullInternetSetting();
//void WpcAddDataEntry(BUF *b, char *name, void *data, UINT size);
//void WpcAddDataEntryBin(BUF *b, char *name, void *data, UINT size);
//void WpcFillEntryName(char *dst, char *name);
//LIST *WpcParseDataEntry(BUF *b);
//void WpcFreeDataEntryList(LIST *o);
//WPC_ENTRY *WpcFindDataEntry(LIST *o, char *name);
//BUF *WpcDataEntryToBuf(WPC_ENTRY *e);
//BUF *WpcGeneratePacket(PACK *pack, X *cert, K *key);
//bool WpcParsePacket(WPC_PACKET *packet, BUF *buf);
//void WpcFreePacket(WPC_PACKET *packet);
//PACK *WpcCall(WT *wt, char *function_name, PACK *pack, X *cert, K *key);

SOCK *WtSockConnectHttpProxy(WT_CONNECT *param, char *target, UINT *error_code);
void WtSetEntranceUrl(WT *wt, char *url);
void WtGetEntranceUrl(WT *wt, char *url, UINT url_size);
void WtSetInternetSetting(WT *wt, INTERNET_SETTING *setting);
void WtGetInternetSetting(WT *wt, INTERNET_SETTING *setting);
PACK *WpcDownloadPack(WT *wt, char *url, BUF **buf);
bool WpcDownloadNoderef(WT *wt, char *url, BUF **buf, char *entrance, UINT entrance_size, UINT64 *timestamp, UINT *error);
//bool WpcLoadNoderefCache(WT *wt, BUF **buf, char *entrance, UINT entrance_size, UINT64 *timestamp);
//void WtGenerateNoderefCacheFilename(char *name, UINT size);
void WtShuffleArray(void **p, UINT num);
LIST *WtLoadNodeRefUrlList();
void WtFreeNodeRefUrlList(LIST *o);
bool WtParseNodeRef(WT *wt, PACK *p, char *entrance, UINT entrance_size, UINT64 *timestamp);
PACK *WtGetPackFromBuf(WT *wt, BUF *buf);
UINT WpcGetEntranceUrl(WT *wt, char *entrance, UINT entrance_size);
UINT WpcGetEntranceUrlEx(WT *wt, char *entrance, UINT entrance_size, UINT cache_expires);
bool WpcGetEntranceUrlFromLocalFile(WT *wt, char *entrance, UINT entrance_size);
UINT WpcCommCheck(WT *wt);
void WtSetDefaultEntranceUrlCacheExpireSpan(WT *wt, UINT span);

PACK *WtWpcCall(WT *wt, char *function_name, PACK *pack, X *cert, K *key, bool global_ip_only);

#endif	// WTWPC_H


