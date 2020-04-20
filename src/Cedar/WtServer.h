// WideTunnel Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// WtServer.h
// WtServer.c のヘッダ

#ifndef	WTSERVER_H
#define WTSERVER_H

// 接続パラメータ
struct WT_CONNECT
{
	char HostName[MAX_HOST_NAME_LEN + 1];		// ホスト名
	char HostNameForProxy[MAX_HOST_NAME_LEN + 1];		// ホスト名 Proxy 用
	UINT Port;									// ポート番号
	UINT ProxyType;								// プロキシサーバーの種類
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];	// プロキシサーバーホスト名
	UINT ProxyPort;								// プロキシサーバーポート番号
	char ProxyUsername[MAX_USERNAME_LEN + 1];	// プロキシサーバーユーザー名
	char ProxyPassword[MAX_USERNAME_LEN + 1];	// プロキシサーバーパスワード
	bool UseCompress;							// 圧縮の使用
	bool DontCheckCert;							// 証明書をチェックしない

	// Server が Wide Controller に接続してもらってきたメッセージ
	wchar_t MsgForServer[MAX_SIZE];
	bool MsgForServerOnce;

	// Server 用
	WT_GATE_CONNECT_PARAM *GateConnectParam;	// 接続パラメータ
	char Pcid[MAX_PATH];						// PCID

	// Client 用
	UCHAR SessionId[WT_SESSION_ID_SIZE];		// 接続先セッション ID
	bool CacheUsed;								// キャッシュが使用された
};

// WTS_CONNECT_THREAD_PARAM
struct WTS_CONNECT_THREAD_PARAM
{
	WT *wt;
	WT_CONNECT connect;
	WT_ACCEPT_PROC *proc;
	void *param;
	TSESSION *session;
	UINT Ver, Build;
};

// WTS_NEW_TUNNEL_THREAD_PARAM
struct WTS_NEW_TUNNEL_THREAD_PARAM
{
	TSESSION *Session;
	SOCKIO *SockIo;
};

// 関数プロトタイプ
void WtCopyConnect(WT_CONNECT *dst, WT_CONNECT *src);
void WtFreeConnect(WT_CONNECT *c);
TSESSION *WtsStart(WT *wt, WT_CONNECT *connect, WT_ACCEPT_PROC *proc, void *param);
void WtsConnectThread(THREAD *thread, void *param);
TSESSION *WtsNewSession(THREAD *thread, WT *wt, WT_CONNECT *connect, WT_ACCEPT_PROC *proc, void *param);
void WtsConnectMain(TSESSION *session);
void WtsConnectInner(TSESSION *session, SOCK *s, char *sni);
SOCK *WtSockConnect(WT_CONNECT *param, UINT *error_code, bool proxy_use_alternative_fqdn);
bool WtgClientUploadSignature(SOCK *s);
void WtsSessionMain(TSESSION *session);
void WtsStop(TSESSION *s);
void WtsWaitForSock(TSESSION *s);
void WtsRecvFromGate(TSESSION *s);
void WtsSendToGate(TSESSION *s);
bool WtsCheckDisconnect(TSESSION *s);
TUNNEL *WtsCreateNewTunnel(TSESSION *s, UINT tunnel_id);
void WtsNewTunnelThread(THREAD *thread, void *param);
void WtsInsertSockIosToSendQueue(TSESSION *s);
bool WtInsertSockIoToSendQueue(TTCP *dest_ttcp, QUEUE *q, TUNNEL *t);
bool WtInsertSockIoToSendQueueEx(TTCP *dest_ttcp, QUEUE *q, TUNNEL *t, UINT remain_buf_size);
void WtInitWtConnectFromInternetSetting(WT_CONNECT *c, INTERNET_SETTING	*s);

#endif	// WTSERVER_H

