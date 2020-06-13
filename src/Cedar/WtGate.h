// WideTunnel Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// WtGate.h
// WtGate.c のヘッダ

#ifndef	WTGATE_H
#define WTGATE_H

// WT_GATE_CONNECT_PARAM
struct WT_GATE_CONNECT_PARAM
{
	char Msid[WT_MSID_SIZE];			// MSID
	UINT64 Expires;						// 有効期限
	UCHAR GateId[SHA1_SIZE];			// ゲートウェイ ID
	UCHAR Signature2[SHA1_SIZE];		// 署名
};

// TCP コネクション
struct TTCP
{
	SOCK *Sock;							// ソケット
	char Hostname[MAX_HOST_NAME_LEN + 1];	// ホスト名
	IP Ip;								// IP アドレス
	UINT Port;							// ポート番号
	UINT64 LastCommTime;				// 最終通信日時
	UINT64 LastKeepAliveTime;			// 最終キープアライブ送信日時
	FIFO *RecvFifo;						// 受信バッファ
	FIFO *SendFifo;						// 送信バッファ
	UINT Mode;							// 読み取りモード
	UINT WantSize;						// 要求しているデータサイズ
	UINT CurrentBlockSize;				// 現在のブロックサイズ
	UINT CurrentBlockConnectionId;		// 現在のブロックのコネクション番号
	bool Disconnected;					// 切断状態
	bool UseCompress;					// 圧縮の使用
	bool MultiplexMode;					// 多重化モード
	bool DisconnectSignalReceived;		// 切断信号を受信したかどうか

	UINT TunnelTimeout;
	UINT TunnelKeepAlive;
	bool TunnelUseAggressiveTimeout;
};

// データブロック
struct DATABLOCK
{
	bool Compressed;					// 圧縮されているかどうか
	UINT TunnelId;						// トンネル ID
	void *Data;							// データ本体
	UINT DataSize;						// データサイズ
	UINT PhysicalSize;					// 物理サイズ
};

// トンネル
struct TUNNEL
{
	QUEUE *BlockQueue;					// 送信予定データブロックキュー
	TTCP *ClientTcp;					// クライアントとの間の通信に使う TCP コネクション
	UINT TunnelId;						// トンネル ID
	SOCKIO *SockIo;						// SOCKIO
	bool SetSockIoEventFlag;			// SOCKIO イベントをセットするかどうかのフラグ
	UCHAR ClientId[SHA1_SIZE];			// クライアント ID
};

// セッション
struct TSESSION
{
	LOCK *Lock;
	REF *Ref;
	UINT SessionType;					// セッションの種類
	SOCK_EVENT *SockEvent;				// ソケットイベント
	UINT64 Tick;						// 現在の Tick 値
	void *RecvBuf;						// 受信用バッファ
	QUEUE *BlockQueue;					// サーバーに対する送信予定データブロックキュー
	bool StateChangedFlag;				// 状態変化フラグ

	// Gate 用
	char Msid[WT_MSID_SIZE];			// MSID
	UCHAR SessionId[WT_SESSION_ID_SIZE];	// セッション ID
	UINT64 EstablishedTick;				// セッション確立日時
	TTCP *ServerTcp;					// サーバー側 TCP コネクション
	bool RequestInitialPack;			// 初期化 Pack の要求
	UINT64 ServerMask64;				// Server Mask 64

	// Server 用
	WT *wt;
	THREAD *ConnectThread;				// Gate への接続用スレッド
	WT_ACCEPT_PROC *AcceptProc;			// Accept スレッドプロシージャ
	void *AcceptProcParam;				// 上記のためのパラメータ
	WT_CONNECT *ConnectParam;			// 接続パラメータ
	UINT ErrorCode;						// エラー発生時のエラーコード
	bool Halt;							// 停止フラグ
	LIST *AcceptThreadList;				// ACCEPT したスレッドのリスト
	bool WasConnected;					// 接続されたことがあるかどうか

	// Client 用
	TUNNEL *ClientTunnel;				// トンネル
	THREAD *ClientThread;				// クライアントスレッド

	// Gate / Server 共通
	LIST *TunnelList;					// トンネルリスト
	LIST *UsedTunnelList;				// 使用済みトンネルリスト

	// Client / Server 共通
	TTCP *GateTcp;						// Gate 側 TCP コネクション
	SOCK *Sock;							// ソケット
	IP ServerLocalIP;					// サーバー側で見たローカル IP
};

// HTTP プロキシ
#define	WG_PROXY_TCP_TIMEOUT_SERVER		(60 * 1000)
#define	WG_PROXY_MAX_POST_SIZE			(1024 * 1024)


// 関数プロトタイプ
bool WtGateConnectParamFromPack(WT_GATE_CONNECT_PARAM *g, PACK *p);
BUF *WtGateConnectParamPayloadToBuf(WT_GATE_CONNECT_PARAM *g);
bool WtGateConnectParamCheckSignature(WIDE *wide, WT_GATE_CONNECT_PARAM *g);
void WtGateConnectParamToPack(PACK *p, WT_GATE_CONNECT_PARAM *g);
void WtgStart(WT *wt, X *cert, K *key, UINT port);
void WtgStop(WT *wt);
void WtgAccept(WT *wt, SOCK *s);
bool WtgSendError(SOCK *s, UINT code);
bool WtgDownloadSignature(SOCK *s, bool* check_ssl_ok, char *gate_secret_key, char *entrance_url_for_proxy);
bool WtgUploadHello(WT *wt, SOCK *s, void *session_id);
int WtgCompareSession(void *p1, void *p2);
TSESSION *WtgNewSession(WT *wt, SOCK *sock, char *msid, void *session_id, bool use_compress, bool request_initial_pack, UINT tunnel_timeout, UINT tunnel_keepalive, bool tunnel_use_aggressive_timeout);
void WtReleaseSession(TSESSION *s);
void WtCleanupSession(TSESSION *s);
TTCP *WtNewTTcp(SOCK *s, bool use_compress, UINT tunnel_timeout, UINT tunnel_keepalive, bool tunnel_use_aggressive_timeout);
void WtFreeTTcp(TTCP *ttcp);
int WtgCompareTunnel(void *p1, void *p2);
TUNNEL *WtgSearchTunnelById(LIST *o, UINT id);
TUNNEL *WtNewTunnel(TTCP *client_tcp, UINT tunnel_id, SOCKIO *sockio);
UINT WtgGenerateNewTunnelId(TSESSION *session);
void WtgSessionMain(TSESSION *s);
void WtgDisconnectAllClientSession(TSESSION *s);
void WtgWaitForSock(TSESSION *s);
void WtgRecvFromClient(TSESSION *s);
void WtgRecvFromServer(TSESSION *s);
void WtRecvTTcp(TSESSION *s, TTCP *ttcp);
void WtRecvTTcpEx(TSESSION *s, TTCP *ttcp, UINT remain_buf_size);
UINT WtRecvSock(TTCP *ttcp, void *buf, UINT size);
UINT WtSendSock(TTCP *ttcp, void *buf, UINT size);
QUEUE *WtParseRecvTTcp(TSESSION *s, TTCP *ttcp);
DATABLOCK *WtNewDataBlock(UINT tunnel_id, void *data, UINT size, int compress_flag);
DATABLOCK *WtRebuildDataBlock(DATABLOCK *src_block, int compress_flag);
void WtFreeDataBlock(DATABLOCK *block, bool no_free_data);
void WtgSendToServer(TSESSION *s);
void WtgSendToClient(TSESSION *s);
void WtSendTTcp(TSESSION *s, TTCP *ttcp);
void WtMakeSendDataTTcp(TSESSION *s, TTCP *ttcp, QUEUE *blockqueue);
bool WtgCheckDisconnect(TSESSION *s);
bool WtIsTTcpDisconnected(TSESSION *s, TTCP *ttcp);
void WtFreeDataBlockQueue(QUEUE *q);
void WtDisconnectTTcp(TTCP *ttcp);
void WtFreeTunnel(TUNNEL *t);
void WtFreeTTcp(TTCP *ttcp);
void WtInsertNewBlockToQueue(QUEUE *dest_queue, TTCP *dest_ttcp, UINT src_tunnel_id, void *data, UINT size);
WT_GATE_CONNECT_PARAM *WtCloneGateConnectParam(WT_GATE_CONNECT_PARAM *p);
void WtFreeGateConnectParam(WT_GATE_CONNECT_PARAM *p);
void WtGenerateClientIdFromIP(UCHAR *client_id, IP *ip);
void WtgHttpProxy(char *url_str, SOCK *s, bool ssl, HTTP_HEADER *first_header, char *shared_secret);

#endif	// WTGATE_H



