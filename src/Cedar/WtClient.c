// WideTunnel Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// WtClient.c
// WideTunnel Client

#include "CedarPch.h"

// セッションメイン
void WtcSessionMain(TSESSION *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	MsSetThreadPriorityRealtime();
#endif  // OS_WIN32

	SetSockEvent(s->SockEvent);

	while (true)
	{
		bool disconnected = false;
		TUNNEL *t = s->ClientTunnel;

		// ソケットイベントを待機
		WtcWaitForSocket(s);

		Lock(s->Lock);
		{
			// フラグのリセット
			t->SetSockIoEventFlag = false;

			do
			{
				s->StateChangedFlag = false;

				// Gate からのデータを受信して処理
				WtcRecvFromGate(s);

				// SOCKIO からキューを生成
				WtcInsertSockIosToSendQueue(s);

				// Gate へデータを送信
				WtcSendToGate(s);

				// TCP コネクションの切断の検査
				disconnected = WtcCheckDisconnect(s);

				if (s->Halt)
				{
					disconnected = true;
				}

				if (disconnected)
				{
					break;
				}
			}
			while (s->StateChangedFlag);

			if (t->SetSockIoEventFlag)
			{
				SockIoSetIoEvent(t->SockIo);
			}
		}
		Unlock(s->Lock);

		if (disconnected)
		{
			// セッションを終了する
			break;
		}
	}

	SockIoDisconnect(s->ClientTunnel->SockIo);
}

// TCP コネクションの切断の検査
bool WtcCheckDisconnect(TSESSION *s)
{
	bool ret = false;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	if (WtIsTTcpDisconnected(s, s->GateTcp))
	{
		// Gate との接続が切断された
		ret = true;
//		Debug("Disconnect Tunnel time: %I64u\n", SystemTime64());
	}

	if (SockIoIsConnected(s->ClientTunnel->SockIo) == false)
	{
		// SOCKIO が切断された
		ret = true;
	}

	return ret;
}

// Gate へデータを送信
void WtcSendToGate(TSESSION *s)
{
	TTCP *ttcp;
	QUEUE *blockqueue;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	ttcp = s->GateTcp;
	blockqueue = s->BlockQueue;

	// 送信データの生成
	WtMakeSendDataTTcp(s, ttcp, blockqueue);

	// 送信
	WtSendTTcp(s, ttcp);
}

// SOCKIO からキューを生成
void WtcInsertSockIosToSendQueue(TSESSION *s)
{
	QUEUE *blockqueue;
	TUNNEL *t;
	SOCKIO *sockio;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (FifoSize(s->GateTcp->SendFifo) > WT_WINDOW_SIZE)
	{
		return;
	}

	blockqueue = s->BlockQueue;
	t = s->ClientTunnel;
	sockio = t->SockIo;

	if (WtInsertSockIoToSendQueueEx(s->GateTcp, blockqueue, t, WT_WINDOW_SIZE - FifoSize(s->GateTcp->SendFifo)))
	{
		// s->StateChangedFlag = true;
	}
}

// Gate からのデータを受信して処理
void WtcRecvFromGate(TSESSION *s)
{
	TTCP *ttcp;
	QUEUE *q;
	DATABLOCK *block;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	ttcp = s->GateTcp;

	// TTCP からデータを受信
	WtRecvTTcp(s, ttcp);

	// 受信データを解釈
	q = WtParseRecvTTcp(s, ttcp);

	// 受信データを SOCKIO に対して配信
	while ((block = GetNext(q)) != NULL)
	{
		SOCKIO *sockio;
		TUNNEL *t = s->ClientTunnel;
		FIFO *fifo;

		sockio = t->SockIo;

		if (block->DataSize != 0)
		{
			// データあり
			fifo = SockIoGetRecvFifo(sockio);

			WriteFifo(fifo, block->Data, block->DataSize);

			SockIoReleaseFifo(fifo);
		}

		WtFreeDataBlock(block, false);

		t->SetSockIoEventFlag = true;
	}

	ReleaseQueue(q);
}

// ソケットイベントを待機
void WtcWaitForSocket(TSESSION *s)
{
	SOCK *sock;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	sock = s->Sock;
	JoinSockToSockEvent(sock, s->SockEvent);

	WaitSockEvent(s->SockEvent, SELECT_TIME);

	s->Tick = Tick64();
}

// 新しいクライアントセッションの作成
TSESSION *WtcNewSession(WT *wt, SOCK *s)
{
	TSESSION *t;
	SOCKIO *sockio;
	// 引数チェック
	if (wt == NULL || s == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TSESSION));
	t->Lock = NewLock();
	t->Ref = NewRef();
	t->SessionType = WT_SESSION_CLIENT;
	t->wt = wt;

	t->SockEvent = NewSockEvent();
	t->RecvBuf = Malloc(RECV_BUF_SIZE);
	t->BlockQueue = NewQueue();

	sockio = NewSockIo(t->SockEvent, NULL);
	t->ClientTunnel = WtNewTunnel(NULL, 0, sockio);
	ReleaseSockIo(sockio);

	t->Sock = s;
	AddRef(s->ref);

	return t;
}

// 接続
UINT WtcConnect(WT *wt, WT_CONNECT *connect, SOCKIO **sockio)
{
	return WtcConnectEx(wt, connect, sockio, 0, 0);
}
UINT WtcConnectEx(WT *wt, WT_CONNECT *connect, SOCKIO **sockio, UINT ver, UINT build)
{
	TSESSION *session;
	SOCK *s;
	UINT code;
	PACK *p;
	THREAD *thread;
	UINT zero = 0;
	SYSTEMTIME tm;
	UINT tunnel_timeout = WT_TUNNEL_TIMEOUT;
	UINT tunnel_keepalive = WT_TUNNEL_KEEPALIVE;
	bool tunnel_use_aggressive_timeout = false;

	// 引数チェック
	if (wt == NULL || connect == NULL || sockio == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Gate に接続
	s = WtSockConnect(connect, &code);
	if (s == NULL)
	{
		// 失敗
		return code;
	}

	//SetSocketSendRecvBufferSize((int)s, WT_SOCKET_WINDOW_SIZE);

	SetTimeout(s, CONNECTING_TIMEOUT);

	// SSL 通信の開始
	if (StartSSLEx(s, NULL, NULL, true, 0, connect->HostName) == false)
	{
		// 失敗
		Debug("StartSSL Failed.\n");
		Disconnect(s);
		ReleaseSock(s);
		return ERR_PROTOCOL_ERROR;
	}

	SystemTime(&tm);

	if (connect->DontCheckCert == false)
	{
		// 証明書のチェック
		if (WtIsTrustedCert(wt, s->RemoteX) == false)
		{
			// 失敗
			Debug("WtIsTrustedCert Failed.\n");
			Disconnect(s);
			ReleaseSock(s);
			return ERR_SSL_X509_UNTRUSTED;
		}
	}

	// シグネチャのアップロード
	if (WtgClientUploadSignature(s) == false)
	{
		// 失敗
		Debug("WtgClientUploadSignature Failed.\n");
		Disconnect(s);
		ReleaseSock(s);
		return ERR_DISCONNECTED;
	}

	// Hello パケットのダウンロード
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		// 失敗
		Debug("HttpClientRecv Failed.\n");
		Disconnect(s);
		ReleaseSock(s);
		return ERR_DISCONNECTED;
	}
	if (PackGetInt(p, "hello") == 0)
	{
		// 失敗
		Debug("HttpClientRecv Failed.\n");
		FreePack(p);
		Disconnect(s);
		ReleaseSock(s);
		return ERR_PROTOCOL_ERROR;
	}
	FreePack(p);

	// 接続パラメータの送信
	p = NewPack();
	if (wt->Wide != NULL)
	{
		PackAddData(p, "client_id", wt->Wide->ClientId, sizeof(wt->Wide->ClientId));
	}
	PackAddStr(p, "method", "connect_session");
	PackAddBool(p, "use_compress", connect->UseCompress);
	PackAddData(p, "session_id", connect->SessionId, WT_SESSION_ID_SIZE);
	PackAddInt(p, "ver", ver);
	PackAddInt(p, "build", build);
	PackAddBool(p, "support_timeout_param", true);
	if (wt->Wide != NULL)
	{
		PackAddInt(p, "se_lang", wt->Wide->SeLang);
	}
	if (HttpClientSend(s, p) == false)
	{
		// 失敗
		Debug("HttpClientRecv Failed.\n");
		FreePack(p);
		Disconnect(s);
		ReleaseSock(s);
		return ERR_DISCONNECTED;
	}
	FreePack(p);

	// 結果の受信
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		// 失敗
		Debug("HttpClientRecv Failed.\n");
		Disconnect(s);
		ReleaseSock(s);
		return ERR_DISCONNECTED;
	}

	code = PackGetInt(p, "code");
	if (code != ERR_NO_ERROR)
	{
		Debug("Gate Error: %u\n", code);
		// エラー発生
		FreePack(p);
		Disconnect(s);
		ReleaseSock(s);
		return code;
	}

	{
		UINT tunnel_timeout2 = PackGetInt(p, "tunnel_timeout");
		UINT tunnel_keepalive2 = PackGetInt(p, "tunnel_keepalive");
		bool tunnel_use_aggressive_timeout2 = PackGetBool(p, "tunnel_use_aggressive_timeout");
		if (tunnel_timeout2 && tunnel_keepalive2)
		{
			tunnel_timeout = tunnel_timeout2;
			tunnel_keepalive = tunnel_keepalive2;
			tunnel_use_aggressive_timeout = tunnel_use_aggressive_timeout2;
		}
	}

	FreePack(p);

	SetTimeout(s, TIMEOUT_INFINITE);

	session = WtcNewSession(wt, s);
	*sockio = session->ClientTunnel->SockIo;
	AddRef((*sockio)->Ref);

	session->GateTcp = WtNewTTcp(s, connect->UseCompress, tunnel_timeout, tunnel_keepalive, tunnel_use_aggressive_timeout);

	thread = NewThread(WtcSessionMainThread, session);
	WaitThreadInit(thread);
	ReleaseThread(thread);

	ReleaseSock(s);

	SockIoSendAll(*sockio, &zero, sizeof(UINT));

	return ERR_NO_ERROR;
}

// セッションのメイン処理を行うスレッド
void WtcSessionMainThread(THREAD *thread, void *param)
{
	TSESSION *session;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	session = (TSESSION *)param;

	AddSockThread(session->wt->SockThreadList, session->Sock, thread);
	NoticeThreadInit(thread);

	WtcSessionMain(session);

	WtReleaseSession(session);
}

// クライアントサービスの開始
void WtcStart(WT *wt)
{
	// 引数チェック
	if (wt == NULL)
	{
		return;
	}

	wt->SockThreadList = NewSockThreadList();
}

// クライアントサービスの停止
void WtcStop(WT *wt)
{
	// 引数チェック
	if (wt == NULL)
	{
		return;
	}

	FreeSockThreadList(wt->SockThreadList);
	wt->SockThreadList = NULL;
}


