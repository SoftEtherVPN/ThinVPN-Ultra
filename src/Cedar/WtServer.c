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


// WtServer.c
// WideTunnel Server

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

// セッションメイン
void WtsSessionMain(TSESSION *s)
{
	UINT i;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// 現在の接続先 Gate の情報を取得
	if (s->Sock != NULL)
	{
		IPToStr(s->wt->CurrentGateIp, sizeof(s->wt->CurrentGateIp), &s->Sock->RemoteIP);

		if (s->ConnectParam != NULL)
		{
			StrCpy(s->wt->CurrentGateIp, sizeof(s->wt->CurrentGateIp), s->ConnectParam->HostName);
		}

		WtSessionLog(s, "s->wt->CurrentGateIp = %s", s->wt->CurrentGateIp);
	}

#ifdef	OS_WIN32
	MsSetThreadPriorityRealtime();
#endif  // OS_WIN32

	SetSockEvent(s->SockEvent);

	WtSessionLog(s, "WtsSessionMain: Start main loop");

	while (true)
	{
		bool disconnected = false;

		// ソケットイベントを待機
		WtsWaitForSock(s);

		Lock(s->Lock);
		{
			UINT i;

			// フラグのリセット
			for (i = 0;i < LIST_NUM(s->TunnelList);i++)
			{
				TUNNEL *t = LIST_DATA(s->TunnelList, i);

				t->SetSockIoEventFlag = false;
			}

			do
			{
				s->StateChangedFlag = false;

				// Gate からのデータを受信して処理
				WtsRecvFromGate(s);

				// SOCKIO からキューを生成
				WtsInsertSockIosToSendQueue(s);

				// Gate へデータを送信
				WtsSendToGate(s);

				// TCP コネクションの切断の検査
				disconnected = WtsCheckDisconnect(s);

				if (disconnected)
				{
					break;
				}
			}
			while (s->StateChangedFlag);

			if (s->Halt)
			{
				WtSessionLog(s, "WtsSessionMain: Main loop: s->Halt == true. Exiting...");
				disconnected = true;
			}

			// 状態が変化した SOCKIO に対してイベントをセット
			for (i = 0;i < LIST_NUM(s->TunnelList);i++)
			{
				TUNNEL *t = LIST_DATA(s->TunnelList, i);

				if (t->SetSockIoEventFlag)
				{
					SockIoSetIoEvent(t->SockIo);
				}
			}
		}
		Unlock(s->Lock);

		if (disconnected)
		{
			// Gate との接続が切断されたのでセッションを終了する
			break;
		}
	}

	WtSessionLog(s, "WtsSessionMain: Exit main loop");

	// 接続先 Gate 情報を消去する
	ClearStr(s->wt->CurrentGateIp, sizeof(s->wt->CurrentGateIp));

	// すべての SOCKIO の切断
	for (i = 0;i < LIST_NUM(s->TunnelList);i++)
	{
		TUNNEL *t = LIST_DATA(s->TunnelList, i);

		SockIoDisconnect(t->SockIo);
	}
}

// SOCKIO からキューを生成
void WtsInsertSockIosToSendQueue(TSESSION *s)
{
	QUEUE *blockqueue;
	UINT i;
	LIST *o = NULL;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	blockqueue = s->BlockQueue;

	for (i = 0;i < LIST_NUM(s->TunnelList);i++)
	{
		TUNNEL *t = LIST_DATA(s->TunnelList, i);
		SOCKIO *sockio;

		sockio = t->SockIo;

		if (FifoSize(s->GateTcp->SendFifo) <= WT_WINDOW_SIZE)
		{
			if (WtInsertSockIoToSendQueueEx(s->GateTcp, blockqueue, t,
				WT_WINDOW_SIZE - FifoSize(s->GateTcp->SendFifo)))
			{
				// s->StateChangedFlag = true;
			}
		}

		if (SockIoIsConnected(sockio) == false)
		{
			// SOCKIO が切断された
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Insert(o, t);
		}
	}

	// SOCKIO が切断されたトンネルを解放する
	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			TUNNEL *t = LIST_DATA(o, i);
			UINT tunnel_id = t->TunnelId;
			DATABLOCK *b;

			b = WtNewDataBlock(tunnel_id, NULL, 0, s->GateTcp->UseCompress ? 1 : 0);
			InsertQueue(s->BlockQueue, b);

			WtSessionLog(s, "Tunnel Id %u: Disconnected", tunnel_id);

			WtFreeTunnel(t);
//			Debug("WtFreeTunnel: %u\n", tunnel_id);

			Delete(s->TunnelList, t);

			WtAddUsedTunnelId(s->UsedTunnelList, tunnel_id, WT_TUNNEL_USED_EXPIRES);
		}

		ReleaseList(o);
	}
}

// SOCKIO から送信されてきたデータをキューに入れる
bool WtInsertSockIoToSendQueue(TTCP *dest_ttcp, QUEUE *q, TUNNEL *t)
{
	return WtInsertSockIoToSendQueueEx(dest_ttcp, q, t, INFINITE);
}
bool WtInsertSockIoToSendQueueEx(TTCP *dest_ttcp, QUEUE *q, TUNNEL *t, UINT remain_buf_size)
{
	SOCKIO *sockio;
	UINT tunnel_id;
	FIFO *fifo;
	bool ret = false;
	// 引数チェック
	if (q == NULL || t == NULL)
	{
		return false;
	}

	sockio = t->SockIo;
	tunnel_id = t->TunnelId;

	fifo = SockIoGetSendFifo(sockio);

	while (true)
	{
		UCHAR *buf;
		UINT read_size;
		DATABLOCK *b;
		void *tmp;

		read_size = MIN(MIN(fifo->size, WT_DEFAULT_BLOCK_SIZE), remain_buf_size);
		if (read_size == 0)
		{
			break;
		}

		buf = (UCHAR *)fifo->p + fifo->pos;

		tmp = Clone(buf, read_size);
		b = WtNewDataBlock(tunnel_id, tmp, read_size, dest_ttcp->UseCompress ? 1 : 0);

		InsertQueue(q, b);

		ReadFifo(fifo, NULL, read_size);

		t->SetSockIoEventFlag = true;

		ret = true;
	}

	SockIoReleaseFifo(fifo);

	return ret;
}

// Gate へデータを送信
void WtsSendToGate(TSESSION *s)
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

// Gate からのデータを受信して処理
void WtsRecvFromGate(TSESSION *s)
{
	TTCP *ttcp;
	QUEUE *q;
	DATABLOCK *block;
	UINT last_tid1 = INFINITE;
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
		UINT tunnel_id = block->TunnelId;
		TUNNEL *t = WtgSearchTunnelById(s->TunnelList, tunnel_id);
		SOCKIO *sockio;
		FIFO *fifo;

		if (t == NULL)
		{
			if (WtIsTunnelIdExistsInUsedTunnelIdList(s->UsedTunnelList, tunnel_id))
			{
				WtSessionLog(s, "WtIsTunnelIdExistsInUsedTunnelIdList hit. tunnel_id = %u", tunnel_id);
				// TODO: 最近切断されてから一定時間が経過していないトンネル ID 宛
				// の通信が来たので切断指令を返信する
				if (last_tid1 != tunnel_id)
				{
					DATABLOCK *b = WtNewDataBlock(tunnel_id, NULL, 0, ttcp->UseCompress ? 1 : 0);
					InsertQueue(s->BlockQueue, b);
					last_tid1 = tunnel_id;
				}
				WtFreeDataBlock(block, false);
				continue;
			}

			// まだ確立されていない新しいトンネル宛にデータが届いたので
			// 新しいトンネルを確立する
			WtSessionLog(s, "WtsCreateNewTunnel: tunnel_id = %u");
			t = WtsCreateNewTunnel(s, tunnel_id);
		}

		sockio = t->SockIo;

		if (block->DataSize != 0)
		{
			// データあり
			fifo = SockIoGetRecvFifo(sockio);

			WriteFifo(fifo, block->Data, block->DataSize);

			SockIoReleaseFifo(fifo);
		}
		else
		{
			// データ無し (切断指示を受信した)
//			Debug("Disconnect Tunnel: %u, time: %I64u\n", tunnel_id, SystemTime64());
			if (SockIoDisconnect(t->SockIo))
			{
				WtSessionLog(s, "Tunnel ID %u: Received the disconnect command from the Gate", tunnel_id);
			}
		}

		WtFreeDataBlock(block, false);

		t->SetSockIoEventFlag = true;
	}

	ReleaseQueue(q);
}

// 新しいトンネルのスレッド
void WtsNewTunnelThread(THREAD *thread, void *param)
{
	WTS_NEW_TUNNEL_THREAD_PARAM *p = (WTS_NEW_TUNNEL_THREAD_PARAM *)param;
	TSESSION *s;
	UINT zero;
	UCHAR *buffer;
	UINT buffer_size = WT_INITIAL_PACK_SIZE;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	s = p->Session;

	LockList(s->AcceptThreadList);
	{
		Insert(s->AcceptThreadList, thread);
		AddRef(thread->ref);
	}
	UnlockList(s->AcceptThreadList);

	NoticeThreadInit(thread);

	buffer = ZeroMalloc(buffer_size);
	if (SockIoRecvAll(p->SockIo, buffer, buffer_size))
	{
		BUF *buf = NewBuf();
		PACK *pack;

		WriteBuf(buf, buffer, buffer_size);
		SeekBuf(buf, 0, 0);

		pack = BufToPack(buf);

		FreeBuf(buf);

		p->SockIo->InitialPack = pack;

		{
			char tmp[MAX_PATH] = CLEAN;
			PackGetStr(pack, "ClientHost", tmp, sizeof(tmp));
			WtSessionLog(s, "New Tunnel ID %u: ClientHost: %s", p->TunnelId, tmp);
		}
	}

	Free(buffer);

	SockIoRecvAll(p->SockIo, &zero, sizeof(UINT));

	CopyIP(&p->SockIo->ServerLocalIP, &p->Session->ServerLocalIP);

	WtSessionLog(s, "Tunnel ID Start AcceptProc(): %u", p->TunnelId);
	p->Session->AcceptProc(thread, p->SockIo, p->Session->AcceptProcParam);
	WtSessionLog(s, "Tunnel ID Exit AcceptProc(): %u", p->TunnelId);

	SockIoDisconnect(p->SockIo);

	LockList(s->AcceptThreadList);
	{
		if (Delete(s->AcceptThreadList, thread))
		{
			ReleaseThread(thread);
		}
	}
	UnlockList(s->AcceptThreadList);

	ReleaseSockIo(p->SockIo);
	WtReleaseSession(p->Session);
	Free(p);
}

// 新しいトンネルを確立する
TUNNEL *WtsCreateNewTunnel(TSESSION *s, UINT tunnel_id)
{
	TUNNEL *t;
	SOCKIO *sockio;
	THREAD *thread;
	WTS_NEW_TUNNEL_THREAD_PARAM *p;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

//	Debug("WtsCreateNewTunnel %u\n", tunnel_id);

	sockio = NewSockIo(s->SockEvent, NULL);
	SockIoSetMaxSendBufferSize(sockio, WT_WINDOW_SIZE);

	p = ZeroMalloc(sizeof(WTS_NEW_TUNNEL_THREAD_PARAM));
	p->Session = s;
	p->SockIo = sockio;
	p->TunnelId = tunnel_id;
	AddRef(s->Ref);

	thread = NewThread(WtsNewTunnelThread, p);

	WaitThreadInit(thread);

	ReleaseThread(thread);

	t = WtNewTunnel(NULL, tunnel_id, sockio);

	Insert(s->TunnelList, t);

	return t;
}

// TCP コネクションの切断の検査
bool WtsCheckDisconnect(TSESSION *s)
{
	bool ret = false;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	if (WtIsTTcpDisconnected(s, s->GateTcp))
	{
		// サーバーとの接続が切断された
		ret = true;
	}

	return ret;
}

// ソケットイベントを待機
void WtsWaitForSock(TSESSION *s)
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

// 接続処理
void WtsConnectInner(TSESSION *session, SOCK *s, char *sni, bool *should_retry_proxy_alternative)
{
	WT *wt;
	PACK *p;
	UINT code;
	SYSTEMTIME tm;
	UINT tunnel_timeout = WT_TUNNEL_TIMEOUT;
	UINT tunnel_keepalive = WT_TUNNEL_KEEPALIVE;
	bool tunnel_use_aggressive_timeout = false;
	bool dummy = false;

	// 引数チェック
	if (session == NULL || s == NULL)
	{
		return;
	}

	if (should_retry_proxy_alternative == NULL)
	{
		should_retry_proxy_alternative = &dummy;
	}

	*should_retry_proxy_alternative = false;

	wt = session->wt;

	SetTimeout(s, CONNECTING_TIMEOUT);

	//SetSocketSendRecvBufferSize((int)s, WT_SOCKET_WINDOW_SIZE);

	// SSL 通信の開始
	if (StartSSLEx(s, NULL, NULL, true, 0, sni) == false)
	{
		// 失敗
		WtSessionLog(session, "StartSSL Failed.");
		session->ErrorCode = ERR_PROTOCOL_ERROR;
		*should_retry_proxy_alternative = true;
		return;
	}

	SystemTime(&tm);

	if (session->ConnectParam->DontCheckCert == false)
	{
		// 証明書のチェック
		if (WtIsTrustedCert(wt, s->RemoteX) == false)
		{
			// 失敗
			WtSessionLog(session, "WtIsTrustedCert Failed.");
			session->ErrorCode = ERR_SSL_X509_UNTRUSTED;

			*should_retry_proxy_alternative = true;
			return;
		}
	}

	// シグネチャのアップロード
	if (WtgClientUploadSignature(s) == false)
	{
		// 失敗
		WtSessionLog(session, "ClientUploadSignature Failed.");
		session->ErrorCode = ERR_DISCONNECTED;
		return;
	}

	// Hello パケットのダウンロード
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		// 失敗
		WtSessionLog(session, "HttpClientRecv Failed.");
		session->ErrorCode = ERR_DISCONNECTED;
		return;
	}
	if (PackGetInt(p, "hello") == 0)
	{
		// 失敗
		WtSessionLog(session, "PackGetInt Failed.");
		FreePack(p);
		session->ErrorCode = ERR_PROTOCOL_ERROR;
		return;
	}
	FreePack(p);

	// 接続パラメータの送信
	p = NewPack();
	PackAddStr(p, "method", "new_session");
	PackAddBool(p, "request_initial_pack", true);
	WtGateConnectParamToPack(p, session->ConnectParam->GateConnectParam);
	PackAddBool(p, "use_compress", session->ConnectParam->UseCompress);
	PackAddBool(p, "support_timeout_param", true);
	PackAddInt(p, "build", CEDAR_BUILD);
	PackAddInt(p, "ver", CEDAR_VER);
	PackAddStr(p, "name_suite", DESK_PRODUCT_NAME_SUITE);
	if (wt->Wide != NULL)
	{
		PackAddInt(p, "se_lang", wt->Wide->SeLang);
		PackAddInt64(p, "server_mask_64", wt->Wide->ServerMask64);
	}
	if (HttpClientSend(s, p) == false)
	{
		// 失敗
		WtSessionLog(session, "HttpClientSend Failed.");
		FreePack(p);
		session->ErrorCode = ERR_DISCONNECTED;
		return;
	}
	FreePack(p);

	// 結果の受信
	p = HttpClientRecv(s);
	if (p == NULL)
	{
		WtSessionLog(session, "HttpClientRecv Failed.");
		session->ErrorCode = ERR_DISCONNECTED;
		return;
	}

	code = PackGetInt(p, "code");
	if (code != ERR_NO_ERROR)
	{
		WtSessionLog(session, "Gate Error: %u", code);
		// エラー発生
		FreePack(p);
		session->ErrorCode = code;
		return;
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

	session->GateTcp = WtNewTTcp(s, session->ConnectParam->UseCompress, tunnel_timeout, tunnel_keepalive, tunnel_use_aggressive_timeout);
	session->GateTcp->MultiplexMode = true;

	SetTimeout(s, TIMEOUT_INFINITE);

	CopyIP(&session->ServerLocalIP, &s->LocalIP);

	WtSessionLog(session, "Connected. LocalIP = %r", &session->ServerLocalIP);

	session->WasConnected = true;

	WtsSessionMain(session);
}

// シグネチャをアップロードする
bool WtgClientUploadSignature(SOCK *s)
{
	HTTP_HEADER *h;
	UINT water_size, rand_size;
	UCHAR *water;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	h = NewHttpHeader("POST", HTTP_WIDE_TARGET2, "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE3));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));

	// 透かしの生成
	rand_size = Rand32() % (HTTP_PACK_RAND_SIZE_MAX * 2);
	water_size = SizeOfWaterMark() + rand_size;
	water = Malloc(water_size);
	Copy(water, GetWaterMark(), SizeOfWaterMark());
	Rand(&water[SizeOfWaterMark()], rand_size);

	// 透かしデータのアップロード
	if (PostHttp(s, h, water, water_size) == false)
	{
		Free(water);
		FreeHttpHeader(h);
		return false;
	}

	Free(water);
	FreeHttpHeader(h);

	return true;
}

// 接続メイン
void WtsConnectMain(TSESSION *session)
{
	SOCK *s;
	UINT err = 0;
	char *sni = NULL;
	WT_CONNECT *connect = session->ConnectParam;
	bool should_retry_proxy_alternative = false;
	bool is_proxy_alternative_fqdn = false;
	// 引数チェック
	if (session == NULL || session->ConnectParam == NULL)
	{
		return;
	}

	WtSessionLog(session, "WtsConnectMain Start.");

	sni = connect->HostName;

	// Gate に接続
	s = WtSockConnect(connect, &err, false);
	if (s == NULL)
	{
		// 失敗
		WtSessionLog(session, "WtSockConnect Failed.");

		if (connect->ProxyType == PROXY_HTTP && err != ERR_PROXY_CONNECT_FAILED &&
			IsEmptyStr(connect->HostNameForProxy) == false && StrCmpi(connect->HostNameForProxy, connect->HostName) != 0)
		{
L_PROXY_RETRY_WITH_ALTERNATIVE_FQDN:
			// HTTP プロキシサーバーの場合で単純プロキシサーバー接続不具合以外
			// の場合は、接続先接続先を HostNameForProxy にして再試行する
			WtSessionLog(session, "WtsConnectMain: Try 1");

			s = WtSockConnect(connect, &err, true);

			if (s == NULL)
			{
				WtSessionLog(session, "WtSockConnect Failed 2. %u", err);
				session->ErrorCode = err;
				return;
			}

			sni = connect->HostNameForProxy;

			is_proxy_alternative_fqdn = true;
		}
		else
		{
			session->ErrorCode = err;
			return;
		}
	}

	WtSessionLog(session, "WtSockConnect Ok.");

	session->Sock = s;
	AddRef(s->ref);

	// 接続処理
	should_retry_proxy_alternative = false;

	WtSessionLog(session, "Begin WtsConnectInner()");

	WtsConnectInner(session, s, sni, &should_retry_proxy_alternative);

	WtSessionLog(session, "End WtsConnectInner()");

	Disconnect(s);
	ReleaseSock(s);

	if (should_retry_proxy_alternative && is_proxy_alternative_fqdn == false && connect->ProxyType == PROXY_HTTP && IsEmptyStr(connect->HostNameForProxy) == false && StrCmpi(connect->HostNameForProxy, connect->HostName) != 0)
	{
		// HTTP プロキシサーバーの場合で単純プロキシサーバー接続不具合以外
		// の場合は、接続先接続先を HostNameForProxy にして再試行する
		session->Sock = NULL;

		WtSessionLog(session, "WtsConnectMain: Try 0 error");

		Disconnect(s);
		ReleaseSock(s);
		s = NULL;
		goto L_PROXY_RETRY_WITH_ALTERNATIVE_FQDN;
	}
}

// ソケット接続
SOCK *WtSockConnect(WT_CONNECT *param, UINT *error_code, bool proxy_use_alternative_fqdn)
{
	CONNECTION c;
	SOCK *sock;
	UINT err = ERR_NO_ERROR;
	// 引数チェック
	if (param == NULL)
	{
		return NULL;
	}

	Zero(&c, sizeof(c));

	sock = NULL;
	err = ERR_INTERNAL_ERROR;

	switch (param->ProxyType)
	{
	case PROXY_DIRECT:
		sock = TcpIpConnectEx(param->HostName, param->Port, false, false, NULL, true, false, false, NULL);
		if (sock == NULL)
		{
			err = ERR_CONNECT_FAILED;
		}
		break;

	case PROXY_HTTP:
		sock = ProxyConnectEx2(&c, param->ProxyHostName, param->ProxyPort,
			(proxy_use_alternative_fqdn ? param->HostNameForProxy :  param->HostName), param->Port,
			param->ProxyUsername, param->ProxyPassword, false, NULL, NULL, 0, param->ProxyUserAgent);
		if (sock == NULL)
		{
			err = c.Err;
		}
		break;

	case PROXY_SOCKS:
		sock = SocksConnect(&c, param->ProxyHostName, param->ProxyPort,
			param->HostName, param->Port,
			param->ProxyUsername, false);
		if (sock == NULL)
		{
			err = c.Err;
		}
		break;
	}

	if (error_code != NULL)
	{
		*error_code = err;
	}

	return sock;
}

// サーバーセッションの作成
TSESSION *WtsNewSession(THREAD *thread, WT *wt, WT_CONNECT *connect, WT_ACCEPT_PROC *proc, void *param)
{
	TSESSION *t;
	// 引数チェック
	if (thread == NULL || wt == NULL || connect == NULL || proc == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TSESSION));
	Format(t->ServerSessionName, sizeof(t->ServerSessionName), "TSESSION_%04u", ++wt->ServerSessionNameSeed);
	t->Lock = NewLock();
	t->Ref = NewRef();
	t->SessionType = WT_SESSION_SERVER;
	t->ConnectThread = thread;
	AddRef(thread->ref);
	t->AcceptProc = proc;
	t->AcceptProcParam = param;
	t->wt = wt;
	t->ConnectParam = ZeroMalloc(sizeof(WT_CONNECT));
	WtCopyConnect(t->ConnectParam, connect);

	t->SockEvent = NewSockEvent();
	t->RecvBuf = Malloc(RECV_BUF_SIZE);
	t->TunnelList = NewList(WtgCompareTunnel);
	t->BlockQueue = NewQueue();

	t->AcceptThreadList = NewList(NULL);
	t->UsedTunnelList = WtNewUsedTunnelIdList();

	WtLogEx(wt, t->ServerSessionName, "WtsNewSession: Create New Server Session: HostName = %s, HostNameForProxy = %s, Port = %u, "
		"ProxyType = %u, ProxyHostName = %s, ProxyPort = %u, ProxyUsername = %s, ProxyUserAgent = %s",
		connect->HostName, connect->HostNameForProxy, connect->Port, connect->ProxyType,
		connect->ProxyHostName, connect->ProxyPort, connect->ProxyUsername, connect->ProxyUserAgent);

	return t;
};

// Gate への接続スレッド
void WtsConnectThread(THREAD *thread, void *param)
{
	WTS_CONNECT_THREAD_PARAM *p;
	TSESSION *session;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	p = (WTS_CONNECT_THREAD_PARAM *)param;

	session = WtsNewSession(thread, p->wt, &p->connect, p->proc, p->param);
	AddRef(session->Ref);
	thread->AppData1 = session;

	NoticeThreadInit(thread);

	WtsConnectMain(session);

	WtReleaseSession(session);

	Free(p);
}

// 接続の停止
void WtsStop(TSESSION *session)
{
	UINT i;
	UINT num_threads;
	THREAD **threads;
	// 引数チェック
	if (session == NULL)
	{
		return;
	}

	session->Halt = true;
	Disconnect(session->Sock);
	SetSockEvent(session->SockEvent);

	WaitThread(session->ConnectThread, INFINITE);

	// Accept した各スレッドの解放
	LockList(session->AcceptThreadList);
	{
		num_threads = LIST_NUM(session->AcceptThreadList);
		threads = ToArray(session->AcceptThreadList);

		DeleteAll(session->AcceptThreadList);
	}
	UnlockList(session->AcceptThreadList);

	for (i = 0;i < num_threads;i++)
	{
		THREAD *t = threads[i];

		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	Free(threads);
}

// 接続の開始
TSESSION *WtsStart(WT *wt, WT_CONNECT *connect, WT_ACCEPT_PROC *proc, void *param)
{
	WTS_CONNECT_THREAD_PARAM *p;
	THREAD *thread;
	TSESSION *ret;
	// 引数チェック
	if (wt == NULL || connect == NULL || proc == NULL)
	{
		return NULL;
	}

	p = ZeroMalloc(sizeof(WTS_CONNECT_THREAD_PARAM));

	WtCopyConnect(&p->connect, connect);
	p->wt = wt;
	p->proc = proc;
	p->param = param;

	thread = NewThread(WtsConnectThread, p);

	WaitThreadInit(thread);

	WtFreeConnect(&p->connect);
	ret = (TSESSION *)thread->AppData1;

	ReleaseThread(thread);

	return ret;
}

// WT_CONNECT のコピー
void WtCopyConnect(WT_CONNECT *dst, WT_CONNECT *src)
{
	// 引数チェック
	if (src == NULL || dst == NULL)
	{
		return;
	}

	Copy(dst, src, sizeof(WT_CONNECT));

	if (src->GateConnectParam != NULL)
	{
		dst->GateConnectParam = WtCloneGateConnectParam(src->GateConnectParam);
	}
}

// WT_CONNECT の解放
void WtFreeConnect(WT_CONNECT *c)
{
	// 引数チェック
	if (c == NULL)
	{
		return;
	}

	if (c->GateConnectParam != NULL)
	{
		WtFreeGateConnectParam(c->GateConnectParam);
		c->GateConnectParam = NULL;
	}
}

// WT_CONNECT を INTERNET_SETTING から作成
void WtInitWtConnectFromInternetSetting(WT_CONNECT *c, INTERNET_SETTING	*s)
{
	// 引数チェック
	if (c == NULL || s == NULL)
	{
		return;
	}

	Zero(c, sizeof(WT_CONNECT));
	c->ProxyType = s->ProxyType;
	StrCpy(c->ProxyHostName, sizeof(c->ProxyHostName), s->ProxyHostName);
	c->ProxyPort = s->ProxyPort;
	StrCpy(c->ProxyUsername, sizeof(c->ProxyUsername), s->ProxyUsername);
	StrCpy(c->ProxyPassword, sizeof(c->ProxyPassword), s->ProxyPassword);
	StrCpy(c->ProxyUserAgent, sizeof(c->ProxyUserAgent), s->ProxyUserAgent);
}

