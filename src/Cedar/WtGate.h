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

// 登録マシーン一覧
struct WG_MACHINE
{
	char Msid[MAX_PATH];				// 固有 ID
	char HostSecret2[MAX_PATH];			// ホストシークレット 2
	char Pcid[MAX_PATH];				// コンピュータ ID
	UINT64 ServerMask64;				// サーバーマスク 64
	UINT64 CreateDate;					// 作成日時
	UINT64 UpdateDate;					// 更新日時
	UINT64 LastServerDate;				// 最後にサーバーが接続した日時
	UINT64 FirstClientDate;				// 最初にクライアントが接続した日時
	UINT64 LastClientDate;				// 最後にクライアントが接続した日時
	int NumServer;						// サーバー接続回数
	int NumClient;						// クライアント接続回数
	char CreateIp[MAX_PATH];			// 作成元 IP アドレス
	char CreateHost[MAX_PATH];			// 作成元 FQDN
	char LastIp[MAX_PATH];				// 最後にサーバーが接続した接続元 IP アドレス
	char WolMacList[1024];				// WoL MAC アドレスリスト
};

// HTTP プロキシ
#define	WG_PROXY_TCP_TIMEOUT_SERVER		(60 * 1000)
#define	WG_PROXY_MAX_POST_SIZE			(1024 * 1024)


// 関数プロトタイプ
bool WtGateConnectParamFromPack(WT_GATE_CONNECT_PARAM *g, PACK *p);
BUF *WtGateConnectParamPayloadToBuf(WT_GATE_CONNECT_PARAM *g);
bool WtGateConnectParamCheckSignature(WIDE *wide, WT_GATE_CONNECT_PARAM *g);
void WtGateConnectParamToPack(PACK *p, WT_GATE_CONNECT_PARAM *g);
void WtgStart(WT *wt, X *cert, K *key, UINT port, bool standalone_mode);
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

void WtgSamInit(WT* wt);
void WtgSamFree(WT* wt);
void WtgSamFlushDatabase(WT* wt);


#endif	// WTGATE_H



