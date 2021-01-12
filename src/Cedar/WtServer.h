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
	char ProxyUserAgent[MAX_SIZE + 1];			// Proxy server user agent
	bool UseCompress;							// 圧縮の使用
	bool DontCheckCert;							// 証明書をチェックしない

	// Server が Wide Controller に接続してもらってきたメッセージ
	wchar_t MsgForServer[MAX_SIZE];
	bool MsgForServerOnce;

	// Server が Wide Controller からもらってきた Lifetime
	UINT64 SessionLifeTime;
	wchar_t SessionLifeTimeMsg[MAX_PATH];

	// Server 用
	WT_GATE_CONNECT_PARAM *GateConnectParam;	// 接続パラメータ
	char Pcid[MAX_PATH];						// PCID

	// Client 用
	UCHAR SessionId[WT_SESSION_ID_SIZE];		// 接続先セッション ID
	UINT64 ServerMask64;						// ServerMask64
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
	UINT TunnelId;
};

// 関数プロトタイプ
void WtCopyConnect(WT_CONNECT *dst, WT_CONNECT *src);
void WtFreeConnect(WT_CONNECT *c);
TSESSION *WtsStart(WT *wt, WT_CONNECT *connect, WT_ACCEPT_PROC *proc, void *param);
void WtsConnectThread(THREAD *thread, void *param);
TSESSION *WtsNewSession(THREAD *thread, WT *wt, WT_CONNECT *connect, WT_ACCEPT_PROC *proc, void *param);
void WtsConnectMain(TSESSION *session);
void WtsConnectInner(TSESSION *session, SOCK *s, char *sni, bool *should_retry_proxy_alternative);
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

