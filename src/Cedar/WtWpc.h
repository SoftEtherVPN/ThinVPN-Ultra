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
//bool WpcLoadNoderefCache(WT *wt, BUF **buf, char *entrance, UINT entrance_size, UINT64 *timestamp);
//void WtGenerateNoderefCacheFilename(char *name, UINT size);
void WtShuffleArray(void **p, UINT num);
LIST *WtLoadNodeRefUrlList();
void WtFreeNodeRefUrlList(LIST *o);
bool WtParseNodeRef(WT *wt, PACK *p, char *entrance, UINT entrance_size, UINT64 *timestamp);
PACK *WtGetPackFromBuf(WT *wt, BUF *buf);
UINT WpcGetEntranceUrlEx(WT *wt, char *entrance, UINT entrance_size, UINT cache_expires, LIST *secondary_str_list);
UINT WpcCommCheck(WT *wt);
void WtSetDefaultEntranceUrlCacheExpireSpan(WT *wt, UINT span);

PACK *WtWpcCallWithCertAndKey(WT *wt, char *function_name, PACK *pack, X *cert, K *key, bool global_ip_only, bool try_secondary);

PACK *WtWpcCall(WT *wt, char *function_name, PACK *pack, UCHAR *host_key, UCHAR *host_secret, bool global_ip_only, bool try_secondary);
PACK *WtWpcCallInner(WT *wt, char *function_name, PACK *pack, UCHAR *host_key, UCHAR *host_secret, bool global_ip_only, char *url);

bool WtIsCommunicationError(UINT error);


#endif	// WTWPC_H


