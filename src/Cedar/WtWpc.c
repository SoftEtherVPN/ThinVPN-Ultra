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


// WtWpc.c
// Web Procedure Call

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

// 通信チェック
UINT WpcCommCheck(WT *wt)
{
	PACK *p, *r;
	UINT ret;
	// 引数チェック
	if (wt == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	PackAddStr(p, "str", "hello");

	r = WtWpcCall(wt, "CommCheck", p, NULL, NULL, false, false);
	FreePack(p);

	ret = GetErrorFromPack(r);
	FreePack(r);

	return ret;
}

// Entrance URL を取得 (キャッシュ付き)
UINT WpcGetEntranceUrlEx(WT *wt, char *entrance, UINT entrance_size, UINT cache_expires, LIST *secondary_str_list)
{
	WideLoadEntryPoint(NULL, entrance, entrance_size, secondary_str_list, NULL, 0, NULL, 0);

	return ERR_NO_ERROR;
}

// noderef.txt リストの解放
void WtFreeNodeRefUrlList(LIST *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	FreeStrList(o);
}

// 配列のシャッフル
void WtShuffleArray(void **p, UINT num)
{
	void **tmp;
	UINT i;
	// 引数チェック
	if (p == NULL)
	{
		return;
	}

	tmp = ZeroMalloc(sizeof(void *) * num);
	for (i = 0;i < num;i++)
	{
		tmp[i] = p[i];
	}

	for (i = 0;i < num;i++)
	{
		UINT n = 0;
		while (true)
		{
			n = Rand32() % num;
			if (tmp[n] != NULL)
			{
				break;
			}
		}
		p[i] = tmp[n];
		tmp[n] = NULL;
	}

	Free(tmp);
}

// noderef.txt のキャッシュ用ファイル名を生成
//void WtGenerateNoderefCacheFilename(char *name, UINT size)
//{
//	char tmp[MAX_PATH];
//	UINT a;
//	UCHAR hash[SHA1_SIZE];
//
//	StrCpy(tmp, sizeof(tmp), MsGetExeFileName());
//	StrUpper(tmp);
//	HashSha1(hash, tmp, StrLen(tmp));
//	Copy(&a, hash, sizeof(UINT));
//
//	Format(tmp, sizeof(tmp), ".noderef-%u.txt", a);
//	ConbinePath(name, size, MsGetTempDir(), tmp);
//}

// noderef.txt の解析
bool WtParseNodeRef(WT *wt, PACK *p, char *entrance, UINT entrance_size, UINT64 *timestamp)
{
	// 引数チェック
	if (wt == NULL || p == NULL || entrance == NULL || timestamp == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "Entrance", entrance, entrance_size) == false)
	{
		return false;
	}

	*timestamp = PackGetInt64(p, "TimeStamp");
	if (*timestamp == 0)
	{
		return false;
	}

	return true;
}

// BUF から Pack の取得
PACK *WtGetPackFromBuf(WT *wt, BUF *buf)
{
	WPC_PACKET packet;
	// 引数チェック
	if (wt == NULL || buf == NULL)
	{
		return NULL;
	}

	if (WpcParsePacket(&packet, buf) == false)
	{
		return NULL;
	}

	return packet.Pack;
}

//// noderef.txt キャッシュの読み込み
//bool WpcLoadNoderefCache(WT *wt, BUF **buf, char *entrance, UINT entrance_size, UINT64 *timestamp)
//{
//	PACK *p;
//	static UINT dummy = 0;
//	char filename[MAX_PATH];
//	// 引数チェック
//	if (wt == NULL || entrance == NULL || timestamp == NULL || buf == NULL)
//	{
//		return false;
//	}
//
//	WtGenerateNoderefCacheFilename(filename, sizeof(filename));
//
//	*buf = ReadDump(filename);
//	if (*buf == NULL)
//	{
//		return false;
//	}
//
//	p = WtGetPackFromBuf(wt, *buf);
//	if (p == NULL)
//	{
//		FreeBuf(*buf);
//		return false;
//	}
//
//	if (WtParseNodeRef(wt, p, entrance, entrance_size, timestamp) == false)
//	{
//		FreePack(p);
//		FreeBuf(*buf);
//		return false;
//	}
//
//	FreePack(p);
//	return true;
//}

// デフォルトの Entrance URL のキャッシュの有効期限の設定
void WtSetDefaultEntranceUrlCacheExpireSpan(WT *wt, UINT span)
{
	// 引数チェック
	if (wt == NULL)
	{
		return;
	}

	wt->DefaultEntranceCacheExpireSpan = span;
}

//// WPC 呼び出し
//PACK *WpcCall(WT *wt, char *function_name, PACK *pack, X *cert, K *key)
//{
//	URL_DATA data;
//	char url[MAX_PATH];
//	BUF *b, *recv;
//	UINT error;
//	WPC_PACKET packet;
//	// 引数チェック
//	if (wt == NULL || function_name == NULL || pack == NULL)
//	{
//		return PackError(ERR_INTERNAL_ERROR);
//	}
//
//	error = WpcGetEntranceUrlEx(wt, url, sizeof(url), wt->DefaultEntranceCacheExpireSpan);
//	if (error != ERR_NO_ERROR)
//	{
//		return PackError(error);
//	}
//	if (ParseUrl(&data, url, true, NULL) == false)
//	{
//		return PackError(ERR_INTERNAL_ERROR);
//	}
//
//	PackAddStr(pack, "function", function_name);
//
//	b = WpcGeneratePacket(pack, cert, key);
//	if (b == NULL)
//	{
//		return PackError(ERR_INTERNAL_ERROR);
//	}
//
//	SeekBuf(b, b->Size, 0);
//	WriteBufInt(b, 0);
//	SeekBuf(b, 0, 0);
//
//	recv = HttpRequest(wt, &data, NULL, &error,
//		wt->CheckSslTrust, b->Buf, NULL, NULL);
//
//	FreeBuf(b);
//
//	if (recv == NULL)
//	{
//		return PackError(error);
//	}
//
//	if (WpcParsePacket(&packet, recv) == false)
//	{
//		FreeBuf(recv);
//		return PackError(ERR_PROTOCOL_ERROR);
//	}
//
//	FreeBuf(recv);
//
//	if (packet.Cert == NULL)
//	{
//		WpcFreePacket(&packet);
//		return PackError(ERR_PROTOCOL_ERROR);
//	}
//
//	if (WtIsTrustedCert(wt, packet.Cert) == false)
//	{
//		WpcFreePacket(&packet);
//		return PackError(ERR_PROTOCOL_ERROR);
//	}
//
//	FreeX(packet.Cert);
//
//	return packet.Pack;
//}

// エントランス URL の設定
void WtSetEntranceUrl(WT *wt, char *url)
{
	// 引数チェック
	if (wt == NULL || url == NULL)
	{
		return;
	}

	Lock(wt->Lock);
	{
		StrCpy(wt->EntranceUrl, sizeof(wt->EntranceUrl), url);
	}
	Unlock(wt->Lock);
}

// エントランス URL の取得
void WtGetEntranceUrl(WT *wt, char *url, UINT url_size)
{
	// 引数チェック
	if (wt == NULL || url == NULL)
	{
		return;
	}

	Lock(wt->Lock);
	{
		StrCpy(url, url_size, wt->EntranceUrl);
	}
	Unlock(wt->Lock);
}

// インターネット設定の設定
void WtSetInternetSetting(WT *wt, INTERNET_SETTING *setting)
{
	// 引数チェック
	if (wt == NULL || setting == NULL)
	{
		return;
	}

	Lock(wt->Lock);
	{
		Copy(wt->InternetSetting, setting, sizeof(INTERNET_SETTING));

		if (IsEmptyStr(wt->InternetSetting->ProxyUserAgent))
		{
			GenerateDefaultUserProxyAgentStr(wt->InternetSetting->ProxyUserAgent, sizeof(wt->InternetSetting->ProxyUserAgent));
		}
	}
	Unlock(wt->Lock);
}

// インターネット設定の取得
void WtGetInternetSetting(WT *wt, INTERNET_SETTING *setting)
{
	// 引数チェック
	if (wt == NULL || setting == NULL)
	{
		return;
	}

	Lock(wt->Lock);
	{
		if (IsEmptyStr(wt->InternetSetting->ProxyUserAgent))
		{
			GenerateDefaultUserProxyAgentStr(wt->InternetSetting->ProxyUserAgent, sizeof(wt->InternetSetting->ProxyUserAgent));
		}

		Copy(setting, wt->InternetSetting, sizeof(INTERNET_SETTING));
	}
	Unlock(wt->Lock);
}

// 並列 WPC 呼び出しスレッド
void WtgWpcCallParallelThreadProc(THREAD* thread, void* param)
{
	WT_PARALLEL_CALL* c = (WT_PARALLEL_CALL*)param;
	if (thread == NULL || c == NULL) return;

	c->ResponsePack = WtWpcCallInner(c->Wt, c->FunctionName, c->RequestPack, NULL, NULL,
		c->GlobalIpOnly, c->Url);
}

// 複数コントローラに対する並列 WPC 呼び出し
PACK* WtgWpcCallParallel(WT* wt, LIST* url_list, PACK* pack, char* function_name, bool global_ip_only)
{
	UINT i;
	PACK* ret = NULL;
	if (wt == NULL || url_list == NULL || pack == NULL)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	LIST* call_list = NewList(NULL);

	for (i = 0;i < LIST_NUM(url_list);i++)
	{
		char* url = LIST_DATA(url_list, i);

		WT_PARALLEL_CALL* c = ZeroMalloc(sizeof(WT_PARALLEL_CALL));

		c->Wt = wt;
		c->RequestPack = ClonePack(pack);
		StrCpy(c->Url, sizeof(c->Url), url);
		StrCpy(c->FunctionName, sizeof(c->FunctionName), function_name);
		c->GlobalIpOnly = global_ip_only;

		c->Thread = NewThread(WtgWpcCallParallelThreadProc, c);

		Add(call_list, c);
	}

	for (i = 0;i < LIST_NUM(call_list);i++)
	{
		WT_PARALLEL_CALL* c = LIST_DATA(call_list, i);

		if (WaitThread(c->Thread, WPC_PARALLEL_WATCHDOG_TIMEOUT) == false)
		{
			AbortExitEx("WPC_PARALLEL_WATCHDOG_TIMEOUT");
		}

		ReleaseThread(c->Thread);

		if (c->ResponsePack != NULL && GetErrorFromPack(c->ResponsePack) == ERR_NO_ERROR && ret == NULL)
		{
			// 1 つ目の非 Error pack が戻ってきたらそいつを応答 Pack にする
			ret = c->ResponsePack;
		}
		else
		{
			// それ以外の Pack 応答は無視する
			FreePack(c->ResponsePack);
		}

		FreePack(c->RequestPack);

		Free(c);
	}

	ReleaseList(call_list);

	return ret;
}

// 通信に起因するエラー (つまり、間の FW 等が問題でネットワーク上のエラーが発生している) かどうか判定
bool WtIsCommunicationError(UINT error)
{
	if (error == ERR_SSL_X509_UNTRUSTED || error == ERR_CERT_NOT_TRUSTED ||
		error == ERR_SSL_X509_EXPIRED || 
		error == ERR_PROTOCOL_ERROR || error == ERR_CONNECT_FAILED ||
		error == ERR_TIMEOUTED || error == ERR_DISCONNECTED)
	{
		return true;
	}

	return false;
}

PACK *WtWpcCallWithCertAndKey(WT *wt, char *function_name, PACK *pack, X *cert, K *key, bool global_ip_only, bool try_secondary)
{
	BUF *k_buf;
	if (wt == NULL || function_name == NULL || pack == NULL)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	if (cert != NULL && key != NULL)
	{
		UCHAR host_key[SHA1_SIZE] = {0};
		UCHAR host_secret[SHA1_SIZE] = {0};

		GetXDigest(cert, host_key, true);

		k_buf = KToBuf(key, false, NULL);

		if (k_buf != NULL)
		{
			HashSha1(host_secret, k_buf->Buf, k_buf->Size);
		}

		FreeBuf(k_buf);

		return WtWpcCall(wt, function_name, pack, host_key, host_secret, global_ip_only, try_secondary);
	}
	else
	{
		return WtWpcCall(wt, function_name, pack, NULL, NULL, global_ip_only, try_secondary);
	}
}

PACK *WtWpcCall(WT *wt, char *function_name, PACK *pack, UCHAR *host_key, UCHAR *host_secret, bool global_ip_only, bool try_secondary)
{
	UINT error = ERR_NO_ERROR;
	PACK *ret = NULL;
	char url[MAX_SIZE] = {0};
	LIST *secondary_list = NewStrList();
	LIST* widegate_ini = NULL;
	LIST* controller_urls_for_gate = NULL;

	WtLog(wt, "WtWpcCall: function_name = %s, global_ip_only = %u, try_secondary = %u", function_name, global_ip_only, try_secondary);

	// Gate の場合: widegate.ini の読み込み
	if (wt->Wide != NULL && wt->Wide->Type == WIDE_TYPE_GATE)
	{
		widegate_ini = WideGateLoadIni();
	}

	if (widegate_ini != NULL)
	{
		UINT i;
		for (i = 0;i < LIST_NUM(widegate_ini);i++)
		{
			INI_ENTRY* e = LIST_DATA(widegate_ini, i);

			if (StrCmpi(e->Key, "ControllerUrl") == 0)
			{
				char* url = e->Value;
				if (IsFilledStr(url))
				{
					if (controller_urls_for_gate == NULL)
					{
						controller_urls_for_gate = NewStrList();
					}

					AddStrToStrListDistinct(controller_urls_for_gate, url);
				}
			}
		}
	}

	if (controller_urls_for_gate != NULL && LIST_NUM(controller_urls_for_gate) >= 1)
	{
		// widegate.ini の ControllerUrl が指定されており、1 つ以上 URL が存在する場合は、
		// 並列方式で呼び出すことにする
		ret = WtgWpcCallParallel(wt, controller_urls_for_gate, pack, function_name, global_ip_only);

		if (ret == NULL)
		{
			ret = PackError(ERR_CONNECT_FAILED);
		}

		goto L_CLEANUP;
	}

	// EntryPoint.txt の読み込み
	error = WpcGetEntranceUrlEx(wt, url, sizeof(url), wt->DefaultEntranceCacheExpireSpan, secondary_list);
	if (error != ERR_NO_ERROR)
	{
		ret = PackError(error);
		goto L_CLEANUP;
	}

	if (IsEmptyStr(wt->Wide->ControllerUrlOverride) == false)
	{
		// コントローラ URL を WideGate.ini 設定で上書き
		StrCpy(url, sizeof(url), wt->Wide->ControllerUrlOverride);
		try_secondary = false;
	}

	if (try_secondary == false)
	{
		// SECONDARY ホストを試さない。普通の URL のみ。従来どおり。
		ret = WtWpcCallInner(wt, function_name, pack, host_key, host_secret, global_ip_only, url);
	}
	else
	{
		PACK *p = NULL;

		// SECONDARY ホストを試す。新方式。
		if (IsEmptyStr(wt->RecommendedSecondaryUrl) == false)
		{
			WtLog(wt, "WtWpcCall: Use wt->RecommendedSecondaryUrl: %s", wt->RecommendedSecondaryUrl);
			Debug("WtWpcCall: Use wt->RecommendedSecondaryUrl: %s\n", wt->RecommendedSecondaryUrl);
			// まず、前回成功したセカンダリ URL を覚えている場合はそれに接続をする
			p = WtWpcCallInner(wt, function_name, pack, host_key, host_secret, global_ip_only, wt->RecommendedSecondaryUrl);

			if (GetErrorFromPack(p) == ERR_NO_ERROR)
			{
				// 成功した。この結果を返す
				WtLog(wt, "WtWpcCall: OK.");
				Debug("WtWpcCall: OK.\n");
				ret = p;
				goto L_CLEANUP;
			}
			else if (WtIsCommunicationError(GetErrorFromPack(p)))
			{
				// 通信エラーが発生した。間におかしな中継 FW がいる可能性がある
				// のでセカンダリ URL キャッシュを削除する
				ClearStr(wt->RecommendedSecondaryUrl, sizeof(wt->RecommendedSecondaryUrl));
				WtLog(wt, "WtWpcCall: CommunicationError. Error: %u", GetErrorFromPack(p));
				Debug("WtWpcCall: CommunicationError. Error: %u\n", GetErrorFromPack(p));
			}
			else
			{
				// 通信自体は成功しているが、本家でエラーが発生した。
				// セカンダリ URL 自体は生きているので、何もしない。
				WtLog(wt, "WtWpcCall: Generic Error. Error: %u", GetErrorFromPack(p));
				Debug("WtWpcCall: Generic Error. Error: %u\n", GetErrorFromPack(p));
			}

			// 失敗した場合はとにかく結果を破棄する
			FreePack(p);
			p = NULL;
		}

		// 次に、本家に接続する。
		WtLog(wt, "WtWpcCall: Use direct: %s", url);
		Debug("WtWpcCall: Use direct: %s\n", url);

#ifndef	WT_TEST_WIDECONTROL_PROXY_CLIENT
		// 本家接続
		p = WtWpcCallInner(wt, function_name, pack, host_key, host_secret, global_ip_only, url);
#else	// WT_TEST_WIDECONTROL_PROXY_CLIENT
		// テスト: エラーにする
		p = PackError(ERR_CONNECT_FAILED);
#endif	// WT_TEST_WIDECONTROL_PROXY_CLIENT

		if (GetErrorFromPack(p) == ERR_NO_ERROR)
		{
			// 成功した。この結果を返す
			ret = p;
			WtLog(wt, "WtWpcCall: OK.");
			Debug("WtWpcCall: OK.\n");
			// 本家と通信できているので、セカンダリ URL キャッシュを削除する
			ClearStr(wt->RecommendedSecondaryUrl, sizeof(wt->RecommendedSecondaryUrl));
			goto L_CLEANUP;
		}
		else if (WtIsCommunicationError(GetErrorFromPack(p)) == false)
		{
			// 本家と通信できているが、本家の側でエラーが発生しているのでもうここで
			// 諦めることとする。この結果を返す
			ret = p;
			WtLog(wt, "WtWpcCall: Generic Error. Error: %u", GetErrorFromPack(p));
			Debug("WtWpcCall: Generic Error. Error: %u\n", GetErrorFromPack(p));
			// 本家と通信できているので、セカンダリ URL キャッシュを削除する
			ClearStr(wt->RecommendedSecondaryUrl, sizeof(wt->RecommendedSecondaryUrl));
			goto L_CLEANUP;
		}
		else
		{
			// 本家と通信できていない。これは、間におかしな中継 FW がいる可能性がある
			// ので、リストからセカンダリを 1 つランダムに選んで、そのセカンダリ
			// との通信を試みる
			UINT num = LIST_NUM(secondary_list);
			char secondary_url[MAX_PATH] = {0};
			PACK *p2 = NULL;

			Zero(secondary_url, sizeof(secondary_url));

			if (num >= 1)
			{
				UINT rand_i = Rand32() % num;
				char *str = LIST_DATA(secondary_list, rand_i);

				StrCpy(secondary_url, sizeof(secondary_url), str);
			}

			if (IsEmptyStr(secondary_url) == false)
			{
				WtLog(wt, "WtWpcCall: Use choosed secondary: %s", secondary_url);
				Debug("WtWpcCall: Use choosed secondary: %s\n", secondary_url);

				// セカンダリの URL を決定した。
				// 接続してみる
				p2 = WtWpcCallInner(wt, function_name, pack, host_key, host_secret, global_ip_only, secondary_url);

				if (GetErrorFromPack(p2) == ERR_NO_ERROR)
				{
					// 成功した。この結果を返す
					ret = p2;
					FreePack(p);
					WtLog(wt, "WtWpcCall: OK.");
					Debug("WtWpcCall: OK.\n");

					// 本家と通信できているので、セカンダリ URL キャッシュを保存する
					StrCpy(wt->RecommendedSecondaryUrl, sizeof(wt->RecommendedSecondaryUrl), secondary_url);
					goto L_CLEANUP;
				}
				else if (WtIsCommunicationError(GetErrorFromPack(p2)) == false)
				{
					// 本家と通信できているが、本家の側でエラーが発生した。
					WtLog(wt, "WtWpcCall: Generic Error. Error: %u", GetErrorFromPack(p2));
					Debug("WtWpcCall: Generic Error. Error: %u\n", GetErrorFromPack(p2));

					// この結果を返す
					ret = p2;
					FreePack(p);

					// セカンダリ URL 自体は生きているので、セカンダリ URL キャッシュを保存する
					StrCpy(wt->RecommendedSecondaryUrl, sizeof(wt->RecommendedSecondaryUrl), secondary_url);
					goto L_CLEANUP;
				}
				else
				{
					// 通信エラーが発生した。間に不正な FW がいる。
					WtLog(wt, "WtWpcCall: CommunicationError. Error: %u", GetErrorFromPack(p2));
					Debug("WtWpcCall: CommunicationError. Error: %u\n", GetErrorFromPack(p2));
					FreePack(p2);
					p2 = NULL;
				}
			}

			// セカンダリ URL が 1 つも存在しない or セカンダリ URL との通信そのものに失敗
			// したので、1 つ目 (本家との直接通信) の結果を返す
			ret = p;
			goto L_CLEANUP;
		}
	}

L_CLEANUP:
	ReleaseStrList(secondary_list);
	WideFreeIni(widegate_ini);
	FreeStrList(controller_urls_for_gate);

	WtLog(wt, "WtWpcCall error: %u", GetErrorFromPack(ret));

	return ret;
}

PACK *WtWpcCallInner(WT *wt, char *function_name, PACK *pack, UCHAR *host_key, UCHAR *host_secret, bool global_ip_only, char *url)
{
	URL_DATA data = CLEAN;
	BUF *b, *recv;
	UINT error;
	WPC_PACKET packet;
	UINT num_retry = 0;
	TOKEN_LIST* url_list = NULL;
	// 引数チェック
	if (wt == NULL || function_name == NULL || pack == NULL)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	if (wt->Wide != NULL && wt->Wide->Type != WIDE_TYPE_GATE)
	{
		// 引数に指定されている url が、セミコロンで区切ることができる場合は、複数の URL にランダムに接続試行する
		// (2020.12.19 新方式)
		url_list = ParseToken(url, ";");
		if (url_list->NumTokens >= 2)
		{
			PACK* url_list_ret_pack = NULL;
			UINT* shuffle_list = GenerateShuffleList(url_list->NumTokens);
			UINT i;
			PACK* first_comm_error = NULL;

			// シャッフル結果で、前回接続できた URL があれば、それを 1 番に持ってくる (順番抜かし)
			if (IsFilledStr(wt->LastTimeOkUrlMulti))
			{
				if (url_list->NumTokens >= 2)
				{
					for (i = 0;i < url_list->NumTokens;i++)
					{
						UINT index = shuffle_list[i];
						if (StrCmp(url_list->Token[index], wt->LastTimeOkUrlMulti) == 0)
						{
							UINT tmp = shuffle_list[0];
							shuffle_list[0] = index;
							shuffle_list[i] = tmp;
							break;
						}
					}
				}
			}

			char ok_url[MAX_PATH] = CLEAN;

			// 順に試行
			for (i = 0;i < url_list->NumTokens;i++)
			{
				if (url_list_ret_pack != NULL)
				{
					// 結果確定！
					break;
				}

				char* url2 = url_list->Token[shuffle_list[i]];
				PACK* pack_request_copy = ClonePack(pack);

				WtLog(wt, "Trying %u for the URL: %s", i, url2);
				Debug("Trying %u for the URL: %s\n", i, url2);
				PACK* p_ret = WtWpcCallInner(wt, function_name, pack_request_copy, host_key, host_secret, global_ip_only, url2);
				UINT p_err = GetErrorFromPack(p_ret);

				if (p_ret != NULL && (p_err == ERR_NO_ERROR || WtIsCommunicationError(p_err) == false))
				{
					// コレを返す
					url_list_ret_pack = p_ret;

					StrCpy(ok_url, sizeof(ok_url), url2);
				}
				else
				{
					// 通信エラーが発生したので次のやつを試す。結果は破棄する
					if (first_comm_error == NULL)
					{
						// 最初の通信エラーは保存しておく
						first_comm_error = p_ret;
					}
					else
					{
						Free(p_ret);
					}
				}

				FreePack(pack_request_copy);
			}

			StrCpy(wt->LastTimeOkUrlMulti, sizeof(wt->LastTimeOkUrlMulti), ok_url);

			Free(shuffle_list);

			if (url_list_ret_pack == NULL)
			{
				url_list_ret_pack = first_comm_error;
			}
			else
			{
				FreePack(first_comm_error);
			}
			FreeToken(url_list);
			return url_list_ret_pack;
		}
		FreeToken(url_list);
	}

L_RETRY:

	if (ParseUrl(&data, url, true, NULL) == false)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	PackAddStr(pack, "function", function_name);

	b = WpcGeneratePacket(pack, host_key, host_secret);
	if (b == NULL)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	SeekBuf(b, b->Size, 0);
	WriteBufInt(b, 0);
	SeekBuf(b, 0, 0);

	recv = HttpRequestEx5(&data, NULL, 0, 0, &error,
		wt->CheckSslTrust, b->Buf, NULL, NULL, NULL, 0, NULL, 0, NULL, NULL, wt, global_ip_only, false);

	if (recv == NULL)
	{
		WtLog(wt, "HttpRequestEx5 error: %u", error);
	}
	else
	{
		WtLog(wt, "HttpRequestEx5 ok. Received %u bytes.", recv->Size);
	}

	FreeBuf(b);

	if (recv == NULL)
	{
#ifndef	WT_TEST_WIDECONTROL_PROXY_CLIENT
		if (WtIsCommunicationError(error))
		{
			if (wt->EnableUpdateEntryPoint && num_retry == 0)
			{
				WtLog(wt, "Trying update Entry Point...");
				Debug("Trying update Entry Point...\n");
				// Wide Controller との上記の通信エラーが発生した場合は
				// EntryPoint.dat が古い可能性があるので
				// GitHub を用いて更新を試みる
				if (WideTryUpdateNewEntryPointModestStandard(wt, NULL))
				{
					WtLog(wt, "Try update Entry Point OK. Retrying...");
					Debug("Try update Entry Point OK. Retrying...\n");
					// 更新されたら接続リトライをしてみる
					num_retry++;
					goto L_RETRY;
				}
				else
				{
					WtLog(wt, "Try update Entry Point error.");
					Debug("Try update Entry Point error.\n");
				}
			}
		}
#endif	// WT_TEST_WIDECONTROL_PROXY_CLIENT

		return PackError(error);
	}

	if (WpcParsePacket(&packet, recv) == false)
	{
		WtLog(wt, "WpcParsePacket parse error.");
		FreeBuf(recv);
		return PackError(ERR_PROTOCOL_ERROR);
	}

	FreeBuf(recv);

	PackAddStr(packet.Pack, "__remote_hostname", data.HostName);
	PackAddInt(packet.Pack, "__remote_port", data.Port);

	return packet.Pack;
}

//// パケットの解放
//void WpcFreePacket(WPC_PACKET *packet)
//{
//	// 引数チェック
//	if (packet == NULL)
//	{
//		return;
//	}
//
//	FreePack(packet->Pack);
//	FreeX(packet->Cert);
//}

//// パケットのパース
//bool WpcParsePacket(WPC_PACKET *packet, BUF *buf)
//{
//	LIST *o;
//	BUF *b;
//	bool ret = false;
//	UCHAR hash[SHA1_SIZE];
//	// 引数チェック
//	if (packet == NULL || buf == NULL)
//	{
//		return false;
//	}
//
//	Zero(packet, sizeof(WPC_PACKET));
//
//	o = WpcParseDataEntry(buf);
//
//	b = WpcDataEntryToBuf(WpcFindDataEntry(o, "PACK"));
//	if (b != NULL)
//	{
//		HashSha1(hash, b->Buf, b->Size);
//
//		packet->Pack = BufToPack(b);
//		FreeBuf(b);
//
//		if (packet->Pack != NULL)
//		{
//			BUF *b;
//
//			ret = true;
//
//			b = WpcDataEntryToBuf(WpcFindDataEntry(o, "HASH"));
//
//			if (b != NULL)
//			{
//				if (b->Size != SHA1_SIZE || Cmp(b->Buf, hash, SHA1_SIZE) != 0)
//				{
//					ret = false;
//					FreePack(packet->Pack);
//				}
//				else
//				{
//					BUF *b;
//
//					Copy(packet->Hash, hash, SHA1_SIZE);
//
//					b = WpcDataEntryToBuf(WpcFindDataEntry(o, "CERT"));
//
//					if (b != NULL)
//					{
//						X *cert = BufToX(b, false);
//						if (cert == NULL)
//						{
//							ret = false;
//							FreePack(packet->Pack);
//						}
//						else
//						{
//							BUF *b = WpcDataEntryToBuf(WpcFindDataEntry(o, "SIGN"));
//
//							if (b == NULL || (b->Size != 128))
//							{
//								ret = false;
//								FreeX(cert);
//								FreePack(packet->Pack);
//							}
//							else
//							{
//								K *k = GetKFromX(cert);
//
//								if (RsaVerify(hash, SHA1_SIZE, b->Buf, k) == false)
//								{
//									ret = false;
//									FreeX(cert);
//									FreePack(packet->Pack);
//								}
//								else
//								{
//									packet->Cert = cert;
//									Copy(packet->Sign, b->Buf, 128);
//								}
//
//								FreeK(k);
//							}
//
//							FreeBuf(b);
//						}
//						FreeBuf(b);
//					}
//				}
//				FreeBuf(b);
//			}
//		}
//	}
//
//	WpcFreeDataEntryList(o);
//
//	return ret;
//}

//// WPC_ENTRY からバッファをデコード
//BUF *WpcDataEntryToBuf(WPC_ENTRY *e)
//{
//	void *data;
//	UINT data_size;
//	UINT size;
//	BUF *b;
//	// 引数チェック
//	if (e == NULL)
//	{
//		return NULL;
//	}
//
//	data_size = e->Size + 4096;
//	data = Malloc(data_size);
//	size = DecodeSafe64(data, e->Data, e->Size);
//
//	b = NewBuf();
//	WriteBuf(b, data, size);
//	SeekBuf(b, 0, 0);
//
//	Free(data);
//
//	return b;
//}

//// パケットの生成
//BUF *WpcGeneratePacket(PACK *pack, X *cert, K *key)
//{
//	UCHAR hash[SHA1_SIZE];
//	BUF *pack_data;
//	BUF *cert_data = NULL;
//	BUF *sign_data = NULL;
//	BUF *b;
//	// 引数チェック
//	if (pack == NULL)
//	{
//		return NULL;
//	}
//
//	pack_data = PackToBuf(pack);
//	HashSha1(hash, pack_data->Buf, pack_data->Size);
//
//	if (cert != NULL && key != NULL)
//	{
//		UCHAR sign[128];
//		cert_data = XToBuf(cert, false);
//
//		RsaSign(sign, hash, sizeof(hash), key);
//
//		sign_data = NewBuf();
//		WriteBuf(sign_data, sign, sizeof(sign));
//		SeekBuf(sign_data, 0, 0);
//	}
//
//	b = NewBuf();
//
//	WpcAddDataEntryBin(b, "PACK", pack_data->Buf, pack_data->Size);
//	WpcAddDataEntryBin(b, "HASH", hash, sizeof(hash));
//
//	if (cert_data != NULL)
//	{
//		WpcAddDataEntryBin(b, "CERT", cert_data->Buf, cert_data->Size);
//		WpcAddDataEntryBin(b, "SIGN", sign_data->Buf, sign_data->Size);
//	}
//
//	FreeBuf(pack_data);
//	FreeBuf(cert_data);
//	FreeBuf(sign_data);
//
//	SeekBuf(b, 0, 0);
//
//	return b;
//}

//// データエントリの検索
//WPC_ENTRY *WpcFindDataEntry(LIST *o, char *name)
//{
//	UINT i;
//	char name_str[WPC_DATA_ENTRY_SIZE];
//	// 引数チェック
//	if (o == NULL || name == NULL)
//	{
//		return NULL;
//	}
//
//	WpcFillEntryName(name_str, name);
//
//	for (i = 0;i < LIST_NUM(o);i++)
//	{
//		WPC_ENTRY *e = LIST_DATA(o, i);
//
//		if (Cmp(e->EntryName, name_str, WPC_DATA_ENTRY_SIZE) == 0)
//		{
//			return e;
//		}
//	}
//
//	return NULL;
//}

//// データエントリのパース
//LIST *WpcParseDataEntry(BUF *b)
//{
//	char entry_name[WPC_DATA_ENTRY_SIZE];
//	char size_str[11];
//	LIST *o;
//	// 引数チェック
//	if (b == NULL)
//	{
//		return NULL;
//	}
//
//	SeekBuf(b, 0, 0);
//
//	o = NewListFast(NULL);
//
//	while (true)
//	{
//		UINT size;
//		WPC_ENTRY *e;
//
//		if (ReadBuf(b, entry_name, WPC_DATA_ENTRY_SIZE) != WPC_DATA_ENTRY_SIZE)
//		{
//			break;
//		}
//
//		Zero(size_str, sizeof(size_str));
//		if (ReadBuf(b, size_str, 10) != 10)
//		{
//			break;
//		}
//
//		size = ToInt(size_str);
//		if ((b->Size - b->Current) < size)
//		{
//			break;
//		}
//
//		e = ZeroMalloc(sizeof(WPC_ENTRY));
//		e->Data = (UCHAR *)b->Buf + b->Current;
//		Copy(e->EntryName, entry_name, WPC_DATA_ENTRY_SIZE);
//		e->Size = size;
//
//		SeekBuf(b, size, 1);
//
//		Add(o, e);
//	}
//
//	return o;
//}

//// データエントリリストの解放
//void WpcFreeDataEntryList(LIST *o)
//{
//	UINT i;
//	// 引数チェック
//	if (o == NULL)
//	{
//		return;
//	}
//
//	for (i = 0;i < LIST_NUM(o);i++)
//	{
//		WPC_ENTRY *e = LIST_DATA(o, i);
//
//		Free(e);
//	}
//
//	ReleaseList(o);
//}

//// データエントリを追加 (バイナリ)
//void WpcAddDataEntryBin(BUF *b, char *name, void *data, UINT size)
//{
//	char *str;
//	// 引数チェック
//	if (b == NULL || name == NULL || (data == NULL && size != 0))
//	{
//		return;
//	}
//
//	str = Malloc(size * 2 + 64);
//
//	EncodeSafe64(str, data, size);
//
//	WpcAddDataEntry(b, name, str, StrLen(str));
//
//	Free(str);
//}

//// データエントリを追加
//void WpcAddDataEntry(BUF *b, char *name, void *data, UINT size)
//{
//	char entry_name[WPC_DATA_ENTRY_SIZE];
//	char size_str[11];
//	// 引数チェック
//	if (b == NULL || name == NULL || (data == NULL && size != 0))
//	{
//		return;
//	}
//
//	WpcFillEntryName(entry_name, name);
//	WriteBuf(b, entry_name, WPC_DATA_ENTRY_SIZE);
//
//	Format(size_str, sizeof(size_str), "%010u", size);
//	WriteBuf(b, size_str, 10);
//
//	WriteBuf(b, data, size);
//}

//// エントリ名を生成
//void WpcFillEntryName(char *dst, char *name)
//{
//	UINT i, len;
//	char tmp[MAX_SIZE];
//	// 引数チェック
//	if (dst == NULL || name == NULL)
//	{
//		return;
//	}
//
//	StrCpy(tmp, sizeof(tmp), name);
//	StrUpper(tmp);
//	len = StrLen(tmp);
//
//	for (i = 0;i < WPC_DATA_ENTRY_SIZE;i++)
//	{
//		dst[i] = ' ';
//	}
//
//	if (len <= WPC_DATA_ENTRY_SIZE)
//	{
//		Copy(dst, tmp, len);
//	}
//	else
//	{
//		Copy(dst, tmp, WPC_DATA_ENTRY_SIZE);
//	}
//}

//// HTTP リクエストの実行
//BUF *HttpRequest(WT *wt, URL_DATA *data, INTERNET_SETTING *setting,
//				UINT *error_code, bool check_ssl_trust, char *post_data,
//				WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param)
//{
//	WT_CONNECT con;
//	SOCK *s;
//	HTTP_HEADER *h;
//	bool use_http_proxy = false;
//	char target[MAX_SIZE * 4];
//	char *send_str;
//	BUF *send_buf;
//	BUF *recv_buf;
//	UINT http_error_code;
//	char len_str[100];
//	UINT content_len;
//	void *socket_buffer;
//	UINT socket_buffer_size = WPC_RECV_BUF_SIZE;
//	UINT num_continue = 0;
//	INTERNET_SETTING wt_setting;
//	SYSTEMTIME tm;
//	// 引数チェック
//	if (data == NULL || wt == NULL)
//	{
//		return NULL;
//	}
//	if (setting == NULL)
//	{
//		WtGetInternetSetting(wt, &wt_setting);
//		setting = &wt_setting;
//	}
//	if (error_code == NULL)
//	{
//		static UINT ret = 0;
//		error_code = &ret;
//	}
//
//	SystemTime(&tm);
//
//	if (tm.wYear > 2034)
//	{
//		// 2034 年以降の Fail Safe (2038 年問題への対応)
//		check_ssl_trust = false;
//	}
//
//	// 接続
//	Zero(&con, sizeof(con));
//	StrCpy(con.HostName, sizeof(con.HostName), data->HostName);
//	con.Port = data->Port;
//	con.ProxyType = setting->ProxyType;
//	StrCpy(con.ProxyHostName, sizeof(con.ProxyHostName), setting->ProxyHostName);
//	con.ProxyPort = setting->ProxyPort;
//	StrCpy(con.ProxyUsername, sizeof(con.ProxyUsername), setting->ProxyUsername);
//	StrCpy(con.ProxyPassword, sizeof(con.ProxyPassword), setting->ProxyPassword);
//
//	if (setting->ProxyType != PROXY_HTTP || data->Secure)
//	{
//		use_http_proxy = false;
//		StrCpy(target, sizeof(target), data->Target);
//	}
//	else
//	{
//		use_http_proxy = true;
//		CreateUrl(target, sizeof(target), data);
//	}
//
//	if (use_http_proxy == false)
//	{
//		// HTTP Proxy 経由でないか、HTTP Proxy 経由であっても SSL 接続の場合
//		s = WtSockConnect(&con, error_code);
//	}
//	else
//	{
//		// HTTP Proxy 経由で、かつ SSL でない接続の場合
//		s = TcpIpConnect(con.ProxyHostName, con.ProxyPort);
//		if (s == NULL)
//		{
//			*error_code = ERR_PROXY_CONNECT_FAILED;
//		}
//	}
//
//	if (s == NULL)
//	{
//		return NULL;
//	}
//
//	if (data->Secure)
//	{
//		// SSL 通信の開始
//		if (StartSSLEx(s, NULL, NULL, true) == false)
//		{
//			// SSL 接続に失敗
//			*error_code = ERR_PROTOCOL_ERROR;
//			Disconnect(s);
//			ReleaseSock(s);
//			return NULL;
//		}
//
//		// SSL 接続が確立された場合は証明書を検査する
//		if (check_ssl_trust)
//		{
//			if (CheckXDateNow(s->RemoteX) == false)
//			{
//				// 接続先 X509 証明書の有効期限切れ
//				*error_code = ERR_SSL_X509_EXPIRED;
//				Disconnect(s);
//				ReleaseSock(s);
//				return NULL;
//			}
//
//			if (WtIsTrustedCert(wt, s->RemoteX) == false)
//			{
//				// 接続先 X509 証明書が信頼できない
//				*error_code = ERR_SSL_X509_UNTRUSTED;
//				Disconnect(s);
//				ReleaseSock(s);
//				return NULL;
//			}
//		}
//	}
//
//	// タイムアウト設定
//	SetTimeout(s, WPC_TIMEOUT);
//
//	// リクエスト生成
//	h = NewHttpHeader(data->Method, target, use_http_proxy ? "HTTP/1.0" : "HTTP/1.1");
//	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
//	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
//	AddHttpValue(h, NewHttpValue("Accept-Language", "ja"));
//	AddHttpValue(h, NewHttpValue("User-Agent", WPC_USER_AGENT));
//	AddHttpValue(h, NewHttpValue("Pragma", "no-cache"));
//	AddHttpValue(h, NewHttpValue("Cache-Control", "no-cache"));
//	AddHttpValue(h, NewHttpValue("Host", data->HeaderHostName));
//
//	if (IsEmptyStr(data->Referer) == false)
//	{
//		AddHttpValue(h, NewHttpValue("Referer", data->Referer));
//	}
//
//	if (StrCmpi(data->Method, WPC_HTTP_POST_NAME) == 0)
//	{
//		ToStr(len_str, StrLen(post_data));
//		AddHttpValue(h, NewHttpValue("Content-Type", "application/x-www-form-urlencoded"));
//		AddHttpValue(h, NewHttpValue("Content-Length", len_str));
//	}
//
//	if (use_http_proxy)
//	{
//		AddHttpValue(h, NewHttpValue("Proxy-Connection", "Keep-Alive"));
//
//		if (IsEmptyStr(setting->ProxyUsername) == false || IsEmptyStr(setting->ProxyPassword) == false)
//		{
//			char auth_tmp_str[MAX_SIZE], auth_b64_str[MAX_SIZE * 2];
//			char basic_str[MAX_SIZE * 2];
//
//			// 認証文字列の生成
//			Format(auth_tmp_str, sizeof(auth_tmp_str), "%s:%s",
//				setting->ProxyUsername, setting->ProxyPassword);
//
//			// Base64 エンコード
//			Zero(auth_b64_str, sizeof(auth_b64_str));
//			Encode64(auth_b64_str, auth_tmp_str);
//			Format(basic_str, sizeof(basic_str), "Basic %s", auth_b64_str);
//
//			AddHttpValue(h, NewHttpValue("Proxy-Authorization", basic_str));
//		}
//	}
//
//	send_str = HttpHeaderToStr(h);
//	FreeHttpHeader(h);
//
//	send_buf = NewBuf();
//	WriteBuf(send_buf, send_str, StrLen(send_str));
//	Free(send_str);
//
//	// POST の場合は送信データを追記
//	if (StrCmpi(data->Method, WPC_HTTP_POST_NAME) == 0)
//	{
//		WriteBuf(send_buf, post_data, StrLen(post_data));
//	}
//
//	// 送信
//	if (SendAll(s, send_buf->Buf, send_buf->Size, s->SecureMode) == false)
//	{
//		Disconnect(s);
//		ReleaseSock(s);
//		FreeBuf(send_buf);
//
//		*error_code = ERR_DISCONNECTED;
//
//		return NULL;
//	}
//
//	FreeBuf(send_buf);
//
//CONT:
//	// 受信
//	h = RecvHttpHeader(s);
//	if (h == NULL)
//	{
//		Disconnect(s);
//		ReleaseSock(s);
//
//		*error_code = ERR_DISCONNECTED;
//
//		return NULL;
//	}
//
//	http_error_code = 0;
//	if (StrLen(h->Method) == 8)
//	{
//		if (Cmp(h->Method, "HTTP/1.", 7) == 0)
//		{
//			http_error_code = ToInt(h->Target);
//		}
//	}
//
//	*error_code = ERR_NO_ERROR;
//
//	switch (http_error_code)
//	{
//	case 401:
//	case 407:
//		// プロキシ認証エラー
//		*error_code = ERR_PROXY_AUTH_FAILED;
//		break;
//
//	case 404:
//		// 404 File Not Found
//		*error_code = ERR_OBJECT_NOT_FOUND;
//		break;
//
//	case 100:
//		// Continue
//		num_continue++;
//		if (num_continue >= 10)
//		{
//			goto DEF;
//		}
//		FreeHttpHeader(h);
//		goto CONT;
//
//	case 200:
//		// 成功
//		break;
//
//	default:
//		// プロトコルエラー
//DEF:
//		*error_code = ERR_PROTOCOL_ERROR;
//		break;
//	}
//
//	if (*error_code != ERR_NO_ERROR)
//	{
//		// エラー発生
//		Disconnect(s);
//		ReleaseSock(s);
//		FreeHttpHeader(h);
//		return NULL;
//	}
//
//	// コンテンツの長さを取得
//	content_len = GetContentLength(h);
//
//	FreeHttpHeader(h);
//
//	socket_buffer = Malloc(socket_buffer_size);
//
//	// コンテンツの受信
//	recv_buf = NewBuf();
//
//	while (true)
//	{
//		UINT recvsize = MIN(socket_buffer_size, content_len - recv_buf->Size);
//		UINT size;
//
//		if (recv_callback != NULL)
//		{
//			if (recv_callback(recv_callback_param,
//				content_len, recv_buf->Size, recv_buf) == false)
//			{
//				// 受信をキャンセル
//				*error_code = ERR_USER_CANCEL;
//				goto RECV_CANCEL;
//			}
//		}
//
//		if (recvsize == 0)
//		{
//			break;
//		}
//
//		size = Recv(s, socket_buffer, recvsize, s->SecureMode);
//		if (size == 0)
//		{
//			// 切断された
//			*error_code = ERR_DISCONNECTED;
//
//RECV_CANCEL:
//			FreeBuf(recv_buf);
//			Free(socket_buffer);
//			Disconnect(s);
//			ReleaseSock(s);
//
//			return NULL;
//		}
//
//		WriteBuf(recv_buf, socket_buffer, size);
//	}
//
//	SeekBuf(recv_buf, 0, 0);
//	Free(socket_buffer);
//
//	Disconnect(s);
//	ReleaseSock(s);
//
//	// 送信
//	return recv_buf;
//}

// ソケット接続
SOCK *WtSockConnectHttpProxy(WT_CONNECT *param, char *target, UINT *error_code)
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
			param->HostName, param->Port,
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

//// 空の INTERNET_SETTING の取得
//INTERNET_SETTING *GetNullInternetSetting()
//{
//	static INTERNET_SETTING ret;
//
//	Zero(&ret, sizeof(ret));
//
//	return &ret;
//}

//// システムのインターネット接続設定を取得する
//void GetSystemInternetSetting(INTERNET_SETTING *setting)
//{
//	bool use_proxy;
//	// 引数チェック
//	if (setting == NULL)
//	{
//		return;
//	}
//
//	Zero(setting, sizeof(INTERNET_SETTING));
//
//	use_proxy = MsRegReadInt(REG_CURRENT_USER,
//		"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
//		"ProxyEnable");
//
//	if (use_proxy)
//	{
//		char *str = MsRegReadStr(REG_CURRENT_USER,
//			"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
//			"ProxyServer");
//		if (str != NULL)
//		{
//			char name[MAX_HOST_NAME_LEN + 1];
//			UINT port;
//
//			if (GetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
//				&port, str, "https"))
//			{
//				setting->ProxyType = PROXY_HTTP;
//				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
//				setting->ProxyPort = port;
//			}
//			else if (GetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
//				&port, str, "http"))
//			{
//				setting->ProxyType = PROXY_HTTP;
//				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
//				setting->ProxyPort = port;
//			}
//			else if (GetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
//				&port, str, "socks"))
//			{
//				setting->ProxyType = PROXY_SOCKS;
//				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
//				setting->ProxyPort = port;
//			}
//			else
//			{
//				if (SearchStrEx(str, "=", 0, false) == INFINITE)
//				{
//					char *host;
//					UINT port;
//					if (ParseHostPort(str, &host, &port, 0))
//					{
//						if (port != 0)
//						{
//							setting->ProxyType = PROXY_HTTP;
//							StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), host);
//							setting->ProxyPort = port;
//						}
//						Free(host);
//					}
//				}
//			}
//
//			Free(str);
//		}
//	}
//}

//// IE のレジストリ文字列からプロキシサーバーの設定を取得する
//bool GetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type)
//{
//	TOKEN_LIST *t;
//	UINT i;
//	bool ret = false;
//	// 引数チェック
//	if (name == NULL || port == NULL || str == NULL || server_type == NULL)
//	{
//		return false;
//	}
//
//	t = ParseToken(str, ";");
//
//	for (i = 0;i < t->NumTokens;i++)
//	{
//		char *s = t->Token[i];
//		UINT i;
//
//		Trim(s);
//
//		i = SearchStrEx(s, "=", 0, false);
//		if (i != INFINITE)
//		{
//			char tmp[MAX_PATH];
//
//			StrCpy(name, name_size, s);
//			name[i] = 0;
//
//			if (StrCmpi(name, server_type) == 0)
//			{
//				char *host;
//				StrCpy(tmp, sizeof(tmp), s + i + 1);
//
//				if (ParseHostPort(tmp, &host, port, 0))
//				{
//					StrCpy(name, name_size, host);
//					Free(host);
//
//					if (*port != 0)
//					{
//						ret = true;
//					}
//					break;
//				}
//			}
//		}
//	}
//
//	FreeToken(t);
//
//	return ret;
//}

//// URL の生成
//void CreateUrl(char *url, UINT url_size, URL_DATA *data)
//{
//	char *protocol;
//	// 引数チェック
//	if (url == NULL || data == NULL)
//	{
//		return;
//	}
//
//	if (data->Secure == false)
//	{
//		protocol = "http://";
//	}
//	else
//	{
//		protocol = "https://";
//	}
//
//	Format(url, url_size, "%s%s%s", protocol, data->HeaderHostName, data->Target);
//}

//// URL のパース
//bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer)
//{
//	char tmp[MAX_SIZE * 3];
//	char server_port[MAX_HOST_NAME_LEN + 16];
//	char *s = NULL;
//	char *host;
//	UINT port;
//	UINT i;
//	// 引数チェック
//	if (data == NULL || str == NULL)
//	{
//		return false;
//	}
//
//	Zero(data, sizeof(URL_DATA));
//
//	if (is_post)
//	{
//		StrCpy(data->Method, sizeof(data->Method), WPC_HTTP_POST_NAME);
//	}
//	else
//	{
//		StrCpy(data->Method, sizeof(data->Method), WPC_HTTP_GET_NAME);
//	}
//
//	if (referrer != NULL)
//	{
//		StrCpy(data->Referer, sizeof(data->Referer), referrer);
//	}
//
//	StrCpy(tmp, sizeof(tmp), str);
//	Trim(tmp);
//
//	// プロトコルの判別
//	if (StartWith(tmp, "http://"))
//	{
//		data->Secure = false;
//		s = &tmp[7];
//	}
//	else if (StartWith(tmp, "https://"))
//	{
//		data->Secure = true;
//		s = &tmp[8];
//	}
//	else
//	{
//		if (SearchStrEx(tmp, "://", 0, false) != INFINITE)
//		{
//			return false;
//		}
//		data->Secure = false;
//		s = &tmp[0];
//	}
//
//	// サーバー名:ポート番号 の取得
//	StrCpy(server_port, sizeof(server_port), s);
//	i = SearchStrEx(server_port, "/", 0, false);
//	if (i != INFINITE)
//	{
//		server_port[i] = 0;
//		s += StrLen(server_port);
//		StrCpy(data->Target, sizeof(data->Target), s);
//	}
//	else
//	{
//		StrCpy(data->Target, sizeof(data->Target), "/");
//	}
//
//	if (ParseHostPort(server_port, &host, &port, data->Secure ? 443 : 80) == false)
//	{
//		return false;
//	}
//
//	StrCpy(data->HostName, sizeof(data->HostName), host);
//	data->Port = port;
//
//	Free(host);
//
//	if ((data->Secure && data->Port == 443) || (data->Secure == false && data->Port == 80))
//	{
//		StrCpy(data->HeaderHostName, sizeof(data->HeaderHostName), data->HostName);
//	}
//	else
//	{
//		Format(data->HeaderHostName, sizeof(data->HeaderHostName),
//			"%s:%u", data->HostName, data->Port);
//	}
//
//	return true;
//}
//
//// Safe64 にエンコード
//void EncodeSafe64(char *dst, void *src, UINT src_size)
//{
//	UINT size;
//	if (dst == NULL || src == NULL)
//	{
//		return;
//	}
//
//	size = B64_Encode(dst, src, src_size);
//	dst[size] = 0;
//
//	Base64ToSafe64(dst);
//}

//// Safe64 をデコード
//UINT DecodeSafe64(void *dst, char *src, UINT src_strlen)
//{
//	char *tmp;
//	UINT ret;
//	if (dst == NULL || src == NULL)
//	{
//		return 0;
//	}
//
//	if (src_strlen == 0)
//	{
//		src_strlen = StrLen(src);
//	}
//
//	tmp = Malloc(src_strlen + 1);
//	Copy(tmp, src, src_strlen);
//	tmp[src_strlen] = 0;
//	Safe64ToBase64(tmp);
//
//	ret = B64_Decode(dst, tmp, src_strlen);
//	Free(tmp);
//
//	return ret;
//}

//// 文字列置換
//void Base64ToSafe64(char *str)
//{
//	UINT i, len;
//	// 引数チェック
//	if (str == NULL)
//	{
//		return;
//	}
//
//	len = StrLen(str);
//
//	for (i = 0;i < len;i++)
//	{
//		switch (str[i])
//		{
//		case '=':
//			str[i] = '(';
//			break;
//
//		case '+':
//			str[i] = ')';
//			break;
//
//		case '/':
//			str[i] = '_';
//			break;
//		}
//	}
//}
//void Safe64ToBase64(char *str)
//{
//	UINT i, len;
//	// 引数チェック
//	if (str == NULL)
//	{
//		return;
//	}
//
//	len = StrLen(str);
//
//	for (i = 0;i < len;i++)
//	{
//		switch (str[i])
//		{
//		case '(':
//			str[i] = '=';
//			break;
//
//		case ')':
//			str[i] = '+';
//			break;
//
//		case '_':
//			str[i] = '/';
//			break;
//		}
//	}
//}
