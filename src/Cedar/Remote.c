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


// Remote.c
// Remote Procedure Call

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

// Stat manager 保存スレッド
void StatManSaveThreadProc(THREAD* thread, void* param)
{
	STATMAN* m = (STATMAN*)param;

	if (m == NULL)
	{
		return;
	}

	while (true)
	{
		UINT interval;
		if (m->Halt)
		{
			break;
		}

		interval = GenRandInterval2(m->Config.SaveInterval, 0);

		Wait(m->HaltEvent1, interval);

		StatManNormalizeAndPoll(m);
	}

	StatManNormalizeAndPoll(m);
}

// Stat manager 送信スレッド
void StatManPostThreadProc(THREAD* thread, void* param)
{
	STATMAN* m = (STATMAN*)param;

	if (m == NULL)
	{
		return;
	}

	UINT num_try = 0;

	while (true)
	{
		UINT interval;
		IP local_ip = CLEAN;

		if (GetMyPrivateIP(&local_ip, false))
		{
			CopyIP(&m->CurrentLocalIp, &local_ip);
		}

		num_try++;

		if (StatManPostMain(m))
		{
			num_try = 0;
		}

		if (m->Halt)
		{
			break;
		}

		interval = GenRandIntervalWithRetry(m->Config.PostInterval, num_try + 1, m->Config.PostInterval * 30, 0);

		Wait(m->HaltEvent2, interval);
	}
}

// POST 送信メイン
bool StatManPostMain(STATMAN* m)
{
	bool ret = false;
	char* json_str = NULL;
	if (m == NULL)
	{
		return false;
	}

	// バージョン番号を増やす
	{
		PACK* p2 = NewPack();

		PackAddInt64(p2, "__Stat_Version_Total", 1);

		StatManAddReport(m, p2);

		FreePack(p2);
	}

	if (IsEmptyStr(m->Config.PostUrl))
	{
		goto LABEL_CLEANUP;
	}

	Lock(m->Lock);
	{
		FOLDER* root = m->Root;
		FOLDER *system = CfgGetFolder(root, "System");
		FOLDER *data = CfgGetFolder(root, "Data");

		if (system != NULL && data != NULL)
		{
			char uid[MAX_PATH] = CLEAN;

			CfgGetStr(system, "Uid", uid, sizeof(uid));

			if (IsFilledStr(uid))
			{
				PACK* json_pack = NewPack();
				char tmp[MAX_PATH] = CLEAN;
				PACK* data_pack = NewPack();
				TOKEN_LIST* data_list;
				UINT i;
				JSON_VALUE* json_root;
				JSON_VALUE* json_data;

				PackAddStr(json_pack, "StatUid", uid);

				PackAddStr(json_pack, "StatGitCommitId", ULTRA_COMMIT_ID);

				char verstr[MAX_SIZE] = CLEAN;
				char exe[MAX_PATH] = CLEAN;

				GetExeName(exe, sizeof(exe));

				GetFileNameFromFilePath(exe, sizeof(exe), exe); // Remove personal information

				OS_INFO* os = GetOsInfo();

				Format(verstr, sizeof(verstr),
					"CEDAR_VER=%u|CEDAR_BUILD=%u|BUILDER_NAME=%s|BUILD_PLACE=%s|APPNAME=%s|"
					"OSTYPE=%u|OSSP=%u|OSNAME=%s|OSPROD=%s|OSVENDOR=%s|OSVER=%s|KERNEL=%s|KERNELVER=%s",
					CEDAR_VER, CEDAR_BUILD, BUILDER_NAME, BUILD_PLACE, exe,
					os->OsType, os->OsServicePack, os->OsSystemName, os->OsProductName, os->OsVendorName, os->OsVersion, os->KernelName, os->KernelVersion
					);

				PackAddStr(json_pack, "StatAppVer", verstr);

				IPToStr(tmp, sizeof(tmp), &m->CurrentLocalIp);

				PackAddStr(json_pack, "StatLocalIp", tmp);

				Zero(tmp, sizeof(tmp));
				GetMachineHostName(tmp, sizeof(tmp));

				PackAddStr(json_pack, "StatLocalFqdn", tmp);

				PackAddStr(json_pack, "SystemName", m->Config.SystemName);
				PackAddStr(json_pack, "LogName", m->Config.LogName);

				data_list = CfgEnumItemToTokenList(data);

				for (i = 0;i < data_list->NumTokens;i++)
				{
					char* name = data_list->Token[i];
					ITEM* item = CfgFindItem(data, name);

					if (item != NULL)
					{
						if (item->Type == ITEM_TYPE_INT64)
						{
							UINT64 value = CfgGetInt64(data, name);

							PackAddInt64(data_pack, name, value);
						}
						else if (item->Type == ITEM_TYPE_STRING)
						{
							wchar_t str[MAX_SIZE] = CLEAN;

							if (CfgGetUniStr(data, name, str, sizeof(str)))
							{
								PackAddUniStr(data_pack, name, str);
							}
						}
					}
				}

				json_root = PackToJsonEx(json_pack, true);

				json_data = PackToJsonEx(data_pack, true);

				JsonSet(JsonValueGetObject(json_root), "Data", json_data);

				json_str = JsonToStr(json_root);

				FreeToken(data_list);
				JsonFree(json_root);
				FreePack(data_pack);
				FreePack(json_pack);
			}
		}
	}
	Unlock(m->Lock);

	if (IsFilledStr(json_str))
	{
		// JSON データをアップロードいたします
		UINT err = HttpPostData(m->Config.PostUrl, CONNECTING_TIMEOUT, json_str, (bool *)&m->Halt);

		if (err == ERR_NO_ERROR)
		{
			ret = true;
		}
	}

LABEL_CLEANUP:

	Free(json_str);

	return ret;
}

// HTTP でデータを Post する
UINT HttpPostData(char* url, UINT timeout, char *post_str, bool *cancel)
{
	UINT ret = ERR_INTERNAL_ERROR;
	if (url == NULL || post_str == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	URL_DATA data = CLEAN;
	if (ParseUrl(&data, url, true, NULL) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	UINT error = ERR_INTERNAL_ERROR;

	BUF* recv = HttpRequestEx5(&data, NULL, timeout, timeout, &error,
		false, post_str, NULL, NULL, NULL, 0, cancel, 6536, NULL, NULL, NULL, false, false);

	if (recv == NULL)
	{
		return error;
	}

	SeekBufToEnd(recv);
	WriteBufChar(recv, 0);

	char* recv_str = recv->Buf;

	if (InStr(recv_str, "ok") == false)
	{
		ret = ERR_PROTOCOL_ERROR;
	}
	else
	{
		ret = ERR_NO_ERROR;
	}

	FreeBuf(recv);

	return ret;
}

// 1 つの 64bit レポートの追加
void StatManReportInt64(STATMAN* m, char* name, UINT64 value)
{
	if (m == NULL || name == NULL)
	{
		return;
	}

	PACK* p = NewPack();

	PackAddInt64(p, name, value);

	StatManAddReport(m, p);

	FreePack(p);
}

// レポートの追加 (PACK で、登録したい値をポンポンを追加する)
void StatManAddReport(STATMAN* m, PACK* p)
{
	FOLDER* data;
	if (m == NULL || p == NULL || m->Root == NULL)
	{
		return;
	}

	data = CfgGetFolder(m->Root, "Data");
	if (data == NULL)
	{
		data = CfgCreateFolder(m->Root, "Data");
	}

	if (data == NULL)
	{
		return;
	}

	Lock(m->Lock);
	{
		UINT i;

		for (i = 0;i < LIST_NUM(p->elements);i++)
		{
			ELEMENT* e = LIST_DATA(p->elements, i);

			if (e->num_value == 1)
			{
				if (e->type == VALUE_INT64)
				{
					ITEM* item;

					UINT64 value = e->values[0]->Int64Value;

					if (EndWith(e->name, "_total"))
					{
						value += CfgGetInt64(data, e->name);
					}

					item = CfgFindItem(data, e->name);
					if (item != NULL)
					{
						CfgDeleteItem(item);
					}

					CfgAddInt64(data, e->name, value);
				}
				else if (e->type == VALUE_STR)
				{
					ITEM* item;

					item = CfgFindItem(data, e->name);
					if (item != NULL)
					{
						CfgDeleteItem(item);
					}

					CfgAddStr(data, e->name, e->values[0]->Str);
				}
				else if (e->type == VALUE_UNISTR)
				{
					ITEM* item;

					item = CfgFindItem(data, e->name);
					if (item != NULL)
					{
						CfgDeleteItem(item);
					}

					CfgAddUniStr(data, e->name, e->values[0]->UniStr);
				}
			}
		}
	}
	Unlock(m->Lock);
}

// Stat manager の停止 (もうこれ以上 Poll コールバックを呼ばないことが保証される)
void StopStatMan(STATMAN* m)
{
	if (m == NULL)
	{
		return;
	}

	m->Halt = true;

	Set(m->HaltEvent1);
	Set(m->HaltEvent2);

	WaitThread(m->SaveThread, INFINITE);
	WaitThread(m->PostThread, INFINITE);
}

// Stat manager の終了
void FreeStatMan(STATMAN* m)
{
	if (m == NULL)
	{
		return;
	}

	StopStatMan(m);

	ReleaseThread(m->SaveThread);
	ReleaseThread(m->PostThread);

	ReleaseEvent(m->HaltEvent1);
	ReleaseEvent(m->HaltEvent2);

	FreeCfgRw(m->CfgRw);

	CfgDeleteFolder(m->Root);

	DeleteLock(m->Lock);

	Free(m);
}

// 正規化して Poll してファイル更新する
void StatManNormalizeAndPoll(STATMAN* m)
{
	FOLDER* root;
	FOLDER* system;
	FOLDER* data;
	if (m == NULL)
	{
		return;
	}

	Lock(m->Lock);
	{
		root = m->Root;
		if (root != NULL)
		{
			system = CfgGetFolder(root, "System");
			if (system == NULL)
			{
				system = CfgCreateFolder(root, "System");
			}

			if (system != NULL)
			{
				char uid[MAX_PATH] = CLEAN;

				CfgGetStr(system, "Uid", uid, sizeof(uid));

				if (IsEmptyStr(uid))
				{
					UCHAR rand[SHA1_SIZE] = CLEAN;

					Rand(rand, sizeof(rand));

					BinToStr(uid, sizeof(uid), rand, sizeof(rand));

					if (CfgIsItem(system, "Uid"))
					{
						ITEM* item = CfgFindItem(system, "Uid");
						if (item != NULL)
						{
							CfgDeleteItem(item);
						}
					}

					CfgAddStr(system, "Uid", uid);
				}
			}

			data = CfgGetFolder(root, "Data");
			if (data == NULL)
			{
				data = CfgCreateFolder(root, "Data");
			}

			if (m->Halt == false)
			{
				PACK* ret = NewPack();

				if (m->Config.Callback != NULL)
				{
					m->Config.Callback(m, m->Config.Param, ret);

					StatManAddReport(m, ret);
				}

				FreePack(ret);
			}
		}

		SaveCfgRwEx2(m->CfgRw, root, (UINT)(SystemTime64() / (24U * 60 * 60 * 1000)), true);
	}
	Unlock(m->Lock);
}

// Stat manager の開始
STATMAN* NewStatMan(STATMAN_CONFIG *config)
{
	FOLDER* root = CLEAN;
	STATMAN* m;
	if (config == NULL)
	{
		return NULL;
	}

	m = ZeroMalloc(sizeof(STATMAN));

	m->Lock = NewLock();

	GetLocalHostIP4(&m->CurrentLocalIp);

	Copy(&m->Config, config, sizeof(STATMAN_CONFIG));

	if (m->Config.PostInterval == 0)
	{
		m->Config.PostInterval = STATMAN_DEFAULT_SEND_INTERVAL;
	}

	if (m->Config.SaveInterval == 0)
	{
		m->Config.SaveInterval = STATMAN_DEFAULT_SAVE_INTERVAL;
	}

	if (UniIsEmptyStr(m->Config.StatFilename))
	{
		UniStrCpy(m->Config.StatFilename, sizeof(m->Config.StatFilename), STATMAN_DEFAULT_FILENAME);
	}

	if (IsEmptyStr(m->Config.SystemName))
	{
		StrCpy(m->Config.SystemName, sizeof(m->Config.SystemName), STATMAN_DEFAULT_SYSTEMNAME);
	}

	if (IsEmptyStr(m->Config.LogName))
	{
		StrCpy(m->Config.LogName, sizeof(m->Config.LogName), STATMAN_DEFAULT_LOGNAME);
	}

	m->CfgRw = NewCfgRwEx2W(&root, m->Config.StatFilename, false, NULL);

	if (root != NULL)
	{
		m->Root = root;
	}
	else
	{
		m->Root = CfgCreateFolder(NULL, TAG_ROOT);
	}

	StatManNormalizeAndPoll(m);

	m->HaltEvent1 = NewEvent();
	m->HaltEvent2 = NewEvent();

	m->SaveThread = NewThread(StatManSaveThreadProc, m);
	m->PostThread = NewThread(StatManPostThreadProc, m);

	return m;
}

// End of RPC
void EndRpc(RPC *rpc)
{
	RpcFree(rpc);
}

// Release the RPC
void RpcFree(RPC *rpc)
{
	RpcFreeEx(rpc, false);
}
void RpcFreeEx(RPC *rpc, bool no_disconnect)
{
	// Validate arguments
	if (rpc == NULL)
	{
		return;
	}

	if (no_disconnect == false)
	{
		Disconnect(rpc->Sock);
	}

	ReleaseSock(rpc->Sock);

	DeleteLock(rpc->Lock);

	Free(rpc);
}

// Get error
UINT RpcGetError(PACK *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return ERR_DISCONNECTED;
	}

	return PackGetInt(p, "error_code");
}

// Error checking
bool RpcIsOk(PACK *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return false;
	}

	if (PackGetInt(p, "error") == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Error code setting
void RpcError(PACK *p, UINT err)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	PackAddInt(p, "error", 1);
	PackAddInt(p, "error_code", err);
}

// Start the RPC dispatcher
PACK *CallRpcDispatcher(RPC *r, PACK *p)
{
	char func_name[MAX_SIZE];
	// Validate arguments
	if (r == NULL || p == NULL)
	{
		return NULL;
	}

	if (PackGetStr(p, "function_name", func_name, sizeof(func_name)) == false)
	{
		return NULL;
	}

	return r->Dispatch(r, func_name, p);
}

// Wait for the next RPC call
bool RpcRecvNextCall(RPC *r)
{
	UINT size;
	void *tmp;
	SOCK *s;
	BUF *b;
	PACK *p;
	PACK *ret;
	// Validate arguments
	if (r == NULL)
	{
		return false;
	}

	s = r->Sock;

	if (RecvAll(s, &size, sizeof(UINT), s->SecureMode) == false)
	{
		return false;
	}

	size = Endian32(size);

	if (size > MAX_PACK_SIZE)
	{
		return false;
	}

	tmp = MallocEx(size, true);

	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		return false;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	SeekBuf(b, 0, 0);
	Free(tmp);

	p = BufToPack(b);
	FreeBuf(b);

	if (p == NULL)
	{
		return false;
	}

	ret = CallRpcDispatcher(r, p);
	FreePack(p);

	if (ret == NULL)
	{
		ret = PackError(ERR_NOT_SUPPORTED);
	}

	b = PackToBuf(ret);
	FreePack(ret);

	size = Endian32(b->Size);
	SendAdd(s, &size, sizeof(UINT));
	SendAdd(s, b->Buf, b->Size);

	if (SendNow(s, s->SecureMode) == false)
	{
		FreeBuf(b);
		return false;
	}

	FreeBuf(b);

	return true;
}

// RPC server operation
void RpcServer(RPC *r)
{
	SOCK *s;
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	s = r->Sock;

	while (true)
	{
		// Wait for the next RPC call
		if (RpcRecvNextCall(r) == false)
		{
			// Communication error
			break;
		}
	}
}

// RPC call
PACK *RpcCall(RPC *r, char *function_name, PACK *p)
{
	PACK *ret;
	UINT num_retry = 0;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || function_name == NULL)
	{
		return NULL;
	}

//	Debug("RpcCall: %s\n", function_name);

	Lock(r->Lock);
	{
		if (p == NULL)
		{
			p = NewPack();
		}

		PackAddStr(p, "function_name", function_name);

RETRY:
		err = 0;
		ret = RpcCallInternal(r, p);

		if (ret == NULL)
		{
			if (r->IsVpnServer && r->Sock != NULL)
			{
				if (num_retry < 1)
				{
					num_retry++;

					// Attempt to reconnect the RPC to the VPN Server
					err = AdminReconnect(r);

					if (err == ERR_NO_ERROR)
					{
						goto RETRY;
					}
				}
			}
		}

		FreePack(p);

		if (ret == NULL)
		{
			if (err == 0)
			{
				err = ERR_DISCONNECTED;
			}

			ret = PackError(err);
			PackAddInt(ret, "error_code", err);
		}
	}
	Unlock(r->Lock);

	return ret;
}

// RPC internal call
PACK *RpcCallInternal(RPC *r, PACK *p)
{
	BUF *b;
	UINT size;
	PACK *ret;
	void *tmp;
	// Validate arguments
	if (r == NULL || p == NULL)
	{
		return NULL;
	}

	if (r->Sock == NULL)
	{
		return NULL;
	}

	b = PackToBuf(p);

	size = Endian32(b->Size);
	SendAdd(r->Sock, &size, sizeof(UINT));
	SendAdd(r->Sock, b->Buf, b->Size);
	FreeBuf(b);

	if (SendNow(r->Sock, r->Sock->SecureMode) == false)
	{
		return NULL;
	}

	if (RecvAll(r->Sock, &size, sizeof(UINT), r->Sock->SecureMode) == false)
	{
		return NULL;
	}

	size = Endian32(size);
	if (size > MAX_PACK_SIZE)
	{
		return NULL;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(r->Sock, tmp, size, r->Sock->SecureMode) == false)
	{
		Free(tmp);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	SeekBuf(b, 0, 0);
	Free(tmp);

	ret = BufToPack(b);
	if (ret == NULL)
	{
		FreeBuf(b);
		return NULL;
	}

	FreeBuf(b);

	return ret;
}

// Start the RPC server
RPC *StartRpcServer(SOCK *s, RPC_DISPATCHER *dispatch, void *param)
{
	RPC *r;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	r = ZeroMallocEx(sizeof(RPC), true);
	r->Sock = s;
	r->Param = param;
	r->Lock = NewLock();
	AddRef(s->ref);

	r->ServerMode = true;
	r->Dispatch = dispatch;

	// Name generation
	Format(r->Name, sizeof(r->Name), "RPC-%u", s->socket);

	return r;
}

// Start the RPC client
RPC *StartRpcClient(SOCK *s, void *param)
{
	RPC *r;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	r = ZeroMalloc(sizeof(RPC));
	r->Sock = s;
	r->Param = param;
	r->Lock = NewLock();
	AddRef(s->ref);

	r->ServerMode = false;

	return r;
}

