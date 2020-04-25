// WideTunnel Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// Wide.c
// Wide API

#include "CedarPch.h"

// Windows プロダクト ID のキャッシュ
static char windows_product_id[MAX_PATH] = {0};
static WT_MACHINE_ID machine_id_cache = {0};
static bool machine_id_cached = false;

// セッション接続情報キャッシュの削除
void WideSessionInfoCacheDel(LIST *o, char *pcid)
{
	// 引数チェック
	if (o == NULL || pcid == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SESSION_INFO_CACHE *c = LIST_DATA(o, i);

			if (StrCmpi(c->Pcid, pcid) == 0)
			{
				Delete(o, c);
				Free(c);
				break;
			}
		}
	}
	UnlockList(o);
}

// セッション接続情報キャッシュの古いものを削除
void WideSessionInfoCacheDeleteExpires(LIST *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		UINT64 now = Tick64();
		LIST *o2 = NewListFast(NULL);

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SESSION_INFO_CACHE *c = LIST_DATA(o, i);

			if (c->Expires < now)
			{
				Add(o2, c);
			}
		}

		for (i = 0;i < LIST_NUM(o2);i++)
		{
			SESSION_INFO_CACHE *c = LIST_DATA(o2, i);

			Free(c);
			Delete(o, c);
		}

		ReleaseList(o2);
	}
	UnlockList(o);
}

// セッション接続情報キャッシュの取得
SESSION_INFO_CACHE *WideSessionInfoCacheGet(LIST *o, char *pcid, UINT64 expire_span)
{
	SESSION_INFO_CACHE *ret = NULL;
	// 引数チェック
	if (o == NULL || pcid == NULL)
	{
		return NULL;
	}

	LockList(o);
	{
		UINT i;

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SESSION_INFO_CACHE *c = LIST_DATA(o, i);

			if (StrCmpi(c->Pcid, pcid) == 0)
			{
				if (c->Expires > Tick64())
				{
					Debug("%I64u\n", c->Expires - Tick64());

					if (expire_span != 0)
					{
						c->Expires = Tick64() + expire_span;
					}

					ret = Clone(c, sizeof(SESSION_INFO_CACHE));

					break;
				}
			}
		}
	}
	UnlockList(o);

	return ret;
}

// セッション接続情報キャッシュの追加
void WideSessionInfoCacheAdd(LIST *o, char *pcid, char *hostname, char *hostname_for_proxy, UINT port,
							 UCHAR *session_id, UINT64 expire_span)
{
	// 引数チェック
	if (o == NULL || pcid == NULL || hostname == NULL || session_id == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		SESSION_INFO_CACHE *c = NULL;

		WideSessionInfoCacheDeleteExpires(o);

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SESSION_INFO_CACHE *cc = LIST_DATA(o, i);

			if (StrCmpi(cc->Pcid, pcid) == 0)
			{
				c = cc;
				break;
			}
		}

		if (c == NULL)
		{
			c = ZeroMalloc(sizeof(SESSION_INFO_CACHE));
			StrCpy(c->Pcid, sizeof(c->Pcid), pcid);
			Add(o, c);
		}

		StrCpy(c->HostName, sizeof(c->HostName), hostname);
		StrCpy(c->HostNameForProxy, sizeof(c->HostNameForProxy), hostname_for_proxy);
		c->Port = port;
		Copy(c->SessionId, session_id, sizeof(c->SessionId));

		c->Expires = Tick64() + expire_span;
	}
	UnlockList(o);
}

// セッション接続情報キャッシュの初期化
LIST *WideInitSessionInfoCache()
{
	LIST *o = NewList(NULL);

	return o;
}

// セッション接続情報キャッシュの解放
void WideFreeSessionInfoCache(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SESSION_INFO_CACHE *c = LIST_DATA(o, i);

		Free(c);
	}

	ReleaseList(o);
}

// 2 つのマシン ID を比較し、同一のマシンであると判断したら true を返す
bool WideCompareMachineId(WT_MACHINE_ID *d1, WT_MACHINE_ID *d2)
{
	UINT n = 0;
	// 引数チェック
	if (d1 == NULL || d2 == NULL)
	{
		return false;
	}

	if (Cmp(d1->ProductIdHash, d2->ProductIdHash, SHA1_SIZE) == 0)
	{
		n++;
	}

	if (Cmp(d1->MachineNameHash, d2->MachineNameHash, SHA1_SIZE) == 0)
	{
		n++;
	}

	if (Cmp(d1->IpAddressHash, d2->IpAddressHash, SHA1_SIZE) == 0)
	{
		n++;
	}

	if (Cmp(d1->MacAddressHash, d2->MacAddressHash, SHA1_SIZE) == 0)
	{
		n++;
	}

	if (Cmp(d1->RamSizeHash, d2->RamSizeHash, SHA1_SIZE) == 0)
	{
		n++;
	}

	if (n >= 2)
	{
		return true;
	}

	return false;
}

// 現在のマシン ID を取得
void WideGetCurrentMachineId(WT_MACHINE_ID *d)
{
	// 引数チェック
	if (d == NULL)
	{
		return;
	}

	if (machine_id_cached == false)
	{
		WideGetCurrentMachineIdMain(d);
		Copy(&machine_id_cache, d, sizeof(WT_MACHINE_ID));
		machine_id_cached = true;
	}
	else
	{
		Copy(d, &machine_id_cache, sizeof(WT_MACHINE_ID));
	}
}
void WideGetCurrentMachineIdMain(WT_MACHINE_ID *d)
{
	char product_id[MAX_PATH];
	char machine_name[MAX_PATH];
	UCHAR mac_address[6];
	IP ip;
	UINT ip_uint;
	MEMINFO mem;
	UINT64 ram_size;
	// 引数チェック
	if (d == NULL)
	{
		return;
	}

	Zero(d, sizeof(WT_MACHINE_ID));

	// プロダクト ID
#ifdef	OS_WIN32
	WideGetWindowsProductId(product_id, sizeof(product_id));
	Trim(product_id);
	StrUpper(product_id);
#endif  // OS_WIN32

	// コンピュータ名
#ifdef	OS_WIN32
	MsGetComputerName(machine_name, sizeof(machine_name));
	Trim(machine_name);
	StrUpper(machine_name);
#endif  // OS_WIN32

	// IP アドレス
	GetMachineIp(&ip);
	ip_uint = IPToUINT(&ip);

	// MAC アドレス
	Zero(mac_address, sizeof(mac_address));
#ifdef	OS_WIN32
	MsGetPhysicalMacAddress(mac_address);
#endif  // OS_WIN32

	// RAM サイズ
	Zero(&mem, sizeof(mem));
	GetMemInfo(&mem);
	ram_size = mem.TotalPhys;

	// ハッシュする
	HashSha1(d->ProductIdHash, product_id, StrLen(product_id));
	HashSha1(d->MachineNameHash, machine_name, StrLen(machine_name));
	HashSha1(d->IpAddressHash, &ip_uint, sizeof(UINT));
	HashSha1(d->MacAddressHash, mac_address, sizeof(mac_address));
	HashSha1(d->RamSizeHash, &ram_size, sizeof(UINT));
}

// 指定されたエラーコードがプロキシエラーかどうか取得
bool WideIsProxyError(UINT code)
{
	switch (code)
	{
	case ERR_PROXY_CONNECT_FAILED:
	case ERR_PROXY_ERROR:
	case ERR_PROXY_AUTH_FAILED:
		return true;
	}

	return false;
}

// エラーコードからエラーレベルを取得
UINT WideGetErrorLevel(UINT code)
{
	switch (code)
	{
	case ERR_PROXY_CONNECT_FAILED:
	case ERR_PROXY_ERROR:
	case ERR_PROXY_AUTH_FAILED:
		// ネットワーク上の障害が原因で発生したエラー
		return DESK_ERRORLEVEL_NETWORK;

	case ERR_NO_INIT_CONFIG:
		// クライアント側の設定が原因で発生したエラー
		return DESK_ERRORLEVEL_CLIENT_SIDE;
	}

	return DESK_ERRORLEVEL_SERVER_SIDE;
}

// WideClient 接続
UINT WideClientConnect(WIDE *w, char *pc_id, UINT ver, UINT build, SOCKIO **sockio)
{
	WT *wt;
	UINT ret;
	WT_CONNECT c;
	char pcid[MAX_PATH];
	// 引数チェック
	if (w == NULL || pcid == NULL || sockio == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	StrCpy(pcid, sizeof(pcid), pc_id);
	Trim(pcid);

	wt = w->wt;

	// WideControl に接続
LABEL_RETRY:
	Debug("Connecting to WideControl...\n");
	ret = WideClientConnectInner(w, &c, pcid, ver, build);
	if (ret == ERR_NO_ERROR)
	{
		Debug("Redirect Host: %s (for proxy: %s):%u\n", c.HostName, c.HostNameForProxy, c.Port);

		ret = WtcConnectEx(wt, &c, sockio, CEDAR_VER, CEDAR_BUILD);

		if (ret != ERR_NO_ERROR)
		{
			if (c.CacheUsed)
			{
				// 接続キャッシュを使用して接続することに失敗した
				// 場合はキャッシュを消去して再試行する
				WideSessionInfoCacheDel(w->SessionInfoCache, pcid);

				Debug("Connect with Session Cache Failed. Retrying...\n");

				goto LABEL_RETRY;
			}
		}
	}
	else
	{
		Debug("Failed: %S\n", _E(ret));
	}

	return ret;
}

// WideClient の開始
WIDE *WideClientStart(char *svc_name, UINT se_lang)
{
	return WideClientStartEx(svc_name, se_lang, NULL, NULL);
}
WIDE *WideClientStartEx(char *svc_name, UINT se_lang, X *master_cert, char *fixed_entrance_url)
{
	WIDE *w;
	if (svc_name == NULL)
	{
		return NULL;
	}

	w = ZeroMalloc(sizeof(WIDE));

	StrCpy(w->SvcName, sizeof(w->SvcName), svc_name);
	w->SeLang = se_lang;
	w->Type = WIDE_TYPE_CLIENT;
	w->SettingLock = NewLock();
	if (master_cert == NULL)
	{
		w->wt = NewWtFromHamcore();
	}
	else
	{
		w->wt = NewWt(master_cert);
	}

	w->wt->EnableUpdateEntryPoint = true; // EntryPoint.dat 自動更新有効

	if (fixed_entrance_url != NULL)
	{
		if (IsEmptyStr(fixed_entrance_url))
		{
			fixed_entrance_url = "https://127.0.0.1/";
		}
		StrCpy(w->wt->FixedEntranceUrl, sizeof(w->wt->FixedEntranceUrl),
			fixed_entrance_url);
	}

	w->wt->Wide = w;
	w->SessionInfoCacheExpires = WT_SESSION_INFO_CACHE_EXPIRES_DEFAULT;
	w->SessionInfoCache = WideInitSessionInfoCache();

	WideClientGenerateClientId(w->ClientId);

	return w;
}

// 新しいクライアント ID の生成
void WideClientGenerateClientId(UCHAR *id)
{
	BUF *b;
	UCHAR machine_hash[SHA1_SIZE];
	UCHAR rand[SHA1_SIZE];
	// 引数チェック
	if (id == NULL)
	{
		return;
	}

	Rand(rand, sizeof(rand));

	b = NewBuf();
	GenerateMachineUniqueHash(machine_hash);
	WriteBuf(b, machine_hash, sizeof(machine_hash));
	WriteBuf(b, rand, sizeof(rand));

	HashSha1(id, b->Buf, b->Size);

	FreeBuf(b);
}

// WideClient の停止
void WideClientStop(WIDE *w)
{
	// 引数チェック
	if (w == NULL)
	{
		return;
	}

	WideFreeSessionInfoCache(w->SessionInfoCache);

	ReleaseWt(w->wt);
	DeleteLock(w->SettingLock);

	Free(w);
}

// WideServer が接続中かどうか取得
bool WideServerIsConnected(WIDE *w)
{
	// 引数チェック
	if (w == NULL)
	{
		return false;
	}

	return w->IsConnected;
}

// 現在のハッシュ文字列を取得
void WideServerGetHash(WIDE *w, char *hash, UINT size)
{
	// 引数チェック
	if (w == NULL || hash == NULL)
	{
		return;
	}

	StrCpy(hash, size, "--------");

	Lock(w->SettingLock);
	{
		if (w->ServerX != NULL)
		{
			UCHAR hash_bin[SHA1_SIZE];

			GetXDigest(w->ServerX, hash_bin, true);

			BinToStr(hash, size, hash_bin, SHA1_SIZE);
		}
	}
	Unlock(w->SettingLock);

	return;
}

// 現在の PCID を取得
bool WideServerGetPcid(WIDE *w, char *pcid, UINT size)
{
	// 引数チェック
	if (w == NULL || pcid == NULL)
	{
		return false;
	}

	Lock(w->SettingLock);
	{
		StrCpy(pcid, size, w->Pcid);
	}
	Unlock(w->SettingLock);

	return true;
}

// 接続メインスレッド
void WideServerConnectMainThread(THREAD *thread, void *param)
{
#ifdef	OS_WIN32
	CONNECT_MAIN_THREAD_PARAM *p;
	WIDE *w;
	UINT ret;
	UINT i;
	UINT pcid_candidate_count = 0;
	bool last_wide_controller_connect_ok = false;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	p = (CONNECT_MAIN_THREAD_PARAM *)param;

	w = p->Wide;

	for (i = 0;;i++)
	{
		WT_CONNECT c;

LABEL_CONNECT_RETRY:

		if (p->Halt)
		{
			break;
		}

		// 接続先の Gate の取得
		Debug("ServerConnect...\n");
		ret = WideServerConnect(w, &c);

		// サーバーから文字列メッセージが届いていれば WIDE 構造体に報告する
		if (UniIsEmptyStr(c.MsgForServer) == false)
		{
			// 最後に届いたものと内容が異なっているかどうか
			if (UniStrCmpi(c.MsgForServer, w->MsgForServer) != 0)
			{
				// 異なっている場合は上書きして、メッセージ到着フラグをセットする
				UniStrCpy(w->MsgForServer, sizeof(w->MsgForServer), c.MsgForServer);
				w->MsgForServerOnce = c.MsgForServerOnce;
				w->MsgForServerArrived = true;
			}
		}
		else
		{
			// サーバーからはメッセージが届いていない場合はメモリ上のメッセージをクリアする
			Zero(w->MsgForServer, sizeof(w->MsgForServer));
			w->MsgForServerOnce = false;
			w->MsgForServerArrived = false;
		}

		if (ret != ERR_NO_ERROR)
		{
			last_wide_controller_connect_ok = false;

			if (ret == ERR_NO_INIT_CONFIG)
			{
				char pcid[MAX_PATH];

				pcid_candidate_count = 0;

LABEL_RETRY:
				// pcid が指定されていない
				ret = WideServerGetPcidCandidate(w, pcid, sizeof(pcid), MsGetUserName());

				if (ret == ERR_NO_ERROR)
				{
					X *x;
					K *k;

					// とりあえず候補としてもらった PCID を登録する
					if (WideServerGetCertAndKey(w, &x, &k))
					{
						ret = WideServerRegistMachine(w, pcid, x, k);
						FreeX(x);
						FreeK(k);

						if (ret == ERR_NO_ERROR)
						{
							// 再接続
							goto LABEL_CONNECT_RETRY;
						}
						else if (ret == ERR_PCID_ALREADY_EXISTS)
						{
							// すでに候補としてもらった PCID が使用されている
							pcid_candidate_count++;

							if (pcid_candidate_count < 10)
							{
								goto LABEL_RETRY;
							}
							else
							{
								ret = ERR_INTERNAL_ERROR;
							}
						}
					}
					else
					{
						ret = ERR_INTERNAL_ERROR;
					}
				}
			}

			if (ret == ERR_RESET_CERT && w->ResetCertProc != NULL)
			{
				// 証明書のリセット要求が届いた
				w->ResetCertProc(w, w->ResetCertProcParam);
			}

			// エラー発生
			w->ServerErrorCode = ret;
			Debug("WideServerConnect: %S\n", _E(ret));
		}
		else
		{
			TSESSION *s;

			Lock(w->SettingLock);
			{
				// PCID の保存
				StrCpy(w->Pcid, sizeof(w->Pcid), c.Pcid);
				Debug("PCID=%s\n", c.Pcid);
			}
			Unlock(w->SettingLock);

			// 接続先 Gate が決定した
			Debug("Redirecting to %s:%u... (for proxy: %s)\n", c.HostName, c.Port, c.HostNameForProxy);

			// 接続
			w->ServerErrorCode = ERR_NO_ERROR;
			s = WtsStart(w->wt, &c, w->ServerAcceptProc, w->ServerAcceptParam);

			w->IsConnected = true;

			// 一定時間ごとに状態をポーリング
			while (true)
			{
				if (p->Halt)
				{
					// 切断
					break;
				}

				if (WaitThread(s->ConnectThread, 0))
				{
					// 切断されている
					if (s->ErrorCode != ERR_NO_ERROR)
					{
						// 何らかのエラーが発生して切断
						w->ServerErrorCode = s->ErrorCode;
					}
					else
					{
						// Gate から切断されて切断
						w->ServerErrorCode = ERR_DISCONNECTED;
					}

					break;
				}
				
				Wait(p->HaltEvent, 256);
			}

			if (s->WasConnected || last_wide_controller_connect_ok == false)
			{
				// エラーカウンタリセット
				i = 0;
			}

			last_wide_controller_connect_ok = true;

			w->IsConnected = false;

			// 切断
			WtsStop(s);
			WtReleaseSession(s);

			Free(c.GateConnectParam);
		}

		// 再試行まで待機
		if (p->Halt == false)
		{
			UINT level = WideGetErrorLevel(w->ServerErrorCode);
			UINT interval = WT_GATE_CONNECT_RETRY * MIN((i + 1), 24);

			if (level == DESK_ERRORLEVEL_SERVER_SIDE)
			{
				// サーバー側問題の場合は 15 秒 × 再試行回数 くらい待つ
				interval *= 10;
			}
			else if (level == DESK_ERRORLEVEL_CLIENT_SIDE)
			{
				// クライアント側問題の場合は 75 秒 × 再試行回数 くらい待つ
				interval *= 50;
			}

			switch (w->ServerErrorCode)
			{
			case ERR_RETRY_AFTER_15_MINS:
				// 15 分後に再試行してください
				interval = 15 * 60 * 1000;
				break;

			case ERR_RETRY_AFTER_1_HOURS:
				// 1 時間後に再試行してください
				interval = 1 * 60 * 60 * 1000;
				break;

			case ERR_RETRY_AFTER_8_HOURS:
				// 8 時間後に再試行してください
				interval = 8 * 60 * 60 * 1000;
				break;

			case ERR_RETRY_AFTER_24_HOURS:
				// 24 時間後に再試行してください
				interval = 24 * 60 * 60 * 1000;
				break;
			}

			interval = (UINT)((UINT64)interval * (UINT64)(Rand32() % 1000) / 1500ULL);

			Debug("Wait %u msec for retry...\n", interval);
			Wait(p->HaltEvent, interval);
		}
	}
#endif  // OS_WIN32
}

// 接続スレッド
void WideServerConnectThread(THREAD *thread, void *param)
{
	WIDE *w;
	WT *wt;
	INTERNET_SETTING setting;
	X *server_x = NULL;
	K *server_k = NULL;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	Debug("WideServerConnectThread Start.\n");

	w = (WIDE *)param;

	wt = w->wt;

	Lock(w->SettingLock);
	{
		// インターネット接続設定の取得
		WideGetInternetSetting(w, &setting);

		// 証明書と秘密鍵の取得
		server_x = CloneX(w->ServerX);
		server_k = CloneK(w->ServerK);
	}
	Unlock(w->SettingLock);

	if (server_x == NULL || server_k == NULL)
	{
		// 証明書が登録されていない
		if (w->FirstFlag == false)
		{
			w->FirstFlag = true;
			w->ServerErrorCode = ERR_PLEASE_WAIT;
		}
		else
		{
			w->ServerErrorCode = ERR_NO_INIT_CONFIG;
		}
	}
	else
	{
		// 接続を試行
		CONNECT_MAIN_THREAD_PARAM param;
		THREAD *t;

		Zero(&param, sizeof(param));
		param.Wide = w;
		param.Halt = false;
		param.HaltEvent = NewEvent();

		// 接続メインスレッドの作成
		t = NewThread(WideServerConnectMainThread, &param);

		while (true)
		{
			// 接続停止命令が届くまで無限ループ
			if (w->HaltReconnectThread)
			{
				// 接続停止命令が届いた
				break;
			}

			Wait(w->HaltReconnectThreadEvent, INFINITE);
		}

		// 接続メインスレッドの停止
		param.Halt = true;
		Set(param.HaltEvent);
		WaitThread(t, INFINITE);

		// スレッドの解放
		ReleaseThread(t);

		ReleaseEvent(param.HaltEvent);
	}

	Debug("WideServerConnectThread: %S\n", _E(w->ServerErrorCode));

	FreeX(server_x);
	FreeK(server_k);
}

// 証明書をチェックしないフラグを設定
void WideSetDontCheckCert(WIDE *w, bool dont_check_cert)
{
	// 引数チェック
	if (w == NULL)
	{
		return;
	}

	w->DontCheckCert = dont_check_cert;

	if (w->wt != NULL)
	{
		w->wt->CheckSslTrust = !w->DontCheckCert;
	}
}

// 証明書をチェックしないフラグを取得
bool WideGetDontCheckCert(WIDE *w)
{
	// 引数チェック
	if (w == NULL)
	{
		return false;
	}

	return w->DontCheckCert;
}

// 証明書と秘密鍵の新規生成
void WideServerGenerateCertAndKey(X **cert, K **key)
{
#ifdef	OS_WIN32
	K *private_key, *public_key;
	NAME *name;
	wchar_t cn[MAX_PATH], o[MAX_PATH], ou[MAX_PATH];
	char tmp[MAX_PATH];
	UCHAR hash[SHA1_SIZE];
	UCHAR rand[SHA1_SIZE];
	X_SERIAL *serial;
	// 引数チェック
	if (cert == NULL || key == NULL)
	{
		return;
	}

	// 鍵ペアの作成
	RsaGen(&private_key, &public_key, 1024);

	// CN=マシン名, O=マシンキー, OU=ユーザー名
	GetMachineName(tmp, sizeof(tmp));
	StrToUni(cn, sizeof(cn), tmp);
	GenerateMachineUniqueHash(hash);
	BinToStr(tmp, sizeof(tmp), hash, sizeof(hash));
	StrToUni(o, sizeof(o), tmp);
	StrToUni(ou, sizeof(ou), MsGetUserName());

	Rand(rand, sizeof(rand));
	serial = NewXSerial(rand, sizeof(rand));
	name = NewName(cn, o, ou, L"JP", NULL, NULL);
	*cert = NewRootX(public_key, private_key, name, 3650, serial);
	*key = private_key;

	FreeName(name);
	FreeK(public_key);
	FreeXSerial(serial);
#endif  // OS_WIN32
}

// クライアント接続
UINT WideClientConnectInner(WIDE *w, WT_CONNECT *c, char *pcid, UINT ver, UINT build)
{
	PACK *r = NULL, *p = NULL;
	UINT ret;
	SESSION_INFO_CACHE *cache = NULL;
	// 引数チェック
	if (w == NULL || c == NULL || pcid == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	cache = WideSessionInfoCacheGet(w->SessionInfoCache, pcid, w->SessionInfoCacheExpires);

	if (cache == NULL)
	{
		r = NewPack();
		PackAddStr(r, "SvcName", w->SvcName);
		PackAddStr(r, "Pcid", pcid);
		PackAddInt(r, "Ver", ver);
		PackAddInt(r, "Build", build);
		PackAddData(r, "ClientId", w->ClientId, sizeof(w->ClientId));
		p = WideCall(w, "ClientConnect", r, false, true);
		FreePack(r);

		ret = GetErrorFromPack(p);
	}
	else
	{
		ret = ERR_NO_ERROR;
	}

	if (ret == ERR_NO_ERROR)
	{
		// WT_CONNECT を準備
		INTERNET_SETTING setting;

		WideGetInternetSetting(w, &setting);

		WtInitWtConnectFromInternetSetting(c, &setting);

		c->DontCheckCert = WideGetDontCheckCert(w);
		c->UseCompress = false;

		if (cache == NULL)
		{
			PackGetStr(p, "Hostname", c->HostName, sizeof(c->HostName));
			PackGetStr(p, "HostnameForProxy", c->HostNameForProxy, sizeof(c->HostNameForProxy));
			c->Port = PackGetInt(p, "Port");
			PackGetData2(p, "SessionId", c->SessionId, sizeof(c->SessionId));

			WideSessionInfoCacheAdd(w->SessionInfoCache, pcid,
				c->HostName, c->HostNameForProxy, c->Port, c->SessionId, w->SessionInfoCacheExpires);

			c->CacheUsed = false;

			Debug("Add Cache for %s: %s\n", pcid, c->HostName);
		}
		else
		{
			StrCpy(c->HostName, sizeof(c->HostName), cache->HostName);
			StrCpy(c->HostNameForProxy, sizeof(c->HostNameForProxy), cache->HostNameForProxy);
			c->Port = cache->Port;
			Copy(c->SessionId, cache->SessionId, sizeof(c->SessionId));

			c->CacheUsed = true;

			Debug("Hit Cache for %s: %s\n", pcid, c->HostName);

			Free(cache);
		}
	}
	else if (ret == ERR_RECV_URL)
	{
		// URL を受信
		PackGetStr(p, "Url", w->RecvUrl, sizeof(w->RecvUrl));
	}
	else if (ret == ERR_RECV_MSG)
	{
		// メッセージを受信
		PackGetUniStr(p, "Msg", w->RecvMsg, sizeof(w->RecvMsg));
	}

	FreePack(p);

	return ret;
}

// サーバー接続
UINT WideServerConnect(WIDE *w, WT_CONNECT *c)
{
	PACK *r, *p;
	UINT ret;
	// 引数チェック
	if (w == NULL || c == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	r = NewPack();

	PackAddInt64(r, "ServerMask64", w->ServerMask64);
	p = WideCall(w, "ServerConnect", r, false, true);
	FreePack(r);

	ret = GetErrorFromPack(p);

	if (ret == ERR_NO_ERROR)
	{
		INTERNET_SETTING setting;

		// WT_CONNECT を作成
		WideGetInternetSetting(w, &setting);
		WtInitWtConnectFromInternetSetting(c, &setting);

		c->GateConnectParam = ZeroMalloc(sizeof(WT_GATE_CONNECT_PARAM));
		if (WtGateConnectParamFromPack(c->GateConnectParam, p) == false)
		{
			Free(c->GateConnectParam);
			ret = ERR_PROTOCOL_ERROR;
		}
		else
		{
			PackGetStr(p, "Hostname", c->HostName, sizeof(c->HostName));
			PackGetStr(p, "HostnameForProxy", c->HostNameForProxy, sizeof(c->HostNameForProxy));
			PackGetStr(p, "Pcid", c->Pcid, sizeof(c->Pcid));
			c->Port = PackGetInt(p, "Port");
			c->DontCheckCert = WideGetDontCheckCert(w);
			c->UseCompress = false;
		}
	}

	PackGetUniStr(p, "MsgForServer", c->MsgForServer, sizeof(c->MsgForServer));
	c->MsgForServerOnce = PackGetBool(p, "MsgForServerOnce");

	FreePack(p);

	return ret;
}

// 環境文字列の取得
UINT WideGetEnvStr(WIDE *w, char *name, char *ret_str, UINT ret_size)
{
	UINT ret = ERR_NO_ERROR;
	PACK *r, *p;
	// 引数チェック
	if (w == NULL || ret_str == NULL || name == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	r = NewPack();
	PackAddStr(r, "Name", name);

	p = WideCall(w, "GetEnvStr", r, false, true);
	FreePack(r);

	ret = GetErrorFromPack(p);

	if (ret == ERR_NO_ERROR)
	{
		if (PackGetStr(p, "Ret", ret_str, ret_size) == false)
		{
			ret = ERR_PROTOCOL_ERROR;
		}
	}

	FreePack(p);

	return ret;
}

// マシン名の変更
UINT WideServerRenameMachine(WIDE *w, char *new_name)
{
	UINT ret = ERR_NO_ERROR;
	PACK *r, *p;
	// 引数チェック
	if (w == NULL || new_name == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	r = NewPack();
	PackAddStr(r, "NewName", new_name);

	p = WideCall(w, "RenameMachine", r, false, true);
	FreePack(r);

	ret = GetErrorFromPack(p);
	FreePack(p);

	Lock(w->SettingLock);
	{
		if (ret == ERR_NO_ERROR)
		{
			StrCpy(w->Pcid, sizeof(w->Pcid), new_name);
			StrLower(w->Pcid);
		}
	}
	Unlock(w->SettingLock);

	return ret;
}

// Gate に Machine を登録
UINT WideServerRegistMachine(WIDE *w, char *pcid, X *cert, K *key)
{
	UINT ret = ERR_NO_ERROR;
	PACK *r, *p;
	WT *wt;
	// 引数チェック
	if (w == NULL || pcid == NULL || cert == NULL || key == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	wt = w->wt;

	r = NewPack();
	PackAddStr(r, "SvcName", w->SvcName);
	PackAddStr(r, "Pcid", pcid);

	p = WtWpcCallWithCertAndKey(wt, "RegistMachine", r, cert, key, false, true);
	FreePack(r);

	ret = GetErrorFromPack(p);

	FreePack(p);

	return ret;
}

// Gate へのログインを試行
UINT WideServerGetLoginInfo(WIDE *w, WIDE_LOGIN_INFO *info)
{
	UINT ret = ERR_NO_ERROR;
	PACK *r, *p;
	// 引数チェック
	if (w == NULL || info == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	r = NewPack();
	p = WideCall(w, "GetLoginInfo", r, false, true);
	FreePack(r);

	ret = GetErrorFromPack(p);

	if (ret == ERR_NO_ERROR)
	{
		Zero(info, sizeof(WIDE_LOGIN_INFO));

		info->MachineId = PackGetInt(p, "MachineId");
		PackGetStr(p, "SvcName", info->SvcName, sizeof(info->SvcName));
		PackGetStr(p, "Msid", info->Msid, sizeof(info->Msid));
		PackGetStr(p, "Pcid", info->Pcid, sizeof(info->Pcid));
		info->CreateDate = PackGetInt64(p, "CreateDate");
		info->UpdateDate = PackGetInt64(p, "UpdateDate");
		info->LastServerDate = PackGetInt64(p, "LastServerDate");
		info->LastClientDate = PackGetInt64(p, "LastClientDate");
		info->NumServer = PackGetInt(p, "NumServer");
		info->NumClient = PackGetInt(p, "NumClient");
	}

	FreePack(p);

	return ret;
}

// PCID 候補の取得
UINT WideServerGetPcidCandidate(WIDE *w, char *name, UINT size, char *current_username)
{
#ifdef	OS_WIN32
	PACK *r, *p;
	char machine_name[MAX_PATH];
	char computer_name[MAX_PATH];
	UINT ret;
	// 引数チェック
	if (w == NULL || name == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}
	if (current_username == NULL)
	{
		current_username = "";
	}

	GetMachineName(machine_name, sizeof(machine_name));
	MsGetComputerName(computer_name, sizeof(computer_name));

	r = NewPack();
	PackAddStr(r, "SvcName", w->SvcName);
	PackAddStr(r, "MachineName", machine_name);
	PackAddStr(r, "ComputerName", computer_name);
	PackAddStr(r, "UserName", current_username);

	p = WideCall(w, "GetPcidCandidate", r, false, true);
	FreePack(r);

	ret = GetErrorFromPack(p);

	if (ret == ERR_NO_ERROR)
	{
		PackGetStr(p, "Ret", name, size);
	}

	FreePack(p);

	return ret;
#else   // OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif  // OS_WIN32
}

// WPC の呼び出し
PACK *WideCall(WIDE *wide, char *function_name, PACK *pack, bool global_ip_only, bool try_secondary)
{
	WT *wt;
	X *server_x = NULL;
	K *server_k = NULL;
	PACK *ret;

	// 引数チェック
	if (wide == NULL || function_name == NULL || pack == NULL)
	{
		return PackError(ERR_INTERNAL_ERROR);
	}

	wt = wide->wt;

	PackAddInt(pack, "se_lang", wide->SeLang);

	WideServerGetCertAndKey(wide, &server_x, &server_k);

	ret = WtWpcCallWithCertAndKey(wt, function_name, pack, server_x, server_k, global_ip_only, try_secondary);

	FreeX(server_x);
	FreeK(server_k);

	return ret;
}

// サーバーのエラーコードを取得
UINT WideServerGetErrorCode(WIDE *w)
{
	// 引数チェック
	if (w == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	return w->ServerErrorCode;
}

// 接続スレッドを開始
void WideServerStartConnectThread(WIDE *w)
{
	// 引数チェック
	if (w == NULL)
	{
		return;
	}

	w->HaltReconnectThread = false;
	w->HaltReconnectThreadEvent = NewEvent();

	// エラーのリセット
	w->ServerErrorCode = ERR_PLEASE_WAIT;

	// スレッドの開始
	w->ConnectThread = NewThread(WideServerConnectThread, w);
}

// 接続スレッドを停止
void WideServerStopConnectThread(WIDE *w)
{
	// 引数チェック
	if (w == NULL)
	{
		return;
	}

	// スレッドの停止
	w->HaltReconnectThread = true;
	Set(w->HaltReconnectThreadEvent);
	WaitThread(w->ConnectThread, INFINITE);

	ReleaseThread(w->ConnectThread);
	w->ConnectThread = NULL;
	ReleaseEvent(w->HaltReconnectThreadEvent);
}

// 再接続を試行する
bool WideServerTryAutoReconnect(WIDE *w)
{
	bool ret = false;
	// 引数チェック
	if (w == NULL)
	{
		return false;
	}

	Lock(w->SettingLock);
	{
		if (w->SuppressReconnect)
		{
			ret = false;
			w->IsSuppressedReconnect = true;
		}
		else
		{
			ret = true;
		}
	}
	Unlock(w->SettingLock);

	return ret;
}

// 再接続を実施しないように設定する
void WideServerSuppressAutoReconnect(WIDE *w, bool suppress)
{
	bool b = false;
	// 引数チェック
	if (w == NULL)
	{
		return;
	}

	Lock(w->SettingLock);
	{
		if (suppress == false)
		{
			if (w->SuppressReconnect)
			{
				w->SuppressReconnect = false;
				if (w->IsSuppressedReconnect)
				{
					b = true;
				}
			}
		}
		else
		{
			if (w->SuppressReconnect == false)
			{
				w->SuppressReconnect = true;
				w->IsSuppressedReconnect = false;
			}
		}
	}
	Unlock(w->SettingLock);

	if (b)
	{
		WideServerReconnect(w);
	}
}

// 再接続を実施
void WideServerReconnect(WIDE *w)
{
	WideServerReconnectEx(w, false);
}
void WideServerReconnectEx(WIDE *w, bool stop)
{
	WT *wt;
	// 引数チェック
	if (w == NULL)
	{
		return;
	}

	wt = w->wt;

	Lock(w->ReconnectLock);
	{
		// 現在スレッドが動作中かどうか調べる
		if (w->ConnectThread != NULL)
		{
			// 接続スレッドを停止
			WideServerStopConnectThread(w);
		}

		if (stop == false)
		{
			// 接続スレッドを開始
			WideServerStartConnectThread(w);
		}
	}
	Unlock(w->ReconnectLock);
}

// インターネット接続設定を取得
void WideGetInternetSetting(WIDE *w, INTERNET_SETTING *setting)
{
	WT *wt;
	// 引数チェック
	if (w == NULL || setting == NULL)
	{
		return;
	}

	wt = w->wt;

	Lock(w->SettingLock);
	{
		WtGetInternetSetting(wt, setting);
	}
	Unlock(w->SettingLock);
}

// インターネット接続設定を設定
void WideSetInternetSetting(WIDE *w, INTERNET_SETTING *setting)
{
	WT *wt;
	// 引数チェック
	if (w == NULL || setting == NULL)
	{
		return;
	}

	wt = w->wt;

	Lock(w->SettingLock);
	{
		WtSetInternetSetting(wt, setting);
	}
	Unlock(w->SettingLock);

	if (w->Type == WIDE_TYPE_SERVER)
	{
		if (WideServerTryAutoReconnect(w))
		{
			WideServerReconnect(w);
		}
	}
}

// 証明書と秘密鍵を設定
void WideServerSetCertAndKey(WIDE *w, X *cert, K *key)
{
	WideServerSetCertAndKeyEx(w, cert, key, false);
}
void WideServerSetCertAndKeyEx(WIDE *w, X *cert, K *key, bool no_reconnect)
{
	// 引数チェック
	if (w == NULL || cert == NULL || key == NULL)
	{
		return;
	}

	Lock(w->SettingLock);
	{
		if (w->ServerX != NULL)
		{
			FreeX(w->ServerX);
		}
		w->ServerX = CloneX(cert);

		if (w->ServerK != NULL)
		{
			FreeK(w->ServerK);
		}
		w->ServerK = CloneK(key);
	}
	Unlock(w->SettingLock);

	if (no_reconnect == false)
	{
		if (WideServerTryAutoReconnect(w))
		{
			WideServerReconnect(w);
		}
	}
}

// 証明書と秘密鍵を取得
bool WideServerGetCertAndKey(WIDE *w, X **cert, K **key)
{
	bool ret = false;
	// 引数チェック
	if (w == NULL || cert == NULL || key == NULL)
	{
		return false;
	}

	Lock(w->SettingLock);
	{
		if (w->ServerX != NULL && w->ServerK != NULL)
		{
			*cert = CloneX(w->ServerX);
			*key = CloneK(w->ServerK);
			ret = true;
		}
	}
	Unlock(w->SettingLock);

	return ret;
}

// Server の開始
WIDE *WideServerStart(char *svc_name, WT_ACCEPT_PROC *accept_proc, void *accept_param, UINT se_lang)
{
	return WideServerStartEx(svc_name, accept_proc, accept_param, se_lang, NULL, NULL);
}
WIDE *WideServerStartEx(char *svc_name, WT_ACCEPT_PROC *accept_proc, void *accept_param, UINT se_lang,
						WIDE_RESET_CERT_PROC *reset_cert_proc, void *reset_cert_proc_param)
{
	return WideServerStartEx2(svc_name, accept_proc, accept_param, se_lang,
		reset_cert_proc, reset_cert_proc_param, NULL, NULL);
}
WIDE *WideServerStartEx2(char *svc_name, WT_ACCEPT_PROC *accept_proc, void *accept_param, UINT se_lang,
						WIDE_RESET_CERT_PROC *reset_cert_proc, void *reset_cert_proc_param,
						X *master_cert, char *fixed_entrance_url)
{
	WIDE *w;
	// 引数チェック
	if (svc_name == NULL || accept_proc == NULL)
	{
		return NULL;
	}

	w = ZeroMalloc(sizeof(WIDE));

	w->SeLang = se_lang;
	if (master_cert == NULL)
	{
		w->wt = NewWtFromHamcore();
	}
	else
	{
		w->wt = NewWt(master_cert);
	}
	w->wt->Wide = w;
	w->Type = WIDE_TYPE_SERVER;
	w->SettingLock = NewLock();
	w->ReconnectLock = NewLock();
	w->ServerAcceptProc = accept_proc;
	w->ServerAcceptParam = accept_param;
	w->ResetCertProc = reset_cert_proc;
	w->ResetCertProcParam = reset_cert_proc_param;

	w->wt->EnableUpdateEntryPoint = true; // EntryPoint.dat 自動更新有効


	if (fixed_entrance_url != NULL)
	{
		if (IsEmptyStr(fixed_entrance_url))
		{
			fixed_entrance_url = "https://127.0.0.1/";
		}
		StrCpy(w->wt->FixedEntranceUrl, sizeof(w->wt->FixedEntranceUrl),
			fixed_entrance_url);
	}

	StrCpy(w->SvcName, sizeof(w->SvcName), svc_name);

	// 接続を開始
	WideServerReconnect(w);

	return w;
}
WIDE *WideServerStartForAcceptQueue(char *svc_name, X *master_cert, char *entrance)
{
	WIDE *w;
	ACCEPT_QUEUE *aq;
	// 引数チェック
	if (svc_name == NULL)
	{
		return NULL;
	}

	aq = NewAcceptQueue();

	w = WideServerStartEx2(svc_name, AcceptQueueAcceptProc, aq, 0, NULL, NULL,
		master_cert, entrance);

	w->AcceptQueue = aq;

	return w;
}

// 次のキューを取得
ACCEPT_QUEUE_ENTRY *AcceptQueueGetNext(WIDE *w)
{
	ACCEPT_QUEUE *aq;
	// 引数チェック
	if (w == NULL)
	{
		return NULL;
	}

	aq = w->AcceptQueue;

	while (true)
	{
		ACCEPT_QUEUE_ENTRY *e;
		if (aq->Halt)
		{
			return NULL;
		}

		Wait(aq->Event, INFINITE);

		if (aq->Halt)
		{
			return NULL;
		}

		LockQueue(aq->Queue);
		{
			e = GetNext(aq->Queue);
		}
		UnlockQueue(aq->Queue);

		if (e != NULL)
		{
			return e;
		}
	}
}

// Accept Proc
void AcceptQueueAcceptProc(THREAD *thread, SOCKIO *sock, void *param)
{
	ACCEPT_QUEUE *aq = (ACCEPT_QUEUE *)param;
	ACCEPT_QUEUE_ENTRY *e;

	if (aq == NULL)
	{
		return;
	}

	e = ZeroMalloc(sizeof(ACCEPT_QUEUE_ENTRY));

	e->EndEvent = NewEvent();
	e->sockio = sock;

	LockQueue(aq->Queue);
	{
		InsertQueue(aq->Queue, e);
	}
	UnlockQueue(aq->Queue);

	Set(aq->Event);

	Wait(e->EndEvent, INFINITE);

	ReleaseEvent(e->EndEvent);

	Free(e);
}

// Accept キューの作成
ACCEPT_QUEUE *NewAcceptQueue()
{
	ACCEPT_QUEUE *aq = ZeroMalloc(sizeof(ACCEPT_QUEUE));

	aq->Event = NewEvent();
	aq->Queue = NewQueue();

	return aq;
}

// Accept キューの解放
void FreeAcceptQueue(ACCEPT_QUEUE *aq)
{
	// 引数チェック
	if (aq == NULL)
	{
		return;
	}

	aq->Halt = true;

	Set(aq->Event);

	ReleaseEvent(aq->Event);

	ReleaseQueue(aq->Queue);

	Free(aq);
}

// Server の停止
void WideServerStop(WIDE *w)
{
	// 引数チェック
	if (w == NULL)
	{
		return;
	}

	WideServerReconnectEx(w, true);

	if (w->ServerX != NULL)
	{
		FreeX(w->ServerX);
	}

	if (w->ServerK != NULL)
	{
		FreeK(w->ServerK);
	}

	DeleteLock(w->SettingLock);
	DeleteLock(w->ReconnectLock);

	ReleaseWt(w->wt);

	if (w->AcceptQueue != NULL)
	{
		FreeAcceptQueue(w->AcceptQueue);
	}

	Free(w);
}

// Secure Pack の保存先フォルダリストの作成
LIST *WideNewSecurePackFolderList()
{
	SECURE_PACK_FOLDER *f;
	LIST *o = NewListFast(NULL);
	char tmp[MAX_PATH] = {0};
	wchar_t tmp2[MAX_PATH] = {0};

#ifndef DESK_SECURE_PACK_EASY_MODE
	// HKEY_LOCAL_MACHINE\SOFTWARE\SoftEther Corporation\Keywords
	f = ZeroMalloc(sizeof(SECURE_PACK_FOLDER));
	f->Type = SECURE_PACK_FOLDER_TYPE_LOCAL_MACHINE;
	UniStrCpy(f->FolderName, sizeof(f->FolderName), L"SOFTWARE\\SoftEther Corporation\\Keywords");
	Add(o, f);

	// HKEY_CURRENT_USER\Software\SoftEther Corporation\Secure Pack
	f = ZeroMalloc(sizeof(SECURE_PACK_FOLDER));
	f->Type = SECURE_PACK_FOLDER_TYPE_CURRENT_USER;
	f->ByMachineOnly = true;
	UniStrCpy(f->FolderName, sizeof(f->FolderName), L"Software\\SoftEther Corporation\\Secure Pack");
	Add(o, f);

	// AppData\Secure Pack
	f = ZeroMalloc(sizeof(SECURE_PACK_FOLDER));
	f->Type = SECURE_PACK_FOLDER_TYPE_DISK;
	f->ByMachineOnly = true;
	ConbinePathW(f->FolderName, sizeof(f->FolderName), MsGetPersonalAppDataDirW(), L"Secure Pack");
	Add(o, f);

	// LocalData\ConfidentialData
	f = ZeroMalloc(sizeof(SECURE_PACK_FOLDER));
	f->Type = SECURE_PACK_FOLDER_TYPE_DISK;
	ConbinePathW(f->FolderName, sizeof(f->FolderName), MsGetLocalAppDataDirW(), L"ConfidentialData");
	Add(o, f);

	// AllUsersAppData\Common Secure Datas
	f = ZeroMalloc(sizeof(SECURE_PACK_FOLDER));
	f->Type = SECURE_PACK_FOLDER_TYPE_DISK;
	ConbinePathW(f->FolderName, sizeof(f->FolderName), MsGetCommonAppDataDirW(), L"Common Secure Datas");
	Add(o, f);

	// Exe Folder
	f = ZeroMalloc(sizeof(SECURE_PACK_FOLDER));
	f->Type = SECURE_PACK_EXE_FOLDER;
	MsGetComputerName(tmp, sizeof(tmp));
	ConvertSafeFileName(tmp, sizeof(tmp), tmp);
	StrToUni(tmp2, sizeof(tmp2), tmp);
	ConbinePathW(f->FolderName, sizeof(f->FolderName), MsGetExeDirNameW(), L".data");
	MakeDirW(f->FolderName);
	MsSetFileToHiddenW(f->FolderName);
	ConbinePathW(f->FolderName, sizeof(f->FolderName), f->FolderName, tmp2);
	MakeDirW(f->FolderName);
	MsSetFileToHiddenW(f->FolderName);
	Add(o, f);
#else	// DESK_SECURE_PACK_EASY_MODE

	// HKEY_LOCAL_MACHINE\SOFTWARE\SoftEther Corporation\Keywords
	f = ZeroMalloc(sizeof(SECURE_PACK_FOLDER));
	f->Type = SECURE_PACK_FOLDER_TYPE_LOCAL_MACHINE;
	UniStrCpy(f->FolderName, sizeof(f->FolderName), L"SOFTWARE\\" DESK_PUBLISHER_NAME_UNICODE L"\\Machine ID");
	Add(o, f);

	// HKEY_CURRENT_USER\Software\SoftEther Corporation\Secure Pack
	f = ZeroMalloc(sizeof(SECURE_PACK_FOLDER));
	f->Type = SECURE_PACK_FOLDER_TYPE_CURRENT_USER;
	f->ByMachineOnly = true;
	UniStrCpy(f->FolderName, sizeof(f->FolderName), L"Software\\" DESK_PUBLISHER_NAME_UNICODE L"\\Machine ID");
	Add(o, f);

#endif	// DESK_SECURE_PACK_EASY_MODE

	WtShuffleArray(o->p, LIST_NUM(o));

	return o;
}

// フォルダリストの解放
void WideFreeSecurePackFolderList(LIST *o)
{
	UINT i;
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SECURE_PACK_FOLDER *f = LIST_DATA(o, i);

		Free(f);
	}

	ReleaseList(o);
}

// Secure Pack を実際に書き込む
void WideWriteSecurePackMain(UINT type, wchar_t *foldername, char *name, PACK *p, bool by_machine_only)
{
	wchar_t filename1[MAX_PATH];
	wchar_t filename2[MAX_PATH];
	// 引数チェック
	if (foldername == NULL || name == NULL)
	{
		return;
	}

	WideGenerateSecurePackFileName(type,
		filename1,
		sizeof(filename1),
		foldername, name,
		false);

	WideGenerateSecurePackFileName(type,
		filename2,
		sizeof(filename2),
		foldername, name,
		true);

	WideWriteSecurePackEntry(type, foldername, filename1, p);

	if (by_machine_only == false)
	{
		WideWriteSecurePackEntry(type, foldername, filename2, p);
	}
}
void WideWriteSecurePackEntry(UINT type, wchar_t *foldername, wchar_t *filename, PACK *p)
{
#ifdef	OS_WIN32
	BUF *b;
	char filename_a[MAX_PATH];
	char foldername_a[MAX_PATH];
	// 引数チェック
	if (foldername == NULL || filename == NULL)
	{
		return;
	}

	UniToStr(filename_a, sizeof(filename_a), filename);
	UniToStr(foldername_a, sizeof(foldername_a), foldername);

	if (p != NULL)
	{
		b = WideWriteSecurePackConvertToBuf(filename, p);
	}
	else
	{
		b = NULL;
	}

	// データを書き込む
	if (type == SECURE_PACK_FOLDER_TYPE_DISK || type == SECURE_PACK_EXE_FOLDER)
	{
		// ファイル
		wchar_t tmp[MAX_PATH];

		ConbinePathW(tmp, sizeof(tmp), foldername, filename);

		if (b != NULL)
		{
			// 作成
			MakeDirW(foldername);
			if (type == SECURE_PACK_EXE_FOLDER)
			{
				// "Data" は隠しディレクトリにする
				MsSetFileToHiddenW(foldername);
			}
			Debug("WriteFile: %S\n", tmp);
			DumpBufW(b, tmp);
		}
		else
		{
			// 削除
			FileDeleteW(tmp);
		}
	}
	else
	{
		// レジストリ
		if (b != NULL)
		{
			// 作成
			Debug("WriteReg: %s\\%s\n", foldername_a, filename_a);
			MsRegWriteBin(type == SECURE_PACK_FOLDER_TYPE_LOCAL_MACHINE ? REG_LOCAL_MACHINE : REG_CURRENT_USER,
				foldername_a, filename_a, b->Buf, b->Size);
		}
		else
		{
			// 削除
			MsRegDeleteValue(type == SECURE_PACK_FOLDER_TYPE_LOCAL_MACHINE ? REG_LOCAL_MACHINE : REG_CURRENT_USER,
				foldername_a, filename_a);
		}
	}

	FreeBuf(b);
#endif  // OS_WIN32
}

// Secure Pack を実際に読み込む
PACK *WideReadSecurePackMain(UINT type, wchar_t *foldername, char *name, bool for_user)
{
	wchar_t filename[MAX_PATH];
	// 引数チェック
	if (foldername == NULL || name == NULL)
	{
		return NULL;
	}

	WideGenerateSecurePackFileName(type,
		filename,
		sizeof(filename),
		foldername, name,
		for_user);

	return WideReadSecurePackEntry(type, foldername, filename);
}
PACK *WideReadSecurePackEntry(UINT type, wchar_t *foldername, wchar_t *filename)
{
#ifdef	OS_WIN32
	BUF *b = NULL;
	PACK *p = NULL;
	char filename_a[MAX_PATH];
	char foldername_a[MAX_PATH];
	// 引数チェック
	if (foldername == NULL || filename == NULL)
	{
		return NULL;
	}

	UniToStr(filename_a, sizeof(filename_a), filename);
	UniToStr(foldername_a, sizeof(foldername_a), foldername);

	// データを読み込む
	if (type == SECURE_PACK_FOLDER_TYPE_DISK || type == SECURE_PACK_EXE_FOLDER)
	{
		// ファイル
		wchar_t tmp[MAX_PATH];

		ConbinePathW(tmp, sizeof(tmp), foldername, filename);

		Debug("ReadFile: %S\n", tmp);
		b = ReadDumpW(tmp);
	}
	else
	{
		// レジストリ
		Debug("ReadReg: %s\\%s\n", foldername_a, filename_a);
		b = MsRegReadBin(type == SECURE_PACK_FOLDER_TYPE_LOCAL_MACHINE ? REG_LOCAL_MACHINE : REG_CURRENT_USER,
			foldername_a, filename_a);
	}

	if (b != NULL)
	{
		p = WideReadSecurePackConvertFromBuf(filename, b);
		FreeBuf(b);
	}

	return p;
#else   // OS_WIN32
	return NULL;
#endif  // OS_WIN32
}

// バッファを Pack に変換する
PACK *WideReadSecurePackConvertFromBuf(wchar_t *filename, BUF *src)
{
	CRYPT *c;
	BUF *b;
	PACK *p = NULL;
	UINT pb_size;
	char filename_a[MAX_PATH];
	// 引数チェック
	if (filename == NULL || src == NULL)
	{
		return NULL;
	}

	UniToStr(filename_a, sizeof(filename_a), filename);

	b = NewBuf();
	WriteBuf(b, src->Buf, src->Size);
	SeekBuf(b, 0, 0);

	// 解読
	c = NewCrypt(filename_a, StrLen(filename_a));
	Encrypt(c, b->Buf, b->Buf, b->Size);
	FreeCrypt(c);

	// <size> の取得
	pb_size = 0;
	ReadBuf(b, &pb_size, sizeof(UINT));
	pb_size = Endian32(pb_size);

	if ((b->Size - b->Current) < (pb_size + SHA1_SIZE))
	{
		// <size> の値に対して長さが足りない
	}
	else
	{
		// <hash> の取得
		UCHAR hash1[SHA1_SIZE];
		UCHAR hash2[SHA1_SIZE];

		if (ReadBuf(b, hash1, sizeof(hash1)) == sizeof(hash1))
		{
			BUF *pb;

			// Pack 本体の取得
			pb = NewBuf();
			WriteBuf(pb, (UCHAR *)b->Buf + b->Current, pb_size);

			// ハッシュの計算
			HashSha1(hash2, pb->Buf, pb->Size);

			if (Cmp(hash1, hash2, SHA1_SIZE) == 0)
			{
				// ハッシュ一致
				SeekBuf(pb, 0, 0);
				p = BufToPack(pb);
			}

			FreeBuf(pb);
		}
	}

	FreeBuf(b);

	return p;
}

// Pack をバッファに変換する
BUF *WideWriteSecurePackConvertToBuf(wchar_t *filename, PACK *p)
{
	BUF *b;
	BUF *pb;
	UINT pb_size;
	UCHAR hash[SHA1_SIZE];
	UINT rand_size;
	void *rand;
	CRYPT *c;
	char filename_a[MAX_PATH];
	// 引数チェック
	if (filename == NULL || p == NULL)
	{
		return NULL;
	}

	UniToStr(filename_a, sizeof(filename_a), filename);

	// <size><hash><data><rand>
	pb = PackToBuf(p);
	pb_size = Endian32(pb->Size);

	b = NewBuf();
	WriteBuf(b, &pb_size, sizeof(UINT));

	HashSha1(hash, pb->Buf, pb->Size);
	WriteBuf(b, hash, sizeof(hash));

	WriteBuf(b, pb->Buf, pb->Size);

	FreeBuf(pb);

	rand_size = Rand32() % 512;
	rand = Malloc(rand_size);
	Rand(rand, rand_size);

	WriteBuf(b, rand, rand_size);

	Free(rand);

	// 暗号化
	c = NewCrypt(filename_a, StrLen(filename_a));
	Encrypt(c, b->Buf, b->Buf, b->Size);
	FreeCrypt(c);

	SeekBuf(b, 0, 0);

	return b;
}

// Secure Pack の名前を生成する
void WideGenerateSecurePackFileName(UINT type, wchar_t *filename, UINT size, wchar_t *foldername, char *name, bool for_user)
{
#ifdef	OS_WIN32
	BUF *b;
	char product_id[MAX_PATH];
	char tmp[MAX_PATH];
	UCHAR hash[SHA1_SIZE];
	char hash_str[MAX_PATH];
	UINT filename_len;
	UINT i;
	bool is_reg = (type == SECURE_PACK_FOLDER_TYPE_LOCAL_MACHINE || type == SECURE_PACK_FOLDER_TYPE_CURRENT_USER);
	char filename_a[MAX_PATH];
	char foldername_a[MAX_PATH];
	// 引数チェック
	if (filename == NULL || foldername == NULL || name == NULL)
	{
		return;
	}

	UniToStr(filename_a, sizeof(filename_a), filename);
	UniToStr(foldername_a, sizeof(foldername_a), foldername);

	WideGetWindowsProductId(product_id, sizeof(product_id));
	StrUpper(product_id);
	Trim(product_id);

	b = NewBuf();

	if (type != SECURE_PACK_EXE_FOLDER)
	{
		if (for_user == false)
		{
			WriteBuf(b, product_id, StrLen(product_id));
		}
		else
		{
			char current_username[MAX_PATH];

			StrCpy(current_username, sizeof(current_username), MsGetUserName());
			StrUpper(current_username);
			Trim(current_username);

			WriteBuf(b, current_username, StrLen(current_username));
		}

		StrCpy(tmp, sizeof(tmp), foldername_a);
		StrUpper(tmp);
		Trim(tmp);
		WriteBuf(b, tmp, StrLen(tmp));
	}
	else
	{
		char c = 0;
		if (for_user)
		{
			c = 1;
		}
		WriteBuf(b, &c, sizeof(c));
	}

	StrCpy(tmp, sizeof(tmp), name);
	StrUpper(tmp);
	Trim(tmp);
	WriteBuf(b, tmp, StrLen(tmp));
	WriteBuf(b, tmp, StrLen(tmp));

	HashSha1(hash, b->Buf, b->Size);
	Copy(&i, hash, sizeof(UINT));
	filename_len = i % 10 + 5 + (is_reg ? 0 : 4);

	BinToStr(hash_str, sizeof(hash_str), hash, sizeof(hash));
	hash_str[filename_len] = 0;

	if (is_reg == false)
	{
		hash_str[filename_len - 4] = '.';
	}

	StrUpper(hash_str);

	FreeBuf(b);

	StrToUni(filename, size, hash_str);
#endif  // OS_WIN32
}

// Secure Pack を読み込む
PACK *WideReadSecurePack(char *name)
{
	LIST *o;
	UINT i;
	PACK *last_p = NULL;
	UINT64 last_p_timestamp = 0;
	WT_MACHINE_ID d;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}

	WideGetCurrentMachineId(&d);

	// 読み込む
	o = WideNewSecurePackFolderList();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT j;
		for (j = 0;j < 2;j++)
		{
			SECURE_PACK_FOLDER *f = LIST_DATA(o, i);
			bool for_user = (j == 0 ? false : true);

			if (f->ByMachineOnly == false || for_user == false)
			{
				PACK *p = WideReadSecurePackMain(f->Type, f->FolderName, name, for_user);

				if (p != NULL)
				{
					WT_MACHINE_ID d2;
					UINT64 ts = PackGetInt64(p, "Timestamp");
					bool b = false;

					if (PackGetData2(p, "MachineId", &d2, sizeof(d2)))
					{
						if (WideCompareMachineId(&d, &d2))
						{
							if (ts != 0 && last_p_timestamp < ts)
							{
								if (last_p != NULL)
								{
									FreePack(last_p);
								}
								last_p = p;
								last_p_timestamp = ts;

								b = true;
							}
						}
					}

					if (b == false)
					{
						FreePack(p);
					}
				}
			}
		}
	}

	WideFreeSecurePackFolderList(o);

	// 書き込む
	if (last_p != NULL)
	{
		WideWriteSecurePackEx(name, last_p, last_p_timestamp);
	}

	return last_p;
}

// Secure Pack の消去
void WideCleanSecurePack(char *name)
{
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	WideWriteSecurePack(name, NULL);
}

// Secure Pack を書き込む
void WideWriteSecurePack(char *name, PACK *p)
{
	WideWriteSecurePackEx(name, p, 0);
}
void WideWriteSecurePackEx(char *name, PACK *p, UINT64 timestamp)
{
	LIST *o;
	UINT i;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}
	if (timestamp == 0)
	{
		timestamp = SystemTime64();
	}

	if (p != NULL)
	{
		WT_MACHINE_ID d;

		WideGetCurrentMachineId(&d);

		DelElement(p, "Timestamp");
		PackAddInt64(p, "Timestamp", timestamp);

		DelElement(p, "MachineId");
		PackAddData(p, "MachineId", &d, sizeof(d));
	}

	o = WideNewSecurePackFolderList();
	for (i = 0;i < LIST_NUM(o);i++)
	{
		SECURE_PACK_FOLDER *f = LIST_DATA(o, i);

		WideWriteSecurePackMain(f->Type, f->FolderName, name, p, f->ByMachineOnly);
	}
	WideFreeSecurePackFolderList(o);
}

// Windows のプロダクト ID を取得
void WideGetWindowsProductId(char *id, UINT size)
{
	if (StrLen(windows_product_id) == 0)
	{
		WideGetWindowsProductIdMain(windows_product_id, sizeof(windows_product_id));
	}

	StrCpy(id, size, windows_product_id);
}
void WideGetWindowsProductIdMain(char *id, UINT size)
{
#ifdef	OS_WIN32
	char *s;
	// 引数チェック
	if (id == NULL)
	{
		return;
	}

	s = MsRegReadStrEx2(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		"ProductId", false, true);

	if (IsEmptyStr(s))
	{
		s = MsRegReadStrEx2(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
			"ProductId", false, true);
	}

	if (IsEmptyStr(s))
	{
		StrCpy(id, size, "--");
	}
	else
	{
		StrCpy(id, size, s);
	}

	Free(s);
#endif  // OS_WIN32
}

// セッションを Pack する
void WideGatePackSession(PACK *p, TSESSION *s, UINT i, UINT num, LIST *sc_list)
{
	char tmp[MAX_PATH];
	// 引数チェック
	if (p == NULL || s == NULL)
	{
		return;
	}

	PackAddStrEx(p, "Msid", s->Msid, i, num);
	PackAddDataEx(p, "SessionId", s->SessionId, sizeof(s->SessionId), i, num);
	PackAddInt64Ex(p, "EstablishedDateTime", TickToTime(s->EstablishedTick), i, num);
	PackAddIntEx(p, "NumClients", LIST_NUM(s->TunnelList), i, num);

	IPToStr(tmp, sizeof(tmp), &s->ServerTcp->Ip);
	PackAddStrEx(p, "IpAddress", tmp, i, num);
	PackAddStrEx(p, "Hostname", s->ServerTcp->Hostname, i, num);

	PackAddInt64Ex(p, "ServerMask64", s->ServerMask64, i, num);

	if (sc_list != NULL)
	{
		Lock(s->Lock);
		{
			UINT i;

			for (i = 0;i < LIST_NUM(s->TunnelList);i++)
			{
				TUNNEL *t = LIST_DATA(s->TunnelList, i);
				SESSION_AND_CLIENT *sc = ZeroMalloc(sizeof(SESSION_AND_CLIENT));

				Copy(sc->SessionId, s->SessionId, sizeof(sc->SessionId));
				Copy(sc->ClientId, t->ClientId, sizeof(sc->ClientId));

				Add(sc_list, sc);
			}
		}
		Unlock(s->Lock);
	}
}

// セッションリストを Pack する
void WideGatePackSessionList(PACK *p, WT *wt, LIST *sc_list)
{
	// 引数チェック
	if (p == NULL || wt == NULL)
	{
		return;
	}

	LockList(wt->SessionList);
	{
		UINT i, num;

		num = LIST_NUM(wt->SessionList);
		for (i = 0;i < num;i++)
		{
			TSESSION *s = LIST_DATA(wt->SessionList, i);

			WideGatePackSession(p, s, i, num, sc_list);
		}

		PackAddInt(p, "NumSession", num);
	}
	UnlockList(wt->SessionList);
}

// Gate の情報を Pack する
void WideGatePackGateInfo(PACK *p, WT *wt)
{
	// 引数チェック
	if (p == NULL || wt == NULL)
	{
		return;
	}

	PackAddData(p, "GateId", wt->GateId, sizeof(wt->GateId));
	PackAddInt(p, "EntryExpires", WideGateGetIniEntry("EntryExpires"));
	PackAddInt(p, "Performance", WideGateGetIniEntry("Performance"));
	PackAddInt(p, "Build", CEDAR_BUILD);
}

// ini ファイル内のエントリを取得
UINT WideGateGetIniEntry(char *name)
{
	LIST *o;
	UINT ret;
	// 引数チェック
	if (name == NULL)
	{
		return 0;
	}

	o = WideGateLoadIni();

	ret = IniIntValue(o, name);

	WideFreeIni(o);

	return ret;
}

// ランダムドメイン名の生成
void WideGenerateRandomDummyDomain(char *str, UINT size)
{
	UINT len;
	char tmp[MAX_PATH];
	UINT i;
	if (str == NULL)
	{
		return;
	}

	len = Rand32() % 16 + 12;

	Zero(tmp, sizeof(tmp));

	for (i = 0;i < len;i++)
	{
		char c = 'a' + Rand32() % ('z' - 'a');

		tmp[i] = c;
	}

	tmp[len - (Rand32() % 6) - 3] = '.';

	StrCpy(str, size, tmp);
}

// 証明書のロード
void WideGateLoadCertKey(X **cert, K **key)
{
	char *server_cert;
	char *server_key;
	LIST *o;

	// 引数チェック
	if (cert == NULL || key == NULL)
	{
		return;
	}

	*cert = NULL;
	*key = NULL;

	o = WideGateLoadIni();

	server_cert = IniStrValue(o, "ServerCert");
	server_key = IniStrValue(o, "ServerKey");

	// 同一ディレクトリにマスター証明書があった場合はそれを用いて自分の証明書
	// を起動時に動的に自動生成する
	{
		X *master_x = FileToX(WT_MASTER_CERT_NAME);
		K *master_k = FileToK(WT_MASTER_KET_NAME, true, NULL);

		if (master_x != NULL && master_k != NULL)
		{
			char domain1[MAX_PATH];
			char domain2[MAX_PATH];
			char serial[MAX_PATH];
			wchar_t domain1w[MAX_PATH];
			wchar_t domain2w[MAX_PATH];

			WideGenerateRandomDummyDomain(domain1, sizeof(domain1));
			WideGenerateRandomDummyDomain(domain2, sizeof(domain2));
			WideGenerateRandomDummyDomain(serial, sizeof(serial));

			StrToUni(domain1w, sizeof(domain1w), domain1);
			StrToUni(domain2w, sizeof(domain2w), domain2);

			if (CheckXandK(master_x, master_k))
			{
				K *pub = NULL;
				K *pri = NULL;
				X_SERIAL *x_serial = NewXSerial(serial, StrLen(serial));
				UINT days = GetDaysUntil2038Ex() - Rand32() % 64;
				NAME *n = NewName(domain1w, NULL, NULL, L"JP", NULL, NULL);
				NAME *n_issuer = NewName(domain2w, NULL, NULL, L"JP", NULL, NULL);
				X *new_x = NULL;

				RsaGen(&pri, &pub, 2048);

				new_x = NewXEx(pub, master_k, master_x, n, days, x_serial, n_issuer);

				FreeXSerial(x_serial);
				FreeName(n);
				FreeName(n_issuer);
				FreeK(pub);

				if (new_x != NULL)
				{
					*cert = new_x;
					*key = pri;
				}
				else
				{
					FreeK(pri);
				}
			}
		}

		FreeX(master_x);
		FreeK(master_k);
	}

	if (*cert == NULL)
	{
		// 上記の方法で動的に生成されない場合は、ファイルから静的にロードする
		*cert = FileToX(server_cert);
		*key = FileToK(server_key, true, NULL);
	}

	if (*cert == NULL || *key == NULL)
	{
		FreeX(*cert);
		FreeK(*key);

		Alert("WideGateLoadCertKey failed.", "WideGate");
		AbortExitEx("WideGateLoadCertKey failed.");
	}

	WideFreeIni(o);

	return;
}

// セッション削除の報告
void WideGateReportSessionDel(WIDE *wide, UCHAR *session_id)
{
	WT *wt;
	// 引数チェック
	if (wide == NULL)
	{
		return;
	}

	if (WideGateGetIniEntry("DisableRegister"))
	{
		// 一時的に登録無効化
		return;
	}


	wt = wide->wt;

	Lock(wide->LockReport);
	{
		PACK *p = NewPack();
		PACK *ret = NULL;

		PackAddStr(p, "GateKey", wide->GateKeyStr);

		PackAddData(p, "SessionId", session_id, WT_SESSION_ID_SIZE);
		WideGatePackGateInfo(p, wt);

		ret = WtWpcCallWithCertAndKey(wt, "ReportSessionDel", p, wide->GateCert, wide->GateKey, true, false);

		if (ret != NULL)
		{
			WideGateSetControllerGateSecretKeyFromPack(wide, ret);
			FreePack(ret);
		}

		FreePack(p);
	}
	Unlock(wide->LockReport);
}

void WideGateSetControllerGateSecretKeyFromPack(WIDE *wide, PACK *p)
{
	char controller_gate_secret_key[64] = {0};

	if (wide == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "ControllerGateSecretKey", controller_gate_secret_key, sizeof(controller_gate_secret_key)))
	{
		if (IsEmptyStr(controller_gate_secret_key) == false)
		{
			WideGateSetControllerGateSecretKey(wide, controller_gate_secret_key);
		}
	}
}

// セッション追加の報告
void WideGateReportSessionAdd(WIDE *wide, TSESSION *s)
{
	WT *wt;
	bool b = true;
	UINT64 gateway_interval = (UINT64)WideGateGetIniEntry("GatewayInterval");
	// 引数チェック
	if (wide == NULL)
	{
		return;
	}

	wt = wide->wt;

	Lock(wide->ReportIntervalLock);
	{
		UINT64 now = Tick64();

		if (wide->LastReportTick == 0 ||
			(wide->LastReportTick + (UINT64)WIDE_REPORT_FAST_SEND_INTERVAL) <= now)
		{
			// 何もしない
		}
		else
		{
			// 最近 WIDE_REPORT_FAST_SEND_INTERVAL ミリ秒以内にセッション追加の報告
			// が行われたので、今回の報告は行わずに、遅延報告を行う

			wide->NextReportTick2 = now + (UINT64)(gateway_interval / 2);

			b = false;
		}
		wide->LastReportTick = now;
	}
	Unlock(wide->ReportIntervalLock);

	if (WideGateGetIniEntry("DisableRegister"))
	{
		// 一時的に登録無効化
		return;
	}


	if (b)
	{
		Lock(wide->LockReport);
		{
			PACK *p = NewPack();
			PACK *ret = NULL;

			PackAddStr(p, "GateKey", wide->GateKeyStr);

			WideGatePackSession(p, s, 0, 1, NULL);
			WideGatePackGateInfo(p, wt);

			ret = WtWpcCallWithCertAndKey(wt, "ReportSessionAdd", p, wide->GateCert, wide->GateKey, true, false);

			if (ret != NULL)
			{
				WideGateSetControllerGateSecretKeyFromPack(wide, ret);
				FreePack(ret);
			}

			FreePack(p);
		}
		Unlock(wide->LockReport);
	}
}

// セッションリストの報告
void WideGateReportSessionList(WIDE *wide)
{
	WT *wt;
	LIST *sc_list;
	// 引数チェック
	if (wide == NULL)
	{
		return;
	}

	if (WideGateGetIniEntry("DisableRegister"))
	{
		// 一時的に登録無効化
		return;
	}

	wt = wide->wt;

	Lock(wide->LockReport);
	{
		PACK *p = NewPack();
		PACK *ret = NULL;
		UINT i;
		UINT num;

		PackAddStr(p, "GateKey", wide->GateKeyStr);

		// SC List 初期化
		sc_list = NewListFast(NULL);

		WideGatePackSessionList(p, wt, sc_list);
		WideGatePackGateInfo(p, wt);

		// SC List の追加と解放
		num = LIST_NUM(sc_list);
		for (i = 0;i < num;i++)
		{
			SESSION_AND_CLIENT *sc = LIST_DATA(sc_list, i);

			PackAddDataEx(p, "SC_SessionId", sc->SessionId, sizeof(sc->SessionId), i, num);
			PackAddDataEx(p, "SC_ClientID", sc->ClientId, sizeof(sc->ClientId), i, num);

			Free(sc);
		}
		ReleaseList(sc_list);

		ret = WtWpcCallWithCertAndKey(wt, "ReportSessionList", p, wide->GateCert, wide->GateKey, true, false);

		if (ret != NULL)
		{
			WideGateSetControllerGateSecretKeyFromPack(wide, ret);
			FreePack(ret);
		}

		FreePack(p);
	}
	Unlock(wide->LockReport);
}

// 報告スレッド
void WideGateReportThread(THREAD *thread, void *param)
{
	WIDE *wide;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	wide = (WIDE *)param;

	while (true)
	{
		UINT64 gateway_interval = (UINT64)WideGateGetIniEntry("GatewayInterval");
		if (wide->GateHalt)
		{
			break;
		}

		// セッションリストの報告
		WideGateReportSessionList(wide);

		if (wide->GateHalt)
		{
			break;
		}

		Lock(wide->ReportIntervalLock);
		{
			// 次の NextReportTick の時刻を計算
			UINT64 now = Tick64();
			UINT64 next = now + gateway_interval;

			wide->NextReportTick = next;
		}
		Unlock(wide->ReportIntervalLock);

		// 次の NextReportTick に到達するまで待機
		while (true)
		{
			bool b = false;
			if (wide->GateHalt)
			{
				break;
			}

			Wait(wide->ReportThreadHaltEvent, 512);

			Lock(wide->ReportIntervalLock);
			{
				UINT64 now = Tick64();
				if (wide->NextReportTick <= now || (wide->NextReportTick2 != 0 && wide->NextReportTick2 <= now))
				{
					wide->NextReportTick2 = 0;
					b = true;
				}
			}
			Unlock(wide->ReportIntervalLock);

			if (b || wide->GateHalt)
			{
				break;
			}
		}
	}
}

// 2020/4/15 追加 アグレッシブタイムアウト機能
// 注意! ファイル I/O を伴うので時々チェックすること
void WideGateLoadAggressiveTimeoutSettings(WIDE *wide)
{
	UINT v1, v2, v3;
	if (wide == NULL)
	{
		return;
	}

	Lock(wide->AggressiveTimeoutLock);
	{
		v1 = WideGateGetIniEntry("TunnelTimeout");
		v2 = WideGateGetIniEntry("TunnelKeepAlive");
		v3 = WideGateGetIniEntry("TunnelUseAggressiveTimeout");

		// 異常に大きい値が ini ファイルに設定されるリスクの軽減
		v1 = MIN(v1, WT_TUNNEL_TIMEOUT_HARD_MAX);
		v2 = MIN(v2, WT_TUNNEL_KEEPALIVE_HARD_MAX);

		if (v1 && v2)
		{
			wide->GateTunnelTimeout = v1;
			wide->GateTunnelKeepAlive = v2;
			wide->GateTunnelUseAggressiveTimeout = v3 ? true : false;
		}
		else
		{
			wide->GateTunnelTimeout = WT_TUNNEL_TIMEOUT;
			wide->GateTunnelKeepAlive = WT_TUNNEL_KEEPALIVE;
			wide->GateTunnelUseAggressiveTimeout = false;
		}
	}
	Unlock(wide->AggressiveTimeoutLock);
}

// 2020/4/15 追加 アグレッシブタイムアウト設定を時々読み込む
void WideGateLoadAggressiveTimeoutSettingsWithInterval(WIDE *wide)
{
	UINT64 now = Tick64();
	if (wide == NULL)
	{
		return;
	}

	Lock(wide->AggressiveTimeoutLock);
	{
		if (wide->GateTunnelTimeoutLastLoadTick == 0 || (wide->GateTunnelTimeoutLastLoadTick + 10000ULL) <= now)
		{
			wide->GateTunnelTimeoutLastLoadTick = now;

			WideGateLoadAggressiveTimeoutSettings(wide);
		}
	}
	Unlock(wide->AggressiveTimeoutLock);
}

// WideGate の開始
WIDE *WideGateStart()
{
	WIDE *w;
	LIST *o;

	w = ZeroMalloc(sizeof(WIDE));

	w->Type = WIDE_TYPE_GATE;
	w->wt = NewWtFromHamcore();
	w->wt->Wide = w;
	w->GateHalt = false;
	w->LockReport = NewLock();
	w->SettingLock = NewLock();
	w->ReportIntervalLock = NewLock();
	w->SecretKeyLock = NewLock();

	o = WideGateLoadIni();
	if (o != NULL)
	{
		char *gate_key = IniStrValue(o, "GateKey");

		if (IsEmptyStr(gate_key) == false)
		{
			StrCpy(w->GateKeyStr, sizeof(w->GateKeyStr), gate_key);
		}

		WideFreeIni(o);
	}

	w->AggressiveTimeoutLock = NewLock();

	w->GateTunnelTimeout = WT_TUNNEL_TIMEOUT;
	w->GateTunnelKeepAlive = WT_TUNNEL_KEEPALIVE;
	w->GateTunnelUseAggressiveTimeout = false;

	// 2020/4/15 追加 アグレッシブタイムアウト機能
	WideGateLoadAggressiveTimeoutSettings(w);

	// 証明書の読み込み
	WideGateLoadCertKey(&w->GateCert, &w->GateKey);

	// Timeout 設定の読み込み

	// Gate の開始
	WtgStart(w->wt, w->GateCert, w->GateKey, WT_PORT);

	// 報告スレッドの開始
	w->ReportThreadHaltEvent = NewEvent();
	w->ReportThread = NewThread(WideGateReportThread, w);

	return w;
}

// WideGate の停止
void WideGateStop(WIDE *wide)
{
	UCHAR gateid[SHA1_SIZE];
	// 引数チェック
	if (wide == NULL)
	{
		return;
	}

	// 報告スレッドの停止
	wide->GateHalt = true;
	Set(wide->ReportThreadHaltEvent);
	WaitThread(wide->ReportThread, INFINITE);
	ReleaseThread(wide->ReportThread);
	ReleaseEvent(wide->ReportThreadHaltEvent);

	// Gate の停止
	Copy(gateid, wide->wt->GateId, SHA1_SIZE);
	WtgStop(wide->wt);

	// リソース解放
	DeleteLock(wide->LockReport);
	DeleteLock(wide->SettingLock);
	DeleteLock(wide->ReportIntervalLock);
	DeleteLock(wide->SecretKeyLock);
	DeleteLock(wide->AggressiveTimeoutLock);
	FreeX(wide->GateCert);
	FreeK(wide->GateKey);

	ReleaseWt(wide->wt);

	Free(wide);
}

void WideGateSetControllerGateSecretKey(WIDE *wide, char *key)
{
	if (wide == NULL || key == NULL || IsEmptyStr(key))
	{
		return;
	}

	Lock(wide->SecretKeyLock);
	{
		StrCpy(wide->ControllerGateSecretKey, sizeof(wide->ControllerGateSecretKey), key);
	}
	Unlock(wide->SecretKeyLock);
}

bool WideGateGetControllerGateSecretKey(WIDE *wide, char *key, UINT key_size)
{
	if (wide == NULL || key == NULL)
	{
		return false;
	}

	key[0] = 0;

	Lock(wide->SecretKeyLock);
	{
		StrCpy(key, key_size, wide->ControllerGateSecretKey);
	}
	Unlock(wide->SecretKeyLock);

	if (IsEmptyStr(key))
	{
		return false;
	}

	return true;
}

// ini の解放
void WideFreeIni(LIST *o)
{
	// 引数チェック
	if (o == NULL)
	{
		return;
	}

	FreeIni(o);
}

// WideGate.ini の読み込み
LIST *WideGateLoadIni()
{
	BUF *b = ReadDump("@WideGate.ini");
	LIST *ini;
	if (b == NULL)
	{
		return NULL;
	}

	ini = ReadIni(b);

	FreeBuf(b);

	return ini;
}

// 暗号化用 RC4 キーを生成
CRYPT *WideServerLocalKeyFileEncrypt()
{
	CRYPT *k;
	char *key = "LOCAL_KEY_RC4_2";
	UCHAR hash[SHA1_SIZE];

	HashSha1(hash, key, StrLen(key));

	k = NewCrypt(hash, sizeof(hash));

	return k;
}

// ローカルキーをバッファに保存
BUF *WideServerSaveLocalKeyToBuffer(K *k, X *x)
{
	PACK *p;
	BUF *b, *pb;
	UCHAR hash[SHA1_SIZE];
	CRYPT *c;
	WT_MACHINE_ID mid;
	// 引数チェック
	if (k == NULL || x == NULL)
	{
		return NULL;
	}

	Zero(&mid, sizeof(mid));
	WideGetCurrentMachineId(&mid);

	b = NewBuf();
	p = NewPack();
	PackAddX(p, "x", x);
	PackAddK(p, "k", k);
	PackAddData(p, "mid", &mid, sizeof(mid));

	pb = PackToBuf(p);
	FreePack(p);

	HashSha1(hash, pb->Buf, pb->Size);

	WriteBuf(b, hash, sizeof(hash));
	WriteBuf(b, pb->Buf, pb->Size);

	FreeBuf(pb);

	SeekBuf(b, 0, 0);

	c = WideServerLocalKeyFileEncrypt();

	Encrypt(c, b->Buf, b->Buf, b->Size);

	FreeCrypt(c);

	return b;
}

// ローカルキーをバッファから読み込む
bool WideServerLoadLocalKeyFromBuffer(BUF *buf, K **k, X **x)
{
	PACK *p;
	UCHAR hash[SHA1_SIZE];
	UCHAR hash2[SHA1_SIZE];
	CRYPT *c;
	BUF *pb;
	BUF *buf2;
	WT_MACHINE_ID mid, current_mid;
	// 引数チェック
	if (buf == NULL || k == NULL || x == NULL)
	{
		return false;
	}

	SeekBuf(buf, 0, 0);

	if (buf->Size <= SHA1_SIZE)
	{
		return false;
	}

	buf2 = NewBuf();
	WriteBuf(buf2, buf->Buf, buf->Size);

	c = WideServerLocalKeyFileEncrypt();

	Encrypt(c, buf2->Buf, buf2->Buf, buf2->Size);

	FreeCrypt(c);

	Copy(hash, buf2->Buf, SHA1_SIZE);

	HashSha1(hash2, ((UCHAR *)buf2->Buf) + SHA1_SIZE, buf2->Size - SHA1_SIZE);

	if (Cmp(hash, hash2, SHA1_SIZE) != 0)
	{
		FreeBuf(buf2);
		return false;
	}

	pb = NewBuf();
	WriteBuf(pb, ((UCHAR *)buf2->Buf) + SHA1_SIZE, buf2->Size - SHA1_SIZE);
	SeekBuf(pb, 0, 0);

	p = BufToPack(pb);
	FreeBuf(pb);

	*x = PackGetX(p, "x");
	*k = PackGetK(p, "k");

	Zero(&mid, sizeof(mid));

	PackGetData2(p, "mid", &mid, sizeof(mid));

	FreePack(p);

	FreeBuf(buf2);

	WideGetCurrentMachineId(&current_mid);

	if (*x == NULL || *k == NULL || WideCompareMachineId(&mid, &current_mid) == false)
	{
		FreeX(*x);
		FreeK(*k);
		return false;
	}

	return true;
}

// ローカルディレクトリの EnterPoint.txt を読み込む (2020 年改造の新方式)
void WideLoadEntryPoint(X **cert, char *url, UINT url_size, LIST *secondary_str_list)
{
	char url_tmp[MAX_SIZE];
	X *cert_tmp;

	UINT64 now = SystemTime64();

	UINT64 secs = now / (UINT64)ENTRANCE_URL_TIME_UPDATE_MSECS;

	BUF *buf = ReadDump(LOCAL_ENTRY_POINT_FILENAME);

	Zero(url_tmp, sizeof(url_tmp));

	if (buf == NULL)
	{
		Alert("Failed to find the local EntryPoint.dat file. Please re-install the software.", DESK_PRODUCT_NAME_SUITE);
		_exit(1);
	}

	cert_tmp = BufToX(buf, true);

	if (cert_tmp == NULL)
	{
		Alert("Failed to parse the local EntryPoint.dat file. Please re-install the software.", DESK_PRODUCT_NAME_SUITE);
		_exit(1);
	}

	SeekBufToBegin(buf);

	ClearStr(url, url_size);

	while (true)
	{
		char *secondary_tag = "SECONDARY:[";
		char *line = CfgReadNextLine(buf);
		if (line == NULL)
		{
			break;
		}

		if (StartWith(line, "http://") || StartWith(line, "https://"))
		{
			StrCpy(url_tmp, sizeof(url_tmp), line);
		}

		if (secondary_str_list != NULL)
		{
			if (StartWith(line, secondary_tag))
			{
				char addr[MAX_PATH];
				UINT len;
				StrCpy(addr, sizeof(addr), line + StrLen(secondary_tag));
				len = StrLen(addr);
				if (addr[len - 1] == ']')
				{
					addr[len - 1] = 0;

					AddStrToStrListDistinct(secondary_str_list, addr);
				}
			}
		}

		Free(line);
	}

	FreeBuf(buf);

	if (IsEmptyStr(url_tmp))
	{
		Alert("Failed to parse the local EntryPoint.dat file. Please re-install the software.", DESK_PRODUCT_NAME_SUITE);
		_exit(1);
	}

	if (url != NULL)
	{
		char secs_str[MAX_SIZE];

		ToStr64(secs_str, secs);

		ReplaceStrEx(url, url_size, url_tmp, ENTRANCE_URL_TIME_REPLACE_TAG, secs_str, false);
	}

	if (cert != NULL)
	{
		*cert = cert_tmp;
	}
	else
	{
		FreeX(cert_tmp);
	}
}


bool WideVerifyNewEntryPointAndSignature(X *master_x, BUF *ep, BUF *sign)
{
	K *pubkey;
	bool ret = false;
	if (master_x == NULL || ep == NULL || sign == NULL)
	{
		return false;
	}

	if (sign->Size < (4096 / 8))
	{
		return false;
	}

	pubkey = GetKFromX(master_x);

	if (pubkey != NULL)
	{
		ret = RsaVerifyEx(ep->Buf, ep->Size, sign->Buf, pubkey, 4096);

		FreeK(pubkey);
	}

	return ret;
}

BUF *WideTryDownloadAndVerifyNewEntryPoint(X *master_x, INTERNET_SETTING *setting, char *base_url, bool *cancel, WT *wt)
{
	UINT i;
	char base_url2[MAX_PATH] = {0};
	char data_url[MAX_PATH] = {0};
	char sign_url[MAX_PATH] = {0};
	BUF *data_buf = NULL;
	BUF *sign_buf = NULL;
	URL_DATA data_url2 = {0};
	URL_DATA sign_url2 = {0};
	BUF *ret = NULL;
	if (master_x == NULL || base_url == NULL)
	{
		return NULL;
	}

	StrCpy(base_url2, sizeof(base_url2), base_url);

	Trim(base_url2);

	i = StrLen(base_url2);
	if (i >= 1)
	{
		if (base_url2[i - 1] == '/')
		{
			base_url2[i - 1] = 0;
		}
	}

	Format(data_url, sizeof(data_url), "%s/EntryPoint.dat", base_url2);
	Format(sign_url, sizeof(sign_url), "%s/EntryPointSign.dat", base_url2);

	ParseUrl(&data_url2, data_url, false, NULL);
	ParseUrl(&sign_url2, sign_url, false, NULL);

	data_buf = HttpRequestEx4(&data_url2, setting, 0, 0, NULL, false, NULL, NULL, NULL, NULL, 0,
		cancel, 65536, NULL, NULL, wt);

	sign_buf = HttpRequestEx4(&sign_url2, setting, 0, 0, NULL, false, NULL, NULL, NULL, NULL, 0,
		cancel, 65536, NULL, NULL, wt);

	if (sign_buf == NULL)
	{
		goto LABEL_CLEANUP;
	}

	if (WideVerifyNewEntryPointAndSignature(master_x, data_buf, sign_buf))
	{
		ret = CloneBuf(data_buf);
	}

LABEL_CLEANUP:
	FreeBuf(data_buf);
	FreeBuf(sign_buf);
	return ret;
}

bool WideTryUpdateNewEntryPoint(wchar_t *dirname, X *master_x, INTERNET_SETTING *setting, bool *cancel, WT *wt)
{
	char *tag = "Update:";
	wchar_t fullpath[MAX_PATH] = {0};
	bool ret = false;
	BUF *current_data = NULL;
	BUF *new_data = NULL;
	char base_url[MAX_PATH] = {0};
	if (dirname == NULL || master_x == NULL || wt == NULL)
	{
		return false;
	}

	CombinePathW(fullpath, sizeof(fullpath), dirname, ENTRY_POINT_RAW_FILENAME_W);

	// Try read
	current_data = ReadDumpW(fullpath);
	if (current_data == NULL)
	{
		goto LABEL_CLEANUP;
	}

	Zero(base_url, sizeof(base_url));

	// Get update base URL
	while (true)
	{
		char *line = CfgReadNextLine(current_data);
		if (line == NULL)
		{
			break;
		}

		if (StartWith(line, tag))
		{
			if (IsEmptyStr(base_url))
			{
				StrCpy(base_url, sizeof(base_url), line + StrLen(tag));

				Trim(base_url);
			}
		}

		Free(line);
	}

	if (IsEmptyStr(base_url))
	{
		goto LABEL_CLEANUP;
	}

	// Try to download new file
	new_data = WideTryDownloadAndVerifyNewEntryPoint(master_x, setting, base_url, cancel, wt);

	// Overwrite the file
	ret = DumpBufW(new_data, fullpath);

LABEL_CLEANUP:
	FreeBuf(current_data);
	FreeBuf(new_data);
	return ret;
}

bool WideTryUpdateNewEntryPointModest(wchar_t *dirname, X *master_x, INTERNET_SETTING *setting, bool *cancel, WT *wt, UINT interval)
{
	UINT64 now = Tick64();

	if (wt == NULL)
	{
		return false;
	}

	if (wt->LastTryUpdateNewEntryPoint == 0 ||
		(now >= (wt->LastTryUpdateNewEntryPoint + (UINT64)interval)))
	{
		bool ret = WideTryUpdateNewEntryPoint(dirname, master_x, setting, cancel, wt);

		if (ret)
		{
			wt->LastTryUpdateNewEntryPoint = now;
		}

		return ret;
	}
	else
	{
		return false;
	}
}

bool WideTryUpdateNewEntryPointModestStandard(WT *wt, bool *cancel)
{
	wchar_t current_dir[MAX_PATH] = {0};
	if (wt == NULL)
	{
		return false;
	}

	GetExeDirW(current_dir, sizeof(current_dir));

	return WideTryUpdateNewEntryPointModest(current_dir, wt->MasterCert,
		wt->InternetSetting, cancel, wt, ENTRY_POINT_UPDATE_FROM_GITHUB_INTERVAL);
}
