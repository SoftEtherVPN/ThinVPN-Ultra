// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// DS.c
// PacketiX Desktop VPN Server

// Build 8600

#include "CedarPch.h"

#ifdef _WIN32
#include "..\PenCore\resource.h"
#endif // _WIN32

// 適用されるポリシーメッセージの表示
void DsPreparePolicyMessage(wchar_t *str, UINT str_size, DS_POLICY_BODY *pol)
{
	wchar_t *msg = _UU("DS_POLICY_NONE");
	wchar_t *otp_str = _UU("DS_POLICY_NO");
	wchar_t *inspection_str = _UU("DS_POLICY_NO");
	wchar_t *disableshare_str = _UU("DS_POLICY_NO");
	wchar_t syslog_str[256];
	URL_DATA url = {0};

	UniStrCpy(syslog_str, sizeof(syslog_str), _UU("DS_POLICY_NONE"));

	UniStrCpy(str, str_size, L"");

	if (pol == NULL || str == NULL)
	{
		return;
	}

	if (IsZero(pol, sizeof(DS_POLICY_BODY)))
	{
		return;
	}

	if (UniIsEmptyStr(pol->ServerMessage) == false)
	{
		msg = pol->ServerMessage;
	}

	if (pol->EnforceOtp)
	{
		otp_str = _UU("DS_POLICY_YES");
	}

	if (pol->EnforceInspection)
	{
		inspection_str = _UU("DS_POLICY_YES");
	}

	if (pol->DisableShare)
	{
		disableshare_str = _UU("DS_POLICY_YES");
	}

	if (IsEmptyStr(pol->SyslogHostname) == false)
	{
		UniFormat(syslog_str, sizeof(syslog_str), _UU("DS_POLICY_SYSLOG"), pol->SyslogHostname, pol->SyslogPort);
	}

	ParseUrl(&url, pol->SrcUrl, false, NULL);

	UniFormat(str, str_size, _UU("DS_POLICY_MESSAGE"), otp_str, disableshare_str, inspection_str,
		syslog_str, msg, url.HostName);
}

// ポリシーファイルのパース
bool DsParsePolicyFile(DS_POLICY_BODY *b, BUF *buf)
{
	LIST *o;
	char *s;
	char *s_hash;
	wchar_t *ws;
	if (b == NULL || buf == NULL)
	{
		return false;
	}

	SeekBufToBegin(buf);

	Zero(b, sizeof(DS_POLICY_BODY));

	o = ReadIni(buf);

	b->EnforceOtp = IniIntValue(o, "ENFORCE_OTP");
	b->EnforceInspection = IniIntValue(o, "ENFORCE_INSPECTION");
	b->DisableShare = IniIntValue(o, "DISABLE_SHARE");

	s = IniStrValue(o, "SYSLOG_HOSTNAME");
	if (IsEmptyStr(s) == false)
	{
		StrCpy(b->SyslogHostname, sizeof(b->SyslogHostname), s);
		b->SyslogPort = IniIntValue(o, "SYSLOG_PORT");

		if (b->SyslogPort == 0 || b->SyslogPort >= 65536)
		{
			b->SyslogPort = SYSLOG_PORT;
		}
	}

	s = IniStrValue(o, "ENFORCE_OTP_ENDWITH");
	s_hash = IniStrValue(o, "ENFORCE_OTP_ENDWITH_SECURITY");
	if (IsEmptyStr(s) == false && IsEmptyStr(s_hash) == false)
	{
		char tmp[128];
		UCHAR hash[SHA256_SIZE];
		BUF *hash2;

		Format(tmp, sizeof(tmp), "I_take_an_oath_that_I_will_not_violate_the_rights_of_our_employees_%s", s);
		StrUpper(tmp);

		HashSha256(hash, tmp, StrLen(tmp));

		hash2 = StrToBin(s_hash);

		if (hash2 != NULL && hash2->Size == SHA256_SIZE &&
			Cmp(hash2->Buf, hash, SHA256_SIZE) == 0)
		{
			// ハッシュ一致
			StrCpy(b->EnforceOtpEndWith, sizeof(b->EnforceOtpEndWith), s);
		}

		FreeBuf(hash2);
	}

	ws = IniUniStrValue(o, "SERVER_MESSAGE");
	if (UniIsEmptyStr(ws) == false)
	{
		wchar_t tmp[1024] = {0};

		UniStrCpy(tmp, sizeof(tmp), ws);

		UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"<br>", L"\r\n", false);

		UniStrCpy(b->ServerMessage, sizeof(b->ServerMessage), tmp);
	}

	FreeIni(o);

	return true;
}

// 現在のポリシーの取得
bool DsPolicyClientGetPolicy(DS_POLICY_CLIENT *c, DS_POLICY_BODY *pol)
{
	Zero(pol, sizeof(DS_POLICY_BODY));
	if (c == NULL || pol == NULL)
	{
		return false;
	}

	if (c->PolicyExpires <= Tick64())
	{
		return false;
	}

	Copy(pol, &c->Policy, sizeof(DS_POLICY_BODY));

	if (IsZero(pol, sizeof(DS_POLICY_BODY)))
	{
		return false;
	}

	return true;
}

// ポリシー取得試行が完了しているかどうか
bool DsIsTryCompleted(DS *ds)
{
	if (ds == NULL)
	{
		return false;
	}

	if (ds->PolicyClient == NULL)
	{
		return false;
	}

	if (ds->PolicyClient->NumTryCompleted >= ds->PolicyClient->NumThreads)
	{
		return true;
	}

	return false;
}

// 現在のポリシーの取得 (DS から)
bool DsGetPolicy(DS *ds, DS_POLICY_BODY *pol)
{
	Zero(pol, sizeof(DS_POLICY_BODY));
	if (ds == NULL || pol == NULL)
	{
		return false;
	}

	return DsPolicyClientGetPolicy(ds->PolicyClient, pol);
}

// ポリシークライアントスレッド
void DsPolicyClientThread(THREAD *thread, void *param)
{
	DS_POLICY_CLIENT *c;
	DS_POLICY_THREAD_CTX *ctx = (DS_POLICY_THREAD_CTX *)param;
	UINT num_try = 0;

	if (thread == NULL || param == NULL)
	{
		return;
	}

	c = ctx->Client;

	while (c->Halt == false)
	{
		UINT i;
		LIST *dns_suffix_list = NULL;

		num_try++;

		if (ctx->ReplaceSuffix)
		{
#ifdef OS_WIN32
			dns_suffix_list = Win32GetDnsSuffixList();
#else	// OS_WIN32
			dns_suffix_list = NewStrList();
#endif	// OS_WIN32
		}

		for (i = 0;i < (dns_suffix_list == NULL ? 1 : LIST_NUM(dns_suffix_list));i++)
		{
			URL_DATA data;
			char url[MAX_PATH];

			if (c->Halt)
			{
				break;
			}

			// URL の確定
			StrCpy(url, sizeof(url), ctx->Url);

			if (dns_suffix_list != NULL)
			{
				char *suffix = LIST_DATA(dns_suffix_list, i);

				ReplaceStrEx(url, sizeof(url), url, "__DOMAIN__", suffix, false);
			}

			//Debug("Policy trying from %s ...\n", url);

			// この URL からのファイルの受信試行
			if (ParseUrl(&data, url, false, NULL))
			{
				UINT err = 0;
				BUF *buf = HttpRequestEx5(&data, NULL, 0, 0, &err, false, NULL, NULL, NULL, NULL, 0, &c->Halt,
					DS_POLICY_CLIENT_MAX_FILESIZE, NULL, NULL, NULL, false, true);

				if (buf != NULL)
				{
					DS_POLICY_BODY pol = {0};

					if (DsParsePolicyFile(&pol, buf))
					{
						StrCpy(pol.SrcUrl, sizeof(pol.SrcUrl), url);

						if (Cmp(&c->Policy, &pol, sizeof(DS_POLICY_BODY)) != 0)
						{
							//Debug("Policy received and updated from '%s'.\n", url);
							Copy(&c->Policy, &pol, sizeof(DS_POLICY_BODY));
						}

						c->PolicyExpires = Tick64() + (UINT64)DS_POLICY_EXPIRES;
					}

					FreeBuf(buf);
				}
				else
				{
					//UniDebug(L"%s\n", _E(err));
				}
			}
		}

		if (num_try == 1)
		{
			c->NumTryCompleted++;
		}

		FreeStrList(dns_suffix_list);

		if (c->Halt)
		{
			break;
		}

		// 次の受信まで待機
		Wait(ctx->HaltEvent, DS_POLICY_CLIENT_UPDATE_INTERVAL);
	}

	ReleaseEvent(ctx->HaltEvent);

	Free(ctx);
}

// ポリシークライアントの開始
DS_POLICY_CLIENT *DsNewPolicyClient(char* server_hash)
{
	char args[MAX_SIZE];
	wchar_t hostname[MAX_PATH] = {0};
	DS_POLICY_CLIENT *c = ZeroMalloc(sizeof(DS_POLICY_CLIENT));

#ifdef	OS_WIN32
	MsGetComputerNameFull(hostname, sizeof(hostname));
#endif	// OS_WIN32

	c->HaltEventList = NewList(NULL);

	c->ThreadList = NewThreadList();

	StrCpy(c->ServerHash, sizeof(c->ServerHash), server_hash);

	Format(args, sizeof(args), "?server_build=%u&server_hostname=%S",
		CEDAR_BUILD, hostname);

	if (true)
	{
		DS_POLICY_THREAD_CTX *ctx = ZeroMalloc(sizeof(DS_POLICY_THREAD_CTX));
		THREAD *t;

		c->NumThreads++;

		ctx->Client = c;

		ctx->HaltEvent = NewEvent();
		AddRef(ctx->HaltEvent->ref);
		Add(c->HaltEventList, ctx->HaltEvent);

		StrCpy(ctx->Url, sizeof(ctx->Url), "https://" DS_POLICY_INDOMAIN_SERVER_NAME ".__DOMAIN__/get-telework-policy/");
		StrCat(ctx->Url, sizeof(ctx->Url), args);
		ctx->ReplaceSuffix = true;

		t = NewThread(DsPolicyClientThread, ctx);

		AddThreadToThreadList(c->ThreadList, t);

		ReleaseThread(t);
	}

	if (true)
	{
		DS_POLICY_THREAD_CTX *ctx = ZeroMalloc(sizeof(DS_POLICY_THREAD_CTX));
		THREAD *t;

		c->NumThreads++;

		ctx->Client = c;

		ctx->HaltEvent = NewEvent();
		AddRef(ctx->HaltEvent->ref);
		Add(c->HaltEventList, ctx->HaltEvent);

		StrCpy(ctx->Url, sizeof(ctx->Url), "https://" DS_POLICY_IP_SERVER_NAME "/get-telework-policy/");
		StrCat(ctx->Url, sizeof(ctx->Url), args);
		ctx->ReplaceSuffix = false;

		t = NewThread(DsPolicyClientThread, ctx);

		AddThreadToThreadList(c->ThreadList, t);

		ReleaseThread(t);
	}

	return c;
}

// ポリシークライアントの終了
void DsFreePolicyClient(DS_POLICY_CLIENT *c)
{
	UINT i;
	if (c == NULL)
	{
		return;
	}

	c->Halt = true;

	for (i = 0; i < LIST_NUM(c->HaltEventList);i++)
	{
		EVENT *e = LIST_DATA(c->HaltEventList, i);

		Set(e);
	}

	FreeThreadList(c->ThreadList);


	for (i = 0; i < LIST_NUM(c->HaltEventList);i++)
	{
		EVENT *e = LIST_DATA(c->HaltEventList, i);

		ReleaseEvent(e);
	}

	ReleaseList(c->HaltEventList);

	Free(c);
}


//// 指定された IP アドレスがプライベート IP アドレスかどうかチェックする
//bool IsIPPrivate(IP *ip)
//{
//	// 引数チェック
//	if (ip == NULL)
//	{
//		return false;
//	}
//
//	if (ip->addr[0] == 10)
//	{
//		return true;
//	}
//
//	if (ip->addr[0] == 172)
//	{
//		if (ip->addr[1] >= 16 && ip->addr[1] <= 31)
//		{
//			return true;
//		}
//	}
//
//	if (ip->addr[0] == 192 && ip->addr[1] == 168)
//	{
//		return true;
//	}
//
//	if (ip->addr[0] == 169 && ip->addr[1] == 254)
//	{
//		return true;
//	}
//
//	return false;
//}

// Bluetooth データ受信処理メイン
void DsBluetoothMain(DS *ds, SOCKIO *sock)
{
#ifdef	OS_WIN32
	UINT64 last_save_tick = 0;
	// 引数チェック
	if (ds == NULL || sock == NULL)
	{
		return;
	}

	DsLog(ds, "DSL_BT_ESTABLISHED");

	while (true)
	{
		wchar_t filename[MAX_PATH];
		UINT filesize;
		UCHAR *data;
		UINT zero = 0;
		wchar_t fullpath[MAX_PATH];

		// ファイル名の受信
		if (SockIoRecvAll(sock, filename, sizeof(filename)) == false)
		{
			break;
		}

		Debug("bluetooth: filename: %S\n", filename);

		filename[MAX_PATH - 1] = 0;

		// ファイルサイズの受信
		if (SockIoRecvAll(sock, &filesize, sizeof(UINT)) == false)
		{
			break;
		}

		filesize = Endian32(filesize);

		if (filesize > DC_BLUETOOTH_MAX_FILESIZE)
		{
			break;
		}

		Debug("bluetooth: filesize: %u\n", filesize);

		// データの受信
		data = Malloc(filesize);

		if (SockIoRecvAll(sock, data, filesize) == false)
		{
			Free(data);
			break;
		}

		Debug("bluetooth: file received ok.\n");

		DsLog(ds, "DSL_RECV_BT_FILE", filename, filesize);

		// データを指定されたディレクトリに保存する
		if (UniIsEmptyStr(ds->BluetoothDir) == false)
		{
			UINT64 now = Tick64();

			if (last_save_tick != 0 &&
				((last_save_tick + (UINT64)DS_BLUETOOTH_FILE_SAVE_INTERVAL) > now))
			{
				SleepThread((UINT)(last_save_tick + (UINT64)DS_BLUETOOTH_FILE_SAVE_INTERVAL - now));
			}

			last_save_tick = now;

			// 一応ディレクトリを作成する
			MsUniMakeDirEx(ds->BluetoothDir);

			// フルパスの生成
			CombinePathW(fullpath, sizeof(fullpath), ds->BluetoothDir, filename);

			// データ保存
			FileWriteAllW(fullpath, data, filesize);

			Debug("file %S saved.\n", fullpath);

			DsLog(ds, "DSL_SAVE_BT_FILE", fullpath, filesize);

			// 受信完了通知
			if (SockIoSendAll(sock, &zero, sizeof(zero)) == false)
			{
				Free(data);
				break;
			}
		}
		else
		{
			SockIoDisconnect(sock);
			break;
		}

		Free(data);
	}

	DsLog(ds, "DSL_BT_CLOSES");
#endif  // OS_WIN32
}

// タスクトレイのアイコンを更新する
void DsUpdateTaskIcon(DS *ds)
{
#ifdef	OS_WIN32
	HICON hIcon;
	LIST *o;
	UINT num = 0;
	wchar_t tmp[MAX_SIZE * 2];
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	if (MsIsTrayInited() == false)
	{
		return;
	}

	hIcon = LoadSmallIcon(ICO_TOWER);

	LockList(ds->ClientList);
	{
		UINT i;

		o = NewListFast(CompareStr);

		if (LIST_NUM(ds->ClientList) >= 1)
		{
			hIcon = LoadSmallIcon(ICO_USER_ADMIN);
		}

		for (i = 0;i < LIST_NUM(ds->ClientList);i++)
		{
			DS_CLIENT *c = LIST_DATA(ds->ClientList, i);

			if (IsInListStr(o, c->HostName) == false)
			{
				Insert(o, c->HostName);
			}
		}

		if (LIST_NUM(o) == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("DS_TRAY_TOOLTIP_0"));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("DS_TRAY_TOOLTIP_1"));

			for (i = 0;i < LIST_NUM(o);i++)
			{
				char *name = LIST_DATA(o, i);
				wchar_t name_w[MAX_PATH];
	
				StrToUni(name_w, sizeof(name_w), name);

				UniStrCat(tmp, sizeof(tmp), name_w);

				if (i != (LIST_NUM(o) - 1))
				{
					UniStrCat(tmp, sizeof(tmp), _UU("DS_TRAY_TOOLTIP_SPLIT"));
				}
			}

			num = LIST_NUM(o);
		}

		ReleaseList(o);
	}
	UnlockList(ds->ClientList);

	if (num != 0)
	{
		hIcon = LoadSmallIcon(ICO_USER_ADMIN);
	}

	MsChangeIconOnTrayEx2((void *)hIcon, tmp, NULL, NULL, 0);
#endif  // OS_WIN32
}

// ログの種類文字列を取得する
wchar_t *DsGetLogTypeStr(UINT ds_log_type)
{
	switch (ds_log_type)
	{
	case DS_LOG_WARNING:
		return _UU("DS_LOG_WARNING");

	case DS_LOG_ERROR:
		return _UU("DS_LOG_ERROR");

	default:
		return _UU("DS_LOG_INFO");
	}
}

// ログをとる
void DsLog(DS *ds, char *name, ...)
{
	va_list args;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);

	DsLogMain(ds, DS_LOG_INFO, name, args);

	va_end(args);
}

void DsLogEx(DS *ds, UINT ds_log_type, char *name, ...)
{
	va_list args;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);

	DsLogMain(ds, ds_log_type, name, args);

	va_end(args);
}

void DsLogMain(DS *ds, UINT ds_log_type, char *name, va_list args)
{
#ifdef	OS_WIN32
	wchar_t buf[MAX_SIZE * 2 + 64];
	wchar_t buf2[MAX_SIZE * 2];
	wchar_t *typestr = DsGetLogTypeStr(ds_log_type);
	SYSLOG_SETTING ss;
	bool lineonly = false;
	DS_POLICY_BODY pol = {0};

	DsGetPolicy(ds, &pol);

	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	if (UniStartWith(buf, L"-------"))
	{
		lineonly = true;
	}

	UniFormat(buf2, sizeof(buf2), L"[%s] %s", typestr, buf);

	if (ds->SaveLogFile)
	{
		// ファイルへのログ保存
		InsertUnicodeRecord(ds->Log, buf2);
	}

	if (lineonly == false)
	{
		if (ds->SupportEventLog	&& ds->SaveEventLog && ds->EventLog != NULL)
		{
			// イベントログへのログ保存
			MsWriteEventLog(ds->EventLog, ds_log_type, buf);
		}

		SiGetSysLogSetting(ds->Server, &ss);

		if (IsEmptyStr(pol.SyslogHostname) == false && pol.SyslogPort != 0)
		{
			// 現在の設定と異なる？
			if (StrCmpi(ss.Hostname, pol.SyslogHostname) != 0 || ss.Port != pol.SyslogPort)
			{
				// ポリシーで Syslog が指定されている場合はこれを強制適用する
				Zero(&ss, sizeof(ss));
				ss.SaveType = 1;
				StrCpy(ss.Hostname, sizeof(ss.Hostname), pol.SyslogHostname);
				ss.Port = pol.SyslogPort;
				SiSetSysLogSetting(ds->Server, &ss);
			}
		}

		SiGetSysLogSetting(ds->Server, &ss);

		if (ss.SaveType != 0)
		{
			// syslog へのログ保存
			DsSendSyslog(ds->Server, buf2);
		}
	}

	Debug("DS_LOG: %S\n", buf2);
#endif  // OS_WIN32
}

// syslog 送信
void DsSendSyslog(SERVER *s, wchar_t *message)
{
	wchar_t tmp[1024];
	char machinename[MAX_HOST_NAME_LEN + 1];
	char datetime[MAX_PATH];
	SYSTEMTIME st;
	// 引数チェック
	if (s == NULL || message == NULL)
	{
		return;
	}

	// ホスト名
	GetMachineName(machinename, sizeof(machinename));

	// 日時
	LocalTime(&st);
	GetDateTimeStrMilli(datetime, sizeof(datetime), &st);

	UniFormat(tmp, sizeof(tmp), L"[%S/" DESK_PUBLISHER_NAME_UNICODE L"] (%S) : %s",
		machinename, datetime, message);

	SendSysLog(s->Syslog, tmp);
}

// plain パスワードでの認証
bool DsAuthUserByPlainPassword(DS *ds, UCHAR *client_id, HUB *hub, char *username, char *password, bool ast)
{
	bool ret;
	// 引数チェック
	if (ds == NULL || client_id == NULL || hub == NULL || username == NULL || password == NULL)
	{
		return false;
	}

	ret = DsTryRadiusCache(ds, client_id, username, password);

	if (ret)
	{
		return true;
	}

	ret = SamAuthUserByPlainPassword(NULL, hub, username, password, ast, NULL, NULL);

	if (ret)
	{
		DsAddRadiusCache(ds, client_id, username, password);
	}

	return ret;
}

// Radius キャッシュリストの初期化
void DsInitRadiusCacheList(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	ds->RadiusCacheList = NewList(NULL);
}

// Radius キャッシュリストの解放
void DsFreeRadiusCacheList(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	DsCleanAllRadiusCache(ds);

	ReleaseList(ds->RadiusCacheList);

	ds->RadiusCacheList = NULL;
}

// すべての Radius キャッシュの消去
void DsCleanAllRadiusCache(DS *ds)
{
	UINT i;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(ds->RadiusCacheList);i++)
	{
		DS_RADIUS_CACHE *c = LIST_DATA(ds->RadiusCacheList, i);

		Free(c);
	}

	DeleteAll(ds->RadiusCacheList);
}

// Radius キャッシュリストのトライ
bool DsTryRadiusCache(DS *ds, UCHAR *client_id, char *username, char *password)
{
	bool ret = false;
	UINT i;
	// 引数チェック
	if (ds == NULL || client_id == NULL || username == NULL || password == NULL)
	{
		return false;
	}

	LockList(ds->RadiusCacheList);
	{
		for (i = 0;i < LIST_NUM(ds->RadiusCacheList);i++)
		{
			DS_RADIUS_CACHE *c = LIST_DATA(ds->RadiusCacheList, i);

			if (Cmp(c->ClientID, client_id, SHA1_SIZE) == 0)
			{
				if (StrCmpi(c->UserName, username) == 0)
				{
					if (StrCmp(c->Password, password) == 0)
					{
						ret = true;
						break;
					}
				}
			}
		}
	}
	UnlockList(ds->RadiusCacheList);

	return ret;
}

// Radius キャッシュリストに追加
void DsAddRadiusCache(DS *ds, UCHAR *client_id, char *username, char *password)
{
	UINT i;
	// 引数チェック
	if (ds == NULL || client_id == NULL || username == NULL || password == NULL)
	{
		return;
	}

	LockList(ds->RadiusCacheList);
	{
		DS_RADIUS_CACHE *c = NULL;

		for (i = 0;i < LIST_NUM(ds->RadiusCacheList);i++)
		{
			DS_RADIUS_CACHE *cc = LIST_DATA(ds->RadiusCacheList, i);

			if (Cmp(cc->ClientID, client_id, SHA1_SIZE) == 0)
			{
				c = cc;
				break;
			}
		}

		if (c == NULL)
		{
			c = ZeroMalloc(sizeof(DS_RADIUS_CACHE));

			Add(ds->RadiusCacheList, c);
		}

		Copy(c->ClientID, client_id, SHA1_SIZE);
		StrCpy(c->UserName, sizeof(c->UserName), username);
		StrCpy(c->Password, sizeof(c->Password), password);
	}
	UnlockList(ds->RadiusCacheList);
}

// サーバーとしてのメイン処理
void DsServerMain(DS *ds, SOCKIO *sock)
{
#ifdef	OS_WIN32
	IP client_ip;
	char client_ip_str[MAX_PATH];
	UINT client_port;
	char client_host[MAX_PATH];
	UINT tunnel_id;
	UCHAR client_id[SHA1_SIZE];
	char client_id_str[MAX_PATH];
	PACK *p;
	UINT client_ver;
	UINT client_build;
	UCHAR rand[SHA1_SIZE];
	UCHAR machine_key[SHA1_SIZE];
	UCHAR secure_password[SHA1_SIZE];
	bool ret;
	UINT svc_type;
	SOCK *s;
	bool check_port;
	char c;
	bool pingmode;
	bool downloadmode;
	UINT download_size;
	bool bluetooth_mode;
	bool is_share_disabled;
	UCHAR bluetooth_mode_client_id[SHA1_SIZE];
	bool first_connection;
	bool last_connection = false;
	bool has_urdp2_client = false;
	bool support_otp = false;
	bool support_otp_enforcement = false;
	bool is_smartcard_auth = false;
	UINT ds_caps = 0;
	UINT urdp_version = 0;
	DS_POLICY_BODY pol = {0};
	// 引数チェック
	if (ds == NULL || sock == NULL)
	{
		return;
	}

	DsGetPolicy(ds, &pol);

	if (pol.EnforceOtp && IsEmptyStr(pol.EnforceOtpEndWith) == false)
	{
		// OTP 強制かつ末尾強制の場合は、適合しないメールアドレスが設定
		// されている場合は削除する
		if (EndWith(ds->OtpEmail, pol.EnforceOtpEndWith) == false)
		{
			ds->EnableOtp = false;
			ClearStr(ds->OtpEmail, sizeof(ds->OtpEmail));
		}
	}

	// 接続元クライアントの情報を取得する
	Zero(client_host, sizeof(client_host));
	Zero(client_id, sizeof(client_id));
	PackGetIp(sock->InitialPack, "ClientIP", &client_ip);
	client_port = PackGetInt(sock->InitialPack, "ClientPort");
	PackGetStr(sock->InitialPack, "ClientHost", client_host, sizeof(client_host));
	tunnel_id = PackGetInt(sock->InitialPack, "TunnelId");
	PackGetData2(sock->InitialPack, "ClientID", client_id, sizeof(client_id));
	BinToStr(client_id_str, sizeof(client_id_str), client_id, sizeof(client_id));
	IPToStr(client_ip_str, sizeof(client_ip_str), &client_ip);

	is_share_disabled = DsIsShareDisabled(ds);

	Rand(rand, sizeof(rand));

	SockIoSetTimeout(sock, DS_PROTOCOL_CONNECTING_TIMEOUT);
	DeskGetMachineKey(machine_key);

	// Pack の受信
	p = SockIoRecvPack(sock);
	if (p == NULL)
	{
		DsSendError(sock, ERR_PROTOCOL_ERROR);
		return;
	}

	// バージョンを取得
	client_ver = PackGetInt(p, "ClientVer");
	client_build = PackGetInt(p, "ClientBuild");
	check_port = PackGetBool(p, "CheckPort");
	pingmode = PackGetBool(p, "PingMode");
	downloadmode = PackGetBool(p, "downloadmode");
	download_size = PackGetInt(p, "download_size");
	bluetooth_mode = false;//PackGetBool(p, "bluetooth_mode");
	first_connection = PackGetBool(p, "FirstConnection");
	has_urdp2_client = PackGetBool(p, "HasURDP2Client");
	support_otp = PackGetBool(p, "SupportOtp");
	support_otp_enforcement = PackGetBool(p, "SupportOtpEnforcement");

	if (MsIsWinXPOrWinVista() == false)
	{
		has_urdp2_client = false;
	}

	if (client_build < 5599)
	{
		first_connection = true;
	}
	Zero(bluetooth_mode_client_id, sizeof(bluetooth_mode_client_id));
	PackGetData2(p, "bluetooth_mode_client_id", bluetooth_mode_client_id, sizeof(bluetooth_mode_client_id));

	FreePack(p);

	if (is_share_disabled)
	{
		if (client_build < 5599)
		{
			// 共有機能が禁止されており、かつ古いバージョンのクライアントが
			// 接続してきた場合はエラーにする
			DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
			return;
		}
	}

	if (ds->EnableOtp && support_otp == false)
	{
		// OTP が有効なのにクライアントが OTP 非サポート
		DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
		return;
	}

	if (pol.EnforceOtp && ds->EnableOtp == false)
	{
		// ポリシーで OTP 強制なのに OTP が設定されていない
		if (support_otp_enforcement == false)
		{
			// クライアントが ERR_DESK_OTP_ENFORCED_BUT_NO エラーを表示不能
			DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
		}
		else
		{
			// クライアントが ERR_DESK_OTP_ENFORCED_BUT_NO エラーを表示可能
			DsSendError(sock, ERR_DESK_OTP_ENFORCED_BUT_NO);
		}
		return;
	}

	if (ds->UseAdvancedSecurity)
	{
		if (client_build < 5599)
		{
			// 新型ユーザー認証を使用する必要があるが
			// 旧型クライアントが接続してきた場合はエラーにする
			DsSendError(sock, ERR_DESK_UNKNOWN_AUTH_TYPE);
			return;
		}
	}

	if (bluetooth_mode)
	{
		// Bluetooth データ受信モード
		bool b = false;

		LockList(ds->ClientList);
		{
			UINT i;
			for (i = 0;i < LIST_NUM(ds->ClientList);i++)
			{
				DS_CLIENT *c = LIST_DATA(ds->ClientList, i);

				if (Cmp(c->ClientID, bluetooth_mode_client_id, SHA1_SIZE) == 0)
				{
					b = true;
				}
			}
		}
		UnlockList(ds->ClientList);

		if (b == false)
		{
			Debug("bluetooth_mode: auth failed.\n");
			DsSendError(sock, ERR_PROTOCOL_ERROR);
			return;
		}

		DsSendError(sock, ERR_NO_ERROR);

		SockIoSetTimeout(sock, INFINITE);
		Debug("bluetooth_mode: accepted.\n");

		DsBluetoothMain(ds, sock);

		return;
	}

#if	0
	if (downloadmode)
	{
		// download mode (テスト用)
		if (download_size <= (100000000))
		{
			void *data = ZeroMalloc(download_size);

			if (SockIoSendAll(sock, data, download_size) == false)
			{
				Debug("Send Failed.\n");
			}
			else
			{
				Debug("Send Ok.\n");
			}
			FreePack(SockIoRecvPack(sock));

			Free(data);
		}
		return;
	}
#endif

	if (pingmode)
	{
		// ping mode (テスト用)
		while (true)
		{
			UINT64 tick;
			if (SockIoRecvAll(sock, &tick, sizeof(tick)) == false)
			{
				break;
			}
			if (SockIoSendAll(sock, &tick, sizeof(tick)) == false)
			{
				break;
			}
		}

		return;
	}

	if (client_ver == 0 || client_build == 0)
	{
		DsSendError(sock, ERR_PROTOCOL_ERROR);
		return;
	}

	if (ds->Active == false)
	{
		// 接続を受け付けていない
		DsSendError(sock, ERR_DESK_NOT_ACTIVE);
		return;
	}

	svc_type = ds->ServiceType;

	// 認証パラメータを送信
	p = NewPack();
	if (ds->UseAdvancedSecurity == false)
	{
		PackAddInt(p, "AuthType", ds->AuthType);
	}
	else
	{
		// ダミー
		PackAddInt(p, "AuthType", 99);
	}
	PackAddInt(p, "ServiceType", ds->ServiceType);
	PackAddData(p, "Rand", rand, sizeof(rand));
	PackAddData(p, "MachineKey", machine_key, sizeof(machine_key));

	ds_caps = DsGetCaps(ds);
	if (has_urdp2_client)
	{
		ds_caps |= DS_CAPS_SUPPORT_URDP2;
		urdp_version = 2;

		if (DeskCheckUrdpIsInstalledOnProgramFiles(2) == false && MsIsVista())
		{
			// UAC による制限が厳しいことを示すフラグを立てる
			ds_caps |= DS_CAPS_RUDP_VERY_LIMITED;
		}
	}
	else
	{
		if (DeskCheckUrdpIsInstalledOnProgramFiles(1) == false && MsIsVista())
		{
			// UAC による制限が厳しいことを示すフラグを立てる
			ds_caps |= DS_CAPS_RUDP_VERY_LIMITED;
		}
	}

	// Windows RDP が有効かどうかのフラグ
	if (MsIsRemoteDesktopAvailable() && MsIsRemoteDesktopEnabled())
	{
		ds_caps |= DS_CAPS_WIN_RDP_ENABLED;
	}

	PackAddInt(p, "DsCaps", ds_caps);

	PackAddBool(p, "IsShareDisabled", is_share_disabled);
	PackAddBool(p, "UseAdvancedSecurity", ds->UseAdvancedSecurity);
	PackAddBool(p, "IsOtpEnabled", ds->EnableOtp);
	ret = SockIoSendPack(sock, p);
	FreePack(p);

	if (ret == false)
	{
		DsSendError(sock, ERR_PROTOCOL_ERROR);
		return;
	}

	// OTP 有効の場合は、OTP パスワードを受信
	if (ds->EnableOtp)
	{
		UINT64 now = Tick64();
		char otp[MAX_PATH];
		bool ok = false;
		bool ok_ticket = false;

		if (first_connection)
		{
			// まずこの機会に急いで OTP を発行する
			if (IsEmptyStr(ds->LastOtp) || (now >= ds->LastOtpExpires) || (ds->OtpNumTry >= DS_OTP_NUM_TRY))
			{
				DsGenerateNewOtp(ds->LastOtp, sizeof(ds->LastOtp), DS_OTP_LENGTH);
				ds->OtpNumTry = 0;
			}
			ds->LastOtpExpires = now + (UINT64)DS_OTP_EXPIRES;
			ds->OtpNumTry++;

			// OTP をメール送信する
			WideServerSendOtpEmail(ds->Wide, ds->LastOtp, ds->OtpEmail, client_ip_str, client_host);
		}

		// クライアントからの OTP を受信する
		p = SockIoRecvPack(sock);
		if (p == NULL)
		{
			DsSendError(sock, ERR_PROTOCOL_ERROR);
			return;
		}

		PackGetStr(p, "Otp", otp, sizeof(otp));

		FreePack(p);

		// OTP 一致 / 不一致を確認し、結果をクライアントに送付する
		if (first_connection)
		{
			ok = (StrCmp(otp, ds->LastOtp) == 0);
		}

		ok_ticket = (StrCmp(otp, ds->OtpTicket) == 0);

		if (ok == false && ok_ticket == false)
		{
			DsSendError(sock, ERR_DESK_OTP_INVALID);
			return;
		}

		// OTP 一致

		if (ok)
		{
			// 覚えをクリア
			ClearStr(ds->LastOtp, sizeof(ds->LastOtp));
			ds->LastOtpExpires = 0;
		}

		p = PackError(ERR_NO_ERROR);

		PackAddStr(p, "OtpTicket", ds->OtpTicket);

		SockIoSendPack(sock, p);

		FreePack(p);
	}

	// 認証データを受信
	p = SockIoRecvPack(sock);
	if (p == NULL)
	{
		DsSendError(sock, ERR_PROTOCOL_ERROR);
		return;
	}

	Zero(secure_password, sizeof(secure_password));
	PackGetData2(p, "SecurePassword", secure_password, sizeof(secure_password));

	if (first_connection)
	{
		DsLogEx(ds, DS_LOG_INFO, "DSL_TUNNEL_CONNECTED",
			tunnel_id, client_ip_str, client_host, client_port, client_id_str);
	}

	ret = false;
	// ユーザー認証を実施
	if (ds->UseAdvancedSecurity == false)
	{
		HUB *hub = GetHub(ds->Server->Cedar, CEDAR_DESKVPN_HUBNAME);
		bool is_password_empty = false;

		// IP アドレスを確認する
		if (IsIpDeniedByAcList(&client_ip, hub->HubDb->AcList))
		{
			// IP アドレスによるアクセス拒否
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_WARNING, "DSL_IP_NG", tunnel_id, client_ip_str);
				DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
			}
			ReleaseHub(hub);
			DsSendError(sock, ((client_build < 5599) ? ERR_ACCESS_DENIED : ERR_IP_ADDRESS_DENIED));
			FreePack(p);
			return;
		}

		ReleaseHub(hub);

		// 旧型ユーザー認証
		if (ds->AuthType == DESK_AUTH_NONE)
		{
			// 認証無し
			is_password_empty = true;
		}
		else if (ds->AuthType == DESK_AUTH_PASSWORD)
		{
			UCHAR hash_of_server_pw[SHA1_SIZE];

			// サーバー側で設定されているパスワードが、空文字でないかどうか確認する
			HashSha1(hash_of_server_pw, NULL, 0);
			if (Cmp(hash_of_server_pw, ds->AuthPassword, SHA1_SIZE) == 0)
			{
				// サーバー側で設定されているパスワードが空文字である
				is_password_empty = true;
			}
			else if (IsZero(ds->AuthPassword, SHA1_SIZE))
			{
				// なぜかサーバー側のパスワードハッシュがゼロである
				is_password_empty = true;
			}
			else
			{
				UCHAR secure_password_2[SHA1_SIZE];

				// パスワード認証
				SecurePassword(secure_password_2, ds->AuthPassword, rand);

				if (Cmp(secure_password, secure_password_2, SHA1_SIZE) == 0)
				{
					// パスワード一致
					ret = true;
				}
			}
		}

		if (is_password_empty)
		{
			// アクセス拒否 - パスワード未設定
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_ERROR, "DSL_AUTH_ANONYMOUS_NG", tunnel_id);
				DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
			}
			DsSendError(sock, ERR_DESK_PASSWORD_NOT_SET);
			FreePack(p);
			return;
		}

		if (ret == false)
		{
			// アクセス拒否
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_ERROR, "DSL_AUTH_OLD_NG", tunnel_id);
				DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
			}
			DsSendError(sock, ERR_DESK_BAD_PASSWORD);
			FreePack(p);
			return;
		}

		if (first_connection)
		{
			DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_OLD_OK",
				tunnel_id);
		}
	}
	else
	{
		// 新型ユーザー認証
		UINT authtype = GetAuthTypeFromPack(p);
		bool auth_ret;
		char auth_username[MAX_SIZE];
		char auth_username_real[MAX_SIZE];
		char plain_password[MAX_SIZE];
		HUB *hub = GetHub(ds->Server->Cedar, CEDAR_DESKVPN_HUBNAME);
		UINT cert_size;
		UCHAR *cert_buf;
		USER *user = NULL;

		// IP アドレスを確認する
		if (IsIpDeniedByAcList(&client_ip, hub->HubDb->AcList))
		{
			// IP アドレスによるアクセス拒否
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_WARNING, "DSL_IP_NG", tunnel_id, client_ip_str);
				DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
			}
			ReleaseHub(hub);
			DsSendError(sock, ((client_build < 5599) ? ERR_ACCESS_DENIED : ERR_IP_ADDRESS_DENIED));
			FreePack(p);
			return;
		}

		Lock(hub->lock);

		Zero(auth_username, sizeof(auth_username));
		PackGetStr(p, "username", auth_username, sizeof(auth_username));

		is_smartcard_auth = PackGetBool(p, "IsSmartCardAuth");

		// まず匿名認証を試行する
		auth_ret = SamAuthUserByAnonymous(hub, auth_username);

		if (auth_ret)
		{
			// ユーザー認証成功
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_AN_OK", tunnel_id, auth_username);
			}
		}

		if (auth_ret == false)
		{
			// 匿名認証に失敗した場合は他の認証方法を試行する
			switch (authtype)
			{
			case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
				if (PackGetStr(p, "plain_password", plain_password, sizeof(plain_password)))
				{
					UCHAR secure_password[SHA1_SIZE];
					UCHAR hashed_password[SHA1_SIZE];

					HashPassword(hashed_password, auth_username, plain_password);
					SecurePassword(secure_password, hashed_password, rand);
					auth_ret = SamAuthUserByPassword(hub, auth_username, rand, secure_password, NULL, NULL, NULL);
					if (auth_ret == false)
					{
						// 外部サーバーを用いたパスワード認証
						auth_ret = DsAuthUserByPlainPassword(ds, client_id, hub, auth_username, plain_password, false);

						if (auth_ret)
						{
							if (first_connection)
							{
								DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_PW2_OK", tunnel_id, auth_username);
							}
						}
					}
					else
					{
						if (first_connection)
						{
							DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_PW_OK", tunnel_id, auth_username);
						}
					}
					if (auth_ret == false)
					{
						bool b = false;
						AcLock(hub);
						{
							b = AcIsUser(hub, "*");
						}
						AcUnlock(hub);

						// アスタリスクユーザーがいる場合はそのユーザーとしてログオンする
						if (b)
						{
							auth_ret = DsAuthUserByPlainPassword(ds, client_id, hub, auth_username, plain_password, true);

							if (auth_ret)
							{
								if (first_connection)
								{
									DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_PW3_OK", tunnel_id, auth_username);
								}
							}
						}
					}
				}
				break;

			case CLIENT_AUTHTYPE_CERT:
				// 証明書認証
				cert_size = PackGetDataSize(p, "cert");
				if (cert_size >= 1 && cert_size <= DC_MAX_SIZE_CERT)
				{
					cert_buf = ZeroMalloc(cert_size);
					if (PackGetData(p, "cert", cert_buf))
					{
						UCHAR sign[4096 / 8];
						UINT sign_size = PackGetDataSize(p, "sign");
						if (sign_size <= sizeof(sign) && sign_size >= 1)
						{
							if (PackGetData(p, "sign", sign))
							{
								BUF *b = NewBuf();
								X *x;
								WriteBuf(b, cert_buf, cert_size);
								x = BufToX(b, false);
								if (x != NULL && x->is_compatible_bit &&
									sign_size == (x->bits / 8))
								{
									K *k = GetKFromX(x);
									// クライアントから受信した署名を確認する
									if (RsaVerifyEx(rand, SHA1_SIZE, sign, k, x->bits))
									{
										// 署名が一致したのでクライアントが確かにこの
										// 証明書を持っていたことが確認できた。
										// 証明書が有効かどうかをチェックする。
										auth_ret = SamAuthUserByCert(hub, auth_username, x);

										if (auth_ret)
										{
											if (first_connection)
											{
												wchar_t tmp[MAX_SIZE];
												GetAllNameFromX(tmp, sizeof(tmp), x);
												DsLogEx(ds, DS_LOG_INFO, "DSL_AUTH_CERT_OK",
													tunnel_id, auth_username, tmp);
											}
										}
									}
									else
									{
										// 認証失敗
									}
									FreeK(k);
								}
								FreeX(x);
								FreeBuf(b);
							}
						}
					}
					Free(cert_buf);
				}
				break;

			case CLIENT_AUTHTYPE_SMART_CARD_TICKET:
				// 既にスマートカードで認証済みのクライアントによるチケット受信
				{
					UCHAR ticket[SHA1_SIZE];

					if (PackGetData2(p, "SmartCardTicket", ticket, SHA1_SIZE))
					{
						if (Cmp(ticket, ds->SmartCardTicket, SHA1_SIZE) == 0)
						{
							auth_ret = true;
						}
					}
				}
				break;
			}
		}

		if (auth_ret)
		{
			user = AcGetUser(hub, auth_username);
			if (user == NULL)
			{
				user = AcGetUser(hub, "*");
				if (user == NULL)
				{
					// 認証失敗
					auth_ret = false;
				}
			}
		}

		if (auth_ret)
		{
			UINT64 user_expires = 0;
			Lock(user->lock);
			{
				// 有効期限を取得
				user_expires = user->ExpireTime;

				StrCpy(auth_username_real, sizeof(auth_username_real), user->Name);
			}
			Unlock(user->lock);

			// 有効期限を検査
			if (user_expires != 0 && user_expires <= SystemTime64())
			{
				// 有効期限が切れています
				auth_ret = false;

				if (first_connection)
				{
					DsLogEx(ds, DS_LOG_WARNING, "DSL_USER_EXPIRED", tunnel_id, auth_username_real);
					DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
				}
			}
			else
			{
				// ユーザー情報の更新
				Lock(user->lock);
				{
					if (true)
					{
						if (first_connection)
						{
							user->NumLogin++;
							user->LastLoginTime = SystemTime64();
						}
					}
				}
				Unlock(user->lock);
			}

			ReleaseUser(user);
		}

		Unlock(hub->lock);

		ReleaseHub(hub);

		if (auth_ret == false)
		{
			// 認証失敗
			if (first_connection)
			{
				DsLogEx(ds, DS_LOG_WARNING, "DSL_AUTH_FAILED", tunnel_id);
				DsReportAuthFailed(ds, tunnel_id, &client_ip, client_host);
			}
			DsSendError(sock, ERR_AUTH_FAILED);
			FreePack(p);
			return;
		}
	}

	FreePack(p);

	if (svc_type == DESK_SERVICE_VNC)
	{
		bool is_locked = false;

		// URDP Server を使用する場合のチェック
		if (MsIsCurrentDesktopAvailableForVnc() == false)
		{
			is_locked = true;
		}

		// 2016.9.24 Windows 10 用により厳密なチェック
		if (ds->IsLocked != NULL)
		{
			if (ds->IsLocked->IsLockedFlag)
			{
				is_locked = true;
			}
		}

		if (is_locked)
		{
			// デスクトップがロックされている
			DsSendError(sock, ERR_DESK_URDP_DESKTOP_LOCKED);
			return;
		}
	}
	else if (svc_type == DESK_SERVICE_RDP)
	{
		// RDP を使用する場合のチェック
		if (MsIsRemoteDesktopEnabled() == false)
		{
			// 無効な場合は有効にする
			if (MsEnableRemoteDesktop())
			{
				SleepThread(1000);
			}

			if (MsIsRemoteDesktopEnabled() == false)
			{
				// リモートデスクトップが無効になっている
				if (MsIsWin2000())
				{
					DsSendError(sock, ERR_DESK_RDP_NOT_ENABLED_2000);
				}
				else if (MsIsVista() == false)
				{
					DsSendError(sock, ERR_DESK_RDP_NOT_ENABLED_XP);
				}
				else
				{
					DsSendError(sock, ERR_DESK_RDP_NOT_ENABLED_VISTA);
				}
				return;
			}
		}
		else
		{
			// 有効な場合でも再度有効にする
			MsEnableRemoteDesktop();
		}
	}

	if (svc_type == DESK_SERVICE_VNC)
	{
		// URDP Server の開始
		DeskStartUrdpServer(ds->UrdpServer, urdp_version);
		if (DeskWaitReadyForUrdpServer() == false)
		{
			// 開始の失敗
			DeskStopUrdpServer(ds->UrdpServer);
			DsSendError(sock, ERR_DESK_URDP_START_FAILED);
			return;
		}
	}

	// 接続
	s = NULL;
	if (check_port)
	{
		// この段階で localhost ポートに接続する
		s = DsConnectToLocalHostService(svc_type, ds->RdpPort);

		if (s == NULL)
		{
			// 開始失敗
			DsSendError(sock, ERR_DESK_FAILED_TO_CONNECT_PORT);

			goto LABEL_END;
		}
	}

	if (is_smartcard_auth == false)
	{
		// 開始成功
		DsSendError(sock, ERR_NO_ERROR);
	}
	else
	{
		// スマートカード認証の場合はチケットも渡す
		DsSendErrorEx(sock, ERR_NO_ERROR, "SmartCardTicket", ds->SmartCardTicket, SHA1_SIZE);
	}

	SockIoSetTimeout(sock, INFINITE);

	// 1 文字待つ
	c = 0;
	SockIoRecvAll(sock, &c, 1);

	if (c == 'A')
	{
		DS_CLIENT *dsc;
		wchar_t text[MAX_SIZE];
		wchar_t title[MAX_SIZE];
		wchar_t datetime[MAX_PATH];
		wchar_t datetime2[MAX_PATH];
		UINT64 connected_datetime;
		UINT64 disconnected_datetime;

		Debug("*** CONNECTED\n");

		if (s == NULL)
		{
			// この段階で localhost ポートに接続する
			s = DsConnectToLocalHostService(svc_type, ds->RdpPort);
		}

		connected_datetime = SystemTime64();

		dsc = ZeroMalloc(sizeof(DS_CLIENT));

		dsc->ConnectedTick = Tick64();
		Copy(&dsc->Ip, &client_ip, sizeof(IP));
		StrCpy(dsc->HostName, sizeof(dsc->HostName), client_host);
		dsc->Port = client_port;
		Copy(dsc->ClientID, client_id, SHA1_SIZE);
		dsc->TunnelID = tunnel_id;

		LockList(ds->ClientList);
		{
			Add(ds->ClientList, dsc);
		}
		UnlockList(ds->ClientList);

		// バルーンを表示する
		GetDateTimeStrEx64(datetime, sizeof(datetime),
			SystemToLocal64(connected_datetime), NULL);
		UniFormat(title, sizeof(title), _UU("DS_BALLON_CONNECTED_TITLE"),
			client_ip_str);
		UniFormat(text, sizeof(text), _UU("DS_BALLON_CONNECTED_TEXT"),
			client_ip_str, client_port, datetime);

		MsChangeIconOnTrayEx2(NULL, NULL, text, title, 1);

		DsUpdateTaskIcon(ds);

		// リレー動作を開始
		DeskRelay(sock, s);

		disconnected_datetime = SystemTime64();

		// バルーンを消す
		GetDateTimeStrEx64(datetime2, sizeof(datetime2),
			SystemToLocal64(disconnected_datetime), NULL);
		UniFormat(title, sizeof(title), _UU("DS_BALLON_DISCONNECTED_TITLE"),
			client_host);
		UniFormat(text, sizeof(text), _UU("DS_BALLON_DISCONNECTED_TEXT"),
			datetime, client_ip_str, client_port, datetime2);

		MsChangeIconOnTrayEx2(NULL, NULL, text, title, 1);

		LockList(ds->ClientList);
		{
			Delete(ds->ClientList, dsc);

			if (LIST_NUM(ds->ClientList) == 0)
			{
				last_connection = true;
			}
		}
		UnlockList(ds->ClientList);

		Debug("*** DISCONNECTED\n");

		DsUpdateTaskIcon(ds);

		Free(dsc);
	}

	if (last_connection)
	{
		DsLogEx(ds, DS_LOG_INFO, "DSL_TUNNEL_DISCONNECTED",
			client_id_str);

		DsCleanAllRadiusCache(ds);
	}

	Disconnect(s);
	ReleaseSock(s);

LABEL_END:

	if (svc_type == DESK_SERVICE_VNC)
	{
		// URDP Server の停止
		DeskStopUrdpServer(ds->UrdpServer);
	}
#endif  // OS_WIN32
}

// OTP 文字列の発行
void DsGenerateNewOtp(char *dst, UINT size, UINT len)
{
	UINT i;
	char tmp[MAX_PATH];
	if (dst == NULL)
	{
		return;
	}

	len = MIN(len, sizeof(tmp) - 1);

	Zero(tmp, sizeof(tmp));

	for (i = 0;i < len;i++)
	{
		char c = '0' + Rand32() % 9;

		tmp[i] = c;
	}

	StrCpy(dst, size, tmp);
}

// 認証失敗報告
void DsReportAuthFailed(DS *ds, UINT tunnel_id, IP *ip, char *hostname)
{
	UINT num;
	char ip_str[MAX_PATH];
	// 引数チェック
	if (ds == NULL || ip == NULL || hostname == NULL)
	{
		return;
	}

	IPToStr(ip_str, sizeof(ip_str), ip);

	DsLockHistory(ds);
	{
		DsAddHistory(ds, ip);

		num = DsGetHistoryCount(ds, ip);

		if (num >= DS_HISTORY_THRESHOLD)
		{
			// 警告を発生させる
			DsLogEx(ds, DS_LOG_ERROR, "DSL_AUTH_ERROR", tunnel_id, ip_str, hostname, (UINT)((UINT64)DS_HISTORY_EXPIRES / 1000ULL), num);
		}
	}
	DsUnlockHistory(ds);
}

// localhost で動作しているサービスポートに接続
SOCK *DsConnectToLocalHostService(UINT svc_type, UINT rdp_port)
{
	SOCK *s = NULL;

	switch (svc_type)
	{
	case DESK_SERVICE_RDP:
		s = Connect("localhost", rdp_port);
		break;

	case DESK_SERVICE_VNC:
		s = Connect("localhost", DS_URDP_PORT);
		break;
	}

	return s;
}

// エラーの送信
void DsSendError(SOCKIO *sock, UINT error_code)
{
	DsSendErrorEx(sock, error_code, NULL, 0, 0);
}
void DsSendErrorEx(SOCKIO *sock, UINT error_code, char *add_value_name, UCHAR *add_value_data, UINT data_size)
{
	PACK *p;
	// 引数チェック
	if (sock == NULL)
	{
		return;
	}

	p = PackError(error_code);

	if (IsEmptyStr(add_value_name) == false)
	{
		PackAddData(p, add_value_name, add_value_data, data_size);
	}

	SockIoSendPack(sock, p);

	FreePack(p);

	if (error_code != ERR_NO_ERROR)
	{
		SockIoSetTimeout(sock, DS_SEND_ERROR_AND_WAIT_SPAN);

		FreePack(SockIoRecvPack(sock));
	}
}

// RPC 関数関係マクロ
#define	DECLARE_RPC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
	data_type t;													\
	Zero(&t, sizeof(t));											\
	in_rpc(&t, p);													\
	err = function(ds, &t);											\
	if (err == ERR_NO_ERROR)										\
		{																\
		out_rpc(ret, &t);											\
		}																\
		free_rpc(&t);													\
		ok = true;														\
	}
#define	DECLARE_RPC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
	data_type t;													\
	Zero(&t, sizeof(t));											\
	in_rpc(&t, p);													\
	err = function(ds, &t);											\
	if (err == ERR_NO_ERROR)										\
		{																\
		out_rpc(ret, &t);											\
		}																\
		ok = true;														\
	}
#define	DECLARE_RPCHUB_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
{																	\
	data_type t;													\
	Zero(&t, sizeof(t));											\
	DelElement(p, "HubName");										\
	PackAddStr(p, "HubName", CEDAR_DESKVPN_HUBNAME);				\
	in_rpc(&t, p);													\
	err = function(a, &t);											\
	if (err == ERR_NO_ERROR)										\
{																\
	out_rpc(ret, &t);											\
}																\
	free_rpc(&t);													\
	ok = true;														\
	if (StartWith(name, "set") || StartWith(name, "add") || StartWith(name, "create") || StartWith(name, "delete"))	\
{																	\
	DsSaveConfig(ds);												\
}																	\
}
#define	DECLARE_RPCHUB(rpc_name, data_type, function, in_rpc, out_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
{																	\
	data_type t;													\
	Zero(&t, sizeof(t));											\
	DelElement(p, "HubName");										\
	PackAddStr(p, "HubName", CEDAR_DESKVPN_HUBNAME);				\
	in_rpc(&t, p);													\
	err = function(a, &t);											\
	if (err == ERR_NO_ERROR)										\
{																\
	out_rpc(ret, &t);											\
}																\
	ok = true;														\
	if (StartWith(name, "set") || StartWith(name, "add") || StartWith(name, "create") || StartWith(name, "delete"))	\
{																	\
	DsSaveConfig(ds);												\
}																	\
}
#define	DECLARE_SC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)	\
	UINT function(RPC *r, data_type *t)									\
	{																	\
	PACK *p, *ret;													\
	UINT err;														\
	if (r == NULL || t == NULL)										\
		{																\
		return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		free_rpc(t);													\
		Zero(t, sizeof(data_type));										\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
		in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}
#define	DECLARE_SC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	UINT function(RPC *r, data_type *t)									\
	{																	\
	PACK *p, *ret;													\
	UINT err;														\
	if (r == NULL || t == NULL)										\
		{																\
		return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
		in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}


// RPC サーバープロシージャ
PACK *DsRpcServer(RPC *r, char *name, PACK *p)
{
	DS *ds = (DS *)r->Param;
	ADMIN admin, *a;
	PACK *ret;
	UINT err;
	bool ok;
	// 引数チェック
	if (r == NULL || name == NULL || p == NULL || ds == NULL)
	{
		return NULL;
	}

	ret = NewPack();
	err = ERR_NO_ERROR;
	ok = false;

	a = &admin;
	Zero(a, sizeof(ADMIN));
	a->Server = ds->Server;
	a->ServerAdmin = true;
	a->HubName = NULL;
	a->Rpc = r;
	a->LogFileList = NULL;

	// RPC 定義 (サーバー側)
	if (0) {}

	// 通常系 RPC
	DECLARE_RPC("GetInternetSetting", INTERNET_SETTING, DtGetInternetSetting, InInternetSetting, OutInternetSetting)
	DECLARE_RPC("SetInternetSetting", INTERNET_SETTING, DtSetInternetSetting, InInternetSetting, OutInternetSetting)
	DECLARE_RPC("GetStatus", RPC_DS_STATUS, DtGetStatus, InRpcDsStatus, OutRpcDsStatus)
	DECLARE_RPC("RegistMachine", RPC_PCID, DtRegistMachine, InRpcPcid, OutRpcPcid)
	DECLARE_RPC("ChangePcid", RPC_PCID, DtChangePcid, InRpcPcid, OutRpcPcid)
	DECLARE_RPC("SetConfig", RPC_DS_CONFIG, DtSetConfig, InRpcDsConfig, OutRpcDsConfig)
	DECLARE_RPC("GetConfig", RPC_DS_CONFIG, DtGetConfig, InRpcDsConfig, OutRpcDsConfig)
	DECLARE_RPC("GetPcidCandidate", RPC_PCID, DtGetPcidCandidate, InRpcPcid, OutRpcPcid)

	// 仮想 HUB 操作系 RPC
	DECLARE_RPCHUB("GetHubRadius", RPC_RADIUS, StGetHubRadius, InRpcRadius, OutRpcRadius)
	DECLARE_RPCHUB("SetHubRadius", RPC_RADIUS, StSetHubRadius, InRpcRadius, OutRpcRadius)
	DECLARE_RPCHUB_EX("AddCa", RPC_HUB_ADD_CA, StAddCa, InRpcHubAddCa, OutRpcHubAddCa, FreeRpcHubAddCa)
	DECLARE_RPCHUB_EX("EnumCa", RPC_HUB_ENUM_CA, StEnumCa, InRpcHubEnumCa, OutRpcHubEnumCa, FreeRpcHubEnumCa)
	DECLARE_RPCHUB_EX("GetCa", RPC_HUB_GET_CA, StGetCa, InRpcHubGetCa, OutRpcHubGetCa, FreeRpcHubGetCa)
	DECLARE_RPCHUB("DeleteCa", RPC_HUB_DELETE_CA, StDeleteCa, InRpcHubDeleteCa, OutRpcHubDeleteCa)
	DECLARE_RPCHUB_EX("CreateUser", RPC_SET_USER, StCreateUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPCHUB_EX("SetUser", RPC_SET_USER, StSetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPCHUB_EX("GetUser", RPC_SET_USER, StGetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPCHUB("DeleteUser", RPC_DELETE_USER, StDeleteUser, InRpcDeleteUser, OutRpcDeleteUser)
	DECLARE_RPCHUB_EX("EnumUser", RPC_ENUM_USER, StEnumUser, InRpcEnumUser, OutRpcEnumUser, FreeRpcEnumUser)
	DECLARE_RPCHUB_EX("EnumCrl", RPC_ENUM_CRL, StEnumCrl, InRpcEnumCrl, OutRpcEnumCrl, FreeRpcEnumCrl)
	DECLARE_RPCHUB_EX("AddCrl", RPC_CRL, StAddCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPCHUB_EX("DelCrl", RPC_CRL, StDelCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPCHUB_EX("GetCrl", RPC_CRL, StGetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPCHUB_EX("SetCrl", RPC_CRL, StSetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPCHUB_EX("SetAcList", RPC_AC_LIST, StSetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPCHUB_EX("GetAcList", RPC_AC_LIST, StGetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPCHUB("SetSysLog", SYSLOG_SETTING, StSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPCHUB("GetSysLog", SYSLOG_SETTING, StGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)

	if (ok == false)
	{
		err = ERR_NOT_SUPPORTED;
	}

	PackAddInt(ret, "error", err);

	return ret;
}

// RPC 定義 (クライアント側)
DECLARE_SC("GetInternetSetting", INTERNET_SETTING, DtcGetInternetSetting, InInternetSetting, OutInternetSetting)
DECLARE_SC("SetInternetSetting", INTERNET_SETTING, DtcSetInternetSetting, InInternetSetting, OutInternetSetting)
DECLARE_SC("GetStatus", RPC_DS_STATUS, DtcGetStatus, InRpcDsStatus, OutRpcDsStatus)
DECLARE_SC("RegistMachine", RPC_PCID, DtcRegistMachine, InRpcPcid, OutRpcPcid)
DECLARE_SC("ChangePcid", RPC_PCID, DtcChangePcid, InRpcPcid, OutRpcPcid)
DECLARE_SC("SetConfig", RPC_DS_CONFIG, DtcSetConfig, InRpcDsConfig, OutRpcDsConfig)
DECLARE_SC("GetConfig", RPC_DS_CONFIG, DtcGetConfig, InRpcDsConfig, OutRpcDsConfig)
DECLARE_SC("GetPcidCandidate", RPC_PCID, DtcGetPcidCandidate, InRpcPcid, OutRpcPcid)

// PCID 候補の取得
UINT DtGetPcidCandidate(DS *ds, RPC_PCID *t)
{
#ifdef	OS_WIN32
	Zero(t, sizeof(RPC_PCID));

	return WideServerGetPcidCandidate(ds->Wide, t->Pcid, sizeof(t->Pcid), MsGetUserName());
#else   // OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif  // OS_WIN32
}

// インターネット接続設定の取得
UINT DtGetInternetSetting(DS *ds, INTERNET_SETTING *t)
{
	Zero(t, sizeof(INTERNET_SETTING));

	WideGetInternetSetting(ds->Wide, t);

	return ERR_NO_ERROR;
}

// インターネット接続設定の設定
UINT DtSetInternetSetting(DS *ds, INTERNET_SETTING *t)
{
	if (t->ProxyType != PROXY_DIRECT)
	{
		if (IsEmptyStr(t->ProxyHostName) || t->ProxyPort == 0)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	WideSetInternetSetting(ds->Wide, t);
	ds->IsConfigured = true;

	DsSaveConfig(ds);

	return ERR_NO_ERROR;
}

// 状態の取得
UINT DtGetStatus(DS *ds, RPC_DS_STATUS *t)
{
#ifdef	OS_WIN32
	HUB *h;
	DS_POLICY_BODY pol;
	Zero(t, sizeof(RPC_DS_STATUS));

	t->Version = DESK_VERSION;
	t->Build = DESK_BUILD;
	StrCpy(t->ExePath, sizeof(t->ExePath), MsGetExeFileName());
	StrCpy(t->ExeDir, sizeof(t->ExeDir), MsGetExeDirName());
	UniStrCpy(t->ExePathW, sizeof(t->ExePathW), MsGetExeFileNameW());
	UniStrCpy(t->ExeDirW, sizeof(t->ExeDirW), MsGetExeDirNameW());
	t->LastError = WideServerGetErrorCode(ds->Wide);
	t->IsConnected = WideServerIsConnected(ds->Wide);
	WideServerGetPcid(ds->Wide, t->Pcid, sizeof(t->Pcid));
	WideServerGetHash(ds->Wide, t->Hash, sizeof(t->Hash));
	t->ServiceType = ds->ServiceType;
	t->IsUserMode = ds->IsUserMode;
	t->Active = ds->Active;
	t->IsConfigured = ds->IsConfigured;
	t->DsCaps = DsGetCaps(ds);
	t->UseAdvancedSecurity = ds->UseAdvancedSecurity;
	t->ForceDisableShare = ds->ForceDisableShare;
	t->SupportEventLog = ds->SupportEventLog;
	t->NumConfigures = ds->NumConfigures;

	if (ds->Wide != NULL && ds->Wide->wt != NULL)
	{
		StrCpy(t->GateIP, sizeof(t->GateIP), ds->Wide->wt->CurrentGateIp);

		t->MsgForServerArrived = ds->Wide->MsgForServerArrived;
		UniStrCpy(t->MsgForServer, sizeof(t->MsgForServer), ds->Wide->MsgForServer);
		t->MsgForServerOnce = ds->Wide->MsgForServerOnce;
	}

	if (DsGetPolicy(ds, &pol))
	{
		// 規制が設定されている
		DsPreparePolicyMessage(t->MsgForServer2, sizeof(t->MsgForServer2), &pol);

		if (pol.DisableShare)
		{
			t->ForceDisableShare = true;
		}

		if (pol.EnforceOtp)
		{
			StrCpy(t->OtpEndWith, sizeof(t->OtpEndWith), pol.EnforceOtpEndWith);
		}
	}
	else
	{
		if (DsIsTryCompleted(ds))
		{
			if (UniIsEmptyStr(t->MsgForServer))
			{
				// 特に規制が設定されていない
				// 利用禁止ブラックリストにも入っていない
				char list_msg[256] = {0};
				UINT i;
				LIST *dns_list = Win32GetDnsSuffixList();

				if (LIST_NUM(dns_list) == 0)
				{
					char dom2[128];
					StrCpy(dom2, sizeof(dom2), "- Local Area Network\r\n");
					StrCat(list_msg, sizeof(list_msg), dom2);
				}
				else
				{
					for (i = 0; i < LIST_NUM(dns_list);i++)
					{
						char *dom = LIST_DATA(dns_list, i);

						if (IsEmptyStr(dom) == false)
						{
							char dom2[128];
							Format(dom2, sizeof(dom2), "- %s\r\n", dom);
							StrCat(list_msg, sizeof(list_msg), dom2);
						}
					}
				}

				UniFormat(t->MsgForServer2, sizeof(t->MsgForServer2), _UU("DS_POLICY_DEFAULT_MSG"), list_msg);

				ReleaseStrList(dns_list);
			}
		}
	}

	if (ds->Server != NULL && ds->Server->Cedar != NULL)
	{
		LockHubList(ds->Server->Cedar);
		{
			h = GetHub(ds->Server->Cedar, CEDAR_DESKVPN_HUBNAME);
		}
		UnlockHubList(ds->Server->Cedar);

		if (h != NULL)
		{
			AcLock(h);
			{
				if (h->HubDb != NULL)
				{
					t->NumAdvancedUsers = LIST_NUM(h->HubDb->UserList);
				}
			}
			AcUnlock(h);

			ReleaseHub(h);
		}
	}

	return ERR_NO_ERROR;
#else   // OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif  // OS_WIN32
}

// PCID の登録
UINT DtRegistMachine(DS *ds, RPC_PCID *t)
{
	X *x;
	K *k;
	UINT ret;

	if (WideServerGetCertAndKey(ds->Wide, &x, &k) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = WideServerRegistMachine(ds->Wide, t->Pcid, x, k);

	if (ret == ERR_NO_ERROR)
	{
		Lock(ds->Wide->SettingLock);
		{
			StrCpy(ds->Wide->Pcid, sizeof(ds->Wide->Pcid), t->Pcid);
		}
		Unlock(ds->Wide->SettingLock);

		WideServerReconnect(ds->Wide);
	}

	FreeX(x);
	FreeK(k);

	return ret;
}

// PCID の変更
UINT DtChangePcid(DS *ds, RPC_PCID *t)
{
	return WideServerRenameMachine(ds->Wide, t->Pcid);
}

// 設定の設定
UINT DtSetConfig(DS *ds, RPC_DS_CONFIG *t)
{
	ds->Active = t->Active;
	ds->PowerKeep = t->PowerKeep;
	Copy(ds->HashedPassword, t->HashedPassword, sizeof(ds->HashedPassword));
	ds->AuthType = t->AuthType;
	Copy(ds->AuthPassword, t->AuthPassword, sizeof(ds->AuthPassword));
	ds->ServiceType = t->ServiceType;
	WideSetDontCheckCert(ds->Wide, t->DontCheckCert);
	ds->IsConfigured = true;
	ds->SaveLogFile = t->SaveLogFile;
	UniStrCpy(ds->BluetoothDir, sizeof(ds->BluetoothDir), t->BluetoothDir);
	ds->UseAdvancedSecurity = t->UseAdvancedSecurity;
	ds->SaveEventLog = t->SaveEventLog;
	ds->DisableShare = t->DisableShare;
	UniStrCpy(ds->AdminUsername, sizeof(ds->AdminUsername), t->AdminUsername);

	ds->EnableOtp = t->EnableOtp;
	StrCpy(ds->OtpEmail, sizeof(ds->OtpEmail), t->OtpEmail);

	DsNormalizeConfig(ds);
	DsSaveConfig(ds);
	DsUpdatePowerKeepSetting(ds);

	return ERR_NO_ERROR;
}

// 設定の取得
UINT DtGetConfig(DS *ds, RPC_DS_CONFIG *t)
{
	Zero(t, sizeof(RPC_DS_CONFIG));

	t->Active = ds->Active;
	t->PowerKeep = ds->PowerKeep;
	Copy(t->HashedPassword, ds->HashedPassword, sizeof(t->HashedPassword));
	t->AuthType = ds->AuthType;
	Copy(t->AuthPassword, ds->AuthPassword, sizeof(t->AuthPassword));
	t->ServiceType = ds->ServiceType;
	t->DontCheckCert = WideGetDontCheckCert(ds->Wide);
	t->SaveLogFile = ds->SaveLogFile;
	UniStrCpy(t->BluetoothDir, sizeof(t->BluetoothDir), ds->BluetoothDir);
	t->UseAdvancedSecurity = ds->UseAdvancedSecurity;
	t->SaveEventLog = ds->SaveEventLog;
	t->DisableShare = ds->DisableShare;
	UniStrCpy(t->AdminUsername, sizeof(t->AdminUsername), ds->AdminUsername);

	t->EnableOtp = ds->EnableOtp;
	StrCpy(t->OtpEmail, sizeof(t->OtpEmail), ds->OtpEmail);

	return ERR_NO_ERROR;
}

// Accept プロシージャ
void DsAcceptProc(THREAD *thread, SOCKIO *sock, void *param)
{
	DS *ds;
	// 引数チェック
	if (thread == NULL || sock == NULL || param == NULL)
	{
		return;
	}

	ds = (DS *)param;

	Debug("Tunnel Accepted.\n");

	DsServerMain(ds, sock);

	Debug("Tunnel Disconnected.\n");
}

// RPC 接続
UINT DtcConnect(char *password, RPC **rpc)
{
#ifdef	OS_WIN32
	SOCK *s;
	PACK *p;
	UINT ret;
	UCHAR hash[SHA1_SIZE];
	// 引数チェック
	if (password == NULL)
	{
		password = "";
	}
	if (rpc == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	s = Connect("localhost", DS_RPC_PORT);
	if (s == NULL)
	{
		return ERR_DESK_RPC_CONNECT_FAILED;
	}

	SetTimeout(s, 5000);

	p = RecvPack(s);

	if (p == NULL)
	{
		ReleaseSock(s);
		return ERR_DESK_RPC_PROTOCOL_ERROR;
	}
	else
	{
		// バージョンチェック
		wchar_t adminname[MAX_PATH];
		UINT build = PackGetInt(p, "Build");
		UINT ver = PackGetInt(p, DS_RPC_VER_SIGNATURE_STR);

		Zero(adminname, sizeof(adminname));
		PackGetUniStr(p, "AdminUsername", adminname, sizeof(adminname));

		FreePack(p);
		if (build == 0 || ver == 0)
		{
			ReleaseSock(s);
			return ERR_DESK_RPC_PROTOCOL_ERROR;
		}

		if (build != DESK_BUILD || ver != DESK_VERSION)
		{
			ReleaseSock(s);
			return ERR_DESK_VERSION_DIFF;
		}

		if (UniIsEmptyStr(adminname) == false && UniStrCmpi(adminname, MsGetUserNameW()) != 0)
		{
			// 管理者ユーザー名が異なる
			ReleaseSock(s);
			return ERR_DESK_DIFF_ADMIN;
		}
	}

	SetTimeout(s, INFINITE);

	p = NewPack();
	if (StrLen(password) == 0)
	{
		Zero(hash, sizeof(hash));
	}
	else
	{
		HashSha1(hash, password, StrLen(password));
	}

	PackAddData(p, "HashedPassword", hash, SHA1_SIZE);
	SendPack(s, p);
	FreePack(p);

	p = RecvPack(s);
	if (p == NULL)
	{
		ReleaseSock(s);
		return ERR_DESK_RPC_PROTOCOL_ERROR;
	}

	ret = GetErrorFromPack(p);
	FreePack(p);

	if (ret != ERR_NO_ERROR)
	{
		ReleaseSock(s);
		return ret;
	}

	*rpc = StartRpcClient(s, NULL);

	ReleaseSock(s);

	return ERR_NO_ERROR;
#else   // OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif  // OS_WIN32
}

// RPC 処理メインプロシージャ
void DsRpcMain(DS *ds, SOCK *s)
{
#ifdef	OS_WIN32
	PACK *p;
	bool ret;
	UCHAR hashed_password[SHA1_SIZE];
	RPC *rpc;
	// 引数チェック
	if (ds == NULL || s == NULL)
	{
		return;
	}

	// バージョン情報等を送信
	p = NewPack();
	PackAddInt(p, DS_RPC_VER_SIGNATURE_STR, DESK_VERSION);
	PackAddBool(p, "IsUserMode", ds->IsUserMode);
	PackAddStr(p, "ExePath", MsGetExeFileName());
	PackAddStr(p, "ExeDir", MsGetExeDirName());
	PackAddStr(p, "UserName", MsGetUserNameEx());
	PackAddUniStr(p, "ExePathW", MsGetExeFileNameW());
	PackAddUniStr(p, "ExeDirW", MsGetExeDirNameW());
	PackAddUniStr(p, "UserNameW", MsGetUserNameExW());
	PackAddUniStr(p, "AdminUsername", ds->AdminUsername);
	PackAddBool(p, "ForceDisableShare", ds->ForceDisableShare);
	PackAddInt(p, "Build", DESK_BUILD);
	ret = SendPack(s, p);
	FreePack(p);
	if (ret == false)
	{
		return;
	}

	// 設定パスワードを確認
	p = RecvPack(s);
	if (p == NULL)
	{
		return;
	}
	if (PackGetBool(p, "Exit") && ds->IsUserMode)
	{
		// ユーザーモードで停止命令を受けた
		FreePack(p);
		MsStopUserModeFromService();
		return;
	}
	Zero(hashed_password, sizeof(hashed_password));
	PackGetData2(p, "HashedPassword", hashed_password, sizeof(hashed_password));
	FreePack(p);

	if (IsZero(ds->HashedPassword, sizeof(ds->HashedPassword)) == false &&
		Cmp(ds->HashedPassword, hashed_password, SHA1_SIZE) != 0)
	{
		// パスワードが不正
		p = PackError(ERR_ACCESS_DENIED);
		SendPack(s, p);
		FreePack(p);
		return;
	}

	// 認証成功
	p = PackError(ERR_NO_ERROR);
	SendPack(s, p);
	FreePack(p);

	ds->NumConfigures++;

	DsSaveConfig(ds);

	// RPC の開始
	rpc = StartRpcServer(s, DsRpcServer, ds);
	RpcServer(rpc);
	RpcFree(rpc);

	DsSaveConfig(ds);
#endif  // OS_WIN32
}

// リスナースレッド
void DsRpcListenerThread(THREAD *thread, void *param)
{
	TCP_ACCEPTED_PARAM *accepted_param;
	LISTENER *r;
	SOCK *s;
	DS *ds;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	accepted_param = (TCP_ACCEPTED_PARAM *)param;
	r = accepted_param->r;
	s = accepted_param->s;
	AddRef(r->ref);
	AddRef(s->ref);
	ds = (DS *)r->ThreadParam;
	AddSockThread(ds->SockThreadList, s, thread);
	NoticeThreadInit(thread);

	Debug("RPC Accepted.\n");

	DsRpcMain(ds, s);
	SleepThread(100);

	DelSockThread(ds->SockThreadList, s);
	ReleaseSock(s);
	ReleaseListener(r);
}

// RPC ポートが動作しているかどうか確認する
bool DsCheckServiceRpcPort()
{
	return DsCheckServiceRpcPortEx(NULL);
}
bool DsCheckServiceRpcPortEx(bool *bad_protocol)
{
	UINT ret;
	DS_INFO info;

	ret = DsGetServiceInfo(&info);

	if (ret == ERR_NO_ERROR)
	{
		return true;
	}
	else if (ret == ERR_PROTOCOL_ERROR)
	{
		if (bad_protocol != NULL)
		{
			*bad_protocol = true;
		}
	}
	else
	{
		if (bad_protocol != NULL)
		{
			*bad_protocol = false;
		}
	}

	return false;
}

// ユーザーモードサービスを停止する
void DsStopUsermodeService()
{
	SOCK *s;
	PACK *p;
	UINT ret = ERR_NO_ERROR;

	s = ConnectEx("localhost", DS_RPC_PORT, 500);
	if (s == NULL)
	{
		return;
	}

	SetTimeout(s, 5000);

	p = RecvPack(s);

	FreePack(p);

	p = NewPack();
	PackAddBool(p, "Exit", true);

	SendPack(s, p);

	FreePack(p);

	SleepThread(100);

	Disconnect(s);
	ReleaseSock(s);
}

// サービスの情報を取得する
UINT DsGetServiceInfo(DS_INFO *info)
{
	SOCK *s;
	PACK *p;
	UINT ret = ERR_NO_ERROR;
	// 引数チェック
	if (info == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	Zero(info, sizeof(DS_INFO));

	s = ConnectEx("localhost", DS_RPC_PORT, 500);
	if (s == NULL)
	{
		return ERR_DESK_RPC_CONNECT_FAILED;
	}

	SetTimeout(s, 5000);

	p = RecvPack(s);

	if (p == NULL)
	{
		ret = ERR_DESK_RPC_PROTOCOL_ERROR;
	}
	else
	{
		PackGetStr(p, "ExeDir", info->ExeDir, sizeof(info->ExeDir));
		PackGetStr(p, "ExePath", info->ExePath, sizeof(info->ExePath));
		PackGetStr(p, "UserName", info->UserName, sizeof(info->UserName));
		PackGetUniStr(p, "ExeDirW", info->ExeDirW, sizeof(info->ExeDirW));
		PackGetUniStr(p, "ExePathW", info->ExePathW, sizeof(info->ExePathW));
		PackGetUniStr(p, "UserNameW", info->UserNameW, sizeof(info->UserNameW));
		if (UniIsEmptyStr(info->ExeDirW))
		{
			StrToUni(info->ExeDirW, sizeof(info->ExeDirW), info->ExeDir);
		}
		if (UniIsEmptyStr(info->ExePathW))
		{
			StrToUni(info->ExePathW, sizeof(info->ExePathW), info->ExePath);
		}
		if (UniIsEmptyStr(info->UserNameW))
		{
			StrToUni(info->UserNameW, sizeof(info->UserNameW), info->UserName);
		}
		info->Version = PackGetInt(p, DS_RPC_VER_SIGNATURE_STR);
		info->IsUserMode = PackGetBool(p, "IsUserMode");
		info->Build = PackGetInt(p, "Build");
		info->ForceDisableShare = PackGetBool(p, "ForceDisableShare");

		if (info->Version == 0)
		{
			ret = ERR_DESK_RPC_PROTOCOL_ERROR;
		}

		FreePack(p);
	}

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// デフォルト設定に戻す
void DsInitDefaultConfig(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	// ユーザー認証無し
	ds->AuthType = DESK_AUTH_NONE;

	// パスワード無し
	Zero(ds->HashedPassword, SHA1_SIZE);

	// 電源維持機能を有効
	ds->PowerKeep = true;

	// ログファイル保存を有効
	ds->SaveLogFile = true;

	// アクティブ
	ds->Active = true;

	if (ds->IsUserMode)
	{
		// ユーザーモードの場合は URDP を使用する
		ds->ServiceType = DESK_SERVICE_VNC;

		if (false) // 2020/4/18 折角実装したが、いったんキャンセル。
			// 一般ユーザー権限しかないユーザーは Remote Desktop Users グループに
			// 入っていない可能性が高いので、RDP で接続しても意味
			// がない。
		{
			// 2020/4/17 ユーザーモードであっても、RDP ポートが開いていて利用可能
			// であれば DESK_SERVICE_RDP にする
			if (MsIsRemoteDesktopAvailable())
			{
				if (MsIsRemoteDesktopCanEnableByRegistory())
				{
					if (MsEnableRemoteDesktop())
					{
						if (MsIsRemoteDesktopEnabled())
						{
							// リモートデスクトップが有効になったようだぞ
							// ポートチェックして、有効なようならこれをデフォルトで
							// 使う
							if (MsCheckLocalhostRemoteDesktopPort())
							{
								ds->ServiceType = DESK_SERVICE_RDP;
							}
						}
					}
				}
			}
		}
	}

	WideSetDontCheckCert(ds->Wide, false);

	DsNormalizeConfig(ds);
}

// 設定の正規化
void DsNormalizeConfig(DS *ds)
{
#ifdef	OS_WIN32
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	if (MsIsRemoteDesktopAvailable() == false)
	{
		// OS がリモートデスクトップをサポートしていない場合は URDP を使用する
		ds->ServiceType = DESK_SERVICE_VNC;
	}

	if (ds->IsUserMode == false)
	{
		// ただしサービスモードの場合は必ず RDP を使用する
		// 例: Windows XP Home Edition などでもここに到達する可能性はある
		//     が、そもそもインストーラの時点で弾かれるべきである
		ds->ServiceType = DESK_SERVICE_RDP;
	}

	if (ds->ServiceType == DESK_SERVICE_RDP)
	{
		// リモートデスクトップを有効にしておく
		MsEnableRemoteDesktop();
	}

	if (IsEmptyStr(ds->OtpEmail))
	{
		// OTP メールアドレス未設定の場合は EnableOtp を false にする
		ds->EnableOtp = false;
	}
#endif  // OS_WIN32
}

// 設定の読み込み
bool DsLoadConfig(DS *ds)
{
	FOLDER *root;
	bool ret;
	// 引数チェック
	if (ds == NULL)
	{
		return false;
	}

	ds->CfgRw = NewCfgRwEx(&root, DS_CONFIG_FILENAME, true);

	if (root == NULL)
	{
		return false;
	}

	// 設定の読み込みメイン
	ret = DsLoadConfigMain(ds, root);

	CfgDeleteFolder(root);

	DsNormalizeConfig(ds);

	return ret;
}

// 設定の書き込み
void DsSaveConfig(DS *ds)
{
	FOLDER *root;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	root = DsSaveConfigMain(ds);
	SaveCfgRw(ds->CfgRw, root);
	CfgDeleteFolder(root);

	if (ds->Wide != NULL)
	{
		ds->Wide->ServerMask64 = DsCalcMask(ds);
	}
}

// 設定の読み込みメイン
bool DsLoadConfigMain(DS *ds, FOLDER *root)
{
	INTERNET_SETTING setting;
	FOLDER *f;
	FOLDER *syslog_f = NULL;
	// 引数チェック
	if (ds == NULL || root == NULL)
	{
		return false;
	}

	ds->PowerKeep = CfgGetBool(root, "PowerKeep");
	ds->SaveLogFile = CfgGetBool(root, "DontSaveLogFile") ? false : true;

	Zero(ds->HashedPassword, SHA1_SIZE);
	CfgGetByte(root, "HashedPassword", ds->HashedPassword, SHA1_SIZE);

	ds->AuthType = CfgGetInt(root, "AuthType");

	switch (ds->AuthType)
	{
	case DESK_AUTH_PASSWORD:
		Zero(ds->AuthPassword, SHA1_SIZE);
		CfgGetByte(root, "AuthPassword", ds->AuthPassword, SHA1_SIZE);
		break;
	}

	ds->ServiceType = CfgGetInt(root, "ServiceType");

	WideSetDontCheckCert(ds->Wide, CfgGetBool(root, "DontCheckCert"));

	ds->Active = CfgGetBool(root, "Active");

	CfgGetUniStr(root, "BluetoothDir", ds->BluetoothDir, sizeof(ds->BluetoothDir));

	ds->IsConfigured = CfgGetBool(root, "IsConfigured");

#ifndef	DESK_DISABLE_NEW_FEATURE
	ds->UseAdvancedSecurity = CfgGetBool(root, "UseAdvancedSecurity");

	ds->SaveEventLog = CfgGetBool(root, "SaveEventLog");
#endif	// DESK_DISABLE_NEW_FEATURE

	ds->DisableShare = CfgGetBool(root, "DisableShare");

	CfgGetUniStr(root, "AdminUsername", ds->AdminUsername, sizeof(ds->AdminUsername));

	ds->NumConfigures = CfgGetInt(root, "NumConfigures");

	ds->EnableOtp = CfgGetBool(root, "EnableOtp");
	CfgGetStr(root, "OtpEmail", ds->OtpEmail, sizeof(ds->OtpEmail));

	f = CfgGetFolder(root, "ProxySetting");

	if (f != NULL)
	{
		DsLoadInternetSetting(f, &setting);

		WideSetInternetSetting(ds->Wide, &setting);
	}

	f = CfgGetFolder(root, DS_CFG_SECURITY_SETTINGS);
	if (f != NULL)
	{
		HUB *h;
		bool b = false;

#ifdef	DESK_DISABLE_NEW_FEATURE
		b = true;
#endif	// DESK_DISABLE_NEW_FEATURE

		h = GetHub(ds->Server->Cedar, CEDAR_DESKVPN_HUBNAME);
		if (h != NULL)
		{
			DelHub(ds->Server->Cedar, h);
			ReleaseHub(h);
		}

		SiLoadHubCfg(ds->Server, f, CEDAR_DESKVPN_HUBNAME);
	}

#ifndef	DESK_DISABLE_NEW_FEATURE
	// syslog
	syslog_f = CfgGetFolder(f, "SyslogSettings");
	if (syslog_f != NULL)
	{
		SYSLOG_SETTING set;

		Zero(&set, sizeof(set));

		set.SaveType = CfgGetInt(syslog_f, "SaveType");
		CfgGetStr(syslog_f, "HostName", set.Hostname, sizeof(set.Hostname));
		set.Port = CfgGetInt(syslog_f, "Port");
		if (set.Port == 0)
		{
			set.Port = SYSLOG_PORT;
		}

		SiSetSysLogSetting(ds->Server, &set);
	}
	else
#endif	// DESK_DISABLE_NEW_FEATURE
	{
		SYSLOG_SETTING set;

		Zero(&set, sizeof(set));

		set.SaveType = 0;
		set.Port = SYSLOG_PORT;

		SiSetSysLogSetting(ds->Server, &set);
	}

	return true;
}

// 設定の書き込みメイン
FOLDER *DsSaveConfigMain(DS *ds)
{
	FOLDER *root;
	FOLDER *f = NULL;
	INTERNET_SETTING setting;
	HUB *h = NULL;
	FOLDER *syslog_f = NULL;
	// 引数チェック
	if (ds == NULL)
	{
		return NULL;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);

	CfgAddBool(root, "PowerKeep", ds->PowerKeep);

	CfgAddBool(root, "DontSaveLogFile", ds->SaveLogFile ? false : true);

#ifndef	DESK_DISABLE_NEW_FEATURE
	CfgAddBool(root, "SaveEventLog", ds->SaveEventLog);
#endif	// DESK_DISABLE_NEW_FEATURE

	CfgAddBool(root, "DisableShare", ds->DisableShare);

	CfgAddBool(root, "EnableOtp", ds->EnableOtp);

	CfgAddStr(root, "OtpEmail", ds->OtpEmail);

	CfgAddBool(root, "IsConfigured", ds->IsConfigured);

	CfgAddBool(root, "Active", ds->Active);

	CfgAddUniStr(root, "AdminUsername", ds->AdminUsername);

	if (ds->SupportBluetooth)
	{
		CfgAddUniStr(root, "BluetoothDir", ds->BluetoothDir);
	}

#ifndef	DESK_DISABLE_NEW_FEATURE
	CfgAddBool(root, "UseAdvancedSecurity", ds->UseAdvancedSecurity);
#endif	// DESK_DISABLE_NEW_FEATURE

	if (IsZero(ds->HashedPassword, SHA1_SIZE) == false)
	{
		CfgAddByte(root, "HashedPassword", ds->HashedPassword, SHA1_SIZE);
	}

	CfgAddInt(root, "AuthType", ds->AuthType);

	CfgAddInt(root, "NumConfigures", ds->NumConfigures);

	switch (ds->AuthType)
	{
	case DESK_AUTH_PASSWORD:
		CfgAddByte(root, "AuthPassword", ds->AuthPassword, SHA1_SIZE);
		break;
	}

	CfgAddInt(root, "ServiceType", ds->ServiceType);

#if	0
	f = CfgCreateFolder(root, "CommSetting");
	DsSaveConfigCommSetting(f);
#endif

	WideGetInternetSetting(ds->Wide, &setting);

	CfgAddBool(root, "DontCheckCert", WideGetDontCheckCert(ds->Wide));

	f = CfgCreateFolder(root, "ProxySetting");

	DsSaveInternetSetting(f, &setting);

	f = CfgCreateFolder(root, DS_CFG_SECURITY_SETTINGS);

	h = GetHub(ds->Server->Cedar, CEDAR_DESKVPN_HUBNAME);
	if (h != NULL)
	{
		Lock(h->lock);
		{
			bool b = false;
#ifdef	DESK_DISABLE_NEW_FEATURE
			b = true;
#endif	// DESK_DISABLE_NEW_FEATURE
			SiWriteHubCfg(f, h);
		}
		Unlock(h->lock);

		ReleaseHub(h);
	}

	// syslog
#ifndef	DESK_DISABLE_NEW_FEATURE
	syslog_f = CfgCreateFolder(f, "SyslogSettings");
	if (syslog_f != NULL)
	{
		SYSLOG_SETTING set;

		SiGetSysLogSetting(ds->Server, &set);

		CfgAddInt(syslog_f, "SaveType", set.SaveType);
		CfgAddStr(syslog_f, "HostName", set.Hostname);
		CfgAddInt(syslog_f, "Port", set.Port);
	}
#endif	// DESK_DISABLE_NEW_FEATURE

	return root;
}

// INTERNET_SETTING の読み込み
void DsLoadInternetSetting(FOLDER *f, INTERNET_SETTING *setting)
{
	BUF *b;
	// 引数チェック
	if (f == NULL || setting == NULL)
	{
		return;
	}

	Zero(setting, sizeof(INTERNET_SETTING));

	setting->ProxyType = CfgGetInt(f, "ProxyType");

	CfgGetStr(f, "ProxyHostName", setting->ProxyHostName, sizeof(setting->ProxyHostName));
	setting->ProxyPort = CfgGetInt(f, "ProxyPort");
	CfgGetStr(f, "ProxyUsername", setting->ProxyUsername, sizeof(setting->ProxyUsername));
	b = CfgGetBuf(f, "ProxyPassword");

	if (b != NULL)
	{
		DsDecryptPassword(b, setting->ProxyPassword, sizeof(setting->ProxyPassword));
	}

	CfgGetStr(f, "ProxyUserAgent", setting->ProxyUserAgent, sizeof(setting->ProxyUserAgent));
	if (IsEmptyStr(setting->ProxyUserAgent))
	{
		StrCpy(setting->ProxyUserAgent, sizeof(setting->ProxyUserAgent), DEFAULT_PROXY_USER_AGENT);
	}

	FreeBuf(b);
}

// INTERNET_SETTING の保存
void DsSaveInternetSetting(FOLDER *f, INTERNET_SETTING *setting)
{
	BUF *b;
	// 引数チェック
	if (f == NULL || setting == NULL)
	{
		return;
	}

	CfgAddInt(f, "ProxyType", setting->ProxyType);

	CfgAddStr(f, "ProxyHostName", setting->ProxyHostName);
	CfgAddInt(f, "ProxyPort", setting->ProxyPort);
	CfgAddStr(f, "ProxyUsername", setting->ProxyUsername);
	b = DsEncryptPassword(setting->ProxyPassword);
	CfgAddBuf(f, "ProxyPassword", b);
	CfgAddStr(f, "ProxyUserAgent", setting->ProxyUserAgent);
	FreeBuf(b);
}

// パスワードの解読
void DsDecryptPassword(BUF *b, char *str, UINT str_size)
{
	UINT size;
	char *tmp;
	CRYPT *c;
	// 引数チェック
	if (b == NULL || str == NULL)
	{
		return;
	}

	size = b->Size;
	tmp = ZeroMalloc(size + 1);

	c = NewCrypt(DS_PASSWORD_ENCRYPT_KEY, StrLen(DS_PASSWORD_ENCRYPT_KEY));
	Encrypt(c, tmp, b->Buf, size);
	FreeCrypt(c);

	StrCpy(str, str_size, tmp);
	Free(tmp);
}

// パスワードの暗号化
BUF *DsEncryptPassword(char *password)
{
	CRYPT *c;
	BUF *b;
	// 引数チェック
	if (password == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, password, StrLen(password));

	c = NewCrypt(DS_PASSWORD_ENCRYPT_KEY, StrLen(DS_PASSWORD_ENCRYPT_KEY));
	Encrypt(c, b->Buf, b->Buf, b->Size);
	FreeCrypt(c);

	return b;
}

// CommSetting の保存
void DsSaveConfigCommSetting(FOLDER *f)
{
	// 引数チェック
	if (f == NULL)
	{
		return;
	}

	CfgAddBool(f, "UDP_Hole_Punching", true);
	CfgAddBool(f, "UDP_DNS_Packet_Capsule", true);
	CfgAddBool(f, "TCP_NAT_Reverse", true);
	CfgAddBool(f, "Univ_Plug_and_Play", true);
	CfgAddBool(f, "Univ_Plug_and_Play_2", true);
	CfgAddBool(f, "TCP_NAT_Auto_PortMapping", true);
	CfgAddBool(f, "TCP_NAT_Full_Cone", true);
	CfgAddBool(f, "TCP_NAT_Restricted_Cone", true);
	CfgAddBool(f, "TCP_NAT_Port_Restricted_Cone", true);
	CfgAddBool(f, "TCP_NAT_Symmetric", true);
	CfgAddBool(f, "TCP_MS_Messenger_Capsule", true);
}

// 設定解放
void DsFreeConfig(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	// 設定保存
	DsSaveConfig(ds);

	// 解放
	FreeCfgRw(ds->CfgRw);
}

// レジストリから RDP のポート番号を取得する
UINT DsGetRdpPortFromRegistry()
{
#ifdef	OS_WIN32
	return MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "PortNumber");
#else   // OS_WIN32
	return 0;
#endif  // OS_WIN32
}

// 設定初期化
void DsInitConfig(DS *ds)
{
	UINT port;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	// 設定読み込み
	if (DsLoadConfig(ds) == false)
	{
		// デフォルト設定
		DsInitDefaultConfig(ds);
	}

	ds->RdpPort = DS_RDP_PORT;

	port = DsGetRdpPortFromRegistry();

	if (port != 0)
	{
		ds->RdpPort = port;
	}

	// 設定保存
	DsSaveConfig(ds);

	DsUpdatePowerKeepSetting(ds);
}

// 証明書のリセット用プロシージャ
void DsResetCertProc(WIDE *wide, void *param)
{
	X *cert = NULL;
	K *key = NULL;
	// 引数チェック
	if (wide == NULL || param == NULL)
	{
		return;
	}

	Debug("--------- Proxy Connect ---------\n");

	// 新規作成
	WideServerGenerateCertAndKey(&cert, &key);

	// ディスクに保存
	DsWriteSecureCertAndKey(cert, key);

	// WideServer に書き込んで再接続
	WideServerSetCertAndKeyEx(wide, cert, key, true);

	FreeX(cert);
	FreeK(key);
}

// マスク値の計算
UINT64 DsCalcMask(DS *ds)
{
#ifdef	OS_WIN32
	UINT64 ret = 0;
	DS_POLICY_BODY pol = {0};
	// 引数チェック
	if (ds == NULL)
	{
		return 0;
	}

	if (ds->IsUserMode)
	{
		ret |= DS_MASK_USER_MODE;
	}
	else
	{
		ret |= DS_MASK_SERVICE_MODE;
	}

	if (ds->EnableOtp)
	{
		ret |= DS_MASK_OTP_ENABLED;
	}

	if (DsGetPolicy(ds, &pol))
	{
		ret |= DS_MASK_POLICY_ENFORCED;
	}

	if (ds->ServiceType == DESK_SERVICE_RDP)
	{
		// RDP モードの場合、Terminal Service (複数セッションログオン) が利用可能か
		// どうか取得する
		if (MsIsTerminalServiceMultiUserInstalled() == false)
		{
			ret |= DS_MASK_WIN_RDP_NORMAL;
		}
		else
		{
			ret |= DS_MASK_WIN_RDP_TS;
		}
	}
	else
	{
		ret |= DS_MASK_URDP_CLIENT;
	}

	return ret;
#else   // OS_WIN32
	return 0;
#endif  // OS_WIN32
}

// 共有機能が無効化されているかどうか調べる
bool DsIsShareDisabled(DS *ds)
{
	DS_POLICY_BODY pol;
	// 引数チェック
	if (ds == NULL)
	{
		return false;
	}

	if (ds->ForceDisableShare)
	{
		return true;
	}

	if (ds->DisableShare)
	{
		return true;
	}

	if (DsGetPolicy(ds, &pol))
	{
		if (pol.DisableShare)
		{
			return true;
		}
	}

	return false;
}

// Caps を取得
UINT DsGetCaps(DS *ds)
{
	UINT ret = 0;
	// 引数チェック
	if (ds == NULL)
	{
		return 0;
	}

	if (ds->SupportBluetooth)
	{
		ret |= DS_CAPS_SUPPORT_BLUETOOTH;
	}

	return ret;
}

// 指定された EXE ファイル名に共有を無効化するシグネチャが書いてあるかどうか検査する
bool DsCheckShareDisableSignature(wchar_t *exe)
{
#ifdef	OS_WIN32
	IO *io;
	UINT size;
	bool ret = false;
	if (exe == NULL)
	{
		exe = MsGetExeFileNameW();
	}

	io = FileOpenW(exe, false);
	if (io == NULL)
	{
		return false;
	}

	size = FileSize(io);
	if (size >= 10000)
	{
		UCHAR tmp[DESK_EXE_DISABLE_SHARE_SIGNATURE_SIZE];
		Zero(tmp, sizeof(tmp));

		FileSeek(io, FILE_BEGIN, size - DESK_EXE_DISABLE_SHARE_SIGNATURE_SIZE);

		FileRead(io, tmp, DESK_EXE_DISABLE_SHARE_SIGNATURE_SIZE);

		if (Cmp(tmp, DESK_EXE_DISABLE_SHARE_SIGNATURE, DESK_EXE_DISABLE_SHARE_SIGNATURE_SIZE) == 0)
		{
			ret = true;
		}
	}

	FileClose(io);

	return ret;
#else   // OS_WIN32
	return false;
#endif  // OS_WIN32
}

// Desktop VPN Server の初期化
DS *NewDs(bool is_user_mode, bool force_share_disable)
{
#ifdef	OS_WIN32
	DS *ds;
	X *cert;
	K *key;
	char server_hash[128] = {0};

	InitWinUi(_UU("DS_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	ds = ZeroMalloc(sizeof(DS));

	Rand(ds->SmartCardTicket, SHA1_SIZE);

	DsGenerateNewOtp(ds->OtpTicket, sizeof(ds->OtpTicket), 128);

	ds->History = NewList(NULL);

	ds->ForceDisableShare = force_share_disable;//DsCheckShareDisableSignature(NULL);

	ds->Server = SiNewServer(false);

	//ds->SupportBluetooth = IsFileExists(DC_BLUETOOTH_FLAG_FILENAME);

	if (MsIsNt() && MsIsAdmin())
	{
		// イベントログ機能は Windows NT でかつ Admin の場合のみサポート
		ds->SupportEventLog = true;
	}

	DsInitRadiusCacheList(ds);

	ds->Log = NewLog(DS_LOG_DIRNAME, "desk", LOG_SWITCH_DAY);
	ds->Log->Flush = true;

	if (ds->SupportEventLog)
	{
		ds->EventLog = MsInitEventLog(DS_EVENTLOG_SOURCE_NAME);
	}

	ds->ClientList = NewList(NULL);

	DsLog(ds, "DSL_LINE");

	ds->UrdpServer = DeskInitUrdpServer();
	ds->IsUserMode = is_user_mode;
	ds->PowerKeepLock = NewLock();
	ds->SockThreadList = NewSockThreadList();

	if (ds->IsUserMode)
	{
		if (Win32IsWindow10OrLater())
		{
			ds->IsLocked = MsNewIsLocked();
		}
	}

	ds->Cedar = NewCedar(NULL, NULL);
	DsLog(ds, "DSL_START1", DESK_VERSION / 100, DESK_VERSION % 100, DESK_BUILD);
	DsLog(ds, "DSL_START2", ds->Cedar->BuildInfo);
	DsLog(ds, "DSL_START3");

	DsUpdateTaskIcon(ds);

	ds->Wide = WideServerStartEx(DESK_SVC_NAME, DsAcceptProc, ds, _GETLANG(),
		DsResetCertProc, ds);

	WideServerSuppressAutoReconnect(ds->Wide, true);

	// 証明書の初期化
	if (DsReadSecureCertAndKey(&cert, &key) == false)
	{
		// 証明書の新規作成
		WideServerGenerateCertAndKey(&cert, &key);
		DsWriteSecureCertAndKey(cert, key);
	}

	// RPC の開始
	ds->RpcListener = NewListenerEx2(ds->Cedar, LISTENER_TCP,
		DS_RPC_PORT, DsRpcListenerThread, ds, true);

	WideServerSetCertAndKey(ds->Wide, cert, key);

	// 設定初期化
	DsInitConfig(ds);

	WideServerSuppressAutoReconnect(ds->Wide, false);

	FreeX(cert);
	FreeK(key);

	WideServerGetHash(ds->Wide, server_hash, sizeof(server_hash));

	// ポリシー規制クライアント開始
	ds->PolicyClient = DsNewPolicyClient(server_hash);

	DsLog(ds, "DSL_START4");

	return ds;
#else   // OS_WIN32
	return NULL;
#endif  // OS_WIN32
}

// PowerKeep の設定に変更があった
void DsUpdatePowerKeepSetting(DS *ds)
{
#ifdef	OS_WIN32
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	Lock(ds->PowerKeepLock);
	{
		if (ds->PowerKeepHandle != NULL)
		{
			MsNoSleepEnd(ds->PowerKeepHandle);
			ds->PowerKeepHandle = NULL;
		}

		if (ds->PowerKeep)
		{
			ds->PowerKeepHandle = MsNoSleepStart(ds->ServiceType == DESK_SERVICE_VNC);
		}
	}
	Unlock(ds->PowerKeepLock);
#endif  // OS_WIN32
}

// 履歴のカウント
UINT DsGetHistoryCount(DS *ds, IP *ip)
{
	UINT i, ret;
	// 引数チェック
	if (ds == NULL || ip == NULL)
	{
		return 0;
	}

	ret = 0;

	DsFlushHistory(ds);

	for (i = 0;i < LIST_NUM(ds->History);i++)
	{
		DS_HISTORY *h = LIST_DATA(ds->History, i);

		if (Cmp(&h->Ip, ip, sizeof(IP)) == 0)
		{
			ret++;
		}
	}

	return ret;
}

// 古い履歴の削除
void DsFlushHistory(DS *ds)
{
	UINT i;
	UINT64 now = Tick64();
	LIST *o;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(ds->History);i++)
	{
		DS_HISTORY *h = LIST_DATA(ds->History, i);

		if (h->Expires <= now)
		{
			Add(o, h);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		DS_HISTORY *h = LIST_DATA(o, i);

		Delete(ds->History, h);

		Free(h);
	}

	ReleaseList(o);
}

// 履歴追加
void DsAddHistory(DS *ds, IP *ip)
{
	DS_HISTORY *h;
	// 引数チェック
	if (ds == NULL || ip == NULL)
	{
		return;
	}

	h = ZeroMalloc(sizeof(DS_HISTORY));

	h->Expires = Tick64() + (UINT64)DS_HISTORY_EXPIRES;
	Copy(&h->Ip, ip, sizeof(IP));

	Add(ds->History, h);

	DsFlushHistory(ds);
}

// 履歴ロック
void DsLockHistory(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	LockList(ds->History);
}

// 履歴ロック解除
void DsUnlockHistory(DS *ds)
{
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	UnlockList(ds->History);
}

// Desktop VPN Server の解放
void FreeDs(DS *ds)
{
#ifdef	OS_WIN32
	UINT i;
	// 引数チェック
	if (ds == NULL)
	{
		return;
	}

	DsLog(ds, "DSL_END1");

	// RPC の停止
	StopAllListener(ds->Cedar);
	StopListener(ds->RpcListener);
	ReleaseListener(ds->RpcListener);

	FreeSockThreadList(ds->SockThreadList);

	// 設定解放
	DsFreeConfig(ds);

	WideServerStop(ds->Wide);

	ReleaseCedar(ds->Cedar);

	if (ds->PowerKeepHandle != NULL)
	{
		MsNoSleepEnd(ds->PowerKeepHandle);
		ds->PowerKeepHandle = NULL;
	}
	DeleteLock(ds->PowerKeepLock);

	DeskFreeUrdpServer(ds->UrdpServer);

	DsLog(ds, "DSL_END2");
	DsLog(ds, "DSL_LINE");

	ReleaseList(ds->ClientList);

	SiReleaseServer(ds->Server);
	ds->Server = NULL;

	MsFreeEventLog(ds->EventLog);

	FreeLog(ds->Log);

	for (i = 0;i < LIST_NUM(ds->History);i++)
	{
		DS_HISTORY *h = LIST_DATA(ds->History, i);

		Free(h);
	}

	ReleaseList(ds->History);

	DsFreeRadiusCacheList(ds);

	if (ds->IsLocked != NULL)
	{
		MsFreeIsLocked(ds->IsLocked);
	}

	DsFreePolicyClient(ds->PolicyClient);

	Free(ds);

	FreeWinUi();
#endif  // OS_WIN32
}

// 証明書の読み込み
bool DsReadSecureCertAndKey(X **cert, K **key)
{
	PACK *p;
	bool ret = false;
	// 引数チェック
	if (cert == NULL || key == NULL)
	{
		return false;
	}

	p = WideReadSecurePack(DESK_SECURE_PACK_NAME);
	if (p == NULL)
	{
		return false;
	}

	*cert = PackGetX(p, "Cert");
	*key = PackGetK(p, "Key");

	if (*cert != NULL && *key != NULL)
	{
		ret = true;
	}
	else
	{
		FreeX(*cert);
		FreeK(*key);
	}

	FreePack(p);

	return ret;
}

// 証明書の書き込み
void DsWriteSecureCertAndKey(X *cert, K *key)
{
	PACK *p;

	// 引数チェック
	if (cert == NULL || key == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddX(p, "Cert", cert);
	PackAddK(p, "Key", key);
	WideWriteSecurePack(DESK_SECURE_PACK_NAME, p);
	FreePack(p);
}

