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

#if 0
// ログとり
static void PrintArgs(char *fmt, va_list args)
{
	static TINY_LOG *t = NULL;
	wchar_t *ret;
	wchar_t *fmt_wchar;
	char *tmp;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}

	fmt_wchar = CopyStrToUni(fmt);
	ret = InternalFormatArgs(fmt_wchar, args, true);

	tmp = CopyUniToStr(ret);
	PrintStr(tmp);

	if (t == NULL)
	{
		t = NewTinyLog();
	}

	{
		char *s = CopyStr(tmp);
		TrimCrlf(s);
		WriteTinyLog(t, s);
		Free(s);
	}

	Free(tmp);

	Free(ret);
	Free(fmt_wchar);
}
static void DebugArgs(char *fmt, va_list args)
{
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}

	PrintArgs(fmt, args);
}
static void Debug(char *fmt, ...)
{
	va_list args;
	// 引数チェック
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);

	DebugArgs(fmt, args);

	va_end(args);
}
#endif

// ネットワーク種類検出を終了し、結果を取得する
void DcFreeNwDetect(DC_NWDETECT* t, DC_NWDETECT_RESULT* result)
{
	Zero(result, sizeof(DC_NWDETECT_RESULT));

	if (t == NULL || result == NULL)
	{
		return;
	}

	t->Halt = true;

	WaitThread(t->Thread, INFINITE);

	ReleaseThread(t->Thread);

	result->IsDetectedByUrl = t->IsDetectedByUrl;
	result->IsFinished = t->IsFinished;

	Free(t);
}

// 1 つの URL を用いてネットワーク種類検出を試みる
bool DcNwDetectProcessOneUrl(DC_NWDETECT* t, char* url, char* expect)
{
	bool ret = false;
	URL_DATA url_data = CLEAN;
	BUF* buf = CLEAN;
	if (t == NULL || url == NULL || expect == NULL)
	{
		return false;
	}

	if (ParseUrl(&url_data, url, false, NULL) == false)
	{
		goto L_CLEAN;
	}

	buf = HttpRequestEx5(&url_data, NULL, t->Settings.TimeoutMsecs, t->Settings.TimeoutMsecs,
		NULL, false, NULL, NULL, NULL, NULL, 0, (bool *)&t->Halt, 65536, NULL, NULL, NULL, false, false);

	if (buf == NULL)
	{
		goto L_CLEAN;
	}

	SeekBufToEnd(buf);
	WriteBufChar(buf, 0);

	ret = InStrEx(buf->Buf, expect, false);

L_CLEAN:
	FreeBuf(buf);
	return ret;
}

// ネットワーク種類検出スレッド
void DcNwDetectThread(THREAD* thread, void* param)
{
	DC_NWDETECT* t = CLEAN;
	UINT i, j;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	t = (DC_NWDETECT*)param;

	// 複数回トライする
	for (j = 0;j < MAX(t->Settings.NumTry, 1);j++)
	{
		// 各 URL に対してトライする
		for (i = 0;i < MAX_NWDETECT_URLS;i++)
		{
			if (t->Halt)
			{
				goto L_CLEAN;
			}

			char* url = t->Settings.NwDetectUrls[i];
			char* expect = t->Settings.NwDetectExpectStrs[i];

			if (IsEmptyStr(url) == false)
			{
				// HTTP 取得試行
				if (DcNwDetectProcessOneUrl(t, url, expect))
				{
					// 成功
					t->IsDetectedByUrl = true;
					t->IsFinished = true;
					goto L_CLEAN;
				}
			}
		}
	}

	t->IsFinished = true;

L_CLEAN:
	if (t->Settings.Callback != NULL)
	{
		t->Settings.Callback(t);
	}
}

// ネットワーク種類検出 (パラメータはパッチから自動設定)
DC_NWDETECT* DcNewNwDetectAuto(DC_NWDETECT_SETTINGS* settings)
{
	DC_NWDETECT_SETTINGS s2 = CLEAN;
	if (settings == NULL)
	{
		return NULL;
	}

	Copy(&s2, settings, sizeof(DC_NWDETECT_SETTINGS));

	StrCpy(s2.NwDetectUrls[0], sizeof(s2.NwDetectUrls[0]),
		Vars_ActivePatch_GetStr("ThinTelework_Installer_DetectUrl0"));
	StrCpy(s2.NwDetectExpectStrs[0], sizeof(s2.NwDetectExpectStrs[0]),
		Vars_ActivePatch_GetStr("ThinTelework_Installer_DetectExpect0"));

	StrCpy(s2.NwDetectUrls[1], sizeof(s2.NwDetectUrls[1]),
		Vars_ActivePatch_GetStr("ThinTelework_Installer_DetectUrl1"));
	StrCpy(s2.NwDetectExpectStrs[1], sizeof(s2.NwDetectExpectStrs[1]),
		Vars_ActivePatch_GetStr("ThinTelework_Installer_DetectExpect1"));

	StrCpy(s2.NwDetectUrls[2], sizeof(s2.NwDetectUrls[2]),
		Vars_ActivePatch_GetStr("ThinTelework_Installer_DetectUrl2"));
	StrCpy(s2.NwDetectExpectStrs[2], sizeof(s2.NwDetectExpectStrs[2]),
		Vars_ActivePatch_GetStr("ThinTelework_Installer_DetectExpect2"));

	StrCpy(s2.NwDetectUrls[3], sizeof(s2.NwDetectUrls[3]),
		Vars_ActivePatch_GetStr("ThinTelework_Installer_DetectUrl3"));
	StrCpy(s2.NwDetectExpectStrs[3], sizeof(s2.NwDetectExpectStrs[3]),
		Vars_ActivePatch_GetStr("ThinTelework_Installer_DetectExpect3"));

	return DcNewNwDetect(&s2);
}

// ネットワーク種類検出
DC_NWDETECT* DcNewNwDetect(DC_NWDETECT_SETTINGS *settings)
{
	DC_NWDETECT* t = CLEAN;
	if (settings == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(DC_NWDETECT));

	Copy(&t->Settings, settings, sizeof(DC_NWDETECT_SETTINGS));

	if (t->Settings.TimeoutMsecs == 0)
	{
		t->Settings.TimeoutMsecs = NWDETECT_TIMEOUT;
	}

	if (t->Settings.NumTry == 0)
	{
		t->Settings.NumTry = NWDETECT_DEFAULT_NUMTRY;
	}

	t->Thread = NewThread(DcNwDetectThread, t);

	return t;
}

// mstsc の引数が .rdp ファイルを含んでいるかどうかチェックする
bool DcIsMstscParamsContainsRdpFile(char *cmdline)
{
	// 引数チェック
	if (cmdline == NULL)
	{
		return false;
	}

	if (InStrEx(cmdline, ".rdp", false))
	{
		return true;
	}

	return false;
}

// 接続の実施
void DcBlueConnectIfNotConnected(DC_BLUE *b)
{
	bool comm_connected = false;
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	Debug("start DcBlueConnectIfNotConnected()\n");

	Lock(b->Lock);
	{
		if (SockIoIsConnected(b->sockio) == false)
		{
			Debug("SockIoIsConnected(b->sockio) = false\n");
			SockIoDisconnect(b->sockio);

			b->sockio = NULL;
		}
		else
		{
			Debug("SockIoIsConnected(b->sockio) = true\n");
		}

		if (b->sockio == NULL)
		{
			UINT ret;

			Debug("Bluetooth: Connecting Socket...\n");
			ret = WideClientConnect(b->Wide, b->Session->Pcid, DESK_VERSION, DESK_BUILD, &b->sockio, 0, false);

			if (ret == ERR_NO_ERROR)
			{
				Debug("Bluetooth: Connect OK.\n");
				comm_connected = true;
			}
			else
			{
				Debug("Bluetooth: Connect Failed. Err = %u\n", ret);
			}
		}
	}
	Unlock(b->Lock);

	if (comm_connected)
	{
		PACK *p;

		Debug("comm_connected = true\n");

		SockIoSetTimeout(b->sockio, DS_PROTOCOL_CONNECTING_TIMEOUT);

		p = NewPack();
		PackAddBool(p, "bluetooth_mode", true);
		PackAddData(p, "bluetooth_mode_client_id", b->ClientId, sizeof(b->ClientId));

		SockIoSendPack(b->sockio, p);

		FreePack(p);

		p = SockIoRecvPack(b->sockio);
		if (p == NULL || GetErrorFromPack(p) != ERR_NO_ERROR)
		{
			SockIoDisconnect(b->sockio);

			Lock(b->Lock);
			{
				ReleaseSockIo(b->sockio);
				b->sockio = NULL;
			}
			Unlock(b->Lock);
			Debug("Bluetooth: protocol error.\n");
		}
		else
		{
			Debug("Bluetooth: established.\n");

			SockIoSetTimeout(b->sockio, INFINITE);
		}

		FreePack(p);
	}
	else
	{
		Debug("comm_connected = false\n");
	}

	Debug("end DcBlueConnectIfNotConnected()\n");
}

// Bluetooth スレッド
void DcBlueThread(THREAD *t, void *param)
{
	DC_BLUE *b;
	DC *dc;
	LIST *o;
	// 引数チェック
	if (t == NULL || param == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	b = (DC_BLUE *)param;

	dc = b->Dc;

	while (b->Halt == false)
	{
		SOCKIO *sock;

		DcBlueConnectIfNotConnected(b);

		sock = b->sockio;

		if (sock == NULL)
		{
			Debug("Wait(b->HaltEvent, DC_BLUETOOTH_SOCK_RETRY_INTERVAL);\n");
			Wait(b->HaltEvent, DC_BLUETOOTH_SOCK_RETRY_INTERVAL);
		}
		else
		{
			// 次のファイルを待機
			while (b->Halt == false)
			{
				BUF *buf;
				wchar_t fullpath[MAX_PATH];
				UINT i;

				// 無視リストにあるファイルの削除の試行
				for (i = 0;i < LIST_NUM(o);i++)
				{
					wchar_t *name = LIST_DATA(o, i);

					FileDeleteW(name);
				}

				// 次のファイルを取得
				buf = DcGetNextFileFromDir(dc->BluetoothDir, fullpath, sizeof(fullpath), o);

				if (buf != NULL)
				{
					// 次のファイルを送信する
					wchar_t filename[MAX_PATH];
					UINT size;
					UINT zero;

					Debug("New File: %S\n", fullpath);

					GetFileNameFromFilePathW(filename, sizeof(filename), fullpath);

					size = buf->Size;

					Debug("File Name: %S, File Size: %u\n", filename, size);

					size = Endian32(size);

					// ファイル名の送信
					SockIoSendAdd(sock, filename, sizeof(filename));

					// ファイルサイズの送信
					SockIoSendAdd(sock, &size, sizeof(UINT));

					// ファイルデータの送信
					SockIoSendAdd(sock, buf->Buf, buf->Size);

					SockIoSendNow(sock);

					// 結果の受信
					if (SockIoRecvAll(sock, &zero, sizeof(zero)) == false)
					{
						Debug("SockIoRecvAll = false\n");
						// 送信に失敗したので切断する
						SockIoDisconnect(sock);
						sock = NULL;

						Lock(b->Lock);
						{
							ReleaseSockIo(b->sockio);

							b->sockio = NULL;
						}
						Unlock(b->Lock);

						Wait(b->HaltEvent, DC_BLUETOOTH_FILE_SEND_FAIL_INTERVAL);
					}
					else
					{
						Debug("SockIoRecvAll = true\n");
						// 送信成功。ファイルを削除
						if (FileDeleteW(fullpath) == false)
						{
							Debug("Add(o): %S\n", fullpath);
							Add(o, CopyUniStr(fullpath));
						}
					}

					FreeBuf(buf);
				}
				else
				{
					Wait(b->HaltEvent, DC_BLUETOOTH_POLLING_INTERVAL);
				}

				if (sock == NULL)
				{
					break;
				}
			}
		}
	}

	Lock(b->Lock);
	{
		if (b->sockio != NULL)
		{
			SockIoDisconnect(b->sockio);
			ReleaseSockIo(b->sockio);
			b->sockio = NULL;
		}
	}
	Unlock(b->Lock);

	UniFreeStrList(o);
}

// Bluetooth セッションの停止
void DcStopBlue(DC_BLUE *b)
{
	SOCKIO *sock;
	// 引数チェック
	if (b == NULL)
	{
		return;
	}

	b->Halt = true;
	Set(b->HaltEvent);

	Lock(b->Lock);
	{
		sock = b->sockio;

		if (sock != NULL)
		{
			AddRef(sock->Ref);
		}
	}
	Unlock(b->Lock);

	if (sock != NULL)
	{
		SockIoDisconnect(sock);
		ReleaseSockIo(sock);
	}

	WaitThread(b->Thread, INFINITE);
	ReleaseThread(b->Thread);

	ReleaseEvent(b->HaltEvent);
	DeleteLock(b->Lock);

	Free(b);
}

// Bluetooth セッションの開始
DC_BLUE *DcStartBlue(DC_SESSION *s)
{
	DC *dc;
	DC_BLUE *b;
	// 引数チェック
	if (s == NULL)
	{
		return NULL;
	}

	dc = s->Dc;

	b = ZeroMalloc(sizeof(DC_BLUE));

	Copy(b->ClientId, dc->Wide->ClientId, SHA1_SIZE);
	b->Halt = false;
	b->HaltEvent = NewEvent();
	b->Lock = NewLock();
	b->Session = s;
	b->Wide = dc->Wide;
	b->Dc = dc;

	b->Thread = NewThread(DcBlueThread, b);

	return b;
}

// 候補一覧の消去
void DcEraseCandidate(DC *dc)
{
	// 引数チェック
	if (dc == NULL)
	{
		return;
	}

	FreeCandidateList(dc->Candidate);

	dc->Candidate = NewCandidateList();
}

// WoL トリガー候補一覧の消去
void DcEraseCandidateWoL(DC *dc)
{
	// 引数チェック
	if (dc == NULL)
	{
		return;
	}

	FreeCandidateList(dc->CandidateWoL);

	dc->CandidateWoL = NewCandidateList();
}

// Default.rdp の書き換え (文字列)
bool DcSetMstscRdpFileStr(char *key_name, char *value)
{
#ifdef	OS_WIN32
	wchar_t name[MAX_PATH];
	wchar_t key1[MAX_PATH];
	wchar_t key1_crlf[MAX_PATH];
	wchar_t start_with[MAX_PATH];
	UINT n = 0;
	wchar_t *s;
	bool is_empty;
	bool ret;
	// 引数チェック
	if (key_name == NULL || value == NULL)
	{
		return true;
	}

	UniFormat(start_with, sizeof(start_with), L"%S:s:", key_name);
	UniFormat(key1, sizeof(key1), L"%S:s:%S", key_name, value);
	UniStrCpy(key1_crlf, sizeof(key1_crlf), key1);
	UniStrCat(key1_crlf, sizeof(key1_crlf), L"\r\n");

	ConbinePathW(name, sizeof(name), MsGetMyDocumentsDirW(), L"Default.rdp");

	s = DcReadRdpFile(name, &is_empty);
	if (s == NULL)
	{
		if (is_empty == false)
		{
			return true;
		}

		return DcWriteRdpFile(name, key1_crlf);
	}

	// s に Unicode で文字列が入っているのでこれを加工する
	if (s != NULL)
	{
		BUF *buf = NewBuf();
		UINT i, len;
		wchar_t tmp[2048];
		UINT wp = 0;

		n = 0;

		len = UniStrLen(s);
		for (i = 0;i < len;i++)
		{
			wchar_t c = s[i];

			switch (c)
			{
			case 13:
			case 10:
				if (c == 13)
				{
					i++;
				}

				tmp[wp++] = 0;
				wp = 0;

				if (UniStartWith(tmp, start_with))
				{
					UniStrCpy(tmp, sizeof(tmp), key1);

					n++;
				}

				WriteBuf(buf, tmp, UniStrLen(tmp) * sizeof(wchar_t));
				WriteBuf(buf, L"\r\n", UniStrLen(L"\r\n") * sizeof(wchar_t));

				break;

			default:
				tmp[wp++] = c;
				break;
			}
		}

		if (n != 0)
		{
			Free(s);

			s = ZeroMalloc(buf->Size + sizeof(wchar_t));
			Copy(s, buf->Buf, buf->Size);
		}

		FreeBuf(buf);
	}

	if (n == 0)
	{
		wchar_t *s2;
		UINT s2_size = UniStrSize(s) + 2048;

		// 強制追加
		s2 = ZeroMalloc(s2_size);
		UniStrCpy(s2, s2_size, s);

		if (UniEndWith(s2, L"\r\n") == false && UniStrLen(s2) != 0)
		{
			UniStrCat(s2, s2_size, L"\r\n");
		}
		UniStrCat(s2, s2_size, key1_crlf);

		Free(s);
		s = s2;
	}

	ret = DcWriteRdpFile(name, s);

	Free(s);

	return ret;
#else   // OS_WIN32
	return false;
#endif  // OS_WIN32
}

// Default.rdp の書き換え (整数)
bool DcSetMstscRdpFileInt(char *key_name, UINT value)
{
#ifdef	OS_WIN32
	wchar_t name[MAX_PATH];
	wchar_t key1[MAX_PATH];
	wchar_t key1_crlf[MAX_PATH];
	bool ret;

	UINT n = 0;
	UINT i;
	wchar_t *s;
	bool is_empty;
	// 引数チェック
	if (key_name == NULL || value >= 10)
	{
		return true;
	}

	UniFormat(key1, sizeof(key1), L"%S:i:%u", key_name, value);
	UniStrCpy(key1_crlf, sizeof(key1_crlf), key1);
	UniStrCat(key1_crlf, sizeof(key1_crlf), L"\r\n");

	ConbinePathW(name, sizeof(name), MsGetMyDocumentsDirW(), L"Default.rdp");

	s = DcReadRdpFile(name, &is_empty);
	if (s == NULL)
	{
		if (is_empty == false)
		{
			return true;
		}

		return DcWriteRdpFile(name, key1_crlf);
	}

	for (i = 0;i < 9;i++)
	{
		wchar_t key2[MAX_PATH];

		UniFormat(key2, sizeof(key2), L"%S:i:%u", key_name, i);

		n += UniReplaceStrEx(s, 0, s, key2, key1, false);
	}

	if (n == 0)
	{
		wchar_t *s2;
		UINT s2_size = UniStrSize(s) + 2048;

		// 強制追加
		s2 = ZeroMalloc(s2_size);
		UniStrCpy(s2, s2_size, s);

		if (UniEndWith(s2, L"\r\n") == false && UniStrLen(s2) != 0)
		{
			UniStrCat(s2, s2_size, L"\r\n");
		}
		UniStrCat(s2, s2_size, key1_crlf);

		Free(s);
		s = s2;
	}

	ret = DcWriteRdpFile(name, s);

	Free(s);

	return ret;
#else   // OS_WIN32
	return false;
#endif  // OS_WIN32
}

// Default.rdp の初期化
void DcInitMstscRdpFile()
{
	DcSetMstscRdpFileInt("authentication level:i", 0);
}

// rdp ファイルの書き込み
bool DcWriteRdpFile(wchar_t *name, wchar_t *s)
{
#ifdef	OS_WIN32
	BUF *b;
	UCHAR bom[2];
	bool ret;
	// 引数チェック
	if (name == NULL || s == NULL)
	{
		return false;
	}

	bom[0] = 0xff;
	bom[1] = 0xfe;

	b = NewBuf();
	WriteBuf(b, bom, 2);
	WriteBuf(b, s, UniStrLen(s) * sizeof(wchar_t));

	ret = DumpBufW(b, name);
	MsSetFileToHiddenW(name);
	FreeBuf(b);

	return ret;
#else   // OS_WIN32
	return false;
#endif  // OS_WIN32
}

// rdp ファイルの読み込み
wchar_t *DcReadRdpFile(wchar_t *name, bool *is_empty)
{
	BUF *b;
	UCHAR bom[2];
	static bool dummy = false;
	wchar_t *ret = NULL;
	UINT ret_size;
	// 引数チェック
	if (name == NULL)
	{
		return NULL;
	}
	if (is_empty == NULL)
	{
		is_empty = &dummy;
	}

	*is_empty = false;

	b = ReadDumpW(name);
	if (b == NULL)
	{
		*is_empty = true;
		return NULL;
	}
	if (b->Size < 2)
	{
		*is_empty = true;
		FreeBuf(b);
		return NULL;
	}

	ReadBuf(b, bom, 2);

	if (bom[0] != 0xff || bom[1] != 0xfe)
	{
		FreeBuf(b);
		return NULL;
	}

	ret_size = b->Size - 2;

	ret = ZeroMalloc(ret_size + sizeof(wchar_t));

	ReadBuf(b, ret, ret_size);

	FreeBuf(b);

	return ret;
}

// プロセスの終了まで待機する
bool DcWaitForProcessExit(void *h, UINT timeout, bool watch_gov_fw_exit)
{
	bool ret = false;
#ifdef	OS_WIN32
	// 引数チェック
	if (h == NULL)
	{
		return true;
	}

	if (watch_gov_fw_exit == false)
	{
		// 通常モード
		if (Win32WaitProcess(h, timeout) == false)
		{
			// タイムアウトした場合はプロセスを Kill する
			Win32TerminateProcess(h);
			ret = false;
		}
		else
		{
			ret = true;
		}
	}
	else
	{
		// gov fw が停止したらタイムアウトしたものとみなすモード
		UINT64 now = Tick64();
		UINT64 giveup = now + (UINT64)timeout;
		if (timeout == INFINITE)
		{
			giveup = 0xFFFFFFFFFFFFFFFFULL;
		}

		while (true)
		{
			now = Tick64();

			if (now >= giveup)
			{
				// タイムアウトした
				ret = false;
				break;
			}

			if (Win32WaitProcess(h, 1000))
			{
				// プロセスが終了した
				ret = true;
				break;
			}

			if (IsSingleInstanceExists(DU_GOV_FW2_SINGLE_INSTANCE_NAME, false) == false)
			{
				// gov fw が終了された
				ret = false;
				break;
			}
		}

		if (ret == false)
		{
			// タイムアウトまたは gov fw 終了時はプロセスを kill する
			Win32TerminateProcess(h);
		}
	}

	Win32CloseProcess(h);

#endif  // OS_WIN32
	return ret;
}

// URDP Client を起動する
void *DcRunUrdpClient(char *arg, UINT *process_id, UINT version)
{
#ifdef	OS_WIN32
	wchar_t exe[MAX_PATH];
	wchar_t arg_w[MAX_SIZE];
	// 引数チェック
	if (arg == NULL)
	{
		return NULL;
	}

	StrToUni(arg_w, sizeof(arg_w), arg);

	DeskInitUrdpFiles(NULL, false, false);

	if (version == 2)
	{
		ConbinePathW(exe, sizeof(exe), MsGetMyTempDirW(), L"urdpclient2.exe");
	}
	else
	{
		ConbinePathW(exe, sizeof(exe), MsGetMyTempDirW(), L"urdpclient.exe");
	}

	return Win32RunEx2W(exe, arg_w, false, process_id);
#else   // OS_WIN32
	return NULL;
#endif  // OS_WIN32
}

// mstsc を起動する
void *DcRunMstsc(DC *dc, wchar_t *mstsc_exe, char *arg, char *target, bool disable_share, UINT *process_id, bool *rdp_file_write_failed)
{
#ifdef	OS_WIN32
	wchar_t *arg_w;
	void *ret;
	bool write_failed = false;
	// 引数チェック
	if (rdp_file_write_failed != NULL)
	{
		*rdp_file_write_failed = false;
	}
	if (dc == NULL || mstsc_exe == NULL || arg == NULL || target == NULL)
	{
		return NULL;
	}

	write_failed = !(DcSetMstscRdpFileInt("redirectdrives", (dc->MstscUseShareDisk && (!disable_share)) ? 1 : 0));
	DcSetMstscRdpFileInt("redirectprinters", (dc->MstscUseSharePrinter && (!disable_share)) ? 1 : 0);
	DcSetMstscRdpFileInt("redirectcomports", (dc->MstscUseShareComPort && (!disable_share)) ? 1 : 0);
	DcSetMstscRdpFileInt("redirectclipboard", (dc->MstscUseShareClipboard && (!disable_share)) ? 1 : 0);
	DcSetMstscRdpFileStr("drivestoredirect", (dc->MstscUseShareDisk && (!disable_share)) ? "*" : "");
	if (MsIsWindows10())
	{
		DcSetMstscRdpFileStr("camerastoredirect", dc->MstscUseShareCamera ? "*" : "");
	}
	DcSetMstscRdpFileInt("audiocapturemode", dc->MstscUseShareAudioRec ? 1 : 0);
	DcSetMstscRdpFileInt("audiomode", 0);
	if (disable_share)
	{
		DcSetMstscRdpFileStr("devicestoredirect", "");
	}
	DcInitMstscRdpFile();

	if (rdp_file_write_failed != NULL)
	{
		*rdp_file_write_failed = write_failed;
	}

	if (write_failed && disable_share)
	{
		return NULL;
	}

	arg_w = CopyStrToUni(arg);

	if (MsIs64BitWindows() == false)
	{
		// 32 bit Windows
		ret = Win32RunEx2W(mstsc_exe, arg_w, false, process_id);
	}
	else
	{
		// 64 bit Windows
		ret = Win32RunEx3W(mstsc_exe, arg_w, false, process_id, true);
		if (ret == NULL)
		{
			ret = Win32RunEx3W(mstsc_exe, arg_w, false, process_id, false);
		}
	}

	Free(arg_w);

	return ret;
#else   // OS_WIN32
	return NULL;
#endif  // OS_WIN32
}

// URDP Client に渡す引数の取得
UINT DcGetUrdpClientArguments(DC_SESSION *s, char *arg, UINT arg_size, bool disable_share, UINT version)
{
	// 引数チェック
	if (s == NULL || arg == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	if (version == 2)
	{
		Format(arg, arg_size, "%s::%u", s->Hostname, s->ListenPort);

		if (s->Dc->MstscUseShareClipboard == false || disable_share)
		{
			StrCat(arg, arg_size, " -noclipboard");
		}

		if (disable_share || (s->Dc->MstscUseShareDisk == false))
		{
			StrCat(arg, arg_size, " -nofileshare");
		}
	}
	else
	{
		if (/*disable_share == false && */s->Dc->MstscUseShareClipboard)
		{
			Format(arg, arg_size, "ServerCutText=1 ClientCutText=1 %s:%u", s->Hostname, s->ListenPort);
		}
		else
		{
			Format(arg, arg_size, "ServerCutText=0 ClientCutText=0 %s:%u", s->Hostname, s->ListenPort);
		}
	}

	return ERR_NO_ERROR;
}

// mstsc.exe に渡す引数の取得
UINT DcGetMstscArguments(DC_SESSION *s, wchar_t *mstsc_exe, char *arg, UINT arg_size)
{
#ifdef	OS_WIN32
	UINT ver;
	char tmp[MAX_PATH * 2];
	DC *dc;
	// 引数チェック
	if (s == NULL || mstsc_exe == NULL || arg == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	dc = s->Dc;

	ver = DcGetMstscVersion(mstsc_exe);
	if (ver == 0)
	{
		return ERR_DESK_FILE_IS_NOT_MSTSC;
	}

	Format(tmp, sizeof(tmp), "/v:%s:%u", s->Hostname, s->ListenPort);

	if (IsEmptyStr(dc->MstscParams) == false)
	{
		char tmp2[MAX_PATH * 2];
		StrCat(tmp, sizeof(tmp), " ");
		StrCpy(tmp2, sizeof(tmp2), dc->MstscParams);
		Trim(tmp2);
		StrCat(tmp, sizeof(tmp), tmp2);
	}

	if (ver == DC_MSTSC_VER_VISTA && dc->MstscUsePublicSwitchForVer6)
	{
		StrCat(tmp, sizeof(tmp), " /public");
	}

	if (dc->MstscLocation == DC_MSTSC_SYSTEM32 && MsIsMstscMultiDisplayAvailable() && dc->DisableMultiDisplay == false)
	{
		StrCat(tmp, sizeof(tmp), " /multimon");
	}

	StrCpy(arg, arg_size, tmp);

#endif	// OS_WIN32
	return ERR_NO_ERROR;
}

// 設定の正規化
void DcNormalizeConfig(DC *dc)
{
#ifdef	OS_WIN32
	// 引数チェック
	if (dc == NULL)
	{
		return;
	}

	// mstsc に関する設定の確認
	if (dc->MstscLocation == DC_MSTSC_SYSTEM32)
	{
		if (DcIsMstscInstalledOnSystem32() == false)
		{
			// system32 には mstsc は存在しない
			dc->MstscLocation = DC_MSTSC_DOWNLOAD;
		}
	}
	else if (dc->MstscLocation == DC_MSTSC_USERPATH)
	{
		if (DcGetMstscVersion(dc->MstscUserPath) == 0)
		{
			// ユーザーが指定したパスには mstsc は存在しない
			dc->MstscLocation = DC_MSTSC_DOWNLOAD;
		}
	}
#endif  // OS_WIN32
}

// 現在の設定における mstsc.exe のパスを取得する
bool DcGetMstscPath(DC *dc, wchar_t *name, UINT size, bool *download_required)
{
	static bool dummy = false;
	bool ret = false;
	// 引数チェック
	if (dc == NULL || name == NULL)
	{
		return false;
	}
	if (download_required == NULL)
	{
		download_required = &dummy;
	}

	// 正規化
	DcNormalizeConfig(dc);

	switch (dc->MstscLocation)
	{
	case DC_MSTSC_SYSTEM32:
		// system32
		DcGetMstscPathOnSystem32(name, size);
		break;

	case DC_MSTSC_DOWNLOAD:
		// download
		DcGetDownloadMstscPath(name, size);
		break;

	case DC_MSTSC_USERPATH:
		// userpath
		UniStrCpy(name, size, dc->MstscUserPath);
		break;
	}

	if (dc->MstscLocation == DC_MSTSC_DOWNLOAD)
	{
		ret = true;
		if (DcGetMstscVersion(name) == 0)
		{
			*download_required = true;
		}
		else
		{
			*download_required = false;
		}
	}
	else
	{
		*download_required = false;

		if (DcGetMstscVersion(name) == 0)
		{
			ret = false;
		}
		else
		{
			ret = true;
		}
	}

	return ret;
}

// mstsc ファイル名変換テーブル
typedef struct MSTSC_FILES
{
	wchar_t *CabinetName;
	wchar_t *DiskName;
} MSTSC_FILES;

static MSTSC_FILES mstsc_files[] =
{
	{L"F1059_mstscax.dll", L"mstscax.dll"},
	{L"F1060_mstsc.exe", L"mstsc.exe"},
	{L"F1061_mstsc.chm", L"mstsc.chm"},
};

// mstsc をダウンロードしてパース
UINT DcDownloadMstsc(DC *dc, WPC_RECV_CALLBACK *callback, void *callback_param)
{
#ifdef	OS_WIN32
	UINT ret;
	wchar_t mstsc_src[MAX_PATH];
	wchar_t temp_dir[MAX_PATH];
	wchar_t cabinet1[MAX_PATH];
	wchar_t cabinet2[MAX_PATH];
	wchar_t msi[MAX_PATH];
	wchar_t dest_dir[MAX_PATH];
	UINT i;
	// 引数チェック
	if (dc == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// mstsc_src.exe をダウンロードする
	ret = DcDownloadMstscExe(dc, mstsc_src, sizeof(mstsc_src), temp_dir, sizeof(temp_dir),
		callback, callback_param);
	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	// Cabinet を保存する
	ConbinePathW(cabinet1, sizeof(cabinet1), temp_dir, L"cabinet1.cab");
	ConbinePathW(cabinet2, sizeof(cabinet2), temp_dir, L"cabinet2.cab");
	if (MsExtractCabinetFileFromExeW(mstsc_src, cabinet1) == false)
	{
		return ERR_DESK_MSTSC_INSTALL_FAILED;
	}

	// cabinet1 を展開する
	if (MsExtractCabW(cabinet1, temp_dir) == false)
	{
		return ERR_DESK_MSTSC_INSTALL_FAILED;
	}

	// msi から Cabinet を展開する
	ConbinePathW(msi, sizeof(msi), temp_dir, L"msrdpcli.msi");
	if (IsFileExistsW(msi) == false)
	{
		return ERR_DESK_MSTSC_INSTALL_FAILED;
	}
	if (MsExtractCabFromMsiW(msi, cabinet2) == false)
	{
		return ERR_DESK_MSTSC_INSTALL_FAILED;
	}

	// cabinet2 を展開する
	if (MsExtractCabW(cabinet2, temp_dir) == false)
	{
		return ERR_DESK_MSTSC_INSTALL_FAILED;
	}

	// ファイルの存在を確認する
	for (i = 0;i < sizeof(mstsc_files) / sizeof(mstsc_files[0]);i++)
	{
		MSTSC_FILES *f = &mstsc_files[i];
		wchar_t src_filename[MAX_PATH];

		ConbinePathW(src_filename, sizeof(src_filename),
			temp_dir, f->CabinetName);

		if (IsFileExistsW(src_filename) == false)
		{
			// ファイルが見つからない
			return ERR_DESK_MSTSC_INSTALL_FAILED;
		}
	}

	// インストールする
	DcGetDownloadMstscDir(dest_dir, sizeof(dest_dir));
	for (i = 0;i < sizeof(mstsc_files) / sizeof(mstsc_files[0]);i++)
	{
		MSTSC_FILES *f = &mstsc_files[i];
		wchar_t src_filename[MAX_PATH];
		wchar_t dst_filename[MAX_PATH];

		ConbinePathW(src_filename, sizeof(src_filename),
			temp_dir, f->CabinetName);

		ConbinePathW(dst_filename, sizeof(dst_filename),
			dest_dir, f->DiskName);

		if (FileCopyW(src_filename, dst_filename) == false)
		{
			// コピー失敗
			return ERR_DESK_MSTSC_INSTALL_FAILED;
		}
	}

	return ERR_NO_ERROR;
#else   // OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif  // OS_WIN32
}

// mstsc をダウンロード
UINT DcDownloadMstscExe(DC *dc, wchar_t *name, UINT name_size, wchar_t *tmp_dir_name, UINT tmp_dir_name_size, WPC_RECV_CALLBACK *callback, void *callback_param)
{
#ifdef	OS_WIN32
	char mstsc_url[MAX_SIZE * 3];
	char mstsc_referer_url[MAX_SIZE * 3];
	wchar_t temp_dir[MAX_PATH];
	UINT ret;
	URL_DATA url_data;
	BUF *buf;
	INTERNET_SETTING setting;
	char *url_env_str;
	UCHAR hash[SHA1_SIZE];
	char hash_str[128];

	// 引数チェック
	if (dc == NULL || name == NULL || tmp_dir_name == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	DcGetInternetSetting(dc, &setting);

	ConbinePathW(temp_dir, sizeof(temp_dir), MsGetMyTempDirW(), L"MsTscTemp");
	MakeDirW(temp_dir);

	url_env_str = _SS("DESK_ENVSTR_MSTSC_51_EXE");

	if (setting.ProxyType != PROXY_DIRECT)
	{
		url_env_str = _SS("DESK_ENVSTR_MSTSC_51_PROXY_EXE");
	}

	// 本体の URL を取得
	ret = DcGetEnvStr(dc, url_env_str, mstsc_url, sizeof(mstsc_url));
	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_OBJECT_NOT_FOUND)
		{
			ret = ERR_DESK_MSTSC_DOWNLOAD_FAILED;
		}
		return ret;
	}

	// Referer を取得
	ret = DcGetEnvStr(dc, _SS("DESK_ENVSTR_MSTSC_51_REF"), mstsc_referer_url, sizeof(mstsc_referer_url));
	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_OBJECT_NOT_FOUND)
		{
			ret = ERR_DESK_MSTSC_DOWNLOAD_FAILED;
		}
		return ret;
	}

	// URL の解釈
	if (ParseUrl(&url_data, mstsc_url, false, mstsc_referer_url) == false)
	{
		return ERR_DESK_MSTSC_DOWNLOAD_FAILED;
	}

	// ファイルのダウンロード
	buf = HttpRequestEx4(&url_data, NULL, 0, 0, &ret,
		false, NULL, callback, callback_param, NULL, 0, NULL, 0, NULL, NULL, dc->Wide->wt);

	if (buf != NULL && buf->Size == 0)
	{
		FreeBuf(buf);
		buf = NULL;
		ret = ERR_DESK_MSTSC_DOWNLOAD_FAILED;
	}

	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_OBJECT_NOT_FOUND)
		{
			ret = ERR_DESK_MSTSC_DOWNLOAD_FAILED;
		}
		return ret;
	}

	// ダウンロードしたファイルが破損していないかどうか確認
	HashSha1(hash, buf->Buf, buf->Size);

	BinToStr(hash_str, sizeof(hash_str), hash, SHA1_SIZE);

	if (StrCmpi(hash_str, "8aeaa9932c2ee263b36a32a620be81eca4eb48b8") != 0 && StrCmpi(hash_str, "ac35a498cab1c91b68ce5d08b19e56bdef3169e7") != 0)
	{
		FreeBuf(buf);
		buf = NULL;
		ret = ERR_DESK_MSTSC_DOWNLOAD_FAILED;
		return ret;
	}

	ConbinePathW(name, name_size, temp_dir, L"mstsc_src.exe");
	UniStrCpy(tmp_dir_name, tmp_dir_name_size, temp_dir);
	DumpBufW(buf, name);

	FreeBuf(buf);

	return ERR_NO_ERROR;
#else   // OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif  // OS_WIN32
}

// 環境文字列を取得
UINT DcGetEnvStr(DC *dc, char *name, char *str, UINT str_size)
{
	UINT ret;
	// 引数チェック
	if (dc == NULL || name == NULL || str == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = WideGetEnvStr(dc->Wide, name, str, str_size);

	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	if (IsEmptyStr(str))
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	return ERR_NO_ERROR;
}

// 現在の設定における mstsc のバージョンを取得
UINT DcGetCurrentMstscVersion(DC *dc)
{
#ifdef	OS_WIN32
	if (MsIs64BitWindows() == false)
	{
		// 32bit
		return DcGetCurrentMstscVersionInner(dc);
	}
	else
	{
		// 64bit
		void *p;
		UINT ret;
		p = MsDisableWow64FileSystemRedirection();
		ret = DcGetCurrentMstscVersionInner(dc);
		MsRestoreWow64FileSystemRedirection(p);
		if (ret != 0)
		{
			return ret;
		}
		return DcGetCurrentMstscVersionInner(dc);
	}
#else   // OS_WIN32
	return 0;
#endif  // OS_WIN32
}
UINT DcGetCurrentMstscVersionInner(DC *dc)
{
	wchar_t tmp[MAX_PATH];
	bool b = false;
	// 引数チェック
	if (dc == NULL)
	{
		return 0;
	}

	if (DcGetMstscPath(dc, tmp, sizeof(tmp), &b) == false)
	{
		return 0;
	}

	return DcGetMstscVersion(tmp);
}

// mstsc のバージョンを取得
UINT DcGetMstscVersion(wchar_t *name)
{
#ifdef	OS_WIN32
	if (MsIs64BitWindows() == false)
	{
		// 32bit
		return DcGetMstscVersionInner(name);
	}
	else
	{
		// 64bit
		void *p;
		UINT ret;
		p = MsDisableWow64FileSystemRedirection();
		ret = DcGetMstscVersionInner(name);
		MsRestoreWow64FileSystemRedirection(p);
		if (ret != 0)
		{
			return ret;
		}
		return DcGetMstscVersionInner(name);
	}
#else   // OS_WIN32
	return 0;
#endif  // OS_WIN32
}
UINT DcGetMstscVersionInner(wchar_t *name)
{
#ifdef	OS_WIN32
	UINT v1, v2, v3, v4;
	UINT os_type = GetOsInfo()->OsType;
	bool is_nt = OS_IS_WINDOWS_NT(os_type);
	// 引数チェック
	if (name == NULL)
	{
		return 0;
	}

	if (MsGetFileVersionW(name, &v1, &v2, &v3, &v4) == false)
	{
		return 0;
	}

	if (v1 == 5 && v2 >= 1)
	{
		// XP
		if (v2 >= 2 || ((v2 == 1 && v4 >= 2180) || (is_nt == false)))
		{
			return DC_MSTSC_VER_XP;
		}
	}
	else if (v1 >= 6)
	{
		// Vista
		return DC_MSTSC_VER_VISTA;
	}

	// より古いバージョン
	return 0;
#else   // OS_WIN32
	return 0;
#endif  // OS_WIN32
}

// system32 上の mstsc ファイル名を取得
void DcGetMstscPathOnSystem32(wchar_t *name, UINT size)
{
#ifdef	OS_WIN32
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	ConbinePathW(name, size, MsGetSystem32DirW(), L"mstsc.exe");
#endif  // OS_WIN32
}

// system32 ディレクトリに mstsc がインストールされているかどうか確認
bool DcIsMstscInstalledOnSystem32()
{
#ifdef	OS_WIN32
	if (MsIs64BitWindows() == false)
	{
		// 32bit
		return DcIsMstscInstalledOnSystem32Inner();
	}
	else
	{
		// 64bit
		void *p;
		bool b;
		p = MsDisableWow64FileSystemRedirection();
		b = DcIsMstscInstalledOnSystem32Inner();
		MsRestoreWow64FileSystemRedirection(p);
		if (b)
		{
			return true;
		}

		return DcIsMstscInstalledOnSystem32Inner();
	}
#else   // OS_WIN32
	return false;
#endif  // OS_WIN32
}
bool DcIsMstscInstalledOnSystem32Inner()
{
	wchar_t name[MAX_PATH];

	DcGetMstscPathOnSystem32(name, sizeof(name));

	if (IsFileExistsW(name) == false)
	{
		// ファイルが存在しない
		return false;
	}

	// バージョンを取得してみる
	if (DcGetMstscVersion(name) == 0)
	{
		// 不正なバージョンである
		return false;
	}

	return true;
}

// ダウンロードディレクトリに mstsc がインストールされているかどうか確認
bool DcIsMstscInstalledOnDownloadDir()
{
	wchar_t dir[MAX_PATH];
	wchar_t mstsc[MAX_PATH];
	wchar_t mstscax[MAX_PATH];

	DcGetDownloadMstscDir(dir, sizeof(dir));

	ConbinePathW(mstsc, sizeof(mstsc), dir, L"mstsc.exe");
	ConbinePathW(mstscax, sizeof(mstscax), dir, L"mstscax.dll");

	if (DcGetMstscVersion(mstsc) == 0 || DcGetMstscVersion(mstscax) == 0)
	{
		return false;
	}

	return true;
}

// 設定の読み込み
void DcLoadConfig(DC *dc, FOLDER *root)
{
	FOLDER *f;
	BUF *b;
	// 引数チェック
	if (dc == NULL || root == NULL)
	{
		return;
	}

	// mstsc の設定
	dc->MstscLocation = CfgGetInt(root, "MstscLocation");
	CfgGetUniStr(root, "MstscUserPath", dc->MstscUserPath, sizeof(dc->MstscUserPath));
	CfgGetStr(root, "MstscParams", dc->MstscParams, sizeof(dc->MstscParams));
	dc->MstscUsePublicSwitchForVer6 = CfgGetBool(root, "MstscUsePublicSwitchForVer6");
	dc->DontShowFullScreenMessage = CfgGetBool(root, "DontShow_FullScreenMessage");
	dc->DisableMultiDisplay = CfgGetBool(root, "DisableMultiDisplay");
	dc->DisableLimitedFw = CfgGetBool(root, "DisableLimitedFw");

	if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity") == false)
	{
		dc->MstscUseShareClipboard = CfgIsItem(root, "MstscUseShareClipboard") ? CfgGetBool(root, "MstscUseShareClipboard") : true;
		dc->MstscUseShareCamera = CfgGetBool(root, "MstscUseShareCamera");
		dc->MstscUseShareDisk = CfgGetBool(root, "MstscUseShareDisk");
		dc->MstscUseSharePrinter = CfgGetBool(root, "MstscUseSharePrinter");
		dc->MstscUseShareComPort = CfgGetBool(root, "MstscUseShareComPort");
		dc->MstscUseShareAudioRec = CfgGetBool(root, "MstscUseShareAudioRec");
	}
	else
	{
		dc->MstscUseShareClipboard = false;
		dc->MstscUseShareCamera = false;
		dc->MstscUseShareDisk = false;
		dc->MstscUseSharePrinter = false;
		dc->MstscUseShareComPort = false;
		dc->MstscUseShareAudioRec = false;
	}

	if (CfgIsItem(root, "EnableVersion2"))
	{
		dc->EnableVersion2 = CfgGetBool(root, "EnableVersion2");
	}
	else
	{
		dc->EnableVersion2 = true;
	}
	WideSetDontCheckCert(dc->Wide, CfgGetBool(root, "DontCheckCert"));

	// 候補
	dc->Candidate = NULL;

	b = CfgGetBuf(root, "Candidate");
	if (b != NULL)
	{
		dc->Candidate = BufToCandidate(b);
		FreeBuf(b);
	}

	if (dc->Candidate == NULL)
	{
		dc->Candidate = NewCandidateList();
	}

	// WoL 候補
	dc->CandidateWoL = NULL;

	b = CfgGetBuf(root, "CandidateWoL");
	if (b != NULL)
	{
		dc->CandidateWoL = BufToCandidate(b);
		FreeBuf(b);
	}

	if (dc->CandidateWoL == NULL)
	{
		dc->CandidateWoL = NewCandidateList();
	}

	// インターネット設定
	f = CfgGetFolder(root, "ProxySetting");
	if (f != NULL)
	{
		INTERNET_SETTING setting;

		Zero(&setting, sizeof(setting));
		DsLoadInternetSetting(f, &setting);
		DcSetInternetSetting(dc, &setting);
	}

	// 拡張認証データ
	if (dc->AdvAuthList == NULL)
	{
		dc->AdvAuthList = NewList(DcCompareAdvAuth);
	}

	f = CfgGetFolder(root, "AdvancedAuthData");
	if (f != NULL)
	{
		TOKEN_LIST *t;

		t = CfgEnumFolderToTokenList(f);
		if (t != NULL)
		{
			UINT i;

			for (i = 0;i < t->NumTokens;i++)
			{
				char *name = t->Token[i];
				FOLDER *ff;
				DC_ADVAUTH *a;

				ff = CfgGetFolder(f, name);
				if (ff != NULL)
				{
					a = ZeroMalloc(sizeof(DC_ADVAUTH));

					StrCpy(a->Pcid, sizeof(a->Pcid), name);
					a->AuthType = CfgGetInt(ff, "AuthType");
					CfgGetStr(ff, "Username", a->Username, sizeof(a->Username));

					switch (a->AuthType)
					{
					case DESK_AUTH_CERT:
						CfgGetUniStr(ff, "CertPath", a->CertPath, sizeof(a->CertPath));
						break;

					case DESK_AUTH_SMARTCARD:
						a->SecureDeviceId = CfgGetInt(ff, "SecureDeviceId");
						CfgGetStr(ff, "SecureCertName", a->SecureCertName, sizeof(a->SecureCertName));
						CfgGetStr(ff, "SecureKeyName", a->SecureKeyName, sizeof(a->SecureKeyName));
						break;
					}

					if (IsEmptyStr(a->Username) ||
						(a->AuthType == DESK_AUTH_CERT && UniIsEmptyStr(a->CertPath)) ||
						(a->AuthType == DESK_AUTH_SMARTCARD && (a->SecureDeviceId == 0 || IsEmptyStr(a->SecureCertName) || IsEmptyStr(a->SecureKeyName))))
					{
						Free(a);
					}
					else
					{
						if (DcGetAdvAuth(dc, a->Pcid) != NULL)
						{
							Free(a);
						}
						else
						{
							Insert(dc->AdvAuthList, a);
						}
					}
				}
			}
			FreeToken(t);
		}
	}
}

// 設定の保存
void DcSaveConfig(DC *dc)
{
	FOLDER *root;
	FOLDER *f;
	BUF *b;
	UINT i;
	// 引数チェック
	if (dc == NULL)
	{
		return;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);

	CfgAddInt(root, "MstscLocation", dc->MstscLocation);
	CfgAddUniStr(root, "MstscUserPath", dc->MstscUserPath);
	CfgAddStr(root, "MstscParams", dc->MstscParams);
	CfgAddBool(root, "MstscUsePublicSwitchForVer6", dc->MstscUsePublicSwitchForVer6);
	CfgAddBool(root, "DontShow_FullScreenMessage", dc->DontShowFullScreenMessage);
	CfgAddBool(root, "DontCheckCert", WideGetDontCheckCert(dc->Wide));
	CfgAddBool(root, "EnableVersion2", dc->EnableVersion2);
	CfgAddBool(root, "DisableMultiDisplay", dc->DisableMultiDisplay);
	CfgAddBool(root, "DisableLimitedFw", dc->DisableLimitedFw);

	if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity") == false)
	{
		CfgAddBool(root, "MstscUseShareClipboard", dc->MstscUseShareClipboard);
		CfgAddBool(root, "MstscUseShareDisk", dc->MstscUseShareDisk);
		CfgAddBool(root, "MstscUseSharePrinter", dc->MstscUseSharePrinter);
		CfgAddBool(root, "MstscUseShareComPort", dc->MstscUseShareComPort);
		CfgAddBool(root, "MstscUseShareAudioRec", dc->MstscUseShareAudioRec);
		CfgAddBool(root, "MstscUseShareCamera", dc->MstscUseShareCamera);
	}

	// Candidate
	b = CandidateToBuf(dc->Candidate);

	CfgAddBuf(root, "Candidate", b);

	FreeBuf(b);

	// Candidate WoL
	b = CandidateToBuf(dc->CandidateWoL);

	CfgAddBuf(root, "CandidateWoL", b);

	FreeBuf(b);

	// インターネット設定
	f = CfgCreateFolder(root, "ProxySetting");
	if (f != NULL)
	{
		INTERNET_SETTING setting;

		DcGetInternetSetting(dc, &setting);
		DsSaveInternetSetting(f, &setting);
	}

	f = CfgCreateFolder(root, "AdvancedAuthData");

	// 拡張認証データ
	for (i = 0;i < LIST_NUM(dc->AdvAuthList);i++)
	{
		FOLDER *ff;
		DC_ADVAUTH *a = LIST_DATA(dc->AdvAuthList, i);

		ff = CfgCreateFolder(f, a->Pcid);

		CfgAddInt(ff, "AuthType", a->AuthType);
		CfgAddStr(ff, "Username", a->Username);

		switch (a->AuthType)
		{
		case DESK_AUTH_CERT:
			CfgAddUniStr(ff, "CertPath", a->CertPath);
			break;

		case DESK_AUTH_SMARTCARD:
			CfgAddInt(ff, "SecureDeviceId", a->SecureDeviceId);
			CfgAddStr(ff, "SecureCertName", a->SecureCertName);
			CfgAddStr(ff, "SecureKeyName", a->SecureKeyName);
			break;
		}
	}

	// 保存
	CfgSaveW(root, dc->ConfigFilename);
	CfgDeleteFolder(root);
}

// DC_ADVAUTH のソート関数
int DcCompareAdvAuth(void *p1, void *p2)
{
	DC_ADVAUTH *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(DC_ADVAUTH **)p1;
	a2 = *(DC_ADVAUTH **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}

	return StrCmpi(a1->Pcid, a2->Pcid);
}

// デフォルト設定にする
void DcInitDefaultConfig(DC *dc)
{
	INTERNET_SETTING setting;
	// 引数チェック
	if (dc == NULL)
	{
		return;
	}

	dc->MstscUseShareClipboard = true;
	dc->MstscUsePublicSwitchForVer6 = true;
	dc->MstscUseShareCamera = true;
	dc->EnableVersion2 = true;

	// システムのインターネット接続設定を取得
	Zero(&setting, sizeof(setting));
	GetSystemInternetSetting(&setting);
	DcSetInternetSetting(dc, &setting);

	dc->Candidate = NewCandidateList();
	dc->CandidateWoL = NewCandidateList();
	dc->AdvAuthList = NewList(DcCompareAdvAuth);

	WideSetDontCheckCert(dc->Wide, false);
}

// 設定の初期化
void DcInitConfig(DC *dc, bool localconfig)
{
	wchar_t data_dir[MAX_PATH];
	FOLDER *root;
	wchar_t config_filename[MAX_PATH];
	// 引数チェック
	if (dc == NULL)
	{
		return;
	}

	// Config ファイル名の決定
	if (localconfig)
	{
		GetExeDirW(data_dir, sizeof(data_dir));
	}
	else
	{
		DeskGetAppDataDir(data_dir, sizeof(data_dir));
	}
	ConbinePathW(config_filename, sizeof(config_filename), data_dir, DC_CONFIG_FILENAME);

	// Config を開く
	root = CfgReadW(config_filename);

	UniStrCpy(dc->ConfigFilename, sizeof(dc->ConfigFilename), config_filename);

#if	0
	if (root == NULL && localconfig)
	{
		// Config ファイル名の決定
		DeskGetAppDataDirOld(data_dir, sizeof(data_dir));
		ConbinePathW(config_filename, sizeof(config_filename), data_dir, DC_CONFIG_FILENAME);

		// Config を開く
		root = CfgReadW(config_filename);

		if (root != NULL)
		{
			UniStrCpy(dc->ConfigFilename, sizeof(dc->ConfigFilename), config_filename);
		}
	}
#endif	// なぞ

	if (root == NULL)
	{
		// 設定の初期化
		DcInitDefaultConfig(dc);
	}
	else
	{
		// 設定の読み込み
		DcLoadConfig(dc, root);

		CfgDeleteFolder(root);
	}

	// 設定の正規化
	DcNormalizeConfig(dc);

	// 設定の保存
	DcSaveConfig(dc);
}

// シン・テレワークシステム クライアントの初期化
DC *NewDc(bool localconfig)
{
	DC *dc;

	dc = ZeroMalloc(sizeof(DC));

	dc->Wide = WideClientStart(DESK_SVC_NAME, _GETLANG());

	//dc->SupportBluetooth = IsFileExists(DC_BLUETOOTH_FLAG_FILENAME);

	// 設定の初期化
	DcInitConfig(dc, localconfig);

	return dc;
}

// シン・テレワークシステム クライアントの解放
void FreeDc(DC *dc)
{
	UINT i;
	// 引数チェック
	if (dc == NULL)
	{
		return;
	}

	WideClientStop(dc->Wide);

	FreeCandidateList(dc->Candidate);

	FreeCandidateList(dc->CandidateWoL);

	for (i = 0;i < LIST_NUM(dc->AdvAuthList);i++)
	{
		DC_ADVAUTH *a = LIST_DATA(dc->AdvAuthList, i);

		Free(a);
	}

	ReleaseList(dc->AdvAuthList);

	Free(dc);
}

// ダウンロードされた mstsc.exe のファイル名を取得
void DcGetDownloadMstscPath(wchar_t *name, UINT name_size)
{
	wchar_t tmp[MAX_PATH];
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	DcGetDownloadMstscDir(tmp, sizeof(tmp));
	ConbinePathW(name, name_size, tmp, L"mstsc.exe");
}

// ダウンロードされた mstsc があるディレクトリ名を取得
void DcGetDownloadMstscDir(wchar_t *name, UINT name_size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MAX_PATH];
	UINT se_lang = _GETLANG();
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	DeskGetAppDataDir(tmp, sizeof(tmp));

	if (se_lang == 0)
	{
		UniStrCpy(tmp2, sizeof(tmp2), L"Downloaded Mstsc Files");
	}
	else
	{
		UniFormat(tmp2, sizeof(tmp2), L"Downloaded Mstsc Files (%u)", se_lang);
	}

	ConbinePathW(name, name_size, tmp, tmp2);
	MakeDirW(name);
}

// セッションの解放
void ReleaseDcSession(DC_SESSION *s)
{
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	if (Release(s->Ref) == 0)
	{
		CleanupDcSession(s);
	}
}

// セッションのクリーンアップ
void CleanupDcSession(DC_SESSION *s)
{
	SOCKIO *sockio;
	// 引数チェック
	if (s == NULL)
	{
		return;
	}

	// Connect スレッドの停止
	s->HaltConnectThread = true;
	Set(s->EventForConnectThread);
	WaitThread(s->ConnectThread, INFINITE);
	ReleaseThread(s->ConnectThread);

	// Listen スレッドの停止
	s->HaltListenThread = true;
	Disconnect(s->Listener);
	Set(s->EventForListenThread);
	WaitThread(s->ListenThread, INFINITE);
	ReleaseThread(s->ListenThread);

	// ソケットスレッドリストの解放
	FreeSockThreadList(s->SockThreadList);

	// キューに残っている SockIo をすべて解放
	while ((sockio = GetNext(s->SockIoQueue)) != NULL)
	{
		SockIoDisconnect(sockio);
		ReleaseSockIo(sockio);
	}
	ReleaseQueue(s->SockIoQueue);

	ReleaseEvent(s->EventForConnectThread);
	ReleaseEvent(s->EventForListenThread);

	ReleaseSock(s->Listener);

	Free(s);
}

// Listen されたソケットを管理するスレッド
void DcListenedSockThread(THREAD *thread, void *param)
{
	DC_LISTENED_SOCK_THREAD_PARAM *p;
	SOCK *sock;
	DC_SESSION *s;
	UINT64 start_tick;
	SOCKIO *io;
	UINT process_id_of_socket_client;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	p = (DC_LISTENED_SOCK_THREAD_PARAM *)param;

	s = p->Session;
	sock = p->Sock;
	Free(p);

	AddSockThread(s->SockThreadList, sock, thread);
	NoticeThreadInit(thread);

	process_id_of_socket_client = GetTcpProcessIdFromSocketReverse(sock);

	// 新しい SockIo が接続されるまでの間待機する
	start_tick = Tick64();

	io = NULL;

	while (true)
	{
		if (Tick64() > (start_tick + (UINT64)DC_TUNNEL_ESTABLISH_TIMEOUT) ||
			s->HaltListenThread)
		{
			// タイムアウトまたはキャンセル
			s->HaltListenThread = true;
			Disconnect(s->Listener);
			break;
		}

		LockQueue(s->SockIoQueue);
		{
			io = NULL;

			if (s->IsShareDisabled && (s->ProcessIdOfClient == 0))
			{
				// 共有機能が禁止されている接続先の場合はクライアントソフトウェア
				// のプロセス ID が取得できない限り処理を続行しない
			}
			else
			{
				if (s->IsShareDisabled &&
					(process_id_of_socket_client != 0 && process_id_of_socket_client != s->ProcessIdOfClient))
				{
					// DC が起動したクライアントソフトウェアのプロセス以外のプロセスが
					// ソケットに接続してきた。おっかしいなあ！
					Debug("Error: Other Process !!\n");

					if (s->ServiceType == DESK_SERVICE_RDP)
					{
						// RDP の場合はダミーデータを最後に流す
						UINT dummy_size = 4096;
						void *data;
						data = ZeroMalloc(dummy_size);
						Send(sock, data, dummy_size, false);
						Free(data);

						SleepThread(50);
					}

					Disconnect(sock);
					UnlockQueue(s->SockIoQueue);

					break;
				}
				else
				{
					io = GetNext(s->SockIoQueue);
				}
			}
		}
		UnlockQueue(s->SockIoQueue);

		if (io != NULL)
		{
			// 新しい SockIo を取得できた
			Set(s->EventForConnectThread);

			if (SockIoIsConnected(io))
			{
				Debug("Allocated New SockIo!\n");
				break;
			}
			else
			{
				SockIoDisconnect(io);
				ReleaseSockIo(io);
				io = NULL;
			}
		}

		// ポーリング
		SleepThread(50);
	}

	if (io != NULL)
	{
		// SockIo を取得したのでリレー処理に移行する
		char c = 'A';
		UINT total_send = 0, total_recv = 0;

		SockIoSendAll(io, &c, 1);

		Debug("Start DeskRelay.\n");
		DeskRelay(io, sock, 500, &total_send, &total_recv);
		Debug("End DeskRelay.\n");

		// SockIo を切断
		SockIoDisconnect(io);
		ReleaseSockIo(io);
	}

	if (s->ServiceType == DESK_SERVICE_RDP)
	{
		// RDP の場合はダミーデータを最後に流す
		UINT dummy_size = 4096;
		void *data;
		data = ZeroMalloc(dummy_size);
		Send(sock, data, dummy_size, false);
		Free(data);

		SleepThread(50);
	}

	Disconnect(sock);
	ReleaseSock(sock);

	DelSockThread(s->SockThreadList, sock);
}

// Listen スレッド
void DcListenThread(THREAD *thread, void *param)
{
	DC_SESSION *s = (DC_SESSION *)param;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		SOCK *a;

		if (s->HaltListenThread)
		{
			break;
		}

		// 新しいコネクションを受け入れる
		a = Accept(s->Listener);

		if (a == NULL || s->HaltConnectThread)
		{
			Disconnect(a);
			ReleaseSock(a);
			break;
		}
		else
		{
			// スレッド作成
			DC_LISTENED_SOCK_THREAD_PARAM *p = ZeroMalloc(sizeof(DC_LISTENED_SOCK_THREAD_PARAM));
			THREAD *t;

			Debug("Accepted!\n");

			p->Session = s;
			p->Sock = a;

			t = NewThread(DcListenedSockThread, p);
			WaitThreadInit(t);
			ReleaseThread(t);
		}
	}

	// Connect スレッドも停止させる
	s->HaltConnectThread = true;
}

// Connect スレッド
void DcConnectThread(THREAD *thread, void *param)
{
	DC_SESSION *s = (DC_SESSION *)param;
	UINT num_retry = 0;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		if (s->HaltConnectThread)
		{
			break;
		}

		// キューの長さが少なくなれば追加コネクションを接続する
		while (true)
		{
			bool b = false;
			SOCKIO *io;
			UINT ret;
			char url[MAX_PATH];
			wchar_t msg[MAX_SIZE];

			if (s->HaltConnectThread)
			{
				break;
			}

			LockQueue(s->SockIoQueue);
			{
				if (s->SockIoQueue->num_item < DC_TUNNEL_QUEUE_SIZE)
				{
					b = true;
				}
			}
			UnlockQueue(s->SockIoQueue);

			if (b == false)
			{
				break;
			}

			// 接続
			ret = DcConnectEx(s->Dc, s, s->Pcid, DcSessionConnectAuthCallback2,
				s, url, sizeof(url), false, &io, false, msg, sizeof(msg),
				DcSessionConnectOtpCallback2, s,
				DcSessionConnectInspectionCallback2, s);

			if (ret == ERR_NO_ERROR)
			{
				// 接続に成功したのでキューに追加
				LockQueue(s->SockIoQueue);
				{
					InsertQueue(s->SockIoQueue, io);
				}
				UnlockQueue(s->SockIoQueue);

				Set(s->EventForListenThread);

				num_retry = 0;
			}
			else
			{
				UINT wait_time = DC_TUNNEL_RECONNECT_RETRY_SPAN;

				// 接続に失敗したので一定時間待ってリトライする
				num_retry++;

				wait_time = MIN(wait_time * num_retry, DC_TUNNEL_RECONNECT_RETRY_SPAN_MAX) * 2;

				if (wait_time == 0) wait_time = 1;
				wait_time = Rand32() % wait_time;

				Debug("Additional tunnel establish failed. Wait for %u msecs...\n", wait_time);

				Wait(s->EventForConnectThread, wait_time);
			}
		}

		if (s->HaltConnectThread)
		{
			break;
		}

		// イベント待機
		Wait(s->EventForConnectThread, INFINITE);
	}
}

// セッション接続
UINT DcSessionConnect(DC_SESSION *s)
{
	SOCKIO *io;
	UINT ret;
	char url[MAX_PATH];
	wchar_t msg[MAX_SIZE];
	// 引数チェック
	if (s == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// 1 個目のセッションを接続
	ret = DcConnectEx(s->Dc, s, s->Pcid, DcSessionConnectAuthCallback1, s,
		url, sizeof(url), true, &io, true, msg, sizeof(msg),
		DcSessionConnectOtpCallback1, s,
		DcSessionConnectInspectionCallback1, s);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		if (ret == ERR_RECV_URL)
		{
			// URL を受信
			s->EventCallback(s, DC_EVENT_URL_RECVED, url);
		}
		else if (ret == ERR_RECV_MSG)
		{
			// メッセージを受信
			s->EventCallback(s, DC_EVENT_MSG_RECVED, msg);
		}
		return ret;
	}

	s->ServiceType = io->UserData1;
	s->DsCaps = io->UserData4;
	s->IsShareDisabled = ((io->UserData3 == 0) ? false : true);
	s->IsLimitedMode = io->UserData5;
	if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
	{
		// 行政システム適応モードであるとみなす
		s->IsLimitedMode = true;
	}
	s->IsEnspectionEnabled = io->UserData6;
	s->IsLimitedFirewallMandated = io->UserData7;
	Debug("DS_CAPS: %u\n", s->DsCaps);

	// この SOCKIO をキューに追加する
	InsertQueue(s->SockIoQueue, io);
	Set(s->EventForListenThread);

	// Connect スレッドの開始
	s->ConnectThread = NewThread(DcConnectThread, s);

	return ERR_NO_ERROR;
}

// 1 回目の検疫コールバック関数
bool DcSessionConnectInspectionCallback1(DC *dc, DC_INSPECT *ins, void *param)
{
	DC_SESSION *s;
	// 引数チェック
	if (dc == NULL || ins == NULL || param == NULL)
	{
		return false;
	}

	s = (DC_SESSION *)param;

	return s->InspectionCallback(dc, ins, s);
}

// 2 回目の検疫コールバック関数
bool DcSessionConnectInspectionCallback2(DC *dc, DC_INSPECT *ins, void *param)
{
	DC_SESSION *s;
	// 引数チェック
	if (dc == NULL || ins == NULL || param == NULL)
	{
		return false;
	}

	s = (DC_SESSION *)param;

	StrCpy(ins->Ticket, sizeof(ins->Ticket), s->InspectionTicket);

	return true;
}

// 1 回目の OTP コールバック関数
bool DcSessionConnectOtpCallback1(DC *dc, char *otp, UINT otp_max_size, void *param)
{
	DC_SESSION *s;
	// 引数チェック
	if (dc == NULL || otp == NULL || param == NULL)
	{
		return false;
	}

	s = (DC_SESSION *)param;

	return s->OtpCallback(dc, otp, otp_max_size, s);
}

// 2 回目の OTP コールバック関数
bool DcSessionConnectOtpCallback2(DC *dc, char *otp, UINT otp_max_size, void *param)
{
	DC_SESSION *s;
	// 引数チェック
	if (dc == NULL || otp == NULL || param == NULL)
	{
		return false;
	}

	s = (DC_SESSION *)param;

	StrCpy(otp, otp_max_size, s->OtpTicket);

	return true;
}

// 1 回目の認証コールバック関数
bool DcSessionConnectAuthCallback1(DC *dc, DC_AUTH *auth, void *param)
{
	DC_SESSION *s;
	char password[MAX_SIZE];
	// 引数チェック
	if (dc == NULL || auth == NULL || param == NULL)
	{
		return false;
	}

	s = (DC_SESSION *)param;

	if (auth->UseAdvancedSecurity == false)
	{
		// 古い認証方法
		switch (auth->AuthType)
		{
		case DESK_AUTH_NONE:
			// 認証無し
			return true;

		case DESK_AUTH_PASSWORD:
			// パスワード認証
			if (s->PasswordCallback(s, password, sizeof(password)) == false)
			{
				return false;
			}

			StrCpy(auth->RetPassword, sizeof(auth->RetPassword), password);

			// パスワードをキャッシュ
			StrCpy(s->CachedPassword, sizeof(s->CachedPassword), password);
			return true;
		}
	}
	else
	{
		// 新しい認証方法
		DC_AUTH a;

		Zero(&a, sizeof(a));

		Copy(a.InRand, auth->InRand, SHA1_SIZE);

		if (s->AdvAuthCallback(s, &a) == false)
		{
			return false;
		}

		a.UseAdvancedSecurity = true;

		Copy(auth, &a, sizeof(DC_AUTH));

		Copy(&s->CachedAuthData, &a, sizeof(DC_AUTH));

		return true;
	}

	// 不明な認証方法
	return false;
}

// 2 回目以降の認証コールバック関数
bool DcSessionConnectAuthCallback2(DC *dc, DC_AUTH *auth, void *param)
{
	DC_SESSION *s;
	UINT auth_type;
	// 引数チェック
	if (dc == NULL || auth == NULL || param == NULL)
	{
		return false;
	}

	s = (DC_SESSION *)param;

	auth_type = auth->AuthType;

	if (auth->UseAdvancedSecurity == false)
	{
		// 古い認証方法
		switch (auth->AuthType)
		{
		case DESK_AUTH_NONE:
			// 認証無し
			return true;

		case DESK_AUTH_PASSWORD:
			// パスワード認証: キャッシュからパスワードを取得して再利用
			StrCpy(auth->RetPassword, sizeof(auth->RetPassword), s->CachedPassword);
			return true;
		}
	}
	else
	{
		// 新しい認証方法 キャッシュを取得
		Copy(auth, &s->CachedAuthData, sizeof(DC_AUTH));

		if (auth->AuthType == DESK_AUTH_SMARTCARD)
		{
			// スマートカード認証の場合は認証済みチケットを渡す
			Copy(auth->SmartCardTicket, s->SmartCardTicket, SHA1_SIZE);
		}

		return true;
	}

	// 不明な認証方法
	return false;
}

// 新しいセッション
UINT NewDcSession(DC *dc, char *pcid, DC_PASSWORD_CALLBACK *password_callback, DC_OTP_CALLBACK *otp_callback, DC_ADVAUTH_CALLBACK *advauth_callback, DC_EVENT_CALLBACK *event_callback, DC_INSPECT_CALLBACK *inspect_callback,
				  void *param, DC_SESSION **session)
{
	DC_SESSION *s;
	SOCK *listener;
	// 引数チェック
	if (dc == NULL || pcid == NULL || password_callback == NULL || event_callback == NULL || session == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// ポートを開く
	listener = DcListen();
	if (listener == NULL)
	{
		return ERR_DESK_LISTENER_OPEN_FAILED;
	}

	// オブジェクトの初期化
	s = ZeroMalloc(sizeof(DC_SESSION));
	s->Ref = NewRef();
	s->Param = param;
	s->Listener = listener;
	s->ListenPort = listener->LocalPort;
	s->PasswordCallback = password_callback;
	s->OtpCallback = otp_callback;
	s->AdvAuthCallback = advauth_callback;
	s->EventCallback = event_callback;
	s->InspectionCallback = inspect_callback;
	DcGetBestHostnameForPcid(s->Hostname, sizeof(s->Hostname), pcid);
	StrCpy(s->Pcid, sizeof(s->Pcid), pcid);
	Trim(s->Pcid);
	s->Dc = dc;
	s->EventForConnectThread = NewEvent();
	s->EventForListenThread = NewEvent();
	s->SockIoQueue = NewQueue();
	s->SockThreadList = NewSockThreadList();

	// Listen スレッドの開始
	s->ListenThread = NewThread(DcListenThread, s);

	*session = s;

	return ERR_NO_ERROR;
}

// 指定した PCID のために最適なホスト名を生成する
void DcGetBestHostnameForPcid(char *hostname, UINT hostname_size, char *pcid)
{
	IP ip;
	bool b = true;
	// 引数チェック
	if (hostname == NULL || pcid == NULL)
	{
		return;
	}

	DcGenerateHostname(hostname, hostname_size, pcid);

	if (GetIP4InnerWithNoCache(&ip, hostname) == false)
	{
		b = false;
	}
	else
	{
		IP local;
		GetIP(&local, "localhost");

		if (Cmp(&local, &ip, sizeof(IP)) != 0)
		{
			b = false;
		}
	}

	if (b)
	{
		return;
	}
	else
	{
		StrCpy(hostname, hostname_size, "127.0.0.1");
	}
}

// 接続先のホスト名の生成
void DcGenerateHostname(char *hostname, UINT hostname_size, char *pcid)
{
	char tmp[MAX_PATH];
	// 引数チェック
	if (hostname == NULL || pcid == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), pcid);
	Trim(tmp);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "_", "-", true);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, " ", "", true);
	if (StartWith(tmp, "-"))
	{
		char tmp2[MAX_PATH];
		StrCpy(tmp2, sizeof(tmp2), "pc");
		StrCat(tmp2, sizeof(tmp2), tmp);
		StrCpy(tmp, sizeof(tmp), tmp2);
	}
	if (EndWith(tmp, "-"))
	{
		StrCat(tmp, sizeof(tmp), "pc");
	}

	if (StrLen(tmp) == 0)
	{
		StrCpy(tmp, sizeof(tmp), "pc");
	}

	StrLower(tmp);

	Format(hostname, hostname_size, DESK_LOCALHOST_DUMMY_FQDN, tmp);
}

// 新しいポートを開いて Listen する
SOCK *DcListen()
{
	UINT port;

	for (port = DC_RDP_PORT_START;port < 10000;port++)
	{
		SOCK *s = ListenEx(port, true);

		if (s != NULL)
		{
			return s;
		}
	}

	return NULL;
}

// localhost 接続許可フラグ (デバッグ用)
static bool dc_allow_localhost = false;
void DcSetDebugFlag(bool allow)
{
	dc_allow_localhost = allow;
}

bool DcGetDebugFlag()
{
	return dc_allow_localhost || WideHasDebugFileWithCorrectKey();
}

// 接続メイン
UINT DcConnectMain(DC *dc, DC_SESSION *dcs, SOCKIO *sock, char *pcid, DC_AUTH_CALLBACK *auth_callback, void *callback_param, bool check_port, bool first_connection, DC_OTP_CALLBACK *otp_callback, DC_SESSION *otp_callback_param, DC_INSPECT_CALLBACK *ins_callback, DC_SESSION *ins_callback_param)
{
#ifdef	OS_WIN32
	PACK *p;
	UINT ret;
	bool b;
	UINT auth_type, svc_type;
	UCHAR rand[SHA1_SIZE];
	UCHAR machine_key[SHA1_SIZE];
	UCHAR my_machine_key[SHA1_SIZE];
	UINT ds_caps = 0;
	bool is_share_disabled = false;
	bool use_advanced_security = false;
	bool is_otp_enabled = false;
	bool run_inspect = false;
	UCHAR smart_card_ticket[SHA1_SIZE];
	UINT64 lifetime = 0;
	wchar_t lifetime_msg[MAX_PATH];
	bool is_server_limited_mode = false;
	wchar_t computer_name[MAX_PATH];
	bool is_limited_firewall_mandated = false;
	// 引数チェック
	if (dc == NULL || sock == NULL || pcid == NULL || auth_callback == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	MsGetComputerNameFullEx(computer_name, sizeof(computer_name), true);

	SockIoSetTimeout(sock, DS_PROTOCOL_CONNECTING_TIMEOUT);

	// MachineKey の取得
	DeskGetMachineKey(my_machine_key);

	// バージョンを送信
	p = NewPack();
	PackAddInt(p, "ClientVer", DESK_VERSION);
	PackAddInt(p, "ClientBuild", DESK_BUILD);
	PackAddBool(p, "CheckPort", check_port);
	PackAddBool(p, "FirstConnection", first_connection);
	PackAddBool(p, "HasURDP2Client", MsIsWinXPOrWinVista() && dc->EnableVersion2);
	PackAddBool(p, "SupportOtp", true);
	PackAddBool(p, "SupportOtpEnforcement", true);
	PackAddBool(p, "SupportInspect", true);
	PackAddBool(p, "SupportServerAllowedMacListErr", true);
	PackAddIp(p, "ClientLocalIP", &sock->ClientLocalIP);
	PackAddUniStr(p, "UserName", MsGetUserNameExW());
	PackAddUniStr(p, "ComputerName", computer_name);
	PackAddBool(p, "SupportWatermark", true);
	b = SockIoSendPack(sock, p);
	FreePack(p);

	if (b == false)
	{
		return ERR_DISCONNECTED;
	}

	// 認証パラメータを受信
	p = SockIoRecvPack(sock);
	if (p == NULL)
	{
		return ERR_DISCONNECTED;
	}
	ret = GetErrorFromPack(p);
	auth_type = PackGetInt(p, "AuthType");
	svc_type = PackGetInt(p, "ServiceType");
	ds_caps = PackGetInt(p, "DsCaps");
	Zero(rand, sizeof(rand));
	PackGetData2(p, "Rand", rand, sizeof(rand));
	Zero(machine_key, sizeof(machine_key));
	PackGetData2(p, "MachineKey", machine_key, sizeof(machine_key));
	is_share_disabled = PackGetBool(p, "IsShareDisabled");
	use_advanced_security = PackGetBool(p, "UseAdvancedSecurity");
	is_otp_enabled = PackGetBool(p, "IsOtpEnabled");
	run_inspect = PackGetBool(p, "RunInspect");
	is_limited_firewall_mandated = PackGetBool(p, "IsLimitedFirewallMandated");

	lifetime = PackGetInt64(p, "Lifetime");
	PackGetUniStr(p, "LifeTimeMsg", lifetime_msg, sizeof(lifetime_msg));

	if (first_connection)
	{
		PackGetUniStr(p, "WatermarkStr1", dcs->WatermarkStr1, sizeof(dcs->WatermarkStr1));
		PackGetUniStr(p, "WatermarkStr2", dcs->WatermarkStr2, sizeof(dcs->WatermarkStr2));
	}

	FreePack(p);
	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		return ret;
	}

	if (is_share_disabled && MsIsWinXPOrWinVista() == false && CanGetTcpProcessId() == false)
	{
		// 接続先が共有機能を禁止している場合は Windows XP 以降が必要
		return ERR_DESK_NEED_WINXP;
	}

	if (is_share_disabled &&
		DcIsMstscParamsContainsRdpFile(dc->MstscParams) &&
		svc_type == DESK_SERVICE_RDP)
	{
		// .rdp ファイルを指定しないでください
		return ERR_DESK_DONT_USE_RDP_FILE;
	}

	// MachineKey の比較
	if (Cmp(machine_key, my_machine_key, SHA1_SIZE) == 0 && DcGetDebugFlag() == false)
	{
		// 同一のマシンである
		return ERR_DESK_LOCALHOST;
	}

	if (is_otp_enabled)
	{
		char otp[MAX_PATH] = {0};

		// OTP が有効なサーバーである。
		// OTP の入力画面を表示する
		if (otp_callback == NULL ||
			otp_callback(dc, otp, sizeof(otp), otp_callback_param) == false)
		{
			// OTP キャンセル
			return ERR_USER_CANCEL;
		}

		// OTP 送信
		p = NewPack();
		PackAddStr(p, "Otp", otp);
		b = SockIoSendPack(sock, p);
		FreePack(p);

		if (b == false)
		{
			return ERR_DISCONNECTED;
		}

		// OTP 結果受信
		p = SockIoRecvPack(sock);
		if (p == NULL)
		{
			return ERR_DISCONNECTED;
		}
		ret = GetErrorFromPack(p);
		if (ret == ERR_NO_ERROR)
		{
			// 認証成功時は OTP チケットを受け取っているので、それを保存
			char otp_ticket[MAX_PATH];

			if (PackGetStr(p, "OtpTicket", otp_ticket, sizeof(otp_ticket)))
			{
				if (IsEmptyStr(otp_ticket) == false)
				{
					if (dcs != NULL)
					{
						StrCpy(dcs->OtpTicket, sizeof(dcs->OtpTicket), otp_ticket);
					}
				}
			}
		}
		FreePack(p);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			return ret;
		}
	}

	if (run_inspect)
	{
		// 検疫を実施する
		DC_INSPECT ins;
		Zero(&ins, sizeof(ins));

		if (ins_callback == NULL || ins_callback(dc, &ins, ins_callback_param) == false)
		{
			// ユーザーキャンセル
			return ERR_USER_CANCEL;
		}

		// 結果送信
		p = NewPack();
		PackAddBool(p, "AntiVirusOk", ins.AntiVirusOk);
		PackAddBool(p, "WindowsUpdateOk", ins.WindowsUpdateOk);
		PackAddStr(p, "MacAddressList", ins.MacAddressList);
		PackAddStr(p, "Ticket", ins.Ticket);

		b = SockIoSendPack(sock, p);
		FreePack(p);

		if (b == false)
		{
			return ERR_DISCONNECTED;
		}
		// 検疫結果受信
		p = SockIoRecvPack(sock);
		if (p == NULL)
		{
			return ERR_DISCONNECTED;
		}
		ret = GetErrorFromPack(p);
		if (ret == ERR_NO_ERROR)
		{
			// 認証成功時はチケットを受け取っているので、それを保存
			char ticket[64];

			if (PackGetStr(p, "InspectionTicket", ticket, sizeof(ticket)))
			{
				if (IsEmptyStr(ticket) == false)
				{
					if (dcs != NULL)
					{
						StrCpy(dcs->InspectionTicket, sizeof(dcs->InspectionTicket), ticket);
					}
				}
			}
		}
		FreePack(p);

		if (ret != ERR_NO_ERROR)
		{
			// エラー発生
			return ret;
		}
	}

	p = NewPack();

	// ユーザー認証
	if (use_advanced_security == false)
	{
		// 古いユーザー認証
		if (auth_type == DESK_AUTH_NONE)
		{
			DC_AUTH a;

			// 匿名認証
			Zero(&a, sizeof(a));
			a.AuthType = DESK_AUTH_NONE;

			if (auth_callback(dc, &a, callback_param) == false)
			{
				FreePack(p);
				return ERR_USER_CANCEL;
			}
		}
		else if (auth_type == DESK_AUTH_PASSWORD)
		{
			DC_AUTH a;
			UCHAR password[SHA1_SIZE];
			UCHAR secure_password[SHA1_SIZE];

			// パスワード認証
			Zero(&a, sizeof(a));
			a.AuthType = DESK_AUTH_PASSWORD;

			if (auth_callback(dc, &a, callback_param) == false)
			{
				FreePack(p);
				return ERR_USER_CANCEL;
			}

			HashSha1(password, a.RetPassword, StrLen(a.RetPassword));
			SecurePassword(secure_password, password, rand);

			PackAddData(p, "SecurePassword", secure_password, sizeof(secure_password));
		}
		else
		{
			// 不明な認証方法
			return ERR_DESK_UNKNOWN_AUTH_TYPE;
		}
	}
	else
	{
		// 高度なユーザー認証
		DC_AUTH a;
		UCHAR sign[4096 / 8];

		Zero(&a, sizeof(a));

		Copy(a.InRand, rand, SHA1_SIZE);

		a.UseAdvancedSecurity = true;

		if (auth_callback(dc, &a, callback_param) == false)
		{
			FreePack(p);
			return ERR_USER_CANCEL;
		}

		switch (a.AuthType)
		{
		case DESK_AUTH_USERPASSWORD:
			// パスワード認証
			FreePack(p);

			p = PackLoginWithPlainPassword(CEDAR_DESKVPN_HUBNAME,
				a.RetUsername,
				a.RetPassword);
			break;

		case DESK_AUTH_CERT:
			// 証明書認証
			FreePack(p);

			p = NULL;

			// 送られてきたデータに署名する
			if (true)
			{
				BUF *x_buf, *k_buf;
				X *x;
				K *k;

				x_buf = NewBuf();
				k_buf = NewBuf();

				WriteBuf(x_buf, a.RetCertData, a.RetCertSize);
				WriteBuf(k_buf, a.RetKeyData, a.RetKeySize);

				x = BufToX(x_buf, false);
				k = BufToK(k_buf, true, false, NULL);

				if (x != NULL && x->is_compatible_bit &&
					x->bits != 0 && (x->bits / 8) <= sizeof(sign))
				{
					if (RsaSignEx(sign, rand, SHA1_SIZE, k, x->bits))
					{
						p = PackLoginWithCert(CEDAR_DESKVPN_HUBNAME,
							a.RetUsername,
							x,
							sign,
							x->bits / 8);
					}
				}

				FreeX(x);
				FreeK(k);

				FreeBuf(x_buf);
				FreeBuf(k_buf);
			}

			if (p == NULL)
			{
				FreePack(p);
				return ERR_PROTOCOL_ERROR;
			}
			break;

		case DESK_AUTH_SMARTCARD:
			// スマートカード認証
			FreePack(p);

			p = NULL;

			// 送られてきたデータにスマートカードで署名した結果を返す
			if (IsZero(a.SmartCardTicket, SHA1_SIZE))
			{
				// 1 回目の認証
				BUF *x_buf;
				X *x;

				x_buf = NewBuf();

				WriteBuf(x_buf, a.RetCertData, a.RetCertSize);

				x = BufToX(x_buf, false);

				if (x != NULL && x->is_compatible_bit &&
					x->bits != 0 && (x->bits / 8) <= sizeof(sign))
				{
					Copy(sign, a.RetSignedData, a.RetSignedDataSize);

					p = PackLoginWithCert(CEDAR_DESKVPN_HUBNAME,
						a.RetUsername,
						x,
						sign,
						x->bits / 8);

					PackAddBool(p, "IsSmartCardAuth", true);
				}

				FreeX(x);

				FreeBuf(x_buf);
			}
			else
			{
				// 2 回目以降はスマートカード認証済みチケットを渡す
				p = NewPack();
				PackAddStr(p, "method", "login");
				PackAddStr(p, "hubname", CEDAR_DESKVPN_HUBNAME);
				PackAddStr(p, "username", a.RetUsername);
				PackAddInt(p, "authtype", CLIENT_AUTHTYPE_SMART_CARD_TICKET);
				PackAddData(p, "SmartCardTicket", a.SmartCardTicket, SHA1_SIZE);
			}

			if (p == NULL)
			{
				FreePack(p);
				return ERR_PROTOCOL_ERROR;
			}
			break;
		}
	}

	b = SockIoSendPack(sock, p);
	FreePack(p);

	if (b == false)
	{
		return ERR_DISCONNECTED;
	}

	// 結果を受信
	p = SockIoRecvPack(sock);
	if (p == NULL)
	{
		return ERR_DISCONNECTED;
	}
	ret = GetErrorFromPack(p);

	if (PackGetData2(p, "SmartCardTicket", smart_card_ticket, SHA1_SIZE))
	{
		// スマートカード認証済みチケットを受信
		Copy(dcs->SmartCardTicket, smart_card_ticket, SHA1_SIZE);
	}

	FreePack(p);

	if (ret != ERR_NO_ERROR)
	{
		// エラー発生
		return ret;
	}

	dcs->LifeTime = lifetime;
	UniStrCpy(dcs->LifeTimeMsg, sizeof(dcs->LifeTimeMsg), lifetime_msg);

	// 接続先サーバーが行政情報システム適応モードか?
	if (sock->ServerMask64 & DS_MASK_IS_LIMITED_MODE)
	{
		is_server_limited_mode = true;
	}

	sock->UserData1 = svc_type;
	sock->UserData3 = is_share_disabled;
	sock->UserData4 = ds_caps;
	sock->UserData5 = is_server_limited_mode;
	sock->UserData6 = run_inspect;
	sock->UserData7 = is_limited_firewall_mandated;

	SockIoSetTimeout(sock, INFINITE);

	return ERR_NO_ERROR;
#else   // OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif  // OS_WIN32
}

// WoL パケットの送信命令
UINT DcTriggerWoL(DC *dc, char *target_pcid, char *trigger_pcid)
{
	SOCKIO *sock = NULL;
	UINT ret = ERR_NO_ERROR;
	char mac_list[1024] = {0};
	if (dc == NULL || target_pcid == NULL || trigger_pcid == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = WideClientGetWoLMacList(dc->Wide, target_pcid, DESK_VERSION, DESK_BUILD, mac_list, sizeof(mac_list));

	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	if (IsEmptyStr(mac_list))
	{
		// ターゲットで WoL 機能が有効化されていない
		ret = ERR_WOL_TARGET_NOT_ENABLED;
	}
	else
	{
		// 指定されたトリガー PC の PCID に接続
		ret = WideClientConnect(dc->Wide, trigger_pcid, DESK_VERSION, DESK_BUILD, &sock, WT_CLIENT_OPTIONS_WOL, true);

		if (ret == ERR_NO_ERROR)
		{
			PACK *p = NULL;
			bool b = false;

			SockIoSetTimeout(sock, DS_PROTOCOL_CONNECTING_TIMEOUT);

			// バージョンを送信
			p = NewPack();
			PackAddInt(p, "ClientVer", DESK_VERSION);
			PackAddInt(p, "ClientBuild", DESK_BUILD);
			PackAddBool(p, "WoLMode", true);
			PackAddStr(p, "mac_list", mac_list);
			b = SockIoSendPack(sock, p);
			FreePack(p);
			if (b == false)
			{
				ret = ERR_DISCONNECTED;
			}
			else
			{
				p = SockIoRecvPack(sock);
				if (p == NULL)
				{
					ret = ERR_DISCONNECTED;
				}
				else
				{
					ret = GetErrorFromPack(p);
					FreePack(p);
				}
			}
		}
	}

	SockIoDisconnect(sock);
	ReleaseSockIo(sock);

	return ret;
}

// 接続
UINT DcConnectEx(DC *dc, DC_SESSION *dcs, char *pcid, DC_AUTH_CALLBACK *auth_callback, void *callback_param, char *ret_url, UINT ret_url_size, bool check_port,
				 SOCKIO **sockio, bool first_connection, wchar_t *ret_msg, UINT ret_msg_size, DC_OTP_CALLBACK *otp_callback, DC_SESSION *otp_callback_param,
				 DC_INSPECT_CALLBACK *ins_callback, DC_SESSION *ins_callback_param)
{
	SOCKIO *sock;
	UINT ret;
	// 引数チェック
	if (dc == NULL || pcid == NULL || auth_callback == NULL || ret_url == NULL || ret_msg == NULL || sockio == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	StrCpy(ret_url, ret_url_size, "");

	// 指定された PCID に接続
	ret = WideClientConnect(dc->Wide, pcid, DESK_VERSION, DESK_BUILD, &sock, 0, false);
	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_RECV_URL)
		{
			// URL を受信
			StrCpy(ret_url, ret_url_size, dc->Wide->RecvUrl);
		}
		else if (ret == ERR_RECV_MSG)
		{
			// メッセージを受信
			UniStrCpy(ret_msg, ret_msg_size, dc->Wide->RecvMsg);
		}
		return ret;
	}

	// 接続メイン
	ret = DcConnectMain(dc, dcs, sock, pcid, auth_callback, callback_param,
		check_port, first_connection, otp_callback, otp_callback_param,
		ins_callback, ins_callback_param);

	if (ret == ERR_NO_ERROR)
	{
		*sockio = sock;
	}
	else
	{
		// 切断
		SockIoDisconnect(sock);
		ReleaseSockIo(sock);
	}

	return ret;
}

// インターネット接続設定の取得
void DcGetInternetSetting(DC *dc, INTERNET_SETTING *setting)
{
	// 引数チェック
	if (dc == NULL || setting == NULL)
	{
		return;
	}

	WideGetInternetSetting(dc->Wide, setting);
}

// インターネット接続設定の設定
void DcSetInternetSetting(DC *dc, INTERNET_SETTING *setting)
{
	// 引数チェック
	if (dc == NULL || setting == NULL)
	{
		return;
	}

	WideSetInternetSetting(dc->Wide, setting);
}

// 拡張認証データの取得
DC_ADVAUTH *DcGetAdvAuth(DC *dc, char *pcid)
{
	DC_ADVAUTH t, *ret;
	// 引数チェック
	if (pcid == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.Pcid, sizeof(t.Pcid), pcid);
	Trim(t.Pcid);

	ret = Search(dc->AdvAuthList, &t);

	return ret;
}

// 拡張認証データの設定
void DcSetAdvAuth(DC *dc, DC_ADVAUTH *advauth)
{
	DC_ADVAUTH *a;
	bool b_new = false;
	// 引数チェック
	if (dc == NULL || advauth == NULL)
	{
		return;
	}

	a = DcGetAdvAuth(dc, advauth->Pcid);
	if (a == NULL)
	{
		a = ZeroMalloc(sizeof(DC_ADVAUTH));

		b_new = true;
	}

	Copy(a, advauth, sizeof(DC_ADVAUTH));

	Trim(a->Pcid);

	if (b_new)
	{
		Insert(dc->AdvAuthList, a);
	}
}

// 拡張認証データリストの消去
void DcClearAdvAuthList(DC *dc)
{
	UINT i;
	// 引数チェック
	if (dc == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(dc->AdvAuthList);i++)
	{
		DC_ADVAUTH *a = LIST_DATA(dc->AdvAuthList, i);

		Free(a);
	}

	DeleteAll(dc->AdvAuthList);
}

// 次のファイルをディレクトリから取得する
BUF *DcGetNextFileFromDir(wchar_t *dirname, wchar_t *filename, UINT filename_size, LIST *ignore_list)
{
	DIRLIST *o;
	UINT i;
	UINT64 min_date;
	wchar_t tmp[MAX_PATH];
	wchar_t fullpath[MAX_PATH];
	BUF *buf;
	// 引数チェック
	if (dirname == NULL)
	{
		return NULL;
	}

	o = EnumDirW(dirname);
	if (o == NULL)
	{
		Debug("EnumDirW Failed.\n");
		return NULL;
	}

	Zero(tmp, sizeof(tmp));

	min_date = 18446744073709551615ULL;

	if (o->NumFiles >= 1)
	{
		Debug("o->NumFiles = %u\n", o->NumFiles);
	}

	for (i = 0;i < o->NumFiles;i++)
	{
		DIRENT *e = o->File[i];

		if (e->Folder == false)
		{
			if (e->FileSize <= (UINT64)DC_BLUETOOTH_MAX_FILESIZE)
			{
				if (e->UpdateDate < min_date)
				{
					wchar_t fullpath[MAX_PATH];
					IO *io;
					bool b = true;

					CombinePathW(fullpath, sizeof(fullpath), dirname, e->FileNameW);

					Debug("File %u: %S\n", i, fullpath);

					if (ignore_list != NULL)
					{
						if (IsInListUniStr(ignore_list, fullpath))
						{
							b = false;
							Debug("IsInListUniStr = true\n");
						}
						else
						{
							Debug("IsInListUniStr = false\n");
						}
					}

					if (b)
					{
						// ファイルが現在書き込み可能かどうか取得する
						Debug("FileOpenW(%S)\n", fullpath);
						io = FileOpenW(fullpath, true);
						if (io != NULL)
						{
							Debug("io != NULL\n");

							FileClose(io);

							min_date = e->UpdateDate;

							UniStrCpy(tmp, sizeof(tmp), e->FileNameW);
						}
						else
						{
							Debug("io = NULL\n");
						}
					}
				}
			}
		}
	}

	FreeDir(o);

	if (UniIsEmptyStr(tmp))
	{
		return NULL;
	}

	CombinePathW(fullpath, sizeof(fullpath), dirname, tmp);
	Debug("fullpath: %S\n", fullpath);

	buf = ReadDumpW(fullpath);
	Debug("ReadDumpW: 0x%x\n", buf);
	if (buf == NULL)
	{
		return NULL;
	}

	UniStrCpy(filename, filename_size, fullpath);

	return buf;
}

