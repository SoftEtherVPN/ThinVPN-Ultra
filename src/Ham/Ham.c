// PacketiX VPN SourceCode
// Hamster Test Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// Ham.c
// Hamster テストプログラム



//#define	VISTA_HAM



#define	HAM_C

#ifdef	WIN32
#define	HAM_WIN32
#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <DbgHelp.h>
#include <Iphlpapi.h>
#include <wtsapi32.h>
#include "../pencore/resource.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <locale.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include <Cedar/Wt.h>
#include <Cedar/Desk.h>
#include "Ham.h"
#include "Scan.h"
#include "Mon.h"



void rdp_test_main(SOCKIO *sio, SOCK *s)
{
	SOCK_EVENT *e;
	FIFO *f1, *f2;
	void *buf;
	UINT buf_size;
	UINT64 disconnect_tick = 0;

	buf_size = 32767;

	buf = Malloc(buf_size);

	e = SockIoGetSockIoEvent(sio);
	JoinSockToSockEvent(s, e);

	f1 = NewFifo();
	f2 = NewFifo();

	SetSockEvent(e);

	while (true)
	{
		UINT ret;
		bool b = false;
		bool disconnected = false;

		WaitSockEvent(e, SELECT_TIME);

		do
		{
			b = false;

			// recv from socket
			while (FifoSize(f1) < WT_WINDOW_SIZE)
			{
				ret = Recv(s, buf, MIN(buf_size, WT_WINDOW_SIZE - FifoSize(f1)), false);
				if (ret == 0)
				{
					disconnected = true;
					break;
				}
				else if (ret == INFINITE)
				{
					break;
				}
				else
				{
					WriteFifo(f1, buf, ret);
					//b = true;
				}
			}

			// recv from sockio
			while (FifoSize(f2) < WT_WINDOW_SIZE)
			{
				ret = SockIoRecvAsync(sio, buf, MIN(buf_size, WT_WINDOW_SIZE - FifoSize(f2)));
				if (ret == 0)
				{
					disconnected = true;
					break;
				}
				else if (ret == INFINITE)
				{
					break;
				}
				else
				{
					WriteFifo(f2, buf, ret);
					//b = true;
				}
			}

			// send to socket
			while (FifoSize(f2) != 0)
			{
				UINT size;
				UCHAR *p = (UCHAR *)f2->p + f2->pos;
				size = FifoSize(f2);

				ret = Send(s, p, size, false);
				if (ret == 0)
				{
					disconnected = true;
					break;
				}
				else if (ret == INFINITE)
				{
					break;
				}
				else
				{
					ReadFifo(f2, NULL, ret);
					b = true;
				}
			}

			// send to sockio
			while (FifoSize(f1) != 0)
			{
				UINT size;
				UCHAR *p = (UCHAR *)f1->p + f1->pos;
				size = FifoSize(f1);

				ret = SockIoSendAsync(sio, p, size);
				if (ret == 0)
				{
					disconnected = true;
					break;
				}
				else if (ret == INFINITE)
				{
					break;
				}
				else
				{
					ReadFifo(f1, NULL, ret);
					b = true;
				}
			}
		}
		while (b);

		if (disconnected)
		{
			if (disconnect_tick == 0)
			{
				disconnect_tick = Tick64();
			}

			if ((disconnect_tick + 1000) <= Tick64())
			{
				Print("Disconnected!!!!!!!!!!!\n");
				break;
			}
		}
	}

	ReleaseSockEvent(e);

	ReleaseFifo(f1);
	ReleaseFifo(f2);

	Free(buf);

	SleepThread(512);
}

void server_accept_test(THREAD *thread, SOCKIO *sock, void *param)
{
	SOCK_EVENT *e;
	UINT cmd = 0;

	Debug("Accepted.\n");

	e = SockIoGetSockIoEvent(sock);

	SockIoRecvAll(sock, &cmd, sizeof(UINT));

	if (cmd == 0)
	{
		// ping
		while (true)
		{
			UINT64 t;

			SockIoRecvAll(sock, &t, sizeof(t));
			if (SockIoSendAll(sock, &t, sizeof(t)) == false)
			{
				break;
			}
		}
	}
	else
	{
		// rdp
		SOCK *s = Connect("localhost", 3389);
		SetSocketSendRecvBufferSize((int)s, WT_SOCKET_WINDOW_SIZE);

		if (s != NULL)
		{
			Debug("connect to localhost OK!\n");
			rdp_test_main(sock, s);

			Disconnect(s);
			ReleaseSock(s);
		}
	}

	Debug("Accept End.\n");

	ReleaseSockEvent(e);
}

// Server
void t(UINT num, char **arg)
{
	WT *wt = NewWtFromHamcore();
	TSESSION *s;
	WT_CONNECT c;
	char *dst = "localhost";

	if (num >= 1)
	{
		dst = arg[0];
	}

	Zero(&c, sizeof(c));
	StrCpy(c.HostName, sizeof(c.HostName), dst);
	c.Port = 443;
	c.UseCompress = false;

	c.GateConnectParam = ZeroMalloc(sizeof(WT_GATE_CONNECT_PARAM));
	c.GateConnectParam->Cert = FileToX("S:\\WT\\Cert\\widecontrol.widetunnel.net.cer");
	if (c.GateConnectParam->Cert == NULL)
	{
		c.GateConnectParam->Cert = FileToX("@widecontrol.widetunnel.net.cer");
	}
	c.GateConnectParam->Expires = SystemTime64() + 100000;
	StrCpy(c.GateConnectParam->Msid, sizeof(c.GateConnectParam->Msid), "TEST");

	s = WtsStart(wt, &c, server_accept_test, NULL);

	GetLine(NULL, 0);

	WtsStop(s);
	WtReleaseSession(s);

	ReleaseWt(wt);

	WtFreeConnect(&c);
}

typedef struct C_PARAM
{
	WT *wt;
	WT_CONNECT *c;
	SOCK *s;
} C_PARAM;

void c_thread(THREAD *thread, void *param)
{
	C_PARAM *cp = param;
	UINT cmd = 1;
	UINT code = 0;
	SOCKIO *sockio;

	Print("Connecting to Gate ....\n");
	code = WtcConnect(cp->wt, cp->c, &sockio);

	if (code != ERR_NO_ERROR)
	{
		Print("Connect to Gate Failed !!\n");
	}
	else
	{
		Print("Connection Established.\n");

		SockIoSendAll(sockio, &cmd, sizeof(UINT));

		rdp_test_main(sockio, cp->s);

		SockIoDisconnect(sockio);
		ReleaseSockIo(sockio);
	}

	Print("Disconnecting...\n");

	Disconnect(cp->s);
	ReleaseSock(cp->s);
	ReleaseWt(cp->wt);

	Free(cp);

	Print("Disconnected.\n");
}

void c_handle_selfkill(THREAD *t, void *p)
{
#ifdef	OS_WIN32
	HANDLE h = (HANDLE)p;

	WaitForSingleObject(h, INFINITE);
	_exit(0);
#endif  // OS_WIN32
}

// Client
void c(UINT num, char **arg)
{
#ifdef	OS_WIN32
	WT *wt = NewWtFromHamcore();
	UINT code;
	WT_CONNECT c;
	SOCKIO *sockio;
	char *dst = "ts.softether.co.jp";

	if (num >= 1)
	{
		dst = arg[0];
	}

	WtcStart(wt);

	Zero(&c, sizeof(c));
	StrCpy(c.HostName, sizeof(c.HostName), dst);
	c.Port = 443;
	c.UseCompress = false;

	if (num >= 2)
	{
		code = WtcConnect(wt, &c, &sockio);

		if (code == ERR_NO_ERROR)
		{
			Print("WtcConnect Ok.\n");

			if (num >= 2)
			{
				UINT cmd = 0;
				SockIoSendAll(sockio, &cmd, sizeof(UINT));

				while (true)
				{
					UINT64 now = Tick64();
					UINT64 a;

					SockIoSendAll(sockio, &now, sizeof(UINT64));
					if (SockIoRecvAll(sockio, &a, sizeof(UINT64)) == false)
					{
						Debug("Disconnected!!\n");
						break;
					}
					else
					{
						Print("Ping: %u\n", (UINT)(Tick64() - a));
					}

					SleepThread(1000);
				}
			}
			else
			{
				SOCK *l = ListenEx(3333, true);

				UINT cmd = 1;
				SockIoSendAll(sockio, &cmd, sizeof(UINT));

				if (l == NULL)
				{
					Print("Listen 3333 Failed !!\n");
				}
				else
				{
					SOCK *a = Accept(l);

					if (a != NULL)
					{
						Debug("A: Tunnel Start Ok!\n");
						rdp_test_main(sockio, a);
						Debug("A: Tunnel End!!!!\n");

						Disconnect(a);
						ReleaseSock(a);
					}
					else
					{
						Print("Accept Failed !!\n");
					}

					Disconnect(l);
					ReleaseSock(l);
				}
			}

			ReleaseSockIo(sockio);
		}
		else
		{
			Print("WtcConnect Failed !!!\n");
		}
	}
	else
	{
		SOCK *l = ListenEx(3333, true);
		if (l == NULL)
		{
			Print("Listen 3333 Failed !!\n");
		}
		else
		{
			HANDLE h = NULL;

			Print("Ready.\n");

			if (1)
			{
				char exe[MAX_PATH];

				ConbinePath(exe, sizeof(exe), MsGetSystem32Dir(), "mstsc.exe");

				if ((h = (HANDLE)Win32RunEx(exe, "/v:127.0.0.1:3333", false)) == NULL)
				{
					Print("Starting %s Failed.\n", exe);
				}
				else
				{
					NewThread(c_handle_selfkill, (void *)h);
				}
			}

			while (true)
			{
				SOCK *a = Accept(l);

				if (a == NULL)
				{
					break;
				}
				else
				{
					C_PARAM *param = ZeroMalloc(sizeof(C_PARAM));
					THREAD *t;

					Print("Start New Thread...\n");

					param->c = &c;
					param->s = a;
					param->wt = wt;
					AddRef(wt->Ref);
					t = NewThread(c_thread, param);
					WaitThread(t,INFINITE);
					ReleaseThread(t);
				}
			}

			Disconnect(l);
			ReleaseSock(l);
		}
	}

	WtcStop(wt);

	ReleaseWt(wt);
#endif  // OS_WIN32
}


// Gate
void g(UINT num, char **arg)
{
	WT *wt = NewWtFromHamcore();
	X *x;
	K *k;

	x = FileToX("S:\\WT\\Cert\\widegate1.widetunnel.net.cer");
	k = FileToK("S:\\WT\\Cert\\widegate1.widetunnel.net.key", true, NULL);
	if (x == NULL || k == NULL)
	{
		x = FileToX("@widegate1.widetunnel.net.cer");
		k = FileToK("@widegate1.widetunnel.net.key", true, NULL);
	}

	WtgStart(wt, x, k, 443);

	GetLine(NULL, 0);

	WtgStop(wt);

	ReleaseWt(wt);
	FreeX(x);
	FreeK(k);
}

void sockio_thread_test(THREAD *t, void *p)
{
	SOCKIO *io = (SOCKIO *)p;
	UINT i;

	for (i = 0;i < 3;i++)
	{
		char tmp[MAX_SIZE];
		UINT size;
		FIFO *f;

		GetDateTimeStr64(tmp, sizeof(tmp), LocalTime64());
		size = Endian32(StrSize(tmp));

		f = SockIoGetRecvFifo(io);
		WriteFifo(f, &size, sizeof(UINT));
		WriteFifo(f, tmp, StrSize(tmp));
		SockIoReleaseFifo(f);

		SockIoSetIoEvent(io);

		SleepThread(128);
	}

	SockIoDisconnect(io);
	ReleaseSockIo(io);
}

void sockio_thread_test_2(THREAD *t, void *p)
{
	SOCKIO *io = (SOCKIO *)p;
	SOCK_EVENT *e;
	UINT total_size = 0;

	e = SockIoGetSentNoticeEvent(io);

	while (true)
	{
		FIFO *f;
		UINT ret;
		UINT size;
		char buf[100];
		if (SockIoIsConnected(io) == false)
		{
			Debug("Disconnected.\n");
			break;
		}

		while (true)
		{
			//SleepThread(Rand32() % 220);
			f = SockIoGetSendFifo(io);

			size = MIN(FifoSize(f), sizeof(buf));
			ret = ReadFifo(f, &buf, size);
			if (ret != 0)
			{
				total_size += size;
				Print("recv: %u\n", total_size);

				SockIoSetIoEvent(io);
			}
			else
			{
				SockIoReleaseFifo(f);
				break;
			}

			SockIoReleaseFifo(f);
		}

		WaitSockEvent(e, INFINITE);
	}

	ReleaseSockEvent(e);
	ReleaseSockIo(io);
}

// sockio test
void sockio_test(UINT num, char **arg)
{
	UINT i;
	UINT total = 0;
	SOCKIO *io = NewSockIo(NULL, NULL);

	AddRef(io->Ref);
	ReleaseThread(NewThread(sockio_thread_test, io));

	while (true)
	{
		UINT size;
		char *buf;

		if (SockIoRecvAll(io, &size, sizeof(UINT)) == false)
		{
			Print("Disconnected.\n");
			break;
		}

		size = Endian32(size);
		buf = ZeroMalloc(size);
		if (SockIoRecvAll(io, buf, size) == false)
		{
			Print("Disconnected.\n");
			Free(buf);
			break;
		}

		Print("%s\n", buf);
		Free(buf);
	}

	ReleaseSockIo(io);

	io = NewSockIo(NULL, NULL);
	SockIoSetMaxSendBufferSize(io, 1);
	AddRef(io->Ref);
	ReleaseThread(NewThread(sockio_thread_test_2, io));

	for (i = 0;i < 10000;i++)
	{
		char c = i % 256;

		if (SockIoSendAll(io, &c, 1) == false)
		{
			Debug("Disconnected.\n");
			break;
		}

		total += 1;

		Print("sent: %u\n", total);
	}

	SockIoDisconnect(io);
	ReleaseSockIo(io);
}

void noderef(UINT num, char **arg)
{
	X *cert = FileToX("S:\\wt\\Cert\\master.cer");
	K *key = FileToK("S:\\wt\\Cert\\master.key", true, NULL);
	PACK *p;
	BUF *b;

	p = NewPack();
	PackAddInt64(p, "TimeStamp", SystemTime64());
	PackAddStr(p, "Entrance", "https://deskvc1.softether.jp/widecontrol/entrance.aspx");
	b = WpcGeneratePacket(p, cert, key);

	SeekBuf(b, b->Size, 0);
	WriteBufInt(b, 0);
	SeekBuf(b, 0, 0);

	Print("%s\n", b->Buf);

	FreeBuf(b);
	FreePack(p);
	FreeX(cert);
	FreeK(key);
}

void clean(UINT num, char **arg)
{
	if (num != 1)
	{
		Print("Usage: clean packname\n");
	}
	else
	{
		WideCleanSecurePack(arg[0]);
		Print("Ok.\n");
	}
}

void test_thread(THREAD *t, void *p)
{
	char tmp[100000];
	UINT i;
	EVENT *e = p;

	for (i = 0;i < sizeof(tmp);i+=1)
	{
		tmp[i] = i;
	}

	for (i = 0;i < 100;i++)
	{
		Malloc(1);
		NewLock();
		NewRef();
	}

	NoticeThreadInit(t);

	Wait(e, INFINITE);
}

#ifdef	OS_WIN32
void unicode_test_for_ms()
{
	Print("--- Win32 Unicode Test ---\n");
	UniPrint(L"MsGetExeDirNameW(): %s\n", MsGetExeDirNameW());
	UniPrint(L"MsGetExeDirName(): %S\n", MsGetExeDirName());
	UniPrint(L"MsGetExeFileNameW(): %s\n", MsGetExeFileNameW());
	UniPrint(L"MsGetExeFileName(): %S\n", MsGetExeFileName());

	UniPrint(L"MsGetLocalAppDataDir(): %S\n", MsGetLocalAppDataDir());
	UniPrint(L"MsGetLocalAppDataDirW(): %s\n", MsGetLocalAppDataDirW());

	UniPrint(L"MsGetCommonAppDataDir(): %S\n", MsGetCommonAppDataDir());
	UniPrint(L"MsGetCommonAppDataDirW(): %s\n", MsGetCommonAppDataDirW());

	UniPrint(L"MsGetWindowsDir(): %S\n", MsGetWindowsDir());
	UniPrint(L"MsGetWindowsDirW(): %s\n", MsGetWindowsDirW());

	UniPrint(L"MsGetSystem32Dir(): %S\n", MsGetSystem32Dir());
	UniPrint(L"MsGetSystem32DirW(): %s\n", MsGetSystem32DirW());

	UniPrint(L"MsGetTempDir(): %S\n", MsGetTempDir());
	UniPrint(L"MsGetTempDirW(): %s\n", MsGetTempDirW());

	UniPrint(L"MsGetWindowsDrive(): %S\n", MsGetWindowsDrive());
	UniPrint(L"MsGetWindowsDriveW(): %s\n", MsGetWindowsDriveW());

	UniPrint(L"MsGetProgramFilesDir(): %S\n", MsGetProgramFilesDir());
	UniPrint(L"MsGetProgramFilesDirW(): %s\n", MsGetProgramFilesDirW());

	UniPrint(L"MsGetCommonStartMenuDir(): %S\n", MsGetCommonStartMenuDir());
	UniPrint(L"MsGetCommonStartMenuDirW(): %s\n", MsGetCommonStartMenuDirW());

	UniPrint(L"MsGetCommonProgramsDir(): %S\n", MsGetCommonProgramsDir());
	UniPrint(L"MsGetCommonProgramsDirW(): %s\n", MsGetCommonProgramsDirW());

	UniPrint(L"MsGetCommonAppDataDir(): %S\n", MsGetCommonAppDataDir());
	UniPrint(L"MsGetCommonAppDataDirW(): %s\n", MsGetCommonAppDataDirW());

	UniPrint(L"MsGetPersonalStartMenuDir(): %S\n", MsGetPersonalStartMenuDir());
	UniPrint(L"MsGetPersonalStartMenuDirW(): %s\n", MsGetPersonalStartMenuDirW());

	UniPrint(L"MsGetPersonalProgramsDir(): %S\n", MsGetPersonalProgramsDir());
	UniPrint(L"MsGetPersonalProgramsDirW(): %s\n", MsGetPersonalProgramsDirW());

	UniPrint(L"MsGetPersonalStartupDir(): %S\n", MsGetPersonalStartupDir());
	UniPrint(L"MsGetPersonalStartupDirW(): %s\n", MsGetPersonalStartupDirW());

	UniPrint(L"MsGetPersonalAppDataDir(): %S\n", MsGetPersonalAppDataDir());
	UniPrint(L"MsGetPersonalAppDataDirW(): %s\n", MsGetPersonalAppDataDirW());

	UniPrint(L"MsGetPersonalDesktopDir(): %S\n", MsGetPersonalDesktopDir());
	UniPrint(L"MsGetPersonalDesktopDirW(): %s\n", MsGetPersonalDesktopDirW());

	UniPrint(L"MsGetMyDocumentsDir(): %S\n", MsGetMyDocumentsDir());
	UniPrint(L"MsGetMyDocumentsDirW(): %s\n", MsGetMyDocumentsDirW());

	UniPrint(L"MsGetMyTempDir(): %S\n", MsGetMyTempDir());
	UniPrint(L"MsGetMyTempDirW(): %s\n", MsGetMyTempDirW());

	UniPrint(L"MsGetUserName(): %S\n", MsGetUserName());
	UniPrint(L"MsGetUserNameW(): %s\n", MsGetUserNameW());

	UniPrint(L"MsGetUserNameEx(): %S\n", MsGetUserNameEx());
	UniPrint(L"MsGetUserNameExW(): %s\n", MsGetUserNameExW());

	UniPrint(L"MsGetWinTempDir(): %S\n", MsGetWinTempDir());
	UniPrint(L"MsGetWinTempDirW(): %s\n", MsGetWinTempDirW());

	if (true)
	{
		char *keyname = "SOFTWARE\\A";
		char *valuename = "TEST_VALUE";
		wchar_t *test_data = L"SoftEther: テスト放出: ABC";
		wchar_t *ret;

		MsRegWriteStrW(REG_CURRENT_USER, keyname, valuename, test_data);

		ret = MsRegReadStrW(REG_CURRENT_USER, keyname, valuename);

		UniPrint(L"MsRegReadStrW: %s\n", ret);

		Free(ret);
	}

	if (true)
	{
		LIST *o = MsGetProcessList();

		MsPrintProcessList(o);

		MsFreeProcessList(o);
	}
}
#endif	// OS_WIN32

void unicode_test(UINT num, char **arg)
{
	wchar_t tmpw[MAX_SIZE];
	char tmp[MAX_SIZE];

	Print("--- Common Unicode Test ---\n");

	GetExeDir(tmp, sizeof(tmp));
	GetExeDirW(tmpw, sizeof(tmpw));
	UniPrint(L"GetExeDirW(): %s\n", tmpw);
	UniPrint(L"GetExeDir(): %S\n", tmp);

	GetExeName(tmp, sizeof(tmp));
	GetExeNameW(tmpw, sizeof(tmpw));
	UniPrint(L"GetExeNameW(): %s\n", tmpw);
	UniPrint(L"GetExeName(): %S\n", tmp);

	Print("\n");
#ifdef	OS_WIN32
	unicode_test_for_ms();
#endif	// OS_WIN32
}

static DS *dss = NULL;

// プロセス開始関数
void StartProcess()
{
#ifdef	OS_WIN32
	// サーバーの開始
	InitCedar();

	if (MsIsUserMode())
	{
		DS_INFO info;
		UINT ret;

		// ユーザーモードの場合、すでにポート 9822 が開かれていないかどうか
		// チェックする
		ret = DsGetServiceInfo(&info);

		if (ret == ERR_NO_ERROR)
		{
			// すでに動作している
			if (info.IsUserMode == false)
			{
				MsgBoxEx(NULL, MB_ICONEXCLAMATION,
					_UU("DS_9822_ALREADY_SVC"),
					info.ExeDir);
			}
			else
			{
				MsgBoxEx(NULL, MB_ICONEXCLAMATION,
					_UU("DS_9822_ALREADY_USER"),
					info.ExeDir, info.UserName);
			}
		}
		else if (ret == ERR_DESK_RPC_PROTOCOL_ERROR)
		{
			// 変なソフトが動作している
			MsgBox(NULL, MB_ICONEXCLAMATION, _UU("DS_9822_WARNING"));
		}
	}

	dss = NewDs(MsIsUserMode());
#endif  // OS_WIN32
}

// プロセス終了関数
void StopProcess()
{
	FreeDs(dss);
	dss = NULL;

	// サーバーの停止
	FreeCedar();
}


void test(UINT num, char **arg)
{
}

void cc(UINT num, char **arg)
{
	WIDE *w = WideClientStart("DESK", _GETLANG());
	char *pcid = "pc6";
	UINT ret;
	SOCKIO *s;

	if (num >= 1)
	{
		pcid = arg[0];
	}

	ret = WideClientConnect(w, pcid, 0, 0, &s);

	if (ret == ERR_NO_ERROR)
	{
		while (true)
		{
			UCHAR tmp[MAX_PATH];

			if (SockIoRecvAll(s, tmp, sizeof(tmp)) == false)
			{
				break;
			}

			Print("Recv: %s\n", tmp);
		}

		SockIoDisconnect(s);
		ReleaseSockIo(s);
	}

	WideClientStop(w);
}

void ss(UINT num, char **arg)
{
	WIDE *w = WideServerStart("DESK", server_accept_test, NULL, _GETLANG());
	X *x = FileToX("@user.cer");
	K *k = FileToK("@user.key", true, NULL);

	WideServerSetCertAndKey(w, x, k);

	if (0)
	{
		// 候補取得
		char cand[MAX_PATH];
		UINT ret = WideServerGetPcidCandidate(w, cand, sizeof(cand), NULL);

		if (ret != 0)
		{
			Print("WideServerGetPcidCandidate: %S\n", _E(ret));
		}
		else
		{
			Print("Candidate: %s\n", cand);
		}
	}

	if (0)
	{
		// 登録
		UINT ret = WideServerRegistMachine(w, "pc6", x, k);

		Print("WideServerRegistMachine: %S\n", _E(ret));
	}

	if (0)
	{
		// ログインしてみる
		WIDE_LOGIN_INFO info;
		UINT ret = WideServerGetLoginInfo(w, &info);
		if (ret != 0)
		{
			Print("WideServerGetLoginInfo: %S\n", _E(ret));
		}
		else
		{
			Print("Ok.\n");
		}
	}

	GetLine(NULL, 0);

	WideServerStop(w);

	FreeX(x);
	FreeK(k);
}

void gg(UINT num, char **arg)
{
	WIDE *w = WideGateStart();

	GetLine(NULL, 0);

	WideGateStop(w);
}

void ds(UINT num, char **arg)
{
	DS *ds = NewDs(true);

	GetLine(NULL, 0);

	FreeDs(ds);
}

bool dc_password_cb(DC_SESSION *s, char *password, UINT password_max_size)
{
	return false;
}

void dc_event_cb(DC_SESSION *s, UINT event_type, void *event_param)
{
	Print("Event: %u\n", event_type);
}

void dc(UINT num, char **arg)
{
	char *pcid = "d";
	DC *dc = NewDc(false);
	DC_SESSION *s;
	UINT ret;

	if (num >= 1)
	{
		pcid = arg[0];
	}

	if (true)
	{
		DcDownloadMstsc(dc, NULL, NULL);
	}

	NewDcSession(dc, pcid, dc_password_cb, NULL, dc_event_cb,
		NULL, &s);

	ret = DcSessionConnect(s);

	Print("%S\n", _E(ret));

	GetLine(NULL, 0);

	ReleaseDcSession(s);

	FreeDc(dc);
}

void dg(UINT num, char **arg)
{
#ifdef	OS_WIN32
	DGExec();
#endif  // OS_WIN32
}

void du(UINT num, char **arg)
{
#ifdef	OS_WIN32
	DUExec();
#endif  // OS_WIN32
}

void di(UINT num, char **arg)
{
#ifdef	OS_WIN32
	DIExec(false);
#endif  // OS_WIN32
}

void diu(UINT num, char **arg)
{
#ifdef	OS_WIN32
	//	DiDebugWithCommandLine("/UNINSTALL:1 /PRODUCT:1 /USERMODE:0 /PATH:\"C:\\Program Files\\Desktop VPN Server\"");
	DIExec(false);
#endif  // OS_WIN32
}

void rsa_test(UINT num, char **arg)
{
	UINT n = 1000;
	UINT i;
	UINT64 start;
	UINT64 span;
	K *priv, *pub;
	UCHAR src[128];
	UCHAR dst[128];
	UCHAR src2[128];
	if (num >= 1)
	{
		n = ToInt(arg[0]);
	}

	RsaGen(&priv, &pub, 1024);
	Rand(src, sizeof(src));

	Print("count: %u  start.\n", n);

	start = Tick64();

	for (i = 0;i < n;i++)
	{
		RsaPublicEncrypt(dst, src, 128, pub);
		RsaPrivateDecrypt(src2, dst, 128, priv);

		if (Cmp(src, src2, 128) != 0)
		{
			Print("Error.\n");
		}
	}

	span = Tick64() - start;

	Print("Time: %u msec.\n", span);
	Print("%.2f / 1 sec.\n", (double)n * 1000.0f / (double)span);

	FreeK(priv);
	FreeK(pub);
}

void download_test(UINT num, char **arg)
{
#ifdef	OS_WIN32
	char *pcid;
	UINT size;
	UINT ret;
	WIDE *wide;
	SOCKIO *sockio;
	if (num == 0)
	{
		Print("Usage: download pcid [size]\n");
		return;
	}

	pcid = arg[0];

	size = 1024 * 1024;
	if (num >= 2)
	{
		size = ToInt(arg[1]);
	}

	Print("Connecting...\n");

	wide = WideClientStart("DESK", _GETLANG());

	ret = WideClientConnect(wide, pcid, 0, 0, &sockio);

	if (ret != ERR_NO_ERROR)
	{
		Print("%S\n", _E(ret));
	}
	else
	{
		PACK *p;
		void *data;
		UINT64 start, end;

		data = Malloc(size);

		p = NewPack();
		PackAddBool(p, "downloadmode", true);
		PackAddInt(p, "download_size", size);

		start = MsGetHiResCounter();
		SockIoSendPack(sockio, p);
		FreePack(p);

		if (SockIoRecvAll(sockio, data, size))
		{
			double span;
			UINT64 bps;
			char tmp[MAX_PATH];

			end = MsGetHiResCounter();

			p = NewPack();
			SockIoSendPack(sockio, p);
			FreePack(p);

			span = MsGetHiResTimeSpan(end - start);

			bps = (UINT64)((double)size * 8.0 / (double)(span));

			ToStr3(tmp, sizeof(tmp), bps);

			Print("%s bps", tmp);
		}
		else
		{
			Print("Disconnected!!\n");
		}

		Free(data);

		SockIoDisconnect(sockio);
	}

	WideClientStop(wide);
#endif  // OS_WIN32
}

void ping_test(UINT num, char **arg)
{
#ifdef	OS_WIN32
	char *pcid;
	UINT count;
	UINT ret;
	WIDE *wide;
	SOCKIO *sockio;
	if (num == 0)
	{
		Print("Usage: ping pcid [num]\n");
		return;
	}

	pcid = arg[0];

	count = 30;
	if (num >= 2)
	{
		count = ToInt(arg[1]);
	}

	Print("Connecting...\n");

	wide = WideClientStart("DESK", _GETLANG());

	ret = WideClientConnect(wide, pcid, 0, 0, &sockio);

	if (ret != ERR_NO_ERROR)
	{
		Print("%S\n", _E(ret));
	}
	else
	{
		UINT i, num;
		double total = 0;
		PACK *p;

		p = NewPack();
		PackAddBool(p, "pingmode", true);

		SockIoSendPack(sockio, p);
		FreePack(p);

		num = 0;

		for (i = 0;i < count;i++)
		{
			UINT64 tick1, tick2, now, diff;
			double diff_double;

			tick1 = MsGetHiResCounter();

			if (SockIoSendAll(sockio, &tick1, sizeof(UINT64)) == false)
			{
				Print("Disconnected.\n");
				break;
			}

			if (SockIoRecvAll(sockio, &tick2, sizeof(UINT64)) == false)
			{
				Print("Disconnected.\n");
				break;
			}

			now = MsGetHiResCounter();

			if (tick1 != tick2)
			{
				Print("Ping Protocol Error !!\n");
				break;
			}

			diff = now - tick2;
			diff_double = MsGetHiResTimeSpan(diff);

			if (count == 1 || i != 0)
			{
				total += diff_double;
				num++;
			}

			Print("Ping %u: %f sec.\n", num, diff_double);

			SleepThread(1000);
		}

		SockIoDisconnect(sockio);

		Print("Aver: %f sec (Count: %u)\n", (double)((double)total / (double)num), num);
	}

	WideClientStop(wide);
#endif  // OS_WIN32
}

void fs_dirr_test(BUF *buf, wchar_t *dirname, UINT depth)
{
	UINT i;
	DIRLIST *dir = EnumDirW(dirname);
	wchar_t *space = UniMakeCharArray(L' ', depth);
	wchar_t tmp[MAX_PATH * 2];

	depth++;

	for (i = 0;i < dir->NumFiles;i++)
	{
		DIRENT *e = dir->File[i];
		wchar_t fullpath[MAX_PATH];

		CombinePathW(fullpath, sizeof(fullpath), dirname, e->FileNameW);

		UniStrCpy(tmp, sizeof(tmp), space);
		UniStrCat(tmp, sizeof(tmp), fullpath);
		if (e->Folder)
		{
			UniStrCat(tmp, sizeof(tmp), L" -->");
		}

		UniStrCat(tmp, sizeof(tmp), L"\r\n");
		WriteBuf(buf, tmp, UniStrLen(tmp) * sizeof(wchar_t));
		UniPrint(L"%s", tmp);

		if (e->Folder)
		{
			fs_dirr_test(buf, fullpath, depth);
		}
		else
		{
			wchar_t filename[MAX_PATH];

			GetFileNameFromFilePathW(filename, sizeof(filename), fullpath);

			if (UniStrCmpi(filename, L"test.txt") == 0)
			{
				BUF *buf = ReadDumpW(fullpath);

				if (buf == NULL)
				{
					Print("******* ERROR\n");
				}
				else
				{
					Print("   %u\n", buf->Size);
					FreeBuf(buf);
				}
			}
		}
	}

	FreeDir(dir);

	Free(space);
}

void fs_test(UINT num, char **arg)
{
	wchar_t current_dir[MAX_PATH];

	GetCurrentDirW(current_dir, sizeof(current_dir));

	while (true)
	{
		wchar_t cmd[MAX_PATH];
		UNI_TOKEN_LIST *t;
		bool ret;

		Print("%S>", current_dir);
		ret = UniGetLine(cmd, sizeof(cmd));

		if (ret == false || UniStrCmpi(cmd, L"exit") == 0)
		{
			break;
		}

		t = UniParseToken(cmd, L" \t");

		if (t->NumTokens == 2)
		{
			wchar_t *t1 = t->Token[0];
			wchar_t *t2 = t->Token[1];

			if (UniStrCmpi(t1, L"cd") == 0)
			{
				CombinePathW(current_dir, sizeof(current_dir), current_dir, t2);
			}
			else if (UniStrCmpi(t1, L"np") == 0)
			{
				wchar_t tmp[MAX_PATH];
				InnerFilePathW(tmp, sizeof(tmp), t2);
				UniPrint(L"NP: %s\n\n", tmp);
			}
			else if (UniStrCmpi(t1, L"dir") == 0)
			{
				wchar_t tmp[MAX_PATH];
				DIRLIST *dir;

				if (UniStrCmpi(t2, L".") == 0)
				{
					UniStrCpy(tmp, sizeof(tmp), current_dir);
				}
				else
				{
					CombinePathW(tmp, sizeof(tmp), current_dir, t2);
				}

				dir = EnumDirW(tmp);
				if (dir == NULL)
				{
					Print("Failed Dir.\n");
				}
				else
				{
					UINT i;

					for (i = 0;i < dir->NumFiles;i++)
					{
						DIRENT *d = dir->File[i];

						UniPrint(L"  %s %u %u\n",
							d->FileNameW,
							d->Folder,
							(UINT)d->FileSize);
					}

					FreeDir(dir);

					Print("\n");
				}
			}
			else if (UniStrCmpi(t1, L"dirr") == 0)
			{
				wchar_t tmp[MAX_PATH];
				BUF *buf = NewBuf();
				char *utf8;
				wchar_t zero = 0;

				if (UniStrCmpi(t2, L".") == 0)
				{
					UniStrCpy(tmp, sizeof(tmp), current_dir);
				}
				else
				{
					CombinePathW(tmp, sizeof(tmp), current_dir, t2);
				}

				fs_dirr_test(buf, tmp, 0);

				WriteBuf(buf, &zero, sizeof(zero));

				utf8 = CopyUniToUtf((wchar_t *)buf->Buf);

				if (utf8 != NULL)
				{
					IO *io;

					io = FileCreateW(L"@dirr_utf8.txt");

					FileWrite(io, utf8, StrLen(utf8));
					//FileWrite(io, buf->Buf, buf->Size);

					FileClose(io);

					io = FileCreateW(L"@dirr_unicode.txt");

					FileWrite(io, buf->Buf, buf->Size);

					FileClose(io);
				}

				Free(utf8);
				FreeBuf(buf);
			}
		}

		UniFreeToken(t);
	}
}

void utftouni_test(UINT num, char **arg)
{
	BUF *b;
	char *utf;
	wchar_t *uni;
	if (num != 2)
	{
		return;
	}

	b = ReadDump(arg[0]);
	if (b == NULL)
	{
		Print("Load Failed.\n");
		return;
	}

	utf = ZeroMalloc(b->Size + 1);
	Copy(utf, b->Buf, b->Size);

	FreeBuf(b);

	uni = CopyUtfToUni(utf);

	Free(utf);

	b = NewBuf();
	WriteBuf(b, uni, UniStrLen(uni) * sizeof(wchar_t));

	Free(uni);

	DumpBuf(b, arg[1]);

	FreeBuf(b);
}

void tcptable_test(UINT num, char **arg)
{
#ifdef	OS_WIN32
	LIST *o;

	o = Win32GetTcpTableListByGetExtendedTcpTable();
	Print("Win32GetTcpTableListByGetExtendedTcpTable\n");
	PrintTcpTableList(o);
	FreeTcpTableList(o);

	o = Win32GetTcpTableListByAllocateAndGetTcpExTableFromStack();
	Print("Win32GetTcpTableListByAllocateAndGetTcpExTableFromStack\n");
	PrintTcpTableList(o);
	FreeTcpTableList(o);

	o = Win32GetTcpTableListByGetTcpTable();
	Print("Win32GetTcpTableListByGetTcpTable\n");
	PrintTcpTableList(o);
	FreeTcpTableList(o);
#endif  // OS_WIN32
}

void unitoutf_test(UINT num, char **arg)
{
	BUF *b;
	wchar_t *uni;
	char *utf;
	if (num != 2)
	{
		return;
	}

	b = ReadDump(arg[0]);
	if (b == NULL)
	{
		Print("Load Failed.\n");
		return;
	}

	uni = ZeroMalloc(b->Size + sizeof(wchar_t));
	Copy(uni, b->Buf, b->Size);

	FreeBuf(b);

	utf = CopyUniToUtf(uni);

	Free(uni);

	b = NewBuf();
	WriteBuf(b, utf, StrLen(utf));

	DumpBuf(b, arg[1]);
	FreeBuf(b);

	Free(utf);
}

void arg_test(UINT num, char **arg)
{
	wchar_t *cmdline = GetCommandLineUniStr();

	AlertW(cmdline, L"arg");

	Free(cmdline);
}

void prompt_test(UINT num, char **arg)
{
	while (true)
	{
		wchar_t *s = Prompt(L"PROMPT>");

		if (s == NULL)
		{
			break;
		}

		UniPrint(L"INPUT: %s\n", s);

		Free(s);
	}
	Print("Abort!\n\n");
}

// テスト関数一覧定義
typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;
	TEST_PROC *proc;
} TEST_LIST;

TEST_LIST test_list[] =
{
	{"test", test},
	{"tcptable", tcptable_test},
	{"noderef", noderef},
	{"s", t},
	{"c", c},
	{"g", g},
	{"ss", ss},
	{"gg", gg},
	{"cc", cc},
	{"ds", ds},
	{"dc", dc},
	{"dg", dg},
	{"du", du},
	{"di", di},
	{"diu", diu},
	{"ping", ping_test},
	{"down", download_test},
	{"clean", clean},
	{"sockio", sockio_test},
	{"rsa", rsa_test},
	{"fs", fs_test},
	{"unitoutf", unitoutf_test},
	{"utftouni", utftouni_test},
	{"arg", arg_test},
	{"prompt", prompt_test},
	{"unicode", unicode_test},
};

// テスト関数
void TestMain(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;

	Print("Hamster Tester\n");
	OSSetHighPriority();

	while (true)
	{
		Print("TEST>");
		if (first && StrLen(cmd) != 0 && g_memcheck == false)
		{
			first = false;
			StrCpy(tmp, sizeof(tmp), cmd);
			exit_now = true;
			Print("%s\n", cmd);
		}
		else
		{
#ifdef	VISTA_HAM
			_exit(0);
#endif
			if (GetLine(tmp, sizeof(tmp)) == false)
			{
				StrCpy(tmp, sizeof(tmp), "q");
			}
		}
		Trim(tmp);
		if (StrLen(tmp) != 0)
		{
			UINT i, num;
			bool b = false;
			TOKEN_LIST *token = ParseCmdLine(tmp);
			char *cmd = token->Token[0];
#ifdef	VISTA_HAM
			if (EndWith(cmd, "vlan") == false)
			{
				_exit(0);
			}
#endif
			if (!StrCmpi(cmd, "exit") || !StrCmpi(cmd, "quit") || !StrCmpi(cmd, "q"))
			{
				FreeToken(token);
				break;
			}
			else
			{
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					if (!StrCmpi(test_list[i].command_str, cmd))
					{
						char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
						UINT j;
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							arg[j] = CopyStr(token->Token[j + 1]);
						}
						test_list[i].proc(token->NumTokens - 1, arg);
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							Free(arg[j]);
						}
						Free(arg);
						b = true;
						Print("\n");
						break;
					}
				}
				if (b == false)
				{
					Print("Invalid Command: %s\n\n", cmd);
				}
			}
			FreeToken(token);

			if (exit_now)
			{
				break;
			}
		}
	}
	Print("Exiting...\n\n");
}

#ifdef	WIN32
// winmain 関数
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	main(0, NULL);
}
#endif

// main 関数
int main(int argc, char *argv[])
{
	bool memchk = false;
	UINT i;
	char cmd[MAX_SIZE];
	char *s;

	InitProcessCallOnce();

	printf("WideTunnel Test Program.\n");
	printf("Copyright (C) 2004-2017 SoftEther Corporation. All Rights Reserved.\n\n");

	cmd[0] = 0;
	if (argc >= 2)
	{
		for (i = 1;i < (UINT)argc;i++)
		{
			s = argv[i];
			if (s[0] == '/')
			{
				if (!StrCmpi(s, "/memcheck"))
				{
					memchk = true;
				}
			}
			else
			{
				StrCpy(cmd, sizeof(cmd), &s[0]);
			}
		}
	}

	InitMayaqua(memchk, true, argc, argv);
	InitCedar();
	TestMain(cmdline);
	FreeCedar();
	FreeMayaqua();

	return 0;
}

