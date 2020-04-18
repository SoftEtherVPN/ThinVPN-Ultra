// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// Desk.c
// PacketiX Desktop VPN Main Source

// Build 5604

#include "CedarPch.h"

// AppData ディレクトリの取得
void DeskGetAppDataDir(wchar_t *name, UINT name_size)
{
#ifdef	OS_WIN32
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	ConbinePathW(name, name_size, MsGetPersonalAppDataDirW(), DESK_SETTINGS_DIR_NAME);
	MakeDirW(name);
#endif  // OS_WIN32
}

// AppData ディレクトリの取得 (古い)
void DeskGetAppDataDirOld(wchar_t *name, UINT name_size)
{
#ifdef	OS_WIN32
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

	ConbinePathW(name, name_size, MsGetPersonalAppDataDirW(), DESK_SETTINGS_DIR_NAME);
#endif  // OS_WIN32
}

// マシンキーの取得
void DeskGetMachineKey(void *data)
{
	BUF *b;
	char name[64];
	char ip_str[64];
	char product_id[MAX_PATH] = {0};
	IP ip;
	OS_INFO *osinfo;
	// 引数チェック
	if (data == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	WideGetWindowsProductId(product_id, sizeof(product_id));
#endif  // OS_WIN32

	b = NewBuf();
	GetMachineName(name, sizeof(name));
	GetMachineIp(&ip);
	IPToStr(ip_str, sizeof(ip_str), &ip);

	osinfo = GetOsInfo();

	WriteBuf(b, name, StrLen(name));
	WriteBuf(b, ip_str, StrLen(ip_str));

	WriteBuf(b, &osinfo->OsType, sizeof(osinfo->OsType));
	WriteBuf(b, osinfo->KernelName, StrLen(osinfo->KernelName));
	WriteBuf(b, osinfo->KernelVersion, StrLen(osinfo->KernelVersion));
	WriteBuf(b, osinfo->OsProductName, StrLen(osinfo->OsProductName));
	WriteBuf(b, &osinfo->OsServicePack, sizeof(osinfo->OsServicePack));
	WriteBuf(b, osinfo->OsSystemName, StrLen(osinfo->OsSystemName));
	WriteBuf(b, osinfo->OsVendorName, StrLen(osinfo->OsVendorName));
	WriteBuf(b, osinfo->OsVersion, StrLen(osinfo->OsVersion));

	WriteBuf(b, product_id, StrLen(product_id));

	Hash(data, b->Buf, b->Size, true);

	FreeBuf(b);
}

// SockIo と SOCK との間のリレー処理
void DeskRelay(SOCKIO *io, SOCK *s)
{
	SOCK_EVENT *e;
	FIFO *f1, *f2;
	void *buf;
	UINT buf_size;
	// 引数チェック
	if (io == NULL || s == NULL)
	{
		return;
	}

	SetTimeout(s, INFINITE);
	SockIoSetTimeout(io, INFINITE);
	SetSocketSendRecvBufferSize((int)s, WT_SOCKET_WINDOW_SIZE);

	buf_size = WT_SOCKET_WINDOW_SIZE;
	buf = Malloc(buf_size);

	e = SockIoGetSockIoEvent(io);
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

			// ソケットからの受信
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
				}
			}

			// SockIo からの受信
			while (FifoSize(f2) < WT_WINDOW_SIZE)
			{
				ret = SockIoRecvAsync(io, buf, MIN(buf_size, WT_WINDOW_SIZE - FifoSize(f2)));
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
				}
			}

			// ソケットへ送信
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

			// SockIo へ送信
			while (FifoSize(f1) != 0)
			{
				UINT size;
				UCHAR *p = (UCHAR *)f1->p + f1->pos;
				size = FifoSize(f1);

				ret = SockIoSendAsync(io, p, size);
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
			break;
		}
	}

	ReleaseSockEvent(e);

	ReleaseFifo(f1);
	ReleaseFifo(f2);

	Free(buf);

	SockIoDisconnect(io);
}

// URDP Server が利用可能になるまで待機する
bool DeskWaitReadyForUrdpServer()
{
	UINT64 start_time = Tick64();

	while (true)
	{
		UINT64 now = Tick64();
		SOCK *s;

		if (now > (start_time + (UINT64)DS_WAIT_FOR_URDP_SERVER_TIMEOUT))
		{
			// タイムアウト
			return false;
		}

		s = ConnectEx("localhost", DS_URDP_PORT, 256);
		if (s != NULL)
		{
			Disconnect(s);
			ReleaseSock(s);
			return true;
		}
	}
}

// RPC が有効になるまで待つ
bool DeskWaitReadyForDeskServerRpc()
{
#ifdef	OS_WIN32
	UINT64 start_time = Tick64();

	while (true)
	{
		UINT64 now = Tick64();
		SOCK *s;

		if (now > (start_time + (UINT64)(60 * 1000)))
		{
			// タイムアウト
			return false;
		}

		s = ConnectEx("localhost", DS_RPC_PORT, 256);
		if (s != NULL)
		{
			Disconnect(s);
			ReleaseSock(s);
			return true;
		}
	}
#else   // OS_WIN32
	return false;
#endif  // OS_WIN32
}

// urdpserver.exe の名前を取得
void DeskGetUrdpServerExeName(wchar_t *name, UINT size, UINT version)
{
	UINT id = 0;
	// 引数チェック
	if (name == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	id = MsGetCurrentTerminalSessionId();
#endif  // OS_WIN32

	//UniFormat(name, size, L"urdpserver_%u.exe", id);
	if (version == 2)
	{
		UniFormat(name, size, L"urdpserver2.exe");
	}
	else
	{
		UniFormat(name, size, L"urdpserver.exe");
	}
}

// 古い URDP Server のプロセスを停止させる
void DeskTerminateOldUrdpProcesses(UINT version)
{
#ifdef	OS_WIN32
	UINT i;
	wchar_t exe[MAX_PATH];
	LIST *o = MsGetProcessList();

	DeskGetUrdpServerExeName(exe, sizeof(exe), version);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);

		if (UniEndWith(p->ExeFilenameW, exe))
		{
			MsKillProcess(p->ProcessId);
		}
	}

	MsFreeProcessList(o);
#endif  // OS_WIN32
}

// RUDP Server を Program Files ディレクトリにインストールする
bool DeskInstallRudpServerToProgramFilesDir()
{
	wchar_t dst_dir[MAX_SIZE];

	DeskGetRudpServerProgramFilesDir(dst_dir, sizeof(dst_dir));

	if (DeskInitUrdpFiles(dst_dir, true, true) == false)
	{
		return false;
	}

	return true;
}

// Program Files 内の RUDP Server をインストールすべきディレクトリ名の取得
void DeskGetRudpServerProgramFilesDir(wchar_t *dir, UINT size)
{
#ifdef	OS_WIN32
	CombinePathW(dir, size, MsGetProgramFilesDirW(), DI_RUDP_INSTALL_DIR);
#endif  // OS_WIN32
}

// Program Files\\Common Files\\ の下にインストールされた RUDP があるかどうか調べる
bool DeskCheckUrdpIsInstalledOnProgramFiles(UINT version)
{
	wchar_t tmp[MAX_PATH];
	wchar_t exe[MAX_PATH];
	wchar_t prog_files_path[MAX_PATH];

	DeskGetUrdpServerExeName(exe, sizeof(exe), version);
	DeskGetRudpServerProgramFilesDir(prog_files_path, sizeof(prog_files_path));

	ConbinePathW(tmp, sizeof(tmp), prog_files_path, exe);

	return IsFileExistsW(tmp);
}

// URDP Server の開始
void DeskStartUrdpServer(URDP_SERVER *u, UINT version)
{
#ifdef	OS_WIN32
	wchar_t exe[MAX_PATH];
	// 引数チェック
	if (u == NULL)
	{
		return;
	}

	DeskGetUrdpServerExeName(exe, sizeof(exe), version);

	Lock(u->Lock);
	{
		if (u->Counter == 0)
		{
			wchar_t tmp[MAX_PATH];
			wchar_t arg[MAX_PATH];
			wchar_t prog_files_path[MAX_PATH];

RUN_NEW_PROCESS:
			DeskGetRudpServerProgramFilesDir(prog_files_path, sizeof(prog_files_path));
			DeskInitUrdpFiles(NULL, false, false);
			DeskTerminateOldUrdpProcesses(version);

			// プロセスの開始
			// まず Program Files\\Common Files\\ の下にインストールされた EXE
			// があるか調べる。もしあればそれを呼ぶ。無ければ Temp ディレクトリ
			// に新たに作成する。
			ConbinePathW(tmp, sizeof(tmp), prog_files_path, exe);

			if (IsFileExistsW(tmp) == false || MsIsVista() == false)
			{
				ConbinePathW(tmp, sizeof(tmp), MsGetMyTempDirW(), exe);
			}

			if (version <= 1)
			{
				UniFormat(arg, sizeof(arg), L"PortNumber=%u LocalHost=1", DS_URDP_PORT);
			}
			else
			{
				Zero(arg, sizeof(arg));
			}

			Debug("URDP: CreateProcess\n");

			if (MsIsNt())
			{
				if (MsExecuteEx3W(tmp, arg, &u->ProcessHandle, false, true) == false)
				{
					u->ProcessHandle = NULL;
				}
			}
			else
			{
				// Win9x 系では hide がうまく機能しないので CreateProcess を用いて起動する
				u->ProcessHandle = Win32RunExW(tmp, arg, true);
			}
		}
		else
		{
			if (Win32IsProcessAlive(u->ProcessHandle) == false)
			{
				Win32CloseProcess(u->ProcessHandle);
				Debug("URDP: RUN_NEW_PROCESS\n");
				goto RUN_NEW_PROCESS;
			}
		}

		u->Counter++;
	}
	Unlock(u->Lock);
#endif  // OS_WIN32
}

// URDP Server の停止
void DeskStopUrdpServer(URDP_SERVER *u)
{
#ifdef	OS_WIN32
	// 引数チェック
	if (u == NULL)
	{
		return;
	}

	Lock(u->Lock);
	{
		if (u->Counter >= 2)
		{
			u->Counter--;
		}
		else if (u->Counter == 1)
		{
			// プロセスの停止
			Debug("URDP: Win32TerminateProcess\n");
			Win32TerminateProcess(u->ProcessHandle);
			Win32CloseProcess(u->ProcessHandle);
			u->ProcessHandle = NULL;

			u->Counter = 0;
		}
	}
	Unlock(u->Lock);
#endif  // OS_WIN32
}

// URDP Server 管理の初期化
URDP_SERVER *DeskInitUrdpServer()
{
	URDP_SERVER *u;

	u = ZeroMalloc(sizeof(URDP_SERVER));
	u->Lock = NewLock();

	return u;
}

// URDP Server 管理の解放
void DeskFreeUrdpServer(URDP_SERVER *u)
{
	// 引数チェック
	if (u == NULL)
	{
		return;
	}

	DeleteLock(u->Lock);

	Free(u);
}

// URDP ファイルの初期化
bool DeskInitUrdpFiles(wchar_t *dst_dir, bool rudp_server_manifest, bool overwrite)
{
#ifdef	OS_WIN32
	wchar_t dst[MAX_PATH];

	if (dst_dir == NULL)
	{
		dst_dir = MsGetMyTempDirW();
	}

	MakeDirExW(dst_dir);

	ConbinePathW(dst, sizeof(dst), dst_dir, L"License.xps");
	if (overwrite || IsFileExistsW(dst) == false)
	{
		if (FileCopyW(L"|License.xps", dst) == false)
		{
			return false;
		}
	}

	ConbinePathW(dst, sizeof(dst), dst_dir, L"logmessages.dll");
	if (overwrite || IsFileExistsW(dst) == false)
	{
		if (FileCopyW(L"|logmessages.dll", dst) == false)
		{
			return false;
		}
	}

	ConbinePathW(dst, sizeof(dst), dst_dir, L"urdpclient.exe");
	if (overwrite || IsFileExistsW(dst) == false)
	{
		if (FileCopyW(L"|urdpclient.exe", dst) == false)
		{
			return false;
		}
	}

	ConbinePathW(dst, sizeof(dst), dst_dir, L"urdpclient2.exe");
	if (overwrite || IsFileExistsW(dst) == false)
	{
		if (FileCopyW(L"|urdpclient2.exe", dst) == false)
		{
			return false;
		}
	}

	ConbinePathW(dst, sizeof(dst), dst_dir, L"urdpconfig.exe");
	if (overwrite || IsFileExistsW(dst) == false)
	{
		if (FileCopyW(L"|urdpconfig.exe", dst) == false)
		{
			return false;
		}
	}

	ConbinePathW(dst, sizeof(dst), dst_dir, L"urdpserver.exe");
	if (overwrite || IsFileExistsW(dst) == false)
	{
		if (FileCopyW(L"|urdpserver.exe", dst) == false)
		{
			return false;
		}
	}

	ConbinePathW(dst, sizeof(dst), dst_dir, L"urdpserver2.exe");
	if (overwrite || IsFileExistsW(dst) == false)
	{
		if (FileCopyW(L"|urdpserver2.exe", dst) == false)
		{
			return false;
		}
	}

	if (rudp_server_manifest)
	{
		ConbinePathW(dst, sizeof(dst), dst_dir, L"urdpserver.exe.manifest");
		if (overwrite || IsFileExistsW(dst) == false)
		{
			if (FileCopyW(L"|urdpserver.exe.manifest", dst) == false)
			{
				return false;
			}
		}

		ConbinePathW(dst, sizeof(dst), dst_dir, L"urdpserver2.exe.manifest");
		if (overwrite || IsFileExistsW(dst) == false)
		{
			if (FileCopyW(L"|urdpserver2.exe.manifest", dst) == false)
			{
				return false;
			}
		}
	}

	ConbinePathW(dst, sizeof(dst), dst_dir, L"wm_hooks.dll");
	if (overwrite || IsFileExistsW(dst) == false)
	{
		if (FileCopyW(L"|wm_hooks.dll", dst) == false)
		{
			return false;
		}
	}

	ConbinePathW(dst, sizeof(dst), dst_dir, L"hookldr.exe");
	if (overwrite || IsFileExistsW(dst) == false)
	{
		if (FileCopyW(L"|hookldr.exe", dst) == false)
		{
			return false;
		}
	}
	ConbinePathW(dst, sizeof(dst), dst_dir, L"screenhooks32.dll");
	if (overwrite || IsFileExistsW(dst) == false)
	{
		if (FileCopyW(L"|screenhooks32.dll", dst) == false)
		{
			return false;
		}
	}

	return true;
#else   // OS_WIN32
	return false;
#endif  // OS_WIN32
}

// UAC の設定を緩和する
void DeskMitigateUacSetting()
{
#ifdef	OS_WIN32
	if (MsIsVista() == false)
	{
		return;
	}

	MsRegWriteInt(REG_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
		"PromptOnSecureDesktop", 0);
#endif  // OS_WIN32
}

// UAC の設定が厳しいかどうか取得する
bool DeskIsUacSettingStrict()
{
#ifdef	OS_WIN32
	if (MsIsVista() == false)
	{
		return false;
	}

	if (MsRegReadInt(REG_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
		"PromptOnSecureDesktop") == 0)
	{
		return false;
	}

	return true;
#else   // OS_WIN32
	return false;
#endif  // OS_WIN32
}
