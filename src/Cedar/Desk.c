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

// Desk.c
// PacketiX Desktop VPN Main Source

// Build 5604

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
UINT DeskRelay(SOCKIO *io, SOCK *s)
{
	SOCK_EVENT *e;
	FIFO *f1, *f2;
	void *buf;
	UINT buf_size;
	UINT total_size = 0;
	// 引数チェック
	if (io == NULL || s == NULL)
	{
		return 0;
	}

	SetTimeout(s, INFINITE);
	SockIoSetTimeout(io, INFINITE);
	SetSocketSendRecvBufferSize(s->socket, WT_SOCKET_WINDOW_SIZE);

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
					total_size += ret;
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
					total_size += ret;
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

	return total_size;
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
	LIST *o = MsGetProcessList(0);

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

// 現在 URDP プロセスが起動しているかどうか調べる
bool DeskCheckUrdpProcessIsRunning()
{
	bool ret = false;
#ifdef OS_WIN32
	LIST *o = MsGetProcessList(0);
	if (o != NULL)
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			MS_PROCESS *proc = LIST_DATA(o, i);
			wchar_t filename[MAX_PATH];

			GetFileNameFromFilePathW(filename, sizeof(filename), proc->ExeFilenameW);

			if (UniInStrEx(filename, L"urdpserver.exe", false) ||
				UniInStrEx(filename, L"urdpserver2.exe", false))
			{
				ret = true;
			}
		}
		MsFreeProcessList(o);
	}
#endif	// OS_WIN32

	return ret;
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

	//ConbinePathW(dst, sizeof(dst), dst_dir, L"License.xps");
	//if (overwrite || IsFileExistsW(dst) == false)
	//{
	//	if (FileCopyW(L"|License.xps", dst) == false)
	//	{
	//		return false;
	//	}
	//}

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
