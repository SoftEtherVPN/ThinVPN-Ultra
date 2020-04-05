// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// DsRpc.h
// DsRpc.c のヘッダ

struct RPC_DS_STATUS
{
	UINT Version;
	UINT Build;
	char ExePath[MAX_PATH];
	wchar_t ExePathW[MAX_PATH];
	char ExeDir[MAX_PATH];
	wchar_t ExeDirW[MAX_PATH];
	UINT LastError;
	bool IsConnected;
	char Pcid[MAX_PATH];
	char Hash[MAX_PATH];
	UINT ServiceType;
	bool IsUserMode;
	bool Active;
	bool IsConfigured;
	UINT DsCaps;
	bool UseAdvancedSecurity;
	bool ForceDisableShare;
	bool SupportEventLog;
	UINT NumConfigures;
	UINT NumAdvancedUsers;
};

struct RPC_PCID
{
	char Pcid[MAX_PATH];
};

struct RPC_DS_CONFIG
{
	bool Active;
	bool PowerKeep;
	bool DontCheckCert;
	UCHAR HashedPassword[SHA1_SIZE];
	bool UseAdvancedSecurity;
	UINT AuthType;
	UCHAR AuthPassword[SHA1_SIZE];
	UINT ServiceType;
	bool SaveLogFile;
	wchar_t BluetoothDir[MAX_PATH];
	bool SaveEventLog;
	bool DisableShare;
	wchar_t AdminUsername[MAX_PATH];
};

void InInternetSetting(INTERNET_SETTING *t, PACK *p);
void OutInternetSetting(PACK *p, INTERNET_SETTING *t);
void InRpcDsStatus(RPC_DS_STATUS *t, PACK *p);
void OutRpcDsStatus(PACK *p, RPC_DS_STATUS *t);
void InRpcPcid(RPC_PCID *t, PACK *p);
void OutRpcPcid(PACK *p, RPC_PCID *t);
void InRpcDsConfig(RPC_DS_CONFIG *t, PACK *p);
void OutRpcDsConfig(PACK *p, RPC_DS_CONFIG *t);


