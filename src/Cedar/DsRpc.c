// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// DsRpc.c
// PacketiX Desktop VPN Server RPC

// Build 8600

#include "CedarPch.h"

// RPC_DS_CONFIG
void InRpcDsConfig(RPC_DS_CONFIG *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DS_CONFIG));

	t->PowerKeep = PackGetBool(p, "PowerKeep");
	t->DontCheckCert = PackGetBool(p, "DontCheckCert");
	t->Active = PackGetBool(p, "Active");
	PackGetData2(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	t->AuthType = PackGetInt(p, "AuthType");
	PackGetData2(p, "AuthPassword", t->AuthPassword, sizeof(t->AuthPassword));
	t->ServiceType = PackGetInt(p, "ServiceType");
	t->SaveLogFile = PackGetBool(p, "SaveLogFile");
	PackGetUniStr(p, "BluetoothDir", t->BluetoothDir, sizeof(t->BluetoothDir));
	t->UseAdvancedSecurity = PackGetBool(p, "UseAdvancedSecurity");
	t->SaveEventLog = PackGetBool(p, "SaveEventLog");
	t->DisableShare = PackGetBool(p, "DisableShare");
	PackGetUniStr(p, "AdminUsername", t->AdminUsername, sizeof(t->AdminUsername));
	t->EnableOtp = PackGetBool(p, "EnableOtp");
	PackGetStr(p, "OtpEmail", t->OtpEmail, sizeof(t->OtpEmail));
	t->EnableInspection = PackGetBool(p, "EnableInspection");
	t->EnableMacCheck = PackGetBool(p, "EnableMacCheck");
	PackGetStr(p, "MacAddressList", t->MacAddressList, sizeof(t->MacAddressList));
	PackGetStr(p, "EmergencyOtp", t->EmergencyOtp, sizeof(t->EmergencyOtp));

	t->RdpEnableGroupKeeper = PackGetBool(p, "RdpEnableGroupKeeper");
	PackGetUniStr(p, "RdpGroupKeepUserName", t->RdpGroupKeepUserName, sizeof(t->RdpGroupKeepUserName));
	t->RdpEnableOptimizer = PackGetBool(p, "RdpEnableOptimizer");
	PackGetStr(p, "RdpStopServicesList", t->RdpStopServicesList, sizeof(t->RdpStopServicesList));
}
void OutRpcDsConfig(PACK *p, RPC_DS_CONFIG *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "PowerKeep", t->PowerKeep);
	PackAddBool(p, "DontCheckCert", t->DontCheckCert);
	PackAddBool(p, "Active", t->Active);
	PackAddData(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackAddInt(p, "AuthType", t->AuthType);
	PackAddData(p, "AuthPassword", t->AuthPassword, sizeof(t->AuthPassword));
	PackAddInt(p, "ServiceType", t->ServiceType);
	PackAddBool(p, "SaveLogFile", t->SaveLogFile);
	PackAddUniStr(p, "BluetoothDir", t->BluetoothDir);
	PackAddBool(p, "UseAdvancedSecurity", t->UseAdvancedSecurity);
	PackAddBool(p, "SaveEventLog", t->SaveEventLog);
	PackAddBool(p, "DisableShare", t->DisableShare);
	PackAddUniStr(p, "AdminUsername", t->AdminUsername);
	PackAddBool(p, "EnableOtp", t->EnableOtp);
	PackAddStr(p, "OtpEmail", t->OtpEmail);
	PackAddBool(p, "EnableInspection", t->EnableInspection);
	PackAddBool(p, "EnableMacCheck", t->EnableMacCheck);
	PackAddStr(p, "MacAddressList", t->MacAddressList);
	PackAddStr(p, "EmergencyOtp", t->EmergencyOtp);

	PackAddBool(p, "RdpEnableGroupKeeper", t->RdpEnableGroupKeeper);
	PackAddUniStr(p, "RdpGroupKeepUserName", t->RdpGroupKeepUserName);
	PackAddBool(p, "RdpEnableOptimizer", t->RdpEnableOptimizer);
	PackAddStr(p, "RdpStopServicesList", t->RdpStopServicesList);
}

// RPC_PCID
void InRpcPcid(RPC_PCID *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_PCID));

	PackGetStr(p, "Pcid", t->Pcid, sizeof(t->Pcid));

}
void OutRpcPcid(PACK *p, RPC_PCID *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Pcid", t->Pcid);
}

// RPC_DS_STATUS
void InRpcDsStatus(RPC_DS_STATUS *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DS_STATUS));

	t->Version = PackGetInt(p, "Version");
	t->Build = PackGetInt(p, "Build");
	PackGetStr(p, "ExePath", t->ExePath, sizeof(t->ExePath));
	PackGetStr(p, "ExeDir", t->ExeDir, sizeof(t->ExeDir));
	PackGetUniStr(p, "ExePathW", t->ExePathW, sizeof(t->ExePathW));
	if (UniIsEmptyStr(t->ExePathW))
	{
		StrToUni(t->ExePathW, sizeof(t->ExePathW), t->ExePath);
	}
	PackGetUniStr(p, "ExeDirW", t->ExeDirW, sizeof(t->ExeDirW));
	if (UniIsEmptyStr(t->ExeDirW))
	{
		StrToUni(t->ExeDirW, sizeof(t->ExeDirW), t->ExeDir);
	}
	t->LastError = PackGetInt(p, "LastError");
	t->IsConnected = PackGetBool(p, "IsConnected");
	PackGetStr(p, "Pcid", t->Pcid, sizeof(t->Pcid));
	PackGetStr(p, "Hash", t->Hash, sizeof(t->Hash));
	t->ServiceType = PackGetInt(p, "ServiceType");
	t->IsUserMode = PackGetBool(p, "IsUserMode");
	t->Active = PackGetBool(p, "Active");
	t->IsConfigured = PackGetBool(p, "IsConfigured");
	t->DsCaps = PackGetInt(p, "DsCaps");
	t->UseAdvancedSecurity = PackGetBool(p, "UseAdvancedSecurity");
	t->ForceDisableShare = PackGetBool(p, "ForceDisableShare");
	t->SupportEventLog = PackGetBool(p, "SupportEventLog");
	t->NumConfigures = PackGetInt(p, "NumConfigures");
	t->NumAdvancedUsers = PackGetInt(p, "NumAdvancedUsers");
	PackGetStr(p, "GateIP", t->GateIP, sizeof(t->GateIP));

	t->MsgForServerArrived = PackGetBool(p, "MsgForServerArrived");
	PackGetUniStr(p, "MsgForServer", t->MsgForServer, sizeof(t->MsgForServer));
	t->MsgForServerOnce = PackGetBool(p, "MsgForServerOnce");

	PackGetUniStr(p, "MsgForServer2", t->MsgForServer2, sizeof(t->MsgForServer2));

	PackGetStr(p, "OtpEndWith", t->OtpEndWith, sizeof(t->OtpEndWith));

	t->EnforceInspection = PackGetBool(p, "EnforceInspection");
	t->EnforceMacCheck = PackGetBool(p, "EnforceMacCheck");

	t->IsAdminOrSystem = PackGetBool(p, "IsAdminOrSystem");
}
void OutRpcDsStatus(PACK *p, RPC_DS_STATUS *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Version", t->Version);
	PackAddInt(p, "Build", t->Build);
	PackAddStr(p, "ExePath", t->ExePath);
	PackAddStr(p, "ExeDir", t->ExeDir);
	PackAddUniStr(p, "ExePathW", t->ExePathW);
	PackAddUniStr(p, "ExeDirW", t->ExeDirW);
	PackAddInt(p, "LastError", t->LastError);
	PackAddBool(p, "IsConnected", t->IsConnected);
	PackAddStr(p, "Pcid", t->Pcid);
	PackAddStr(p, "Hash", t->Hash);
	PackAddInt(p, "ServiceType", t->ServiceType);
	PackAddBool(p, "IsUserMode", t->IsUserMode);
	PackAddBool(p, "Active", t->Active);
	PackAddBool(p, "IsConfigured", t->IsConfigured);
	PackAddInt(p, "DsCaps", t->DsCaps);
	PackAddBool(p, "UseAdvancedSecurity", t->UseAdvancedSecurity);
	PackAddBool(p, "ForceDisableShare", t->ForceDisableShare);
	PackAddBool(p, "SupportEventLog", t->SupportEventLog);
	PackAddInt(p, "NumConfigures", t->NumConfigures);
	PackAddInt(p, "NumAdvancedUsers", t->NumAdvancedUsers);
	PackAddStr(p, "GateIP", t->GateIP);

	PackAddBool(p, "MsgForServerArrived", t->MsgForServerArrived);
	PackAddUniStr(p, "MsgForServer", t->MsgForServer);
	PackAddBool(p, "MsgForServerOnce", t->MsgForServerOnce);

	PackAddUniStr(p, "MsgForServer2", t->MsgForServer2);

	PackAddStr(p, "OtpEndWith", t->OtpEndWith);

	PackAddBool(p, "EnforceInspection", t->EnforceInspection);
	PackAddBool(p, "EnforceMacCheck", t->EnforceMacCheck);

	PackAddBool(p, "IsAdminOrSystem", t->IsAdminOrSystem);
}

// INTERNET_SETTING
void InInternetSetting(INTERNET_SETTING *t, PACK *p)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(INTERNET_SETTING));

	t->ProxyType = PackGetInt(p, "ProxyType");
	PackGetStr(p, "ProxyHostName", t->ProxyHostName, sizeof(t->ProxyHostName));
	t->ProxyPort = PackGetInt(p, "ProxyPort");
	PackGetStr(p, "ProxyUsername", t->ProxyUsername, sizeof(t->ProxyUsername));
	PackGetStr(p, "ProxyPassword", t->ProxyPassword, sizeof(t->ProxyPassword));
	PackGetStr(p, "ProxyUserAgent", t->ProxyUserAgent, sizeof(t->ProxyUserAgent));
}
void OutInternetSetting(PACK *p, INTERNET_SETTING *t)
{
	// 引数チェック
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "ProxyType", t->ProxyType);
	PackAddStr(p, "ProxyHostName", t->ProxyHostName);
	PackAddInt(p, "ProxyPort", t->ProxyPort);
	PackAddStr(p, "ProxyUsername", t->ProxyUsername);
	PackAddStr(p, "ProxyPassword", t->ProxyPassword);
	PackAddStr(p, "ProxyUserAgent", t->ProxyUserAgent);
}


