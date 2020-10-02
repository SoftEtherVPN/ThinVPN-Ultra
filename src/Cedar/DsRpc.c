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


// DsRpc.c
// PacketiX Desktop VPN Server RPC

// Build 8600

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

	t->ShowWatermark = PackGetBool(p, "ShowWatermark");
	PackGetUniStr(p, "WatermarkStr", t->WatermarkStr, sizeof(t->WatermarkStr));

	t->EnableWoLTarget = PackGetBool(p, "EnableWoLTarget");
	t->EnableWoLTrigger = PackGetBool(p, "EnableWoLTrigger");

	PackGetStr(p, "RegistrationPassword", t->RegistrationPassword, sizeof(t->RegistrationPassword));
	PackGetStr(p, "RegistrationEmail", t->RegistrationEmail, sizeof(t->RegistrationEmail));
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

	PackAddBool(p, "ShowWatermark", t->ShowWatermark);
	PackAddUniStr(p, "WatermarkStr", t->WatermarkStr);

	PackAddBool(p, "EnableWoLTarget", t->EnableWoLTarget);
	PackAddBool(p, "EnableWoLTrigger", t->EnableWoLTrigger);

	PackAddStr(p, "RegistrationPassword", t->RegistrationPassword);
	PackAddStr(p, "RegistrationEmail", t->RegistrationEmail);
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
	PackGetStr(p, "System", t->System, sizeof(t->System));
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
	t->EnforceWatermark = PackGetBool(p, "EnforceWatermark");

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
	PackAddStr(p, "System", t->System);
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
	PackAddBool(p, "EnforceWatermark", t->EnforceWatermark);

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


