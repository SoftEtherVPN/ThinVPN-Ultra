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


// SeLowUser.h
// Header for SeLowUser.c

#ifndef	SELOWUSER_H
#define	SELOWUSER_H

#include <Cedar/SeLowCommon.h>

//// Macro
#define	SL_USER_INSTALL_LOCK_TIMEOUT		60000		// Lock acquisition timeout
#define	SL_USER_AUTO_PUSH_TIMER				60000		// Timer to start the installation automatically

//// Type

// SU
struct SU
{
	void *hFile;							// File handle
	SL_ADAPTER_INFO_LIST AdapterInfoList;	// Adapter list cache
};

// Adapter
struct SU_ADAPTER
{
	char AdapterId[MAX_PATH];				// Adapter ID
	char DeviceName[MAX_PATH];				// Device name
	void *hFile;							// File handle
	void *hEvent;							// Event handle
	bool Halt;
	UINT CurrentPacketCount;
	UCHAR GetBuffer[SL_EXCHANGE_BUFFER_SIZE];	// Read buffer
	UCHAR PutBuffer[SL_EXCHANGE_BUFFER_SIZE];	// Write buffer
};

// Adapter list items
struct SU_ADAPTER_LIST
{
	SL_ADAPTER_INFO Info;					// Adapter information
	char Guid[128];							// GUID
	char Name[MAX_SIZE];					// Name
	char SortKey[MAX_SIZE];					// Sort key
};


//// Function prototype
SU *SuInit();
SU *SuInitEx(UINT wait_for_bind_complete_tick);
void SuFree(SU *u);
TOKEN_LIST *SuEnumAdapters(SU *u);
SU_ADAPTER *SuOpenAdapter(SU *u, char *adapter_id);
void SuCloseAdapter(SU_ADAPTER *a);
void SuCloseAdapterHandleInner(SU_ADAPTER *a);
bool SuGetPacketsFromDriver(SU_ADAPTER *a);
bool SuGetNextPacket(SU_ADAPTER *a, void **buf, UINT *size);
bool SuPutPacketsToDriver(SU_ADAPTER *a);
bool SuPutPacket(SU_ADAPTER *a, void *buf, UINT size);

SU_ADAPTER_LIST *SuAdapterInfoToAdapterList(SL_ADAPTER_INFO *info);
LIST *SuGetAdapterList(SU *u);
void SuFreeAdapterList(LIST *o);
int SuCmpAdaterList(void *p1, void *p2);

bool SuInstallDriver(bool force);
bool SuInstallDriverInner(bool force);
bool SuIsSupportedOs(bool on_install);
bool SuCopySysFile(wchar_t *src, wchar_t *dst);

void SuDeleteGarbageInfs();
void SuDeleteGarbageInfsInner();
bool SuLoadDriversHive();
bool SuUnloadDriversHive();

#endif	// SELOWUSER_H



