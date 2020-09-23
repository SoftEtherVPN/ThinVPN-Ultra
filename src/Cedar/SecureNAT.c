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


// SecureNAT.c
// SecureNAT code

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

// SecureNAT server-side thread
void SnSecureNATThread(THREAD *t, void *param)
{
	SNAT *s;
	CONNECTION *c;
	SESSION *se;
	POLICY *policy;
	HUB *h;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	s = (SNAT *)param;
	// Create a server connection
	c = NewServerConnection(s->Cedar, NULL, t);
	c->Protocol = CONNECTION_HUB_SECURE_NAT;

	// Apply the default policy
	policy = ClonePolicy(GetDefaultPolicy());

	// Not to limit the number of broadcast
	policy->NoBroadcastLimiter = true;

	h = s->Hub;
	AddRef(h->ref);

	// create a server session
	se = NewServerSession(s->Cedar, c, s->Hub, SNAT_USER_NAME, policy);
	se->SecureNATMode = true;
	se->SecureNAT = s;
	c->Session = se;
	ReleaseConnection(c);

	HLog(se->Hub, "LH_NAT_START", se->Name);

	// User name
	se->Username = CopyStr(SNAT_USER_NAME_PRINT);

	s->Session = se;
	AddRef(se->ref);

	// Notification initialization completion
	NoticeThreadInit(t);

	ReleaseCancel(s->Nat->Virtual->Cancel);
	s->Nat->Virtual->Cancel = se->Cancel1;
	AddRef(se->Cancel1->ref);

	if (s->Nat->Virtual->NativeNat != NULL)
	{
		CANCEL *old_cancel = NULL;

		Lock(s->Nat->Virtual->NativeNat->CancelLock);
		{
			if (s->Nat->Virtual->NativeNat->Cancel != NULL)
			{
				old_cancel = s->Nat->Virtual->NativeNat->Cancel;

				s->Nat->Virtual->NativeNat->Cancel = se->Cancel1;

				AddRef(se->Cancel1->ref);
			}
		}
		Unlock(s->Nat->Virtual->NativeNat->CancelLock);

		if (old_cancel != NULL)
		{
			ReleaseCancel(old_cancel);
		}
	}

	// Main function of the session
	Debug("SecureNAT Start.\n");
	SessionMain(se);
	Debug("SecureNAT Stop.\n");

	HLog(se->Hub, "LH_NAT_STOP");

	ReleaseHub(h);

	ReleaseSession(se);
}

// Release the SecureNAT
void SnFreeSecureNAT(SNAT *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Stop the session 
	StopSession(s->Session);
	ReleaseSession(s->Session);

	// Virtual machine release
	Virtual_Free(s->Nat->Virtual);

	// NAT release
	NiFreeNat(s->Nat);

	DeleteLock(s->lock);

	Free(s);
}

// Create a new SecureNAT
SNAT *SnNewSecureNAT(HUB *h, VH_OPTION *o)
{
	SNAT *s;
	THREAD *t;
	// Validate arguments
	if (h == NULL || o == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(SNAT));
	s->Cedar = h->Cedar;
	s->Hub = h;
	s->lock = NewLock();

	// Create a NAT
	s->Nat = NiNewNatEx(s, o);

	// Initialize the virtual machine
	VirtualInit(s->Nat->Virtual);

	// Create a thread
	t = NewThread(SnSecureNATThread, s);
	WaitThreadInit(t);
	ReleaseThread(t);

	return s;
}

