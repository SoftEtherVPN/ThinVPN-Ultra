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


// Table.h
// Header of Table.c

#ifndef	TABLE_H
#define	TABLE_H

#define	UNICODE_CACHE_FILE		L".unicode_cache_%s.dat"

#define	LANGLIST_FILENAME		"|languages.txt"
#define	LANGLIST_FILENAME_WINE	"|languages_wine.txt"

#define	LANG_CONFIG_FILENAME	L"@lang.config"
#define	LANG_CONFIG_TEMPLETE	"|lang.config"

// Language constant
#define SE_LANG_JAPANESE			0	// Japanese
#define SE_LANG_ENGLISH				1	// English
#define SE_LANG_CHINESE_ZH			2	// Simplified Chinese


// String table
struct TABLE
{
	char *name;
	char *str;
	wchar_t *unistr;
};

// String table
struct TABLE_REPLACE_STR
{
	char* oldstr;
	wchar_t* olduni;
	char* newstr;
	wchar_t* newuni;
};

// Unicode cache structure
typedef struct UNICODE_CACHE
{
	char StrFileName[256];	// String file name
	UINT StrFileSize;		// String file size
	char MachineName[256];	// Machine name
	UINT OsType;			// OS type
	UCHAR hash[MD5_SIZE];	// Hash
	UCHAR CharSet[64];		// Type of character code
} UNICODE_CACHE;

// Macro
#define	_SS(name)		(GetTableStr((char *)(name)))
#define	_UU(name)		(GetTableUniStr((char *)(name)))
#define	_II(name)		(GetTableInt((char *)(name)))
#define	_E(name)		(GetUniErrorStr((UINT)(name)))
#define	_EA(name)		(GetErrorStr((UINT)(name)))
#define _GETLANG()		(_II("LANG"))

// Language list
struct LANGLIST
{
	UINT Id;						// Number
	char Name[32];					// Identifier
	wchar_t TitleEnglish[128];		// English notation
	wchar_t TitleLocal[128];		// Local notation
	LIST *LcidList;					// Windows LCID list
	LIST *LangList;					// UNIX LANG environment variable list
};


// Function prototype
bool LoadTable(char *filename);
bool LoadTableW(wchar_t *filename);
bool LoadTableMain(wchar_t *filename);
bool LoadTableFromBuf(BUF *b);
void FreeTable();
TABLE *ParseTableLine(char *line, char *prefix, UINT prefix_size, LIST *replace_list);
void UnescapeStr(char *src);
int CmpTableName(void *p1, void *p2);
TABLE *FindTable(char *name);
TOKEN_LIST *GetTableNameStartWith(char *str);
char *GetTableStr(char *name);
wchar_t *GetTableUniStr(char *name);
char *GetErrorStr(UINT err);
wchar_t *GetUniErrorStr(UINT err);
UINT GetTableInt(char *name);
void GenerateUnicodeCacheFileName(wchar_t *name, UINT size, wchar_t *strfilename, UINT strfilesize, UCHAR *filehash);
void SaveUnicodeCache(wchar_t *strfilename, UINT strfilesize, UCHAR *hash);
bool LoadUnicodeCache(wchar_t *strfilename, UINT strfilesize, UCHAR *hash);
void InitTable();

LIST *LoadLangList();
void FreeLangList(LIST *o);

LANGLIST *GetBestLangByName(LIST *o, char *name);
LANGLIST *GetBestLangByLcid(LIST *o, UINT lcid);
LANGLIST *GetBestLangByLangStr(LIST *o, char *str);
LANGLIST *GetBestLangForCurrentEnvironment(LIST *o);
LANGLIST *GetLangById(LIST *o, UINT id);

bool LoadLangConfig(wchar_t *filename, char *str, UINT str_size);
bool LoadLangConfigCurrentDir(char *str, UINT str_size);
bool SaveLangConfig(wchar_t *filename, char *str);
bool SaveLangConfigCurrentDir(char *str);

void GetCurrentLang(LANGLIST *e);
UINT GetCurrentLangId();

void GetCurrentOsLang(LANGLIST *e);
UINT GetCurrentOsLangId();

#endif	// TABLE_H



