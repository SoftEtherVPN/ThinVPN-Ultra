// SoftEther VPN Source Code - Stable Edition Repository
// Build Utility
// 
// SoftEther VPN Server, Client and Bridge are free software under the Apache License, Version 2.0.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on SoftEther VPN project in GitHub.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// This stable branch is officially managed by Daiyuu Nobori, the owner of SoftEther VPN Project.
// Pull requests should be sent to the Developer Edition Master Repository on https://github.com/SoftEtherVPN/SoftEtherVPN
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
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
// AGAINST US (SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI OR OTHER
// SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND
// OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
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
// COMPLETELY AT YOUR OWN RISK. THE SOFTETHER VPN PROJECT HAS DEVELOPED AND
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
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


using System;
using System.Threading;
using System.Text;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Drawing.Drawing2D;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using CoreUtil;
using System.Linq;

namespace BuildUtil
{
	// Basic path information
	public static class Paths
	{
		public static readonly string ExeFileName = Env.ExeFileName;
		public static readonly string ExeDirName = Env.ExeFileDir;
		public static readonly string SolutionBinDirName = ExeDirName;
		public static readonly string SolutionBaseDirName = IO.NormalizePath(Path.Combine(SolutionBinDirName, @"..\"));
		public static readonly string UtilityDirName = IO.NormalizePath(Path.Combine(SolutionBinDirName, @"..\BuildFiles\Utility"));

		public static readonly string UltraBaseDirName = IO.NormalizePath(Directory.Exists(Path.Combine(SolutionBinDirName, @"..\..\submodules\")) ? Path.Combine(SolutionBinDirName, @"..\..\submodules\IPA-DN-Ultra\src") : Path.Combine(SolutionBinDirName, @"..\"));
		public static readonly string UltraBinDirName = IO.NormalizePath(Path.Combine(UltraBaseDirName, "bin"));
		public static readonly string UltraBuildFilesDirName = IO.NormalizePath(Path.Combine(UltraBaseDirName, "BuildFiles"));

		public static readonly string VisualStudioSolutionFileName;
		public static readonly string DebugSnapshotBaseDir = @"S:\NTTVPN\DebugFilesSnapshot";
		public static readonly string ReleaseDestDir = @"s:\NTTVPN\Releases";
		public const string Prefix = "";

		public static readonly string ReleaseDestDir_SEVPN = @"s:\NTTVPN\Releases_SEVPN";

		public static readonly string BuildHamcoreFilesDirName = Path.Combine(SolutionBinDirName, "BuiltHamcoreFiles");
		public static readonly string VisualStudioVCDir;
		public static readonly string VisualStudioVCBatchFileName;
		public static readonly string DotNetFramework35Dir;
		public static readonly string MSBuildFileName;
		public static readonly string TmpDirName;
		public static readonly DateTime StartDateTime = DateTime.Now;
		public static readonly string StartDateTimeStr;
		public static readonly string CmdFileName;
		public static readonly string ManifestsDir = Path.Combine(UltraBuildFilesDirName, "Manifests");
		public static readonly string XCopyExeFileName = Path.Combine(Env.SystemDir, "xcopy.exe");
		public static readonly string ReleaseDir = Path.Combine(SolutionBaseDirName, @"tmp\Release");
		public static readonly string ReleaseSrckitDir = Path.Combine(SolutionBaseDirName, @"tmp\ReleaseSrcKit");
		public static readonly string StringsDir = Path.Combine(SolutionBaseDirName, @"BuildFiles\Strings");
		public static readonly string CrossCompilerBaseDir = @"S:\CommomDev\xc";
		public static readonly string UnixInstallScript = Path.Combine(SolutionBaseDirName, @"BuildFiles\UnixFiles\InstallScript.txt");
		public static readonly string OssCommentsFile = Path.Combine(StringsDir, "OssComments.txt");
		public static readonly string AutorunSrcDir = IO.NormalizePath(Path.Combine(SolutionBaseDirName, @"..\Autorun"));
		public static readonly string MicrosoftSDKDir;
		public static readonly string MakeCatFilename;
		public static readonly string RcFilename;
		public static readonly string SoftEtherBuildDir = Env.SystemDir.Substring(0, 2) + @"\tmp\softether_build_dir";
		public static readonly string OpenSourceDestDir = Env.SystemDir.Substring(0, 2) + @"\tmp\softether_oss_dest_dir";

		// Initialize
		static Paths()
		{
			// Starting date and time string
			Paths.StartDateTimeStr = Str.DateTimeToStrShort(Paths.StartDateTime);

			// Check whether the execution path is the bin directory in the VPN directory
			if (Paths.SolutionBinDirName.EndsWith(@"\bin", StringComparison.InvariantCultureIgnoreCase) == false)
			{
				throw new ApplicationException(string.Format("'{0}' is not a VPN bin directory.", Paths.SolutionBinDirName));
			}

			// Determine the Visual Studio solution file
			string slnFileName = Directory.EnumerateFiles(SolutionBaseDirName).Where(x => x.EndsWith(".sln")).Single();

			Paths.VisualStudioSolutionFileName = Path.Combine(SolutionBaseDirName, slnFileName);

			if (File.Exists(Paths.VisualStudioSolutionFileName) == false)
			{
				throw new ApplicationException(string.Format("'{0}' is not a VPN base directory.", Paths.SolutionBaseDirName));
			}

			// Get the VC++ directory
			// Visual Studio 2008
			if (IntPtr.Size == 4)
			{
				Paths.VisualStudioVCDir = IO.RemoteLastEnMark(Reg.ReadStr(RegRoot.LocalMachine, @"SOFTWARE\Microsoft\VisualStudio\9.0\Setup\VC", "ProductDir"));
			}
			else
			{
				Paths.VisualStudioVCDir = IO.RemoteLastEnMark(Reg.ReadStr(RegRoot.LocalMachine, @"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\9.0\Setup\VC", "ProductDir"));
			}
			if (Str.IsEmptyStr(Paths.VisualStudioVCDir))
			{
				throw new ApplicationException("Visual C++ directory not found.\n");
			}
			if (Directory.Exists(Paths.VisualStudioVCDir) == false)
			{
				throw new ApplicationException(string.Format("Directory '{0}' not found.", Paths.VisualStudioVCDir));
			}

			// Get the VC++ batch file name
			Paths.VisualStudioVCBatchFileName = Path.Combine(Paths.VisualStudioVCDir, "vcvarsall.bat");
			if (File.Exists(Paths.VisualStudioVCBatchFileName) == false)
			{
				throw new ApplicationException(string.Format("File '{0}' not found.", Paths.VisualStudioVCBatchFileName));
			}

			bool x86_dir = false;

			// Get Microsoft SDK 6.0a directory
			if (IntPtr.Size == 4)
			{
				Paths.MicrosoftSDKDir = IO.RemoteLastEnMark(Reg.ReadStr(RegRoot.LocalMachine, @"SOFTWARE\Wow6432Node\Microsoft\Microsoft SDKs\Windows\v6.0A", "InstallationFolder"));
			}
			else
			{
				Paths.MicrosoftSDKDir = IO.RemoteLastEnMark(Reg.ReadStr(RegRoot.LocalMachine, @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v6.0A", "InstallationFolder"));
			}

			// Get makecat.exe file name
			Paths.MakeCatFilename = Path.Combine(Paths.MicrosoftSDKDir, @"bin\" + (x86_dir ? @"x86\" : "") + "makecat.exe");

			// Get the rc.exe file name
			Paths.RcFilename = Path.Combine(Paths.MicrosoftSDKDir, @"bin\" + (x86_dir ? @"x86\" : "") + "rc.exe");

			// Get the cmd.exe file name
			Paths.CmdFileName = Path.Combine(Env.SystemDir, "cmd.exe");
			if (File.Exists(Paths.CmdFileName) == false)
			{
				throw new ApplicationException(string.Format("File '{0}' not found.", Paths.CmdFileName));
			}

			// Get .NET Framework 3.5 directory
			Paths.DotNetFramework35Dir = Path.Combine(Env.WindowsDir, @"Microsoft.NET\Framework\v3.5");

			// Get msbuild.exe directory
			Paths.MSBuildFileName = Path.Combine(Paths.DotNetFramework35Dir, "MSBuild.exe");
			if (File.Exists(Paths.MSBuildFileName) == false)
			{
				throw new ApplicationException(string.Format("File '{0}' not found.", Paths.MSBuildFileName));
			}

			// Get the TMP directory
			Paths.TmpDirName = Path.Combine(Paths.SolutionBaseDirName, "tmp");
			if (Directory.Exists(Paths.TmpDirName) == false)
			{
				Directory.CreateDirectory(Paths.TmpDirName);
			}
		}
	}
}


