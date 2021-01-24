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

namespace BuildTool
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

        public static readonly string TmpDirName;
        public static readonly DateTime StartDateTime = DateTime.Now;
        public static readonly string StartDateTimeStr;
        public static readonly string CmdFileName;
        public static readonly string ManifestsDir = Path.Combine(UltraBuildFilesDirName, "Manifests");
        public static readonly string XCopyExeFileName = Path.Combine(Env.SystemDir, "xcopy.exe");
        public static readonly string MicrosoftSDKDir;
        public static readonly string MicrosoftSDKBinDir;
        public static readonly string MakeCatFilename;
        public static readonly string RcFilename;

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

            // Get Microsoft SDK directory
            if (IntPtr.Size == 8)
            {
                Paths.MicrosoftSDKDir = IO.RemoteLastEnMark(Reg.ReadStr(RegRoot.LocalMachine, @"SOFTWARE\Wow6432Node\Microsoft\Microsoft SDKs\Windows\v10.0", "InstallationFolder"));
            }
            else
            {
                Paths.MicrosoftSDKDir = IO.RemoteLastEnMark(Reg.ReadStr(RegRoot.LocalMachine, @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v10.0", "InstallationFolder"));
            }

            if (Str.IsEmptyStr(Paths.MicrosoftSDKDir))
            {
                throw new ApplicationException("Microsoft SDK not found.");
            }

            Paths.MicrosoftSDKBinDir = Path.Combine(Paths.MicrosoftSDKDir, @"bin\x86");

            if (File.Exists(Path.Combine(Paths.MicrosoftSDKBinDir, "rc.exe")) == false)
            {
                // rc.exe not found. Enum alternative sub directories
                string tmp = Path.GetDirectoryName(Paths.MicrosoftSDKBinDir);

                foreach (string subDir in Directory.EnumerateDirectories(tmp).OrderByDescending(x => x))
                {
                    string tmp2 = Path.Combine(tmp, subDir, "x86");

                    if (File.Exists(Path.Combine(tmp2, "rc.exe")))
                    {
                        Paths.MicrosoftSDKBinDir = tmp2;
                        break;
                    }
                }
            }

            // Get makecat.exe file name
            Paths.MakeCatFilename = Path.Combine(Paths.MicrosoftSDKBinDir, "makecat.exe");

            // Get the rc.exe file name
            Paths.RcFilename = Path.Combine(Paths.MicrosoftSDKBinDir, "rc.exe");

            // Get the cmd.exe file name
            Paths.CmdFileName = Path.Combine(Env.SystemDir, "cmd.exe");
            if (File.Exists(Paths.CmdFileName) == false)
            {
                throw new ApplicationException(string.Format("File '{0}' not found.", Paths.CmdFileName));
            }

            // Get the TMP directory
            Paths.TmpDirName = Path.Combine(Paths.SolutionBaseDirName, "tmp");
            if (Directory.Exists(Paths.TmpDirName) == false)
            {
                Directory.CreateDirectory(Paths.TmpDirName);
            }
        }

        // Visual Studio 2019 の「VsDevCmd.bat」ファイルのパスを取得する
        public static string GetVsDevCmdFilePath()
        {
            string vsWhere = Path.Combine(Paths.UltraBuildFilesDirName, @"Utility\vswhere.exe");
            string args = @"-version [16.0,17.0) -sort -requires Microsoft.Component.MSBuild -find Common7\Tools\VsDevCmd.bat";

            using (Process p = new Process())
            {
                var info = p.StartInfo;

                info.FileName = vsWhere;
                info.UseShellExecute = false;
                info.CreateNoWindow = true;
                info.Arguments = args;

                info.RedirectStandardOutput = true;

                if (p.Start() == false)
                {
                    throw new Exception($"Starting '{vsWhere}' failed.");
                }

                var r = p.StandardOutput;

                string line = r.ReadLine();
                if (string.IsNullOrEmpty(line))
                {
                    throw new Exception($"'{vsWhere}' returned error. Perhaps no Visual C++ 2019 installed directory found.");
                }

                return line.Trim();
            }
        }

        static bool TryNormalizeGitCommitId(string src, out string dst)
        {
            dst = "";

            if (Str.IsEmptyStr(src)) return false;

            src = src.Trim();

            byte[] data = Str.HexToByte(src);

            if (data.Length != 20)
                return false;

            dst = Str.ByteToHex(data).ToLower();

            return true;
        }

        public static string GetUltraVersionLabel()
        {
            string tmpPath = Paths.SolutionBaseDirName;

            string readmePath = Path.Combine(tmpPath, @"..\submodules\IPA-DN-Ultra\README.md");

            string[] lines = File.ReadAllLines(readmePath);

            string tag = "[Current Version]";
            foreach (string line in lines)
            {
                int i = line.IndexOf(tag, StringComparison.OrdinalIgnoreCase);
                if (i != -1)
                {
                    string ver = line.Substring(i + tag.Length).Trim();

                    return ver;
                }
            }

            return "Unknown";
        }

        public static string GetUltraSubmoduleCommitId()
        {
            string tmpPath = Paths.SolutionBaseDirName;

            // Get the HEAD contents
            while (true)
            {
                string headFilename = Path.Combine(tmpPath, @".git\modules\submodules\IPA-DN-Ultra\HEAD");

                try
                {
                    if (File.Exists(headFilename))
                    {
                        var headContents = File.ReadAllLines(headFilename);
                        foreach (string line in headContents)
                        {
                            if (TryNormalizeGitCommitId(line, out string commitId))
                            {
                                return commitId;
                            }

                            string[] tokens = line.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

                            if (tokens.Length == 2 && tokens[0] == "ref:")
                            {
                                string refFilename = tokens[1].Trim();
                                string refFullPath = Path.Combine(Path.GetDirectoryName(headFilename), refFilename);

                                var lines2 = File.ReadAllLines(refFullPath);
                                if (lines2.Length >= 1 && Str.IsEmptyStr(lines2[0]) == false)
                                {
                                    return lines2[0];
                                }
                            }
                        }
                    }
                }
                catch { }

                string parentPath = Path.GetDirectoryName(tmpPath);
                if (tmpPath.Equals(parentPath, StringComparison.OrdinalIgnoreCase)) return "";

                tmpPath = parentPath;
            }
        }
    }
}


