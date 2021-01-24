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

namespace BuildTool
{
    // Build utility for Win32
    public static class Win32BuildTool
    {
        // Generate a version information resource
        public static void GenerateVersionInfoResource(string targetExeName, string outName, string rc_name, string product_name, string postfix, string commitId, string verLabel)
        {
            int build, version;
            string name;
            DateTime date;

            if (Str.IsEmptyStr(commitId))
            {
                commitId = "unknown";
            }

            ReadBuildInfoFromTextFile(out build, out version, out name, out date);

            if (Str.IsEmptyStr(rc_name))
            {
                rc_name = "ver.rc";
            }

            string templateFileName = Path.Combine(Paths.UltraBuildFilesDirName, @"VerScript\" + rc_name);
            string body = Str.ReadTextFile(templateFileName);

            string exeFileName = Path.GetFileName(targetExeName);

            exeFileName += " (Ultra: " + verLabel + ", " + commitId + ")";

            if (Str.IsEmptyStr(product_name))
            {
                product_name = "Unknown Product";
            }

            string internalName = product_name;

            if (Str.IsEmptyStr(postfix) == false)
            {
                internalName += " " + postfix;
            }

            body = Str.ReplaceStr(body, "$PRODUCTNAME$", product_name);

            body = Str.ReplaceStr(body, "$INTERNALNAME$", internalName);
            body = Str.ReplaceStr(body, "$YEAR$", date.Year.ToString());
            body = Str.ReplaceStr(body, "$FILENAME$", exeFileName);
            body = Str.ReplaceStr(body, "$VER_MAJOR$", (version / 100).ToString());
            body = Str.ReplaceStr(body, "$VER_MINOR$", (version % 100).ToString());
            body = Str.ReplaceStr(body, "$VER_BUILD$", build.ToString());

            IO f = IO.CreateTempFileByExt(".rc");
            string filename = f.Name;

            f.Write(Str.AsciiEncoding.GetBytes(body));

            f.Close();

            ExecCommand(Paths.RcFilename, "/nologo \"" + filename + "\"");

            string rcDir = Path.GetDirectoryName(filename);
            string rcFilename = Path.GetFileName(filename);
            string rcFilename2 = Path.GetFileNameWithoutExtension(rcFilename);

            string resFilename = Path.Combine(rcDir, rcFilename2) + ".res";

            IO.MakeDirIfNotExists(Path.GetDirectoryName(outName));

            IO.FileCopy(resFilename, outName, true, false);
        }

        // Flush to disk
        public static void Flush()
        {
            string txt = IO.CreateTempFileNameByExt(".txt");
            byte[] ret = Secure.Rand(64);

            FileStream f = File.Create(txt);

            f.Write(ret, 0, ret.Length);

            f.Flush();

            f.Close();

            File.Delete(txt);
        }

        // Write the build number and the version number in the text file
        public static void WriteBuildInfoToTextFile(int build, int version, string name, DateTime date)
        {
            string filename = Path.Combine(Paths.SolutionBaseDirName, "CurrentBuild.txt");

            WriteBuildInfoToTextFile(build, version, name, date, filename);
        }
        public static void WriteBuildInfoToTextFile(int build, int version, string name, DateTime date, string filename)
        {
            using (StreamWriter w = new StreamWriter(filename))
            {
                w.WriteLine("BUILD_NUMBER {0}", build);
                w.WriteLine("VERSION {0}", version);
                w.WriteLine("BUILD_NAME {0}", name);
                w.WriteLine("BUILD_DATE {0}", Str.DateTimeToStrShort(date));

                w.Flush();
                w.Close();
            }
        }

        // Read the build number and the version number from a text file
        public static void ReadBuildInfoFromTextFile(out int build, out int version, out string name, out DateTime date)
        {
            string filename = Path.Combine(Paths.SolutionBaseDirName, "CurrentBuild.txt");

            ReadBuildInfoFromTextFile(out build, out version, out name, out date, filename);
        }
        public static void ReadBuildInfoFromTextFile(out int build, out int version, out string name, out DateTime date, string filename)
        {
            char[] seps = { '\t', ' ', };
            name = "";
            date = new DateTime(0);

            using (StreamReader r = new StreamReader(filename))
            {
                build = version = 0;

                while (true)
                {
                    string line = r.ReadLine();
                    if (line == null)
                    {
                        break;
                    }

                    string[] tokens = line.Split(seps, StringSplitOptions.RemoveEmptyEntries);
                    if (tokens.Length == 2)
                    {
                        if (tokens[0].Equals("BUILD_NUMBER", StringComparison.InvariantCultureIgnoreCase))
                        {
                            build = int.Parse(tokens[1]);
                        }

                        if (tokens[0].Equals("VERSION", StringComparison.InvariantCultureIgnoreCase))
                        {
                            version = int.Parse(tokens[1]);
                        }

                        if (tokens[0].Equals("BUILD_NAME", StringComparison.InvariantCultureIgnoreCase))
                        {
                            name = tokens[1];

                            name = Str.ReplaceStr(name, "-", "_");
                        }

                        if (tokens[0].Equals("BUILD_DATE", StringComparison.InvariantCultureIgnoreCase))
                        {
                            date = Str.StrToDateTime(tokens[1]);
                        }
                    }
                }

                r.Close();

                if (build == 0 || version == 0 || Str.IsEmptyStr(name) || date.Ticks == 0)
                {
                    throw new ApplicationException(string.Format("Wrong file data: '{0}'", filename));
                }
            }
        }

        // Command execution
        public static void ExecCommand(string exe, string arg, bool shell_execute = false, bool no_stdout = false)
        {
            string outputStr = "";

            Process p = new Process();
            p.StartInfo.FileName = exe;
            p.StartInfo.Arguments = arg;
            p.StartInfo.UseShellExecute = shell_execute;

            if (no_stdout)
            {
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.RedirectStandardOutput = true;
            }

            if (shell_execute)
            {
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            }

            Con.WriteLine("Executing '{0} {1}'...", exe, arg);

            p.Start();

            p.WaitForExit();

            if (no_stdout)
            {
                string s1 = p.StandardOutput.ReadToEnd();
                string s2 = p.StandardError.ReadToEnd();
                outputStr = "---\r\n" + s1 + "\r\n" + s2 + "\r\n---\r\n";
            }

            int ret = p.ExitCode;
            if (ret != 0)
            {
                throw new ApplicationException(string.Format("Child process '{0}' returned error code {1}.\r\n{2}", exe, ret, outputStr));
            }

            Kernel.SleepThread(50);
        }
    }
}
