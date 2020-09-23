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
	public static class BuildToolCommands
	{
		// Test processing
		[ConsoleCommandMethod(
			"Run Test Procedure.",
			"Test",
			"Run Test Procedure."
			)]
		static int Test(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			TestClass.Test();

			return 0;
		}

		// Check the stb file consistency
		[ConsoleCommandMethod(
			"Check the stb file consistency",
			"StbChecker [dir]",
			"Check the stb file consistency",
			"[dir]:Specify the target directory."
			)]
        static int StbChecker(ConsoleService c, string cmdName, string str)
        {
			ConsoleParam[] args =
			{
				new ConsoleParam("[dir]"),
            };
            ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			string hamcore_dir = vl.DefaultParam.StrValue;

			if (Str.IsEmptyStr(hamcore_dir))
			{
				hamcore_dir = Path.Combine(Paths.UltraBinDirName, "hamcore");
			}

			string[] stb_files = Directory.GetFiles(hamcore_dir, "*.stb", SearchOption.TopDirectoryOnly);

            if (stb_files.Length == 0)
            {
                Console.WriteLine("Error: There are no .stb files in the directory '" + hamcore_dir + "'.");
                return -1;
            }

            int total_num = 0;

            for (int i = 0; i < stb_files.Length; i++)
            {
                for (int j = 0; j < stb_files.Length; j++)
                {
                    if (i != j)
                    {
                        Console.WriteLine("---\nComparing '{1}' to '{0}'...", Path.GetFileName(stb_files[i]), Path.GetFileName(stb_files[j]));

                        total_num += Stb.Compare(stb_files[i], stb_files[j]);
                    }
                }
            }

            Console.WriteLine("--- Results ---");
            if (total_num == 0)
            {
                Console.WriteLine("OK: Excellent! There are no errors between multilanguage stb files.");
                Console.WriteLine();
                Console.WriteLine("   - In Jurassic Park: \"It's a UNIX system! I know this!\"");
                return 0;
            }
            else
            {
                Console.WriteLine($"ERROR: There are {total_num} errors on multilanguage stb files.");
                return -3;
            }
        }

        // Set the version of the PE to 4
        [ConsoleCommandMethod(
			"Set the version of the PE file to 4.",
			"SetPE4 [filename]",
			"Set the version of the PE file to 4.",
			"[filename]:Specify the target filename."
			)]
		static int SetPE4(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[filename]", ConsoleService.Prompt, "Filename: ", ConsoleService.EvalNotEmpty, null)
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			PEUtil.SetPEVersionTo4(vl.DefaultParam.StrValue);

			return 0;
		}

		// Set the Manifest
		[ConsoleCommandMethod(
			"Set the manifest to the executable file.",
			"SetManifest [filename] [/MANIFEST:manifest_file_name]",
			"Set the manifest to the executable file.",
			"[filename]:Specify the target executable filename.",
			"MANIFEST:Specify the manifest XML file."
			)]
		static int SetManifest(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[filename]", ConsoleService.Prompt, "Target Filename: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("MANIFEST", ConsoleService.Prompt, "Manifest Filename: ", ConsoleService.EvalNotEmpty, null),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			PEUtil.SetManifest(vl.DefaultParam.StrValue, vl["MANIFEST"].StrValue);

			return 0;
		}

		// Generate a version information resource
		[ConsoleCommandMethod(
			"Generate a Version Information Resource File.",
			"GenerateVersionResource [targetFileName] [/OUT:destFileName]",
			"Generate a Version Information Resource File.",
			"[targetFileName]:Specify the target exe/dll file name.",
			"OUT:Specify the output .res file.",
			"RC:Specify a template RC file name.")]
		static int GenerateVersionResource(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[targetFileName]", ConsoleService.Prompt, "Target Filename: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("OUT", ConsoleService.Prompt, "Dst Filename: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("PRODUCT"),
				new ConsoleParam("RC"),
				new ConsoleParam("POSTFIX"),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			string targetFilename = vl.DefaultParam.StrValue;
			string outFilename = vl["OUT"].StrValue;
			string product_name = vl["PRODUCT"].StrValue;
			string postfix = vl["POSTFIX"].StrValue;

			Win32BuildTool.GenerateVersionInfoResource(targetFilename, outFilename, vl["RC"].StrValue, product_name, postfix, Paths.GetUltraSubmoduleCommitId());

			return 0;
		}

		// Measure the number of lines of code
		[ConsoleCommandMethod(
			"Count the number of lines of the sources.",
			"Count [DIR]",
			"Count the number of lines of the sources.",
			"[DIR]:dir name.")]
		static int Count(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[DIR]", null, null, null, null),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			string dir = vl.DefaultParam.StrValue;
			if (Str.IsEmptyStr(dir))
			{
				dir = Paths.SolutionBaseDirName;
			}

			string[] files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);

			int numLines = 0;
			int numBytes = 0;
			int numComments = 0;
			int totalLetters = 0;

			Dictionary<string, int> commentsDict = new Dictionary<string, int>();

			foreach (string file in files)
			{
				string ext = Path.GetExtension(file);

				if (Str.StrCmpi(ext, ".c") || Str.StrCmpi(ext, ".cpp") || Str.StrCmpi(ext, ".h") ||
                    Str.StrCmpi(ext, ".rc") || Str.StrCmpi(ext, ".stb") || Str.StrCmpi(ext, ".cs")
                     || Str.StrCmpi(ext, ".fx") || Str.StrCmpi(ext, ".hlsl"))
				{
					if (Str.InStr(file, "\\.svn\\") == false && Str.InStr(file, "\\seedll\\") == false && Str.InStr(file, "\\see\\") == false && Str.InStr(file, "\\openssl\\") == false)
					{
						string[] lines = File.ReadAllLines(file);

						numLines += lines.Length;
						numBytes += (int)new FileInfo(file).Length;

						foreach (string line in lines)
						{
							if (Str.InStr(line, "//") && Str.InStr(line, "// Validate arguments") == false)
							{
								if (commentsDict.ContainsKey(line) == false)
								{
									commentsDict.Add(line, 1);
								}
								numComments++;

								totalLetters += line.Trim().Length - 3;
							}
						}
					}
				}
			}

			Con.WriteLine("{0} Lines,  {1} Bytes.  {2} Comments ({3} distinct, aver: {4})", Str.ToStr3(numLines), Str.ToStr3(numBytes),
				Str.ToStr3(numComments), commentsDict.Count, totalLetters / numComments);

			return 0;
		}

		// Copy the file
		[ConsoleCommandMethod(
			"Copy a File.",
			"FileCopy [src] [/DEST:dest]",
			"Copy a File.",
			"[src]:Specify the source file.",
			"DEST:Specify the destination file.")]
		static int FileCopy(ConsoleService c, string cmdName, string str)
		{
			ConsoleParam[] args =
			{
				new ConsoleParam("[src]", ConsoleService.Prompt, "Src Filename: ", ConsoleService.EvalNotEmpty, null),
				new ConsoleParam("DEST", ConsoleService.Prompt, "Dst Filename: ", ConsoleService.EvalNotEmpty, null),
			};
			ConsoleParamValueList vl = c.ParseCommandList(cmdName, str, args);

			string destFileName = vl["DEST"].StrValue;
			string srcFileName = vl.DefaultParam.StrValue;

			IO.FileCopy(srcFileName, destFileName, true, false);

			return 0;
		}
	}
}

