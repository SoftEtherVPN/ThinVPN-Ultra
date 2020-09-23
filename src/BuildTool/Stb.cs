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
using System.Collections.Generic;
using System.IO;
using CoreUtil;

public class StbTable
{
    List<string> tagList;
    public string[] TagList
    {
        get
        {
            return tagList.ToArray();
        }
    }

    string name;
    public string Name
    {
        get { return name; }
    }

    string str;
    public string String
    {
        get { return str; }
    }

    public StbTable(string name, string str)
    {
        this.name = name;
        this.str = str;

        tagList = ParseTagList(str);
    }

    public static string UnescapeStr(string str)
    {
        int i, len;
        string tmp;

        len = str.Length;
        tmp = "";

        for (i = 0; i < len; i++)
        {
            if (str[i] == '\\')
            {
                i++;
                switch (str[i])
                {
                    case '\\':
                        tmp += '\\';
                        break;

                    case ' ':
                        tmp += ' ';
                        break;

                    case 'n':
                    case 'N':
                        tmp += '\n';
                        break;

                    case 'r':
                    case 'R':
                        tmp += '\r';
                        break;

                    case 't':
                    case 'T':
                        tmp += '\t';
                        break;
                }
            }
            else
            {
                tmp += str[i];
            }
        }

        return tmp;
    }

    public static StbTable ParseTableLine(string line, ref string prefix)
    {
        int i, len;
        int string_start;
        int len_name;
        string name, name2;

        line = line.TrimStart(' ', '\t');
        len = line.Length;
        if (len == 0)
        {
            return null;
        }

        if (line[0] == '#' || (line[0] == '/' && line[1] == '/'))
        {
            return null;
        }

        bool b = false;
        len_name = 0;
        for (i = 0; i < line.Length; i++)
        {
            if (line[i] == ' ' || line[i] == '\t')
            {
                b = true;
                break;
            }
            len_name++;
        }

        if (b == false)
        {
            return null;
        }

        name = line.Substring(0, len_name);

        string_start = len_name;
        for (i = len_name; i < len; i++)
        {
            if (line[i] != ' ' && line[i] != '\t')
            {
                break;
            }
            string_start++;
        }
        if (i == len)
        {
            return null;
        }

        string str = line.Substring(string_start);

        str = UnescapeStr(str);

        if (Str.StrCmpi(name, "PREFIX"))
        {
            prefix = str;
            prefix = prefix.TrimStart();

            if (Str.StrCmpi(prefix, "$") || Str.StrCmpi(prefix, "NULL"))
            {
                prefix = "";
            }

            return null;
        }

        name2 = "";

        if (prefix != "")
        {
            name2 += prefix + "@";
        }

        name2 += name;

        return new StbTable(name2, str);
    }

    public static bool CompareTagList(string[] list1, string[] list2)
    {
        if (list1.Length != list2.Length)
        {
            return false;
        }

        int i;
        for (i = 0; i < list1.Length; i++)
        {
            if (list1[i] != list2[i])
            {
                return false;
            }
        }

        return true;
    }

    public static List<string> ParseTagList(string str)
    {
        List<string> list = new List<string>();
        int i, len;
        int mode = 0;
        string tmp = "";

        str += "_";

        len = str.Length;

        for (i = 0; i < len; i++)
        {
            char c = str[i];

            if (mode == 0)
            {
                switch (c)
                {
                    case '%':
                        if (str[i + 1] == '%')
                        {
                            i++;
                            tmp += c;
                        }
                        else
                        {
                            mode = 1;
                            tmp = "" + c;
                        }
                        break;

                    default:
                        tmp = "" + c;
                        break;
                }
            }
            else
            {
                string tag;

                switch (c)
                {
                    case 'c':
                    case 'C':
                    case 'd':
                    case 'i':
                    case 'o':
                    case 'u':
                    case 'x':
                    case 'X':
                    case 'e':
                    case 'E':
                    case 'f':
                    case 'g':
                    case 'G':
                    case 'n':
                    case 'N':
                    case 's':
                    case 'S':
                    case 'r':
                    case ' ':
                        tmp += c;
                        tag = tmp;
                        list.Add(tag);
                        mode = 0;
                        break;
                    default:
                        tmp += c;
                        break;
                }
            }
        }

        return list;
    }
}

public class Stb
{
    Dictionary<string, StbTable> tableList;
    string name;
    public string Name
    {
        get { return name; }
    }

    public Stb(string fileName)
    {
        init(File.ReadAllBytes(fileName), fileName);
    }

    public Stb(string fileName, string name)
    {
        init(File.ReadAllBytes(fileName), name);
    }

    public Stb(byte[] data, string name)
    {
        init(data, name);
    }

    void init(byte[] data, string name)
    {
        if (data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf)
        {
            byte[] tmp = new byte[data.Length - 3];
            Array.Copy(data, 3, tmp, 0, data.Length - 3);
            data = tmp;
        }

        StringReader sr = new StringReader(Str.Utf8Encoding.GetString(data));
        tableList = new Dictionary<string, StbTable>();

        this.name = name;
        string prefix = "";

        while (true)
        {
            string tmp = sr.ReadLine();
            if (tmp == null)
            {
                break;
            }

            StbTable t = StbTable.ParseTableLine(tmp, ref prefix);
            if (t != null)
            {
                if (tableList.ContainsKey(t.Name.ToUpper()) == false)
                {
                    tableList.Add(t.Name.ToUpper(), t);
                }
                else
                {
                    ShowWarning(name, string.Format("Duplicated '{0}'", t.Name));
                }
            }
        }
    }

    protected static void ShowWarning(string name, string str)
    {
        Console.WriteLine("{0}: Warning: {1}", name, str);
    }

    protected static void ShowError(string name, string str)
    {
        Console.WriteLine("{0}: Error: {1}", name, str);
    }

    public static int Compare(string file1, string file2)
    {
        Stb stb1 = new Stb(file1, "File1");
        Stb stb2 = new Stb(file2, "File2");
        int num = 0;

        string file1_fn = Path.GetFileName(file1);
        string file2_fn = Path.GetFileName(file2);

        foreach (string name1 in stb1.tableList.Keys)
        {
            if (name1.Equals("DEFAULT_FONT_WIN7", StringComparison.InvariantCultureIgnoreCase) ||
                name1.Equals("DEFAULT_FONT_HIGHDPI", StringComparison.InvariantCultureIgnoreCase))
            {
                continue;
            }

            StbTable t1 = stb1.tableList[name1];

            if (stb2.tableList.ContainsKey(name1) == false)
            {
                ShowError(stb2.name, string.Format("Missing '{0}'", t1.Name));
                num++;
            }
            else
            {
                StbTable t2 = stb2.tableList[name1];

                if (StbTable.CompareTagList(t1.TagList, t2.TagList) == false)
                {
                    ShowError(stb2.name, string.Format("Difference printf-style parameters '{0}'", t1.Name));
                    num++;
                }
            }
        }

        Console.WriteLine("\nThere are {0} errors.\n\n{1}\n", num,
            (num == 0 ? "Good work! No problem!" : "You must correct them!"));

        return num;
    }
}
