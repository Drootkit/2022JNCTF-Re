/*
    一个SFX的自解压程序，仿照lyceum进行一个密码隐藏
    进去之后可以找到一个C#的程序
    首先会判断启动进程explorer，进行反调试
    正常情况下进行一个crc32微改对输入进行加密，不正常情况则进行重启
    CRC32进行的对输入的一个encode。
    真的：C0nf19ur1n9_Af1_15_V37y_P@1nfu1_@ffa17
    假的：7h@t'5_wh@t_You'11_d0_w1th_th3_d3bu993r
    打开sfx的时候，背景是一个docx文档，然后该弹什么弹什么
    通过检查
*/

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Threading;


// 进行一个crc32的过程。
class f506ea0b732ed5
{
    static char[] x = {' ', '\t', '\r', 'z', '_', '\n'};

    static long[] c631427085f5383 =  {
        2352429337, 404171025, 403904920, 504590376, 471216289, 437672209, 303059104, 202834080, 471216289, 403904920, 
        437672209, 2553487393, 2218065969, 504590376, 471216289, 2553487393, 471216289, 236077113, 2553487393, 2586988577, 
        336857481, 101742865, 101992840, 2553487393, 2150898065, 2150898049, 471216289, 403904920, 504590376, 303059104, 
        471216289, 2553487393, 2150898049, 504590376, 504590376, 1318952, 471216289, 101742865
    };
    
    static UInt32[] c0fd5442b55ae36c452a80216b78d =  {
      0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
      0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
      0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
      0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
      0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
      0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
      0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
      0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
      0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
      0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
      0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
      0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
      0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
      0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
      0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
      0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
      0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
      0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
      0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
      0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
      0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
      0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
      0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
      0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
      0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
      0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
      0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
      0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
      0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
      0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
      0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
      0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
    };

    // 这个是真正的flag的判断方式，位移后异或然后根据表中的值进行查找，查找之后和新的数组进行比较，之后进行计算出一个值来和恭喜你成功的字符串进行生成后打印。

    public static void a8024a5a223063ca0f93442436138()
    {
        long [] res = new long [128];

        Console.Write("Please Input The Flag: ");
        string in2 = Console.ReadLine();

        int len = in2.Length;
        int i=0;
        int flag=0;
        for(UInt32 j = 0; j<len; j++, i++)
        {   
            //这里注意计算的优先级，和python默认的优先级不一样。
            res[i] = (c0fd5442b55ae36c452a80216b78d[(in2[i] | 0x10) + 32] ^ (in2[i] - 32)) & 0x9e3779b9;
            if (res[i] != c631427085f5383[i])
            {
                flag++;
            }
        }

        if(flag-0 != 0)
        {
            switch (flag % 2)
            {
                case 0:
                    d442019e47fc59f23f80f9bc668eca2.ETKoudGXzdT();
                    break;
                case 1:
                    d442019e47fc59f23f80f9bc668eca2.i2nfyPFq();
                    break;
                case 2:
                    d442019e47fc59f23f80f9bc668eca2.tzzkbA35F();
                    break;
            }
        }
        else
        {
            MessageBox.Show("Congratulations "+Environment.UserName+" you reverse me!!");
        }
    }

    // 这是发现不是正常启动的判断flag，这是一个假的flag
    public static void ZRTwsmv6v4n()
    {
            int[] cmp = {23, 97, 77, 14, 120, 63, 127, 126, 101, 58, 43, 85, 121, 102, 120, 93, 110, 59, 127, 109, 61, 37, 40, 59, 84, 97, 82, 14, 55, 57, 127, 109, 62, 24, 42, 51, 25, 58, 127};
            int [] res = new int[52];
            string ins;
            int i=0;

            Console.WriteLine("Please input the Flag: ");
            ins = Console.ReadLine();
            foreach(int item in ins)
            {
                res[i] =(char) (item ^ x[i++ % x.Length]);
                if(res[i-1] != cmp[i-1])
                {
                    d442019e47fc59f23f80f9bc668eca2.ETKoudGXzdT();//输入假的flag直接关机
                }
                else
                {
                    // 假的flag输入之后输对了就会出现这个，告诉他这是假的flag，这要是都看不出来就可以去死了
                    MessageBox.Show("Congratulations "+Environment.UserName+" you reverse me??");
                    Thread.Sleep(300);
                    Console.WriteLine("############    $$$$$$$$$$$$$$");
                    Console.WriteLine("#               $             $ ");
                    Console.WriteLine("#               $              $ ");
                    Console.WriteLine("#               $             $");
                    Console.WriteLine("#############   $$$$$$$$$$$$$$");
                    Console.WriteLine("            #   $             $");
                    Console.WriteLine("            #   $              $");
                    Console.WriteLine("            #   $            $");
                    Console.WriteLine("#############   $$$$$$$$$$$$$");
                    Console.WriteLine("HaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHaHawhat to you do ** hacker?\n");
                    Thread.Sleep(2000);
                    d442019e47fc59f23f80f9bc668eca2.i2nfyPFq();
                    break;
                }
            }
    }
}

//关机，重启，注销，这是对非explorer进程启动的惩罚。
class d442019e47fc59f23f80f9bc668eca2
{
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref   IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref   long pluid);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool ExitWindowsEx(int flg, int rea);

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        internal const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        internal const int EWX_LOGOFF = 0x00000000;
        internal const int EWX_SHUTDOWN = 0x00000001;
        internal const int EWX_REBOOT = 0x00000002;
        internal const int EWX_FORCE = 0x00000004;
        internal const int EWX_POWEROFF = 0x00000008;
        internal const int EWX_FORCEIFHUNG = 0x00000010;

        private static void DoExitWin(int flg)
        {
            bool ok;
            TokPriv1Luid tp;
            IntPtr hproc = GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            ok = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref   htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            ok = LookupPrivilegeValue(null, SE_SHUTDOWN_NAME, ref   tp.Luid);
            ok = AdjustTokenPrivileges(htok, false, ref   tp, 0, IntPtr.Zero, IntPtr.Zero);
            ok = ExitWindowsEx(flg, 0);
        }

        public static void i2nfyPFq()
        {
            // Console.WriteLine("reboot");
            DoExitWin(EWX_FORCE | EWX_REBOOT); //重启
        }

        public static void ETKoudGXzdT()
        {
            // Console.WriteLine("shutdown");
            DoExitWin(EWX_FORCE | EWX_POWEROFF);    //关机
        }

        public static void tzzkbA35F()
        {
            // Console.WriteLine("zhuxiao");
            DoExitWin(EWX_FORCE | EWX_LOGOFF);      //注销
        }

}

//  https://bbs.csdn.net/topics/390206295   找到父进程
public static class ProcessExtensions 
{ 
        private static string FindIndexedProcessName(int pid) 
        {
            //var是一个推断类型, 根据程序实际进行赋值
            var processName = Process.GetProcessById(pid).ProcessName;
            var processesByName = Process.GetProcessesByName(processName);
            string processIndexdName = null;

            for (var index = 0; index < processesByName.Length; index++)
            {
                processIndexdName = index == 0 ? processName : processName + "#" + index;
                var processId = new PerformanceCounter("Process", "ID Process", processIndexdName); 
                if ((int)processId.NextValue() == pid) 
                { 
                    return processIndexdName; 
                }
            }
            return processIndexdName; 
        } 
 
        private static Process FindPidFromIndexedProcessName(string indexedProcessName) 
        { 
            var parentId = new PerformanceCounter("Process", "Creating Process ID", indexedProcessName); 
            return Process.GetProcessById((int)parentId.NextValue()); 
        } 
 
        public static Process Parent(this Process process) 
        { 
            return FindPidFromIndexedProcessName(FindIndexedProcessName(process.Id));
        } 
}

class db3a4a2828e7fe755c7d8061105ea07b
{
    static void Main(string[] args)
    {
        try
        {
            DriveInfo driveInfo = new DriveInfo("C");
            long s = driveInfo.TotalSize/1024/1024/1024;

            Console.WriteLine("Hello "+ Environment.UserName +". Are you ready to reverse me ?");
            Thread.Sleep(500);

            //判断该程序是不是由explorer进程启动的，不然就直接退出。
            if(Equals(Process.GetCurrentProcess().Parent().ProcessName, "explorer") && s < 99 )
            {
                f506ea0b732ed5.a8024a5a223063ca0f93442436138();
            }
            else
            {
                f506ea0b732ed5.ZRTwsmv6v4n();
            }
        }
        catch
        {
            MessageBox.Show("Hello "+Environment.UserName);
        }
    }
}