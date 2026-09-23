using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Windows.Security.FirewallPolicy
{
    internal static class X
    {
        internal static string S(byte[] b)
        {
            byte[] r = new byte[b.Length];
            for (int i = 0; i < b.Length; i++)
                r[i] = (byte)(b[i] ^ (byte)(0xA3 + i * 0x5B));
            return Encoding.ASCII.GetString(r);
        }

        internal static readonly byte[] _policy2 = new byte[] { 0xEB, 0xB0, 0x3C, 0xC0, 0x4C, 0x0C, 0xA2, 0x0E, 0x3D, 0xA1, 0x61, 0xE3, 0x8B, 0x2B, 0xFE, 0x81, 0x61 };
        internal static readonly byte[] _fwrule = new byte[] { 0xEB, 0xB0, 0x3C, 0xC0, 0x4C, 0x0C, 0xA2, 0x0E, 0x3D, 0xA1, 0x63, 0xF9, 0x8B, 0x27 };
    }

    internal static class FirewallPolicy
    {
        private const int PROFILE_DOMAIN = 0x1;
        private const int PROFILE_PRIVATE = 0x2;
        private const int PROFILE_PUBLIC = 0x4;
        private const int PROFILE_ALL = 0x7FFFFFFF;

        private const int PROTO_TCP = 6;
        private const int DIR_IN = 1;
        private const int ACTION_ALLOW = 1;

        private static object NewPolicy()
        {
            Type t = Type.GetTypeFromProgID(X.S(X._policy2));
            if (t == null) throw new InvalidOperationException("policy COM class unavailable");
            return Activator.CreateInstance(t);
        }

        private static object NewRule()
        {
            Type t = Type.GetTypeFromProgID(X.S(X._fwrule));
            if (t == null) throw new InvalidOperationException("rule COM class unavailable");
            return Activator.CreateInstance(t);
        }

        private static object Get(object o, string name)
        {
            return o.GetType().InvokeMember(name, BindingFlags.GetProperty, null, o, null);
        }

        private static void Set(object o, string name, object value)
        {
            o.GetType().InvokeMember(name, BindingFlags.SetProperty, null, o, new object[] { value });
        }

        private static object Call(object o, string name, params object[] args)
        {
            return o.GetType().InvokeMember(name, BindingFlags.InvokeMethod, null, o, args);
        }

        private static object Find(object rules, string name)
        {
            try { return Call(rules, "Item", name); }
            catch (TargetInvocationException) { return null; }
            catch (COMException) { return null; }
        }

        private static int ParseProfiles(string spec)
        {
            switch ((spec ?? "domain").ToLowerInvariant())
            {
                case "domain": return PROFILE_DOMAIN;
                case "private": return PROFILE_PRIVATE;
                case "public": return PROFILE_PUBLIC;
                case "all":
                case "any": return PROFILE_ALL;
                default:
                    if (spec.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        return Convert.ToInt32(spec.Substring(2), 16);
                    return int.Parse(spec);
            }
        }

        private static string FormatProfiles(int mask)
        {
            if (mask == PROFILE_ALL) return "all (0x7FFFFFFF)";
            System.Collections.Generic.List<string> parts = new System.Collections.Generic.List<string>();
            if ((mask & PROFILE_DOMAIN) != 0) parts.Add("domain");
            if ((mask & PROFILE_PRIVATE) != 0) parts.Add("private");
            if ((mask & PROFILE_PUBLIC) != 0) parts.Add("public");
            return string.Join(",", parts.ToArray()) + string.Format(" (0x{0:X})", mask);
        }

        private static int CmdShow(string name)
        {
            object rule = Find(Get(NewPolicy(), "Rules"), name);
            if (rule == null) { Console.WriteLine("[-] rule not found: " + name); return 1; }
            Console.WriteLine("[+] name={0}", Get(rule, "Name"));
            Console.WriteLine("    enabled={0}", Get(rule, "Enabled"));
            Console.WriteLine("    direction={0}", Get(rule, "Direction"));
            Console.WriteLine("    action={0}", Get(rule, "Action"));
            Console.WriteLine("    protocol={0}", Get(rule, "Protocol"));
            Console.WriteLine("    localports={0}", Get(rule, "LocalPorts"));
            Console.WriteLine("    remoteaddresses={0}", Get(rule, "RemoteAddresses"));
            Console.WriteLine("    profiles={0}", FormatProfiles(Convert.ToInt32(Get(rule, "Profiles"))));
            return 0;
        }

        private static int CmdSetProfiles(string name, string spec)
        {
            int mask = ParseProfiles(spec);
            object rule = Find(Get(NewPolicy(), "Rules"), name);
            if (rule == null) { Console.WriteLine("[-] rule not found: " + name); return 1; }
            Set(rule, "Profiles", mask);
            Console.WriteLine("[+] rule '{0}' profiles set to {1}", name, FormatProfiles(mask));
            return 0;
        }

        private static int CmdAdd(string name, string port, string spec, string remote)
        {
            int mask = ParseProfiles(spec);
            object rules = Get(NewPolicy(), "Rules");
            if (Find(rules, name) != null) { Console.WriteLine("[-] rule already exists: " + name); return 1; }
            object rule = NewRule();
            Set(rule, "Name", name);
            Set(rule, "Protocol", PROTO_TCP);
            Set(rule, "LocalPorts", port);
            Set(rule, "Direction", DIR_IN);
            Set(rule, "Action", ACTION_ALLOW);
            Set(rule, "Enabled", true);
            Set(rule, "Profiles", mask);
            if (!string.IsNullOrEmpty(remote)) Set(rule, "RemoteAddresses", remote);
            Call(rules, "Add", rule);
            Console.WriteLine("[+] rule '{0}' added (tcp/{1}, profiles={2}{3})",
                name, port, FormatProfiles(mask), string.IsNullOrEmpty(remote) ? "" : ", remote=" + remote);
            return 0;
        }

        private static int CmdDel(string name)
        {
            Call(Get(NewPolicy(), "Rules"), "Remove", name);
            Console.WriteLine("[+] rule '{0}' removed", name);
            return 0;
        }

        private static void Usage()
        {
            Console.WriteLine("FwPolicySvc.exe <command> [args]");
            Console.WriteLine();
            Console.WriteLine("  show <ruleName>                                         print a rule's settings");
            Console.WriteLine("  setprofiles <ruleName> <domain|private|public|all|0xMASK>  change a rule's profile scope");
            Console.WriteLine("  add <ruleName> <port> [profileSpec] [remoteAddr]        add an inbound TCP allow rule");
            Console.WriteLine("  del <ruleName>                                          remove a rule");
            Console.WriteLine();
            Console.WriteLine("Requires administrator or SYSTEM.");
        }

        [STAThread]
        private static int Main(string[] args)
        {
            try
            {
                if (args.Length == 0) { Usage(); return 2; }
                switch (args[0].ToLowerInvariant())
                {
                    case "show":
                        if (args.Length < 2) { Usage(); return 2; }
                        return CmdShow(args[1]);
                    case "setprofiles":
                        if (args.Length < 3) { Usage(); return 2; }
                        return CmdSetProfiles(args[1], args[2]);
                    case "add":
                        if (args.Length < 3) { Usage(); return 2; }
                        return CmdAdd(args[1], args[2], args.Length > 3 ? args[3] : "domain", args.Length > 4 ? args[4] : null);
                    case "del":
                        if (args.Length < 2) { Usage(); return 2; }
                        return CmdDel(args[1]);
                    default:
                        Usage(); return 2;
                }
            }
            catch (Exception ex)
            {
                Exception inner = (ex is TargetInvocationException && ex.InnerException != null) ? ex.InnerException : ex;
                Console.WriteLine("[-] " + inner.Message);
                return 1;
            }
        }
    }
}
