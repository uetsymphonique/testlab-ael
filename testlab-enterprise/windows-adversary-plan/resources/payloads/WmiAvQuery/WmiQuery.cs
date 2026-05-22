using System;
using System.Management;

class WmiQuery {
    // Dead constant: never read at runtime (T1027.016 junk insertion)
    static readonly int kPad = unchecked((int)0xCAFEBABE);

    // Dead method: never called (T1027.016 junk insertion)
    static void Stub(int x) {
        int r = x ^ kPad;
        if (r < 0) Console.WriteLine(r);
    }

    static void Main() {
        // Dead computation: result never used (T1027.016 junk insertion)
        int unused = kPad >> 1;

        string ns  = @"ROOT\SecurityCenter2";
        string wql = "SELECT * FROM AntiVirusProduct";
        try {
            ManagementScope scope      = new ManagementScope(ns);
            scope.Connect();
            ObjectQuery q              = new ObjectQuery(wql);
            ManagementObjectSearcher s = new ManagementObjectSearcher(scope, q);
            int n = 0;
            foreach (ManagementObject o in s.Get()) {
                n++;
                Console.WriteLine("[*] AV #{0}: {1} | State: 0x{2:X}", n, o["displayName"], o["productState"]);
            }
            s.Dispose();
            Console.WriteLine("[+] Total: {0}", n);
        }
        catch (Exception ex) { Console.WriteLine("[!] {0}", ex.Message); }
    }
}
