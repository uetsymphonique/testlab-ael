# FwPolicySvc — Flow

**Entry:** `FirewallPolicy.Main(string[] args)` · **Artifact summary:** in-process COM writes to the registry-backed Windows Firewall policy store — rule profile scope changed, rule added, or rule removed

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1 | FwPolicySvc.exe XOR-decodes two firewall COM ProgIDs into memory | — [no-artifact] → #2 #5 | Stealth / T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File | PE holds no plaintext ProgID strings; both are position-dependent XOR byte arrays |
| 2 | FwPolicySvc.exe instantiates the firewall policy COM server in-process (Type.GetTypeFromProgID + Activator.CreateInstance) | FirewallAPI.dll loaded in-process [memory] → #3 | Execution / T1559.001 — Inter-Process Communication: Component Object Model | in-proc COM activation; FirewallAPI.dll is normally loaded by the Windows Firewall console or netsh |
| 3 | FwPolicySvc.exe resolves the target rule by name (INetFwPolicy2.Rules propget + INetFwRules.Item) | — [no-artifact] → #4 #5 #8 | Discovery / T1012 — Query Registry | read-only name lookup in the rules collection |
| 4 | FwPolicySvc.exe overwrites the resolved rule's Profiles mask (INetFwRule.Profiles propput) | rule profile scope in policy store [registry] | Defense Impairment / T1686.003 — Disable or Modify System Firewall: Windows Host Firewall | existing rule scope normally edited via Windows Firewall console or netsh; store is registry-backed |
| 5 | FwPolicySvc.exe builds a new rule object and sets Name/Protocol/LocalPorts/Direction/Action/Enabled/Profiles (INetFwRule propputs) | in-memory rule object [no-artifact] → #6 | Defense Impairment / T1686.003 — Disable or Modify System Firewall: Windows Host Firewall | in-memory only; not yet persisted |
| 6 | FwPolicySvc.exe commits the new rule to the store (INetFwRules.Add) | new inbound allow rule in policy store [registry] | Defense Impairment / T1686.003 — Disable or Modify System Firewall: Windows Host Firewall | inbound allow rules normally created via Windows Firewall console or netsh |
| 7 | FwPolicySvc.exe removes a rule from the store by name (INetFwRules.Remove) | firewall rule removed from policy store [registry] | Defense Impairment / T1686.003 — Disable or Modify System Firewall: Windows Host Firewall | rule removal normally performed via Windows Firewall console or netsh |
| 8 | FwPolicySvc.exe reads and prints the resolved rule's properties to stdout (INetFwRule propgets) | — [no-artifact] | Discovery / T1012 — Query Registry | read-only property dump; caller may redirect stdout to a file |
