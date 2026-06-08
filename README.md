# ATT&CK Evaluation Lab — Adversary Emulation Plans

Adversary emulation plans aligned with the **MITRE ATT&CK Evaluation** for testing detection capabilities of security products on a Windows Enterprise environment.

This repository is an extended version of the [ATT&CK Evaluations Library](https://github.com/attackevals/ael) by MITRE. The original content under `ael/` stores past adversary emulation scenarios used as reference. Current plans under `testlab-enterprise/` are independently designed to the technique scope MITRE published for this evaluation year.

---

## Technique Scope

Two scenarios define the mandatory technique scope for this evaluation:

| File | Scenario | Focus |
|---|---|---|
| [`testlab-enterprise/mitre-outline/Scenario 1.md`](testlab-enterprise/mitre-outline/Scenario%201.md) | Crimeware-as-a-Service | Windows endpoint — ransomware / wipe endpoint chain |
| [`testlab-enterprise/mitre-outline/Scenario 2.md`](testlab-enterprise/mitre-outline/Scenario%202.md) | PRC Espionage Group | Enterprise-wide, cross-platform: Windows + Linux + AWS, APT-style |

All techniques added to any plan must appear in one of these two scope files.

---

## Current Plan: `windows-adversary-plan`

Located at [`testlab-enterprise/windows-adversary-plan/`](testlab-enterprise/windows-adversary-plan/).

Models a Windows Server 2022 Active Directory intrusion through three independent attack paths. All paths share the same lab environment (`testlab.local`); the server-side path is the longest chain and ends with destructive impact across IIS01 and DC01.

### Lab Environment

| Role | Hostname | IP |
|---|---|---|
| Domain Controller / DNS | `DC01` | `10.12.10.10` |
| IIS Server | `IIS01` | `10.12.10.20` |
| Workstation | `WS01` | `10.12.10.30` |
| Attacker machine | operator-controlled | `192.168.56.2` |

### Attack Paths

**Path 1 — HTML Smuggling** ([`html-smuggling-path/`](testlab-enterprise/windows-adversary-plan/Emulation_Plan/html-smuggling-path/))

User-driven path on WS01. Unrestricted file upload stages a malicious HTML lure on `upload.testlab.local`. The victim receives `cert_bundle.txt` via HTML smuggling, executes a copy-paste PowerShell chain, and an HTA dropper downloads dnscat2 + Herpaderping and establishes DNS C2 as the domain user.

**Path 2 — Toneshell Sideloading** ([`toneshell-path/`](testlab-enterprise/windows-adversary-plan/Emulation_Plan/toneshell-path/))

User-driven path on WS01. A fake update lure delivers a password-protected RAR archive. The victim extracts and double-clicks an LNK shortcut that triggers DLL sideloading of the Toneshell backdoor into `waitfor.exe` via `regsvr32.exe` + `mavinject.exe`, establishing TCP C2.

**Path 3 — IIS AppPool Escalation** ([`iis-apppool-escalation-path/`](testlab-enterprise/windows-adversary-plan/Emulation_Plan/iis-apppool-escalation-path/))

Server-side path: IIS01 → DC01. Five-phase chain:

| Phase | File | Key Behaviors |
|---|---|---|
| 1 — Initial Access & C2 | `Phase 1.md` | CVE-2025-55182 React RSC RCE → react2shell; EfsPotato SYSTEM; Herpaderping ghost; dnscat2 DNS C2 on IIS01 |
| 2 — Discovery & Credential Access | `Phase 2.md` | ReflectDump LSASS via `RtlCreateProcessReflection`; XOR-encrypted `f.elif`; exfil via react2shell; host & domain recon (WmiAvQuery, nltest, net group) |
| 3 — Lateral Movement & Persistence | `Phase 3.md` | Pass the Hash via go-thehash.exe; WMI + SCM dual-path execution on DC01; 4 persistence mechanisms (svcbackup account, WMI subscription, SYSVOL logon script, registry-backed service) |
| 4 — Collection & Exfiltration | `Phase 4.md` | NtdsRawDump.exe VSS shadow + direct volume access → NTDS harvest; in-memory ZIP + AES-256-CBC double encryption; NETLOGON relay staging; exfil via react2shell HTTP C2 |
| 5 — Impact | `Phase 5.md` | CertMaint.exe: VSS deletion, MSSQL$SQLEXPRESS stop, AES-256-CBC encrypt UploadPortalDB; logon-screen registry defacement + ransom notes on DC01 |

Plan summary and full Mermaid flow diagrams: [`Emulation_Plan/summary.md`](testlab-enterprise/windows-adversary-plan/Emulation_Plan/summary.md)

---

## Repository Layout

```
ael/                          # Reference: past MITRE ATT&CK Evaluation scenarios (read-only insight source)
  Enterprise/
    mustang_panda/
    scattered_spider/
    ...

testlab-enterprise/           # Active workspace — all current plans live here
  mitre-outline/
    Scenario 1.md             # Technique scope: Crimeware-as-a-Service
    Scenario 2.md             # Technique scope: PRC Espionage Group
    check.py                  # Technique coverage checker
  windows-adversary-plan/
    Emulation_Plan/
      html-smuggling-path/
      toneshell-path/
      iis-apppool-escalation-path/
      summary.md
    resources/
      payloads/               # Tools, exploits, and custom implants
      setup/                  # Lab infrastructure setup docs

plan-for-agent/               # Authoring methodology docs (guides for writing phases and criteria)
mitre-knowledge-base/         # Per-tactic ATT&CK technique theory
atomic-red-team/atomics/      # Atomic Red Team — concrete technique implementation examples
```

---

## Technique Coverage Check

Run from `testlab-enterprise/mitre-outline/` to verify plan coverage against the scope files:

```bash
# Check a full attack path directory against a scope file
python check.py --scope "Scenario 1.md" --folder ../windows-adversary-plan/Emulation_Plan/iis-apppool-escalation-path

# Check specific phase files
python check.py --scope "Scenario 1.md" Phase1.md Phase2.md

# Reset all marks in a scope file
python check.py --reset --scope "Scenario 1.md"
```

Out-of-scope entries are written to `<scope>_out_of_scope.csv`.

---

## Reference Libraries

| Path | Purpose |
|---|---|
| `plan-for-agent/` | Methodology docs: phase structure, detection criteria, category assignment, behavior breakdown, technique mapping |
| `mitre-knowledge-base/techniques/` | Per-tactic ATT&CK descriptions, sub-techniques, detection notes |
| `atomic-red-team/atomics/` | Concrete technique commands and test definitions (ART) |
| `ael/Enterprise/` | Past MITRE evaluation scenarios — insight only, not for copying |

---

## Authoring a New Phase

Consult [`CLAUDE.md`](CLAUDE.md) for the full workflow. Short path:

1. Select techniques from `Scenario 1.md` or `Scenario 2.md`.
2. Read theory in `mitre-knowledge-base/techniques/` and consult `atomic-red-team/atomics/` for implementation.
3. Write the Phase file per [`plan-for-agent/emulation-plan-structure.md`](plan-for-agent/emulation-plan-structure.md).
4. Before finalizing the Reference Table: write Detection Criteria for every row first (`plan-for-agent/guides/detection-criteria.md`), then assign Category labels (`plan-for-agent/guides/category-assignment.md`).
