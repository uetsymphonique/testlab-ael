# Attack Chain Templates

Reference templates for common attack chain patterns. Since the specific MITRE ATT&CK Evaluation scenarios have not been fully published, these templates are drawn from observed past scenarios to help predict likely cases from the published technique list.

## Phase 1

```mermaid
flowchart LR
    IA["Initial Access"] -->|"trigger payload"| EX1["Execution"]
    EX1 -. "establish channel (optional)" .-> C2["Command and Control"]
    EX1 -. "maintain foothold (optional)" .-> PE1["Persistence"]
    IA -. "evade delivery controls" .-> DE1["Defense Evasion"]
    EX1 -. "hide process / script traces" .-> DE1
```

## Phase 2

```mermaid
flowchart LR
    DI["Discovery"] -->|"identify useful assets/accounts"| CA["Credential Access"]
```

Phase 2 output: discovered hosts, services, trust paths, and credentials become operational input for later expansion.

## Phase 3

Phase 3 input: use Phase 2 findings to choose lateral paths, target privileged accounts, and execute on remote systems.

```mermaid
flowchart LR
    LM["Lateral Movement"] -->|"execute on remote host"| EX2["Execution"]
    PE2["Privilege Escalation"] -->|"run with higher privileges"| EX2
    EX2 -. "persist on new host (optional)" .-> PE3["Persistence"]
    LM -. "bypass remote restrictions" .-> DE3["Defense Evasion"]
    PE2 -. "avoid privilege-use detection" .-> DE3
```

## Phase 4

```mermaid
flowchart LR
    CO["Collection"] -->|"stage and transfer data"| EF["Exfiltration"]
```

## Phase 5

```mermaid
flowchart LR
    IM["Impact"]
```
