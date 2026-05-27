> Topic: #MITRE-evaluation #PurpleTeaming #SOC-Benchmarking #Adversary-Emulation
# Overview
## Total Evaluation Score (TES)

The MITRE Evaluation now introduces a new metric with a single composite score — the Total Evaluation Score (TES) — based on the following 4 evaluation questions:
+ *Coverage -> Detection Coverage (DC)*: **Did the tool see it?** For each executed technique, did the platform generate an alert, and was that alert actionable (sufficient information to act on)? — scored at the behavior level, not by alert count.
+ *Importance -> Attack Chain Weighting (ACW)*: **How critical was that technique?** Each detection and protection score is multiplied by the technique's importance in the attack chain. Missing a high-severity pivot is therefore penalized more heavily than missing a low-risk reconnaissance step.
+ *Precision -> Detection Precision (DP), Protection Precision (PP)*: **Did it alert with signal — not noise?** Penalizes systems with many false positives and fragmented case management — both drain SOC capacity without improving defensive posture.
+ *Speed -> Detection Speed (DS)*: **How fast did it respond?** The elapsed time from technique execution to the first automated alert.
TES is calculated as `DQI + PQI` (Detection Quality Index scale 0.0–1.0 and Protection Quality Index scale 0.0–1.0) — overall scale 0.0–2.0.
## Source-of-Action Modifiers

This suffix designates **who or which operational model** produced the detection and protection quality — it does not reflect the value of the score itself.

| Edit   | Name                         | Operational Meaning                                                                                                                                                 |
| ------ | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| (P)    | **Platform**                 | Fully automated platform with no human involvement. The customer's SOC team works directly from system-generated alerts.                                             |
| (P/AI) | **Platform + AI**            | Platform augmented with AI (Copilot). AI assists with alert enrichment, but human analysts make the final decisions.                                                 |
| (S/H)  | **Service + Human Analysts** | Managed service model (MDR/MSSP). Vendor analysts directly validate, enrich, and provide remediation recommendations.                                               |
| S/AI   | **Service + AI SOC**         | AI-driven SOC service capable of autonomous investigation and recommendations with analyst-equivalent capability and accountability.                                 |
| Mixed  | Hybrid                       | A blend of platform automation, human analysts, and AI operating within integrated workflows.                                                                        |

# DQI - Detection Quality Index

The DQI measures how accurately a solution identifies adversary behaviors without blocking them. DQI is the arithmetic mean of three components:

**Main Formula:**

$$DQI = \frac{Weighted\_DC\_normalized + DP + DS\_normalized}{3}$$

---

## Detection Coverage (DC)

This component is scored per **ATT&CK technique (behavior)**, not by alert count. If a technique generates multiple alerts, MITRE takes only the score of the highest-quality alert.
### DC Tier Definitions

| **Tier** | **Score** | **MITRE Definition & Criteria**                                                                                                                                             |
| -------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DC-3** | 3.0       | **Actionable:** Alert clearly identifies the ATT&CK technique/sub-technique. Provides sufficient context to act immediately without further investigation.                  |
| **DC-2** | 2.0       | **Correlated (Generic):** Alert identifies suspicious behavior only at the general Tactic level (e.g., "Credential Access") without specifying the technique. Requires analyst follow-up. |
| **DC-1** | 1.0       | **Observed:** Raw logs (telemetry) are recorded at the backend but no alert is generated. Detectable only through manual hunting or log review.                             |
| **DC-0** | 0.0       | **Not Observed:** Complete blind spot. No alert and no telemetry.                                                                                                           |

**Required context elements for a perfect score (DC-3)**
To achieve DC-3, at least one alert must provide all 6 of the following:

| **Context** | **Required Information**                                                                   |
| ----------- | ------------------------------------------------------------------------------------------ |
| **WHO**     | User identity, account, or entity (e.g., CORP\jsmith).                                     |
| **WHAT**    | Detection Criteria — the behavior being tested.                                            |
| **WHEN**    | Timestamp of the behavior.                                                                 |
| **WHERE**   | At minimum: Hostname and IP address.                                                       |
| **HOW**     | Enrichment at the ATT&CK (sub-)technique level.                                            |
| **SEVERITY**| Any indicator that the behavior is malicious or suspicious.                                |

### Attack Chain Weighting (ACW)

DC scores are not summed equally — each is multiplied by the technique's criticality.

|**Level**|**Weight**|**Behavior Characteristics**|**Example**|
|---|---|---|---|
|**Critical**|1.0×|High impact, real-world prevalence, hard to detect, enables primary attack objectives.|T1003 OS Credential Dumping|
|**High**|0.75×|Significant impact, common, but not yet chain-ending.|T1105 Ingress Tool Transfer|
|**Medium**|0.5×|Moderate impact, typically preparatory or intermediate steps.|T1082 System Information Discovery|
|**Low**|0.25×|Low impact, easy to detect, limited strategic value in isolation.|T1033 System Owner/User Discovery|

**Normalization Formula:**

$$Weighted\_DC\_normalized = \frac{\sum(DC\_technique \times ACW\_technique)}{\sum ACW\_technique \times 3.0}$$

---

## Detection Precision (DP)

DP measures analyst efficiency. Unlike conventional ML models, MITRE's DP directly penalizes False Positives and fragmented case management because both consume SOC time without delivering security value.

**Formula:**

$$DP = \frac{TP}{TP + FP + (Cases - 1)}$$

- **TP (True Positive):** Number of unique malicious behaviors correctly detected.
- **FP (False Positive):** Number of unique benign behaviors incorrectly flagged.
- **Cases:** Number of incident cases pushed to analyst for investigation. If the platform has no case consolidation, each alert counts as 1 case.

**More detail on Cases:**
If a platform lacks automatic alert grouping (case consolidation), each individual alert is counted as 1 case. MITRE illustrates this as follows:
Both vendors correctly detect 50 malicious behaviors (TP = 50) with zero false positives (FP = 0), but in practice:
* **Vendor A (Fragmented):** The system has no grouping capability, pushing out 50 separate alerts (Cases = 50). The analyst must open 50 tabs and investigate 50 times. Per the MITRE formula, the DP score collapses to just **50.5%** ($50 / (50 + 0 + 49)$).
* **Vendor B (Well-consolidated):** The system recognizes the attack chain and groups all 50 behaviors into a single investigation case (Cases = 1). The analyst handles it once. DP reaches the maximum **100%** ($50 / (50 + 0 + 0)$).
By including the `Cases` parameter, MITRE accurately reflects the reality that Vendor B makes the SOC team 10–16× more efficient than Vendor A.

False Positive (FP) Criteria for Detection

|**Counts as FP**|**Does NOT count as FP**|
|---|---|
|A legitimate business application is incorrectly flagged and generates an alert.|An alert about legitimate behavior that runs silently in the background without creating a case requiring analyst action.|

---

## Detection Speed (DS)

Measures the elapsed time from adversary technique execution to the first automated platform alert (human processing time not counted).

|**Tier**|**Time Threshold**|**Score**|**Operational Significance**|
|---|---|---|---|
|**Real-Time**|< 15 minutes|1.0|Gold standard; enables proactive containment.|
|**Acceptable Delay**|15–30 minutes|0.75|Still useful for Incident Response operations.|
|**Significant Delay**|> 30 minutes|0.5|Significantly reduces response opportunity.|
|**No Detection**|No alert|0.0|No alert means no speed score.|

**Cloud Architecture Note:** Cloud platforms may experience UI display latency due to rendering (15–60s), API polling (30–120s), or log pipeline delays (1–5 min). For fairness, MITRE allows vendors to submit backend API timestamps; if the actual backend detection time is demonstrably faster, the score is calculated from the backend timestamp.

**Normalization Formula:**

$$DS\_normalized = \frac{\sum Speed\_score\_per\_technique}{N\_total\_techniques}$$
## DQI calculation example

**Step 1: Calculate Weighted Detection Coverage (Weighted_DC_normalized)**

Assume the system is tested against the following 4 techniques:

|**Technique**|**DC Tier (Score)**|**Criticality Weight (ACW)**|
|---|---|---|
|**T1003.001 (Credential Dumping)**|DC-3 (3.0)|Critical (1.0×)|
|**T1059.001 (PowerShell)**|DC-3 (3.0)|High (0.75×)|
|**T1082 (System Discovery)**|DC-2 (2.0)|Medium (0.5×)|
|**T1033 (User Discovery)**|DC-0 (0.0)|Low (0.25×)|

**Calculation steps:**

1. **Numerator (Sum of weighted DC scores):** $(3.0 \times 1.0) + (3.0 \times 0.75) + (2.0 \times 0.5) + (0.0 \times 0.25) = 3.0 + 2.25 + 1.0 + 0.0 = 6.25$.
2. **Denominator (Sum of ACW weights):** $1.0 + 0.75 + 0.5 + 0.25 = 2.5$.
3. **Raw Weighted_DC:** $\frac{6.25}{2.5} = 2.5$.
4. **Normalize (divide by maximum score 3.0):** $\frac{2.5}{3.0} = 0.833$.

_Note: A simple unweighted average would give $\frac{3+3+2+0}{4} = 0.667$ (66.7%). Applying ACW raises the score to 83.3% because the solution performed well on the most important steps (Critical and High); missing a low-risk reconnaissance step has little strategic impact._

---

**Step 2: Calculate Detection Precision (DP)**

Assume the platform recorded the following figures across the full evaluation:

- **TP (True Positive):** 35 malicious behaviors correctly detected and alerted.
- **FP (False Positive):** 5 incorrect alerts targeting legitimate system behaviors.
- **Cases:** All alerts consolidated by the system into 4 independent investigation cases.

Applying the DP formula:

$$DP = \frac{TP}{TP + FP + (Cases - 1)}$$

$$DP = \frac{35}{35 + 5 + (4 - 1)} = \frac{35}{43} = 0.814$$

---

**Step 3: Calculate Detection Speed (DS_normalized)**

Assume the platform generated some alerts at "Real-Time" (1.0) and others at "Acceptable Delay" (0.75). After averaging the speed scores across all detected techniques, the platform achieves: **DS_normalized = 0.708**.

---

**Step 4: Calculate the Detection Quality Index (DQI)**

Combine all 3 normalized components into the final DQI formula:

$$DQI = \frac{Weighted\_DC\_normalized + DP + DS\_normalized}{3}$$

$$DQI = \frac{0.833 + 0.814 + 0.708}{3} = \frac{2.355}{3} = 0.785$$

**Conclusion:** The Detection Quality Index (DQI) for this security system is 0.785, equivalent to 78.5% detection quality performance.
# PQI -  Protection Quality Index

The PQI measures how effectively a solution blocks adversary techniques before they cause significant damage, with protective features enabled. It evaluates both the strategic value of _when_ a block occurs and how clearly the system communicates that blocking decision.

**Main Formula:**

$$PQI = \frac{Weighted\_PC\_normalized + PP}{2}$$

_(Scale 0.0 to 1.0, equivalent to 0%–100%)_.

---

## Protection Coverage (PC)

Protection testing follows a stage-gated format: as soon as the solution blocks at any stage, the test ends and subsequent steps are not executed. Each test receives a PC score based on two factors: **Block timing** is the primary factor, and **Context quality** is the secondary factor.
### Context Elements
**7 Context Elements of a Block Alert**

|**Element**|**Required Information**|
|---|---|
|**WHO**|User identity or entity.|
|**WHAT**|Detection Criteria — the behavior being tested.|
|**WHEN**|Timestamp of the block action.|
|**WHERE**|At minimum: Hostname and IP address.|
|**HOW**|Technical decision mechanism (e.g., policy, ML, signature).|
|**WHY**|Reason the behavior is considered malicious.|
|**RECOMMENDED ACTION**|Suggested next step for the SOC team (investigation/remediation guidance).|
### PC Tier Assignment Matrix
**PC Tier Assignment Matrix**

_Core principle: Block timing is the deciding factor. A late block cannot achieve PC-3 regardless of how complete the context is. Conversely, an early block with insufficient context also cannot achieve PC-3._

| **Block Stage**                                           | **Full context (6–7/7)** | **Partial context (4–5/7)** | **Minimal context (1–3/7)** | **No block**  |
| --------------------------------------------------------- | ------------------------ | --------------------------- | --------------------------- | ------------- |
| **Stage 1–2** (At or before the first Critical technique) | PC-3 (3.0)               | PC-2 (2.0)                  | PC-1 (1.0)                  | PC-0 (0.0)    |
| **Stage 3** (Mid-chain)                                   | PC-2 (2.0)               | PC-2 (2.0)                  | PC-1 (1.0)                  | PC-0 (0.0)    |
| **Stage 4+** (Late stage)                                 | PC-1 (1.0)               | PC-1 (1.0)                  | PC-1 (1.0)                  | PC-0 (0.0)    |
| **No block at any stage**                                 | PC-0 (0.0)               | PC-0 (0.0)                  | PC-0 (0.0)                  | PC-0 (0.0)    |

### Attack Chain Weighting (ACW) 

PC scores are multiplied by the Attack Chain Weighting (ACW), the same as on the detection (DQI) side. Blocking a Critical technique (1.0×) earns substantially more points than blocking a Low technique (0.25×).

**Normalization Formula:**

$$Weighted\_PC = \frac{\sum(PC\_test \times ACW\_test)}{\sum ACW\_test}$$

$$Weighted\_PC\_normalized = \frac{Weighted\_PC}{3.0}$$

---

## Protection Precision (PP)

PP measures the balance between stopping threats and maintaining business continuity. False Positives are measured objectively through observable system disruption.

**Formula:**

$$PP = \frac{TP}{TP + FP}$$

- **TP (True Positive):** Number of unique malicious behaviors correctly blocked without disrupting business operations. Due to stage-gated testing, successfully blocking 1 test counts as 1 TP.
- **FP (False Positive):** Number of legitimate behaviors incorrectly blocked, OR malicious blocks that also disrupted/broke legitimate business operations.

---

## PQI Calculation Example

**Calculating Weighted Protection Coverage (Weighted_PC_normalized)**

Based on an evaluation with 5 tests, results are as follows:

|**Test**|**Technique**|**PC Tier**|**PC Score**|**ACW Weight**|**Criticality**|
|---|---|---|---|---|---|
|1|T1003.001 Credential Dumping|PC-3|3.0|1.0×|Critical|
|2|T1486 Ransomware|PC-3|3.0|1.0×|Critical|
|3|T1059.001 PowerShell|PC-2|2.0|0.75×|High|
|4|T1082 System Discovery|PC-1|1.0|0.5×|Medium|
|5|T1078 Valid Accounts|PC-2|2.0|1.0×|Critical|

**Calculation steps:**

- **Step 1 — Numerator (Sum of weighted scores):** (3.0 × 1.0) + (3.0 × 1.0) + (2.0 × 0.75) + (1.0 × 0.5) + (2.0 × 1.0) = 3.0 + 3.0 + 1.5 + 0.5 + 2.0 = 10.0.
- **Step 2 — Denominator (Sum of ACW weights):** 1.0 + 1.0 + 0.75 + 0.5 + 1.0 = 4.25.
- **Step 3 — Weighted_PC:** 10.0 / 4.25 = 2.353.
- **Normalize (Weighted_PC_normalized):** 2.353 / 3.0 = 0.784 (78.4%).

**Calculating Protection Precision (PP)**

- Protection Precision result: PP = 0.714, calculated from 10 True Positives (TPs) and 4 False Positives (FPs) during false-positive validation.

**PQI Final Calculation**
- **Formula:** PQI = (Weighted_PC_normalized + PP) / 2.
- **Applying the figures:** PQI = (0.784 + 0.714) / 2 = 1.498 / 2.
- **Result:** PQI = 0.749, equivalent to 74.9% Protection Quality.
# End-to-End TES Worked Example

From the worked example: DQI = 0.785; PQI = 0.749. => TES = DQI + PQI = 1.534 (range 0.0–2.0)

**Published Results**

Published results will include the TES score, the Source-of-Action modifier suffix, and the full component breakdown table. The same TES calculation can produce different published entries depending on who operates the solution:

| **Published Entry**                                                 | **TES** | **DQI** | **PQI** | **DC** | **DP** | **DS** | **PC** | **PP** |
| ------------------------------------------------------------------- | ------- | ------- | ------- | ------ | ------ | ------ | ------ | ------ |
| **Vendor A (P)**<br>Platform only — your SOC operates it            | 1.496   | 0.747   | 0.749   | 0.833  | 0.700  | 0.708  | 0.784  | 0.714  |
| **Vendor B (S/H)**<br>Same platform scores, human analysts included | 1.496   | 0.747   | 0.749   | 0.833  | 0.700  | 0.708  | 0.784  | 0.714  |
| **Vendor C (S/AI)**<br>AI SOC produces the detection quality        | 1.496   | 0.747   | 0.749   | 0.833  | 0.700  | 0.708  | 0.784  | 0.714  |

**Key takeaways:**

- The TES and all component scores are identical across Modifier types when core quality is equivalent.
- The Modifier suffix is not a penalty or bonus — it is purely for attribution, recording the source of the action.
- Customers use Modifiers to evaluate which operational model best fits their organization, not to adjust scores.

**Score Sensitivity: What Changes DQI vs PQI**

This section builds intuition for how specific operational improvements or regressions affect DQI, PQI, and the overall TES.

| **Operational Change**                                              | **Affected Component**                           | **Direction** | **Approximate TES Impact**                                              |
| ------------------------------------------------------------------- | ------------------------------------------------ | ------------- | ----------------------------------------------------------------------- |
| **Improve T1003.001 (Critical) from DC-2 to DC-3**                  | Detection Coverage (Weighted_DC) → **DQI**       | Up (↑)        | **+0.04 to +0.08** (varies by technique mix).                           |
| **Consolidate 50 fragmented cases down to 5**                       | Detection Precision (DP) → **DQI**               | Up (↑)        | **+0.03 to +0.07** (case reduction dominates).                          |
| **Reduce detection latency from 20 min to 10 min**                  | Detection Speed (DS) → **DQI**                   | Up (↑)        | **+0.08** (jump from "Delay" tier to "Real-Time" tier).                  |
| **Move block timing earlier from Stage 3 to Stage 1**               | Protection Coverage (PC × ACW) → **PQI**         | Up (↑)        | **+0.05 to +0.12** (varies by technique mix).                           |
| **One additional false-positive block**                             | Protection Precision (PP) → **PQI**              | Down (↓)      | **−0.02 to −0.05** (depends on number of TPs).                         |
| **Block context improved from Partial to Full (Stage 1–2)**         | PC Tier raised from 2 to 3 → **PQI**             | Up (↑)        | **+0.03 to +0.06** (after ACW weighting).                               |
