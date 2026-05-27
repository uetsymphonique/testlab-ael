# Core Principles

The MITRE ATT&CK Evaluation methodology is built on 4 core principles:
+ **Intelligence-Driven Scenarios**: Scenarios are designed based on CTI analysis of real-world campaigns, prioritized by prevalence and impact.
+ **Behavior over Signatures**: Tests focus on evaluating the ability to detect/prevent behaviors rather than relying on signatures (hash/IOC/etc.).
+ **Methodological Transparency**
+ **Continuous Evolution**
# Evaluation Process

> CTI Team - Red Team - Detection Engineering Team - Execution Team

**CTI:** Selects APT groups, collects TTPs, and produces an adversary emulation plan mapped to ATT&CK.
**Red Development Team**: Develops complete intrusion scenarios based on the plan.
**Detection Engineering Team**: Defines standards for defensive outcomes, establishes criteria for what constitutes a high-quality alert (required contextual fields), and identifies false-positive cases.
**Execution Team**: Operates the evaluation during the vendor's designated week, including Red Team operators who perform the simulation and Threat Hunt Coordinators who work with the vendor to record results displayed on the platform in real time.

There is also an **Infrastructure Team** responsible for designing, building, and maintaining the test environment, working with the vendor, and providing support during setup and testing.

# Scoring 

(new in 2026), the MITRE ATT&CK Evaluation introduced a new formula covering DQI (detection), PQI (prevention), and TES = DQI + PQI, while also providing Source-of-Action Modifiers that clarify who or what operational model produced the scored outcome [[Scoring Specification]]

# What you need to know to prepare for evaluation

## What lowers your score

- **Alert spam:** Generating too many low-context alerts for the same single behavior.
- **Fragmented cases:** Managing 50 behaviors across 50 separate incidents instead of consolidating them into a single case.
- **Late blocks:** Only blocking the ransomware encryption after the attacker has already stolen credentials and completed lateral movement.
- **Missing block context:** The system blocks but provides no user identity, no ATT&CK technique mapping, and no remediation guidance.
- **False positives:** Incorrectly blocking legitimate business applications or scripts.

## What improves your score

- **Technique-level detection** with a clearly identified ATT&CK mapping.
- **Alert consolidation:** Aggregating the entire attack chain into a single correlated incident.
- **Early blocking:** Blocking at or before the first Critical technique in the chain.
- **Full block transparency:** WHO, WHAT, WHEN, WHERE, HOW, WHY, and Recommended Action.
- **High precision:** Allowing all legitimate business activities to proceed without disruption.

=> Vendors are advised to **produce a single, high-quality, consolidated alert per behavior**, with telemetry correlated and easily accessible within the same workflow. This achieves DC-3 (maximum detection coverage), minimizes analyst burden, and maximizes the Detection Precision (DP) score.

## Key scoring principles to internalize

- **Behavior-level scoring:** Detection Coverage (DC) is scored per ATT&CK technique, not per alert. Generating 15 alerts for 1 technique still yields only 1 DC score based on the best-quality alert — the system always rewards consolidation.
- **ACW applies to detection only:** Attack Chain Weighting (ACW) is applied to Detection Coverage only. For protection, the Prevention Impact Weight (PIW) already accounts for technique severity through block timing, avoiding double-counting.
- **Block timing is the primary factor:** Block timing determines the PIW multiplier. Blocking at Stage 1 (Critical, 1.0×) yields twice the score of blocking at Stage 3 (Medium, 0.5×), regardless of context quality.
- **Block context is a secondary factor:** Within the same block timing window, full context (6–7/7 elements) achieves PC-3 or PC-2, while partial context achieves PC-2 or PC-1. Good context cannot compensate for a late block.
- **"Observe before blocking" strategy is valid:** If a platform intentionally delays blocking to gather intelligence, it can still receive a higher PIW score by providing evidence that the delay was deliberate observation rather than a missed detection.

Finally, this section emphasizes that **a low score is not necessarily a sign of poor product quality — it is an opportunity for improvement ahead of the 2027 evaluation**. Scores reflect performance against specific scenarios, and the per-technique public data is the most actionable information vendors can use to shape their technical roadmap.