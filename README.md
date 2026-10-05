# JadePuffer Threat Hunt & Security Incident Report

**Agent-driven ransomware intrusion against the Flowforge estate**


**Prepared by:** Angel Gabriel Perez Rosales

**Report date:** September 15, 2026

**Version:** 1.0

**Classification:** Training / Portfolio - Contains simulated IOCs and attack data

# Table of Contents

- [1 Statement of Confidentiality and Use](#1-statement-of-confidentiality-and-use)
- [2 Engagement Information](#2-engagement-information)
- [3 Investigation Objectives and Scope](#3-investigation-objectives-and-scope)
- [4 Executive Summary](#4-executive-summary)
- [5 Technical Analysis](#5-technical-analysis)
  - [5.1 Affected Systems & Data](#51-affected-systems--data)
  - [5.2 Initial Access and Exploitation](#52-initial-access-and-exploitation)
  - [5.3 Execution, Command and Control, and Persistence](#53-execution-command-and-control-and-persistence)
  - [5.4 Credential Access and Secret Harvesting](#54-credential-access-and-secret-harvesting)
  - [5.5 Discovery and Internal Pivoting](#55-discovery-and-internal-pivoting)
  - [5.6 Privilege Escalation and Account Persistence](#56-privilege-escalation-and-account-persistence)
  - [5.7 Impact: Encryption, Destruction, and Ransom Note](#58-impact-encryption-destruction-and-ransom-note)
  - [5.8 Autonomy Analysis](#59-autonomy-analysis)
  - [5.9 Real or Noise: Baseline Separation](#510-real-or-noise-baseline-separation)
- [6 Indicators of Compromise](#6-indicators-of-compromise)
- [7 Root Cause Analysis](#7-root-cause-analysis)
- [8 Containment and Recommendations](#8-containment-and-recommendations)
- [9 MITRE ATT&CK Mapping](#9-mitre-attck-mapping)
- [Appendix A - Technical Timeline](#appendix-a---technical-timeline)
- [Appendix B - Case Evidence Matrix](#appendix-b---case-evidence-matrix)
- [Appendix C - Representative KQL and References](#appendix-c---representative-kql-and-references)
  - [Representative KQL](#representative-kql)
  - [External References](#external-references)


# 1 Statement of Confidentiality and Use

This report documents a simulated threat-hunting and incident-response scenario in a training environment. The indicators, hostnames, credentials, addresses, and attack sequence are included for defensive analysis and portfolio documentation. 

The report is intended to preserve the investigative reasoning, evidence sources, KQL pivots, and conclusions used to reconstruct the JadePuffer intrusion.

# 2 Engagement Information

| Field | Detail |
|---|---|
| Analyst | Angel Gabriel Perez Rosales |
| Role | Security Analyst / Threat Hunter |
| Environment | Flowforge simulated AI-workflow estate |
| Primary SIEM | Microsoft Sentinel / Log Analytics |
| Incident name | JADE PUFFER |
| Event date | July 30, 2026 |
| Investigation window | Approximately 19:20–19:37 UTC |
| Simulation RunId | `jp-46-20260730` |
| Malicious LLM session | `jp-7f3c9a21` |

# 3 Investigation Objectives and Scope

The investigation was structured to produce a reproducible incident narrative rather than a collection of isolated flags. The objectives were to:

- Establish the initial access vector and validate the named vulnerability associated with the exploited Langflow endpoint.

- Reconstruct process, network, system, container, audit, file, database, and LLM-agent activity across the full attack window.

- Distinguish attacker-controlled activity from benign developer and platform baseline noise.

- Determine whether execution was human-driven, fully autonomous, or human-tasked with autonomous follow-through.

- Document credential access, internal discovery, persistence, privilege escalation, impact, and the ransom artifact.

- Map observed behavior to MITRE ATT&CK and produce containment and hardening recommendations.

Primary telemetry sources used during the hunt included LinuxProcess_CL, LinuxNetwork_CL, LinuxSystem_CL, LLMAgentLogs_CL, Syslog, LinuxAudit_CL, LinuxContainer_CL, and LinuxFile_CL. The hunt window centered on 2026-07-30 approximately 19:20-19:37 UTC, with supporting baseline queries outside that window.

# 4 Executive Summary

| Field | Detail |
|---|---|
| Incident ID | `RunId: jp-46-20260730` |
| Incident Severity | Critical |
| Incident Type | Agent-driven ransomware / credential theft / lateral movement |
| Initial Access | Langflow `/api/v1/validate/code` — `CVE-2025-3248` |
| Primary Compromised Host | `ff-lf-01` |
| Attack Window | Approximately 17 minutes of tightly clustered attacker activity |
| Investigation Status | Completed |

### Incident Overview

On July 30, 2026, suspicious execution was identified on the Flowforge Langflow host `ff-lf-01`. The initial investigation showed the legitimate Langflow service spawning an additional `python3.11` interpreter containing an encoded command. Correlation with application and agent telemetry linked this execution to exploitation of Langflow's `/api/v1/validate/code` endpoint and `CVE-2025-3248`.

The intrusion then progressed rapidly through command and control, persistence, credential harvesting, internal service discovery, abuse of default MinIO credentials, access to infrastructure secrets, Nacos privilege escalation, creation of the `svc_maint` account, a Docker socket probe, and destructive database operations. The observed attacker activity formed a dense sequence lasting approximately 17 minutes rather than the scattered pattern seen in normal workstation and application activity.

The impact phase used MySQL's `AES_ENCRYPT()` function against 1,342 configuration records, followed by destruction of the original `config_info` and `history` tables. The attacker then created a `README_RANSOM` table containing payment instructions.

The LLM-agent session showed a human providing tasking, after which the agent selected technical actions, adapted to unexpected results, corrected failed attempts, and continued through impact without evidence of step-by-step human direction. The incident is therefore assessed as **human-tasked but autonomously executed**.

### Key Findings

- Initial access was achieved through the exposed Langflow code-validation endpoint associated with `CVE-2025-3248`.
- Langflow's legitimate `python3.11` process spawned attacker-controlled Python interpreters, including PID `4471` and later PID `4491`.
- C2 traffic was established to `45.131.66.106:4444`.
- Persistence was established through a `langflow` cron job configured to execute every 30 minutes.
- An attacker-controlled `pg_dump` targeted Langflow application credential data, distinct from the legitimate nightly backup process.
- The harvested data represented eight provider families: OpenAI, Anthropic, DeepSeek, Gemini, Alibaba, Aliyun, Tencent, and Huawei. The case evidence also recorded a larger set of individual stored secrets.
- Internal discovery identified MinIO at `10.4.0.20:9000`, MySQL at `10.4.0.30:3306`, and Nacos at `10.4.0.40:8848`.
- MinIO accepted the default credential pair `minioadmin:minioadmin`.
- `credentials.json` was retrieved from the `terraform-state` bucket after the agent adapted its parser from the expected JSON format to the XML response it actually received.
- The first Nacos privileged-account attempt failed at `19:34:36` UTC because the password hash was blank. A corrected attempt succeeded 31 seconds later.
- The administrative account `svc_maint` was created successfully at `19:35:07` UTC.
- The Docker socket was queried with `GET /containers/json`; however, the available telemetry did not capture the response body, so the returned container names could not be established.
- `AES_ENCRYPT()` affected 1,342 records, followed by `DROP TABLE config_info` and `DROP TABLE history`.
- The attacker created `README_RANSOM` and inserted a payment address.

### Immediate Actions Taken

Analytical actions included correlating process, network, database, Linux, Syslog, and LLM-agent telemetry; identifying malicious infrastructure and credentials; distinguishing attacker activity from legitimate baseline activity; documenting indicators of compromise; and mapping observed behavior to the MITRE ATT&CK framework.

The investigation also identified several defensive priorities, including patching vulnerable Langflow instances, removing default credentials, rotating exposed secrets, restricting access to internal management services, monitoring anomalous Python process relationships, and detecting unusual LLM-agent activity.

### Stakeholder Impact

An incident of this scope could result in operational downtime, recovery costs, regulatory scrutiny, and reputational damage. The speed and autonomous nature of the attack also highlights the need for stronger segmentation, credential protection, and rapid detection capabilities to reduce the risk of similar incidents progressing before defenders can respond.

**Security and Engineering Teams:**  
The compromise demonstrated that credentials stored across interconnected AI, cloud, database, and infrastructure services can allow an attacker to move rapidly between systems. The autonomous nature of the attack further reduces the time defenders may have to identify and contain malicious activity.

**Business Operations:**  
Encryption of 1,342 database records and destruction of the original `config_info` and `history` tables demonstrates the potential for loss of availability, configuration data, and operational continuity.


# 5 Technical Analysis

## 5.1 Affected Systems & Data

| Host | IP Address | Primary Service | Observed Impact |
|---|---|---|---|
| `ff-lf-01` | `10.4.0.10` | Langflow AI workflow server | Initial RCE, attacker Python, C2, cron persistence, discovery, Docker socket probe |
| `ff-minio-01` | `10.4.0.20` | MinIO object storage | Default credentials abused; `terraform-state/credentials.json` retrieved |
| `ff-db-01` | `10.4.0.30` | MySQL database server | 1,342 records encrypted; `config_info` and `history` dropped; ransom table created |
| `ff-nacos-01` | `10.4.0.40` | Nacos configuration service | Privileged account-creation attempt; `svc_maint` created and authenticated |

## 5.2 Initial Access and Exploitation

The investigation began with suspicious process creation on `ff-lf-01` around 19:21 UTC. `python3.11` was expected in this environment because Langflow itself runs under Python, so the executable name alone could not establish compromise.

The normal startup lineage was:

```text
systemd (PID 1)
  └─ python3.11 /opt/langflow/.venv/bin/langflow run --host 0.0.0.0 --port 7860
```

Shortly afterward, the Langflow process spawned another interpreter:

```text
python3.11 /opt/langflow/.venv/bin/langflow run --host 0.0.0.0 --port 7860
  └─ python3 -c <base64 payload>
```

This changed the investigative question from whether Python was legitimate to why the Langflow service was spawning an encoded child interpreter.

Representative KQL:

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:19:00) .. datetime(2026-07-30 19:21:00))
| where DvcHostname == "ff-lf-01"
| where TargetProcessName == "python3.11"
| project TimeGenerated, ActorUsername, ActingProcessName, ActingProcessId,
          ActingProcessCommandLine, TargetProcessName, TargetProcessId,
          TargetProcessCommandLine, ActingProcessGuid
| sort by TimeGenerated asc
```

<img src="media/image1.png" width="900" alt="Initial attacker Python execution on ff-lf-01">

**Figure 1 — Initial attacker Python execution on `ff-lf-01`.**

Agent telemetry linked the suspicious child process to exploitation of:

```text
POST /api/v1/validate/code
```

The named vulnerability was `CVE-2025-3248`, an unauthenticated Langflow RCE affecting vulnerable versions of the code-validation endpoint. Syslog associated the request with external source `64.20.53.230`, which is treated in this report as a staging/initial-access indicator rather than the confirmed C2 destination.

**Assessment:** Initial access is supported by the exposed Langflow endpoint, `CVE-2025-3248`, Syslog request evidence, and the resulting Python child process under the Langflow service context.

The investigation identified a successful request to the Langflow code-validation endpoint:

> **Finding:** At `19:20:00 UTC`, the Langflow service received a `POST` request to `/api/v1/validate/code`. The request returned HTTP `200`, originated from `64.20.53.230`, and used the Python `requests` library (`python-requests/2.32.3`).

The following Syslog query was used to identify the request:

```kql
Syslog
| where RunId_CF == "jp-46-20260730"
| where ProcessName == "langflow" and SyslogMessage has "validate/code"
| where TimeGenerated between (
    datetime(2026-07-30 19:15:00) ..
    datetime(2026-07-30 19:30:00)
)
| project TimeGenerated, SyslogMessage

<img src="media/imagee1.png" width="900" alt="Initial attacker Python execution on ff-lf-01">

## 5.3 Execution, Command and Control, and Persistence

The attacker-controlled interpreter established an outbound connection to:

```text
45.131.66.106:4444
```

The connection was significant not merely because port `4444` is non-standard, but because it was created by the same suspicious Python process already tied to the Langflow exploitation chain.

<img src="media/image2.png" width="900" alt="Linux system telemetry showing command and control activity">

**Figure 2 — System telemetry associated with the recurring C2 command.**

The investigation then pivoted to persistence. Linux audit telemetry showed a `cron-change` event under the `langflow` account, and Linux system telemetry showed a scheduled command retrieving content from `45.131.66.106:4444` and piping it to `python3`.

Shell-history evidence established the cadence as every 30 minutes.

Representative queries:

```kql
LinuxAudit_CL
| where TimeGenerated between (datetime(2026-07-30 19:00:00) .. datetime(2026-07-30 20:00:00))
| project TimeGenerated, AuditKey, Subj, Success, TargetUsername, Uid, Tty, Type
| order by TimeGenerated asc
```

```kql
LinuxSystem_CL
| where TimeGenerated between (datetime(2026-07-30 18:00:00) .. datetime(2026-07-30 21:00:00))
| where EventOriginalMessage has_any ("curl -s", "python3 -", "cron", "CRON")
| project TimeGenerated, ProcessName, EventOriginalMessage, Facility, Computer
| order by TimeGenerated asc
```

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:40:00))
| where Command has_any ("crontab", "/etc/cron", "cron.d", "45.131.66.106")
| project TimeGenerated, ShellUser, Command, Pwd, ReturnCode
| order by TimeGenerated asc
```

**Assessment:** The attacker established a recurring C2 mechanism under the `langflow` account using cron to re-establish communications with `45.131.66.106:4444` every 30 minutes.

## 5.4 Credential Access and Secret Harvesting

The next stage focused on `pg_dump` activity against the Langflow PostgreSQL backend. `pg_dump` was also used by a legitimate nightly backup process, so the process name alone was insufficient to identify malicious activity.

Process lineage separated the two behaviors:

- Legitimate backup: `bash /opt/backup/run-nightly.sh` → `pg_dump`
- Attacker activity: `python3.11` (PID `4471`) → `pg_dump`

<img src="media/image3.png" width="900" alt="Legitimate and attacker pg_dump process lineage">

**Figure 3 — `pg_dump` executions distinguished by parent process.**

The attacker-controlled command targeted application credential data:

```text
pg_dump -h 127.0.0.1 -U langflow -d langflow -t variable -t api_key
```

The session evidence showed credentials spanning eight provider families:

- OpenAI
- Anthropic
- DeepSeek
- Gemini
- Alibaba
- Aliyun
- Tencent
- Huawei

The case evidence also recorded a larger collection of individual stored secrets. The important investigative distinction was that the malicious dump was tied to the `langflow` service context and attacker Python lineage rather than the routine `backup` account.

<img src="media/image4.png" width="900" alt="Agent log showing harvested secrets">

**Figure 4 — LLM-agent telemetry associated with the credential dump and secret classification.**

Representative correlation query:

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId =~ "jp-46-20260730"
| project TimeGenerated, ActorUsername, ActingProcessName,
          ActingProcessCommandLine, TargetProcessName,
          TargetProcessCommandLine, TargetProcessId, RunId
| order by TimeGenerated asc
```

**Assessment:** The attacker used the compromised Langflow service context to dump application credential data and harvest provider/API secrets. Parent process and account identity were more reliable discriminators than the `pg_dump` binary itself.

## 5.5 Discovery and Internal Pivoting

A second attacker-controlled interpreter, PID `4491`, was identified on `ff-lf-01`. Network telemetry associated with this PID showed a rapid internal sweep across the Flowforge network.

```kql
LinuxNetwork_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId =~ "jp-46-20260730"
| where ActingProcessId == 4491
| project TimeGenerated, DstIpAddr, DstPortNumber
| sort by TimeGenerated asc
```

The process contacted:

| Destination | Service |
|---|---|
| `10.4.0.20:9000` | MinIO |
| `10.4.0.30:3306` | MySQL |
| `10.4.0.40:8848` | Nacos |

The connections occurred within a very short interval, consistent with automated service discovery rather than interactive manual exploration.

### MinIO Access

The agent then tested MinIO and successfully authenticated with the factory-default credentials:

```text
minioadmin:minioadmin
```

<img src="media/image5.png" width="900" alt="Agent sequence showing MinIO access and parser adaptation">

**Figure 5 — MinIO access, parser adaptation, object retrieval, and pivot toward Nacos.**

MinIO Syslog showed retrieval of:

```text
terraform-state/credentials.json
```

The response initially arrived in XML when the agent expected JSON. Rather than stopping, the agent recognized the mismatch, adjusted the parser, and retried immediately. The corrected request succeeded.

This sequence is important because it demonstrates adaptive behavior rather than execution of a fixed, pre-authored sequence.

**Assessment:** PID `4491` performed internal service discovery, authenticated to MinIO using default credentials, and retrieved infrastructure credential material after adapting to an unexpected response format.

## 5.6 Privilege Escalation and Account Persistence

The Nacos service became the next pivot. Syslog showed a rejected privileged account-creation request at:

```text
19:34:36 UTC
```

The server returned HTTP `403` because the password hash was blank.

<img src="media/image6.png" width="900" alt="Nacos rejected request">

**Figure 6 — Nacos rejected the initial privileged account-creation attempt.**

The agent corrected the password-hash problem and retried. Host audit telemetry then recorded a successful account creation at:

```text
19:35:07 UTC
username: svc_maint
PID: 8801
UID: 997
```

<img src="media/image7.png" width="900" alt="Nacos successful account creation">

**Figure 7 — Successful creation and authentication of `svc_maint`.**

The correction occurred 31 seconds after the failed request. This machine-paced failure-diagnosis-and-retry cycle is one of the strongest behavioral indicators that the operation was being driven by an adaptive agent rather than a person manually responding to each event.

Representative query:

```kql
LinuxAudit_CL
| where TimeGenerated between (datetime(2026-07-30 19:30:00) .. datetime(2026-07-30 19:40:00))
| where RunId =~ "jp-46-20260730"
| where Computer =~ "ff-nacos-01"
| where AuditType =~ "ADD_USER"
| project TimeGenerated, EventOriginalMessage
| order by TimeGenerated asc
```

**Assessment:** The initial Nacos privileged-account attempt failed, the agent corrected the error, and `svc_maint` was created successfully 31 seconds later.


## 5.7 Impact: Encryption, Destruction, and Ransom Note

Database Syslog showed the destructive phase beginning with:

```sql
UPDATE config_info SET content=AES_ENCRYPT(content,@k)
```

The operation affected **1,342 rows**.

This was followed by:

```sql
DROP TABLE config_info;
DROP TABLE history;
```

<img src="media/image10.png" width="900" alt="Database encryption and table destruction">

**Figure 10 — `AES_ENCRYPT()` applied to 1,342 rows, followed by table destruction.**

The attacker then created a ransom table:

```sql
CREATE TABLE README_RANSOM (msg text)
```

and inserted payment instructions containing the Bitcoin address:

```text
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
```

<img src="media/image11.png" width="900" alt="Ransom note table creation">

**Figure 11 — Creation and population of `README_RANSOM`.**

Because both `CREATE TABLE` and `INSERT` activity were present in the database logs, `README_RANSOM` is established as a database table rather than inferred from agent narration.

**Assessment:** The intrusion achieved ransomware impact through database encryption, destruction of the original tables, and creation of a ransom-note table.

## 5.8 Autonomy Analysis

The `LLMAgentLogs_CL` dataset contained more than one conversation. The malicious activity was isolated to session:

```text
jp-7f3c9a21
```

The session contained human-authored tasking that directed the agent toward compromising the Flowforge estate and valuable Langflow/PostgreSQL credentials. After that tasking, the telemetry showed the agent generating its own technical decisions and tool actions.

<img src="media/image12.png" width="900" alt="JadePuffer LLM session activity">

**Figure 12 — Attack-session agent responses spanning credential access through impact.**

Evidence supporting autonomous execution included:

- selection and exploitation of the Langflow endpoint;
- establishment of C2 and recurring persistence;
- internal service discovery;
- selection of MinIO as a useful pivot;
- parser correction after receiving XML instead of expected JSON;
- correction of the failed Nacos account-creation attempt;
- continued progression into destructive database operations;
- a tightly clustered event sequence with no human-paced pauses.

The strongest fields for demonstrating the autonomy pattern are:

- `LLMAgentLogs_CL.user_input` — human tasking;
- `LLMAgentLogs_CL.model_response` — agent-generated decisions;
- `LLMAgentLogs_CL.tool_name` / tool activity — execution;
- `TimeGenerated` — machine-speed progression;
- `session_id` — separation of the malicious conversation from normal estate traffic.

**Assessment:** The operation was **human-tasked but autonomous in execution**. A person established the objective, while the LLM agent independently selected and adapted the technical steps used to pursue it.

## 5.9 Real or Noise: Baseline Separation

A major part of the hunt was distinguishing attacker activity from legitimate background behavior.

### Python Process Lineage

Several `python3.11` processes existed on `ff-lf-01`. The process name itself was not unique. The distinguishing field was `ActingProcessName` and the associated parent-child lineage.

<img src="media/image13.png" width="900" alt="Python process lineage grouped by parent">

**Figure 13 — Grouping `python3.11` spawns by parent isolates the attacker interpreters.**

The normal Langflow process was started by `systemd`, while the attacker chain showed `python3.11` spawning additional `python3.11` interpreters.

<img src="media/image14.png" width="900" alt="Attacker Python process chain">

**Figure 14 — Attacker Python lineage associated with credential access, discovery, MinIO activity, and the Docker probe.**

### External Network Activity

The host also made legitimate external connections. The confirmed malicious connection was distinguished by both destination port and process correlation:

```text
PID 4471 → 45.131.66.106:4444
```

The relevant field for the challenge's external-address baseline test was `DstPortNumber`, with attacker value `4444`.

### Temporal Concentration

Benign Python spawns were scattered throughout the working day. The attacker activity was concentrated into one continuous burst of approximately **17 minutes**, covering initial access, C2, credential access, service discovery, privilege escalation, and impact.

**Assessment:** The strongest separation from baseline came from three properties used together: **process lineage, process-correlated network behavior, and tightly clustered timing**.

---

# 6. Indicators of Compromise

| Type | Indicator | Context |
|---|---|---|
| Endpoint | `/api/v1/validate/code` | Langflow exploit endpoint |
| Vulnerability | `CVE-2025-3248` | Unauthenticated Langflow RCE |
| Initial-access / staging IP | `64.20.53.230` | External source associated with exploit request in the simulation |
| C2 | `45.131.66.106:4444` | Confirmed attacker channel |
| Process | `python3.11` | Malicious only when correlated with suspicious parent/child lineage |
| Persistence | `cron` every 30 minutes under `langflow` | Recurring C2 retrieval/execution |
| Credential access | `pg_dump` | Malicious instance spawned by attacker-controlled Python |
| Internal service | `10.4.0.20:9000` | MinIO |
| Internal service | `10.4.0.30:3306` | MySQL |
| Internal service | `10.4.0.40:8848` | Nacos |
| Default credential | `minioadmin:minioadmin` | Used to access MinIO |
| Credential artifact | `terraform-state/credentials.json` | Retrieved from MinIO |
| Account | `svc_maint` | Administrative account created during intrusion |
| Agent session | `jp-7f3c9a21` | Malicious LLM-agent conversation |
| Docker API request | `GET /containers/json` | Runtime reconnaissance through `/var/run/docker.sock` |
| Database function | `AES_ENCRYPT()` | Used against 1,342 records |
| Dropped tables | `config_info`, `history` | Data destruction |
| Ransom table | `README_RANSOM` | Extortion artifact |
| Payment address | `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` | Ransom payment destination |

> `RunId: jp-46-20260730` is intentionally excluded from the IOC table because it is simulation correlation metadata, not an attacker indicator.

---

# 7. Root Cause and Contributing Factors

The primary root cause was exposure of a vulnerable Langflow code-validation path that allowed unauthenticated remote code execution. Several additional weaknesses enabled the intrusion to progress from a single application compromise into a multi-system ransomware event.

- **Publicly exposed and vulnerable Langflow instance:** Langflow was accessible on port `7860` and vulnerable through `/api/v1/validate/code`. Internet-facing applications should be minimized, restricted, and kept current with security patches.

- **Default credentials:** MinIO accepted `minioadmin:minioadmin`. Default credentials should be removed or changed before a service is placed into operation.

- **Sensitive credentials accessible from application data:** API keys and provider credentials were retrievable from the Langflow PostgreSQL backend. Application secrets should be stored with strong access controls and rotated after suspected exposure.

- **Infrastructure credentials in object storage:** `credentials.json` was retrievable from the `terraform-state` bucket. Infrastructure-as-code state and adjacent objects should not become long-lived secret stores.

- **Accessible container-management interface:** The compromised host could query `/var/run/docker.sock`. Access to container-management interfaces should be tightly restricted because it can significantly increase the impact of an application compromise.

- **Insufficient privilege separation and segmentation:** The attack progressed from Langflow compromise to credential access, internal service discovery, MinIO access, Nacos administrative access, and database impact. Stronger service isolation and least-privilege controls can reduce this blast radius.

- **Insufficient egress restriction:** The compromised host established C2 over TCP/4444. Application-aware egress filtering could have blocked or surfaced the connection earlier.

- **Telemetry coverage limitations:** Process hashes were not populated and Docker response data was not collected. These gaps did not prevent reconstruction of the attack, but they reduced certainty for specific investigative questions.

The incident demonstrates why preventing a single vulnerability is not enough. Defense in depth is required to stop an application compromise from becoming an infrastructure-wide incident.

---

# 8. Containment and Recommendations

## Immediate Containment Priorities for a Production Environment

- Isolate `ff-lf-01` while preserving volatile, process, and network telemetry.
- Block `45.131.66.106` and review all outbound TCP/4444 activity.
- Disable or remove `svc_maint` and review all Nacos privileged accounts.
- Revoke and rotate credentials exposed through the Langflow database and MinIO object store.
- Preserve forensic copies of impacted databases and logs before restoration.
- Restore the affected configuration datastore from a known-good backup after integrity validation.

## Hardening Recommendations

- Patch Langflow to a version that remediates `CVE-2025-3248`; restrict or disable `/api/v1/validate/code` where not required.
- Remove MinIO default credentials and enforce unique, strong service credentials.
- Move application and infrastructure secrets to a managed secrets platform with short-lived, scoped credentials.
- Restrict access to `/var/run/docker.sock` and other container-management interfaces.
- Rotate Nacos signing/authentication material and invalidate existing tokens where compromise is suspected.
- Apply network segmentation between AI workflow services, object storage, configuration services, and production databases.
- Enforce egress allowlisting for application servers where operationally feasible.
- Alert on unexpected `python3.11` → `python3.11` parent-child relationships.
- Alert on `pg_dump` spawned by unexpected parents or service identities.
- Detect C2-like outbound connections from application processes to uncommon destination ports.
- Detect privileged Nacos account creation and unusual authentication changes.
- Detect Docker socket access from application contexts that do not normally manage containers.
- Detect `AES_ENCRYPT()` followed by `DROP TABLE` or other destructive database activity.
- Preserve LLM-agent telemetry where agentic systems are used internally so defenders can correlate human tasking, model decisions, and tool execution.

---

# 9. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence / Activity |
|---|---|---|
| Initial Access | **T1190 — Exploit Public-Facing Application** | Langflow exposed on port `7860`; exploitation through `/api/v1/validate/code` and `CVE-2025-3248` |
| Execution | **T1059.006 — Command and Scripting Interpreter: Python** | Attacker-controlled `python3.11` interpreters |
| Command and Control | **T1571 — Non-Standard Port** | `45.131.66.106:4444` |
| Persistence | **T1053.003 — Scheduled Task/Job: Cron** | `langflow` cron job reconnecting every 30 minutes |
| Credential Access | **T1555 — Credentials from Password Stores** | Langflow application credential/API-key data dumped from PostgreSQL |
| Credential Access | **T1552 — Unsecured Credentials** | Application/provider secrets available to compromised service context |
| Discovery | **T1046 — Network Service Discovery** | PID `4491` discovered MinIO, MySQL, and Nacos |
| Credential Access | **T1078.001 — Valid Accounts: Default Accounts** | `minioadmin:minioadmin` |
| Credential Access | **T1552.001 — Credentials In Files** | `credentials.json` from `terraform-state` |
| Collection | **T1005 — Data from Local System** | Data and credential material collected from compromised services |
| Privilege Escalation | **T1068 — Exploitation for Privilege Escalation** | Exercise mapping for the Nacos privilege-escalation path |
| Persistence | **T1136.001 — Create Account: Local Account** | Exercise mapping for creation of `svc_maint` |
| Privilege Escalation | **T1611 — Escape to Host** | Docker socket probe with `GET /containers/json`; successful escape not established |
| Impact | **T1486 — Data Encrypted for Impact** | `AES_ENCRYPT()` against 1,342 rows |
| Impact | **T1485 — Data Destruction** | `DROP TABLE config_info` and `DROP TABLE history` |

> Some mappings above follow the exercise's supplied ATT&CK classification. Where the underlying activity is application-specific rather than a perfect fit for an ATT&CK sub-technique, the mapping should be interpreted as the closest exercise-aligned representation rather than a claim of exact semantic equivalence.

---

# Appendix A — Technical Timeline

Times below are event times in UTC, not the wall-clock times when challenge answers were submitted.

| Time (UTC) | Event | Result / Interpretation |
|---|---|---|
| 19:20:01 | `POST /api/v1/validate/code` | Initial Langflow exploitation activity |
| 19:20:04 | `python3 -c <base64 payload>` | First attacker interpreter active |
| 19:22:04 | Outbound `45.131.66.106:4444` | C2 channel established |
| ~19:25 | `pg_dump` under attacker lineage | Langflow credential data targeted |
| ~19:25 | Secret classification | Eight provider families identified |
| 19:27:28 | Second `python3.11` interpreter | PID `4491`; internal discovery stage |
| ~19:27 | Internal service sweep | MinIO, MySQL, and Nacos identified |
| ~19:27 | MinIO authentication | `minioadmin:minioadmin` accepted |
| ~19:30 | Parser correction | Agent adapted to XML response and refetched object |
| ~19:30 | `credentials.json` retrieval | Credential material obtained from `terraform-state` |
| 19:34:36 | Nacos request rejected | HTTP 403; blank password hash rejected |
| 19:35:07 | `svc_maint` created | Corrected privileged account creation succeeds |
| 19:35:18 | Nacos login succeeds | New account authenticated |
| 19:35:35 | `GET /containers/json` | Docker socket reachable; response body not captured |
| 19:36:30 | `AES_ENCRYPT(content,@k)` | 1,342 rows affected |
| 19:36:37 | `DROP TABLE config_info` | Original configuration table destroyed |
| 19:36:38 | `DROP TABLE history` | History table destroyed |
| 19:36:39 | `CREATE TABLE README_RANSOM` | Ransom artifact created |
| 19:36:44 | Ransom message inserted | Payment instructions stored |
| ~19:37 | Attack chain ends | Continuous malicious activity spans roughly 17 minutes |

---

# Appendix B — Case Evidence Matrix

| # | Finding | Result |
|---:|---|---|
| 1 | Exploited endpoint | `/api/v1/validate/code` |
| 2 | Named weakness | `CVE-2025-3248` |
| 3 | Staging address | `64.20.53.230` |
| 4 | Spawned interpreter | `python3.11`, Langflow parent |
| 5 | Fileless claim | Not established — SHA256 absent across process telemetry |
| 6 | Beacon | `45.131.66.106:4444` |
| 7 | Persistence | cron, every 30 minutes, `langflow` |
| 8 | Credential dump | `pg_dump`, attacker activity under `langflow` context |
| 9 | Credential result | Eight provider families, including OpenAI, Anthropic, DeepSeek |
| 10 | Second interpreter | PID `4491` |
| 11 | Internal sweep | `10.4.0.20:9000`, `10.4.0.30:3306`, `10.4.0.40:8848` |
| 12 | MinIO access | `minioadmin:minioadmin` |
| 13 | Object retrieved | `terraform-state/credentials.json` |
| 14 | Unexpected format | XML; parser adjusted and request retried |
| 15 | Rejected attempt | `19:34:36`, blank password hash rejected |
| 16 | Corrective attempt | `19:35:07`, PID `8801`, UID `997` |
| 17 | Persistent account | `svc_maint` |
| 18 | Container probe | `GET /containers/json` via `/var/run/docker.sock`; returned containers not established |
| 19 | Encryption and destruction | `AES_ENCRYPT`, 1,342 rows, `config_info` and `history` dropped |
| 20 | Ransom note | `README_RANSOM`, `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` |
| 21 | Malicious session | `jp-7f3c9a21` |
| 22 | Autonomy verdict | Human-tasked, autonomously executed |
| 23 | Python baseline discriminator | `ActingProcessName`, attacker value `python3.11` |
| 24 | External-network discriminator | `DstPortNumber`, attacker value `4444` |
| 25 | Timing discriminator | Tightly clustered burst, approximately 17 minutes |

---

# Appendix C — Representative KQL

## Initial Python Process Lineage

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:19:00) .. datetime(2026-07-30 19:21:00))
| where DvcHostname == "ff-lf-01"
| where TargetProcessName == "python3.11"
| project TimeGenerated, ActorUsername, ActingProcessName, ActingProcessId,
          ActingProcessCommandLine, TargetProcessName, TargetProcessId,
          TargetProcessCommandLine, ActingProcessGuid
| sort by TimeGenerated asc
```

## Fileless-Claim Validation

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 00:00:00) .. datetime(2026-07-31 00:00:00))
| summarize
    TotalEvents = count(),
    WithSHA256 = countif(isnotempty(TargetProcessSHA256)),
    WithoutSHA256 = countif(isempty(TargetProcessSHA256))
```

## C2 and Cron Activity

```kql
LinuxSystem_CL
| where TimeGenerated between (datetime(2026-07-30 18:00:00) .. datetime(2026-07-30 21:00:00))
| where EventOriginalMessage has_any ("curl -s", "python3 -", "cron", "CRON")
| project TimeGenerated, ProcessName, EventOriginalMessage, Facility, Computer
| order by TimeGenerated asc
```

## Attacker `pg_dump`

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId =~ "jp-46-20260730"
| project TimeGenerated, ActorUsername, ActingProcessName,
          ActingProcessCommandLine, TargetProcessName,
          TargetProcessCommandLine, TargetProcessId, RunId
| order by TimeGenerated asc
```

## Internal Sweep by PID 4491

```kql
LinuxNetwork_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId =~ "jp-46-20260730"
| where ActingProcessId == 4491
| project TimeGenerated, DstIpAddr, DstPortNumber
| sort by TimeGenerated asc
```

## MinIO Object Retrieval

```kql
Syslog
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId_CF =~ "jp-46-20260730"
| where Computer =~ "ff-minio-01" and SyslogMessage has "GetObject"
| project TimeGenerated, SyslogMessage
```

## Nacos Rejected Request

```kql
Syslog
| where RunId_CF == "jp-46-20260730"
| where Computer == "ff-nacos-01" and SyslogMessage has "403"
| project TimeGenerated, SyslogMessage
```

## Nacos Corrective Account Creation

```kql
LinuxAudit_CL
| where TimeGenerated between (datetime(2026-07-30 19:30:00) .. datetime(2026-07-30 19:40:00))
| where RunId =~ "jp-46-20260730"
| where Computer =~ "ff-nacos-01"
| where AuditType =~ "ADD_USER"
| project TimeGenerated, EventOriginalMessage
| order by TimeGenerated asc
```

## Docker Runtime Probe

```kql
LinuxContainer_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId =~ "jp-46-20260730"
| project TimeGenerated, Operation, RunId, ContainerId, ImageName, ImageRef
| order by TimeGenerated asc
```

## Database Encryption and Destruction

```kql
Syslog
| where RunId_CF == "jp-46-20260730"
| where Computer == "ff-db-01"
| where SyslogMessage has "AES_ENCRYPT" or SyslogMessage has "DROP TABLE"
| project TimeGenerated, SyslogMessage
```

## Ransom-Note Creation

```kql
Syslog
| where RunId_CF == "jp-46-20260730"
| where Computer == "ff-db-01"
| where SyslogMessage has "CREATE TABLE" or SyslogMessage has "README_RANSOM"
| project TimeGenerated, SyslogMessage
```

## LLM Session Activity

```kql
LLMAgentLogs_CL
| where RunId == "jp-46-20260730"
| where session_id == "jp-7f3c9a21"
| where TimeGenerated between (datetime(2026-07-30 19:19:00) .. datetime(2026-07-30 19:40:00))
| project TimeGenerated, session_id, actor, user_input, model_response,
          tool_name, tool_args, tool_result
| sort by TimeGenerated asc
```

## Python Baseline by Parent Process

```kql
LinuxProcess_CL
| where DvcHostname == "ff-lf-01"
| where TargetProcessName == "python3.11"
| summarize count() by ActingProcessName
| sort by count_ desc
```

---


## External References

Langflow security advisory for CVE-2025-3248: [<u>GitHub Security Advisory - Langflow Unauth RCE</u>](https://github.com/langflow-ai/langflow/security/advisories/GHSA-rvqx-wpfh-mfx7)



**End of Report**
