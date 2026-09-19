# JadePuffer Threat Hunt & Security Incident Report

**Agent-driven ransomware intrusion against the Flowforge estate**


**Prepared by:** Angel Gabriel Perez Rosales

**Report date:** September 15, 2026

**Version:** 1.0

**Classification:** Training / Portfolio - Contains simulated IOCs and attack data

# Table of Contents

1\. Statement of Confidentiality and Use

2\. Engagement Information

3\. Investigation Objectives and Scope

4\. Executive Summary

5\. Technical Analysis

5.1 Affected Systems & Data

5.2 Initial Access and Exploitation

5.3 Execution, Command and Control, and Persistence

5.4 Credential Access and Secret Harvesting

5.5 Discovery and Internal Pivoting

5.6 Privilege Escalation and Account Persistence

5.7 Container-Escape Probe

5.8 Impact: Encryption, Destruction, and Ransom Note

5.9 Autonomy Analysis

5.10 Real or Noise: Baseline Separation

6\. Indicators of Compromise

7\. Root Cause Analysis

8\. Containment and Recommendations

9\. MITRE ATT&CK Mapping

Appendix A. Technical Timeline

Appendix B. Case Evidence Matrix

Appendix C. Representative KQL and References

# 1 Statement of Confidentiality and Use

This report documents a simulated threat-hunting and incident-response scenario in a training environment. The indicators, hostnames, credentials, addresses, and attack sequence are included for defensive analysis and portfolio documentation. They should not be interpreted as evidence of compromise against a real organization unless independently validated.

The report is intended to preserve the investigative reasoning, evidence sources, KQL pivots, and conclusions used to reconstruct the JadePuffer intrusion. Sensitive values should be reviewed before public publication.

# 2 Engagement Information

| **Analyst**            | Angel Gabriel Perez Rosales                                    |
|------------------------|----------------------------------------------------------------|
| **Role**               | Security Analyst / Threat Hunter                               |
| **Environment**        | Flowforge training estate                                      |
| **Investigation date** | July 30, 2026 event window; report prepared September 15, 2026 |
| **Primary SIEM**       | Microsoft Sentinel / Log Analytics                             |
| **Incident name**      | JadePuffer                                                     |

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

| **Incident Severity**        | Critical                                                      |
|------------------------------|---------------------------------------------------------------|
| **Incident Type**            | Agent-driven ransomware / credential theft / lateral movement |
| **Initial Access**           | Langflow /api/v1/validate/code - CVE-2025-3248                |
| **Primary Compromised Host** | ff-lf-01 (Langflow)                                           |
| **Attack Window**            | ~17 minutes of tightly clustered attacker activity            |
| **Autonomy Assessment**      | Human-tasked, followed by autonomous machine-paced execution  |

On July 30, 2026, the Flowforge estate was compromised through Langflow's code-validation endpoint. The case evidence attributes initial access to CVE-2025-3248, a critical unauthenticated code-execution weakness in vulnerable Langflow versions. The exploit resulted in Python execution under the Langflow service context on ff-lf-01. From that foothold, the intrusion progressed through command-and-control, credential harvesting, internal discovery, abuse of default credentials, privilege escalation against Nacos, a container-runtime probe, and destructive encryption of the MySQL-backed configuration datastore.

The attack chain was unusually compressed. Attacker activity ran as a continuous burst of roughly seventeen minutes rather than as scattered interactive activity. The LLM-agent session and host telemetry together show a human-tasked pattern: one session supplied the mission, while subsequent tool use and corrective behavior proceeded without human-paced pauses. The agent adapted when MinIO returned XML rather than the expected JSON, recomputed a rejected password hash, retried the account-creation action, and then continued directly to impact operations.

The impact phase used the MySQL AES_ENCRYPT function against 1,342 records, followed by destruction of the original config_info and history tables. A new README_RANSOM table was created and populated with payment instructions. The same investigation also identified a persistent Nacos administrator account named svc_maint, outbound C2 to 45.131.66.106:4444, a Terraform-state credential file retrieved from MinIO, and the extraction of 214 stored secrets from the Langflow database.

# 5 Technical Analysis

## 5.1 Affected Systems & Data

| **Host**    | **IP**    | **Role**                    | **Observed Impact**                                                            |
|-------------|-----------|-----------------------------|--------------------------------------------------------------------------------|
| ff-lf-01    | 10.4.0.10 | Langflow AI workflow server | Initial RCE, attacker Python, C2, pg_dump, discovery, Docker socket probe      |
| ff-minio-01 | 10.4.0.20 | MinIO object storage        | Default credentials abused; terraform-state/credentials.json retrieved         |
| ff-db-01    | 10.4.0.30 | MySQL database              | 1,342 records encrypted; config_info and history dropped; ransom table created |
| ff-nacos-01 | 10.4.0.40 | Nacos configuration service | Forged JWT path, admin account svc_maint created and authenticated             |

## 5.2 Initial Access and Exploitation

The exploited endpoint was /api/v1/validate/code on the Langflow service. The case identifies CVE-2025-3248 as the named weakness. This vulnerability affects vulnerable Langflow deployments where crafted unauthenticated requests can cause arbitrary Python code execution. Process telemetry on ff-lf-01 showed python3.11 spawned from the Langflow server command line, followed by immediate id and uname execution, establishing that the foothold was active under the Langflow service context.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th>LinuxProcess_CL<br />
| where RunId == "jp-46-20260730"<br />
| where DvcHostname == "ff-lf-01"<br />
| where TimeGenerated between (datetime(2026-07-30 19:19:30) .. datetime(2026-07-30 19:21:00))<br />
| project TimeGenerated, TargetProcessName, TargetProcessCommandLine, ActingProcessName, ActingProcessCommandLine</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

<img src="media/image1.png" style="width:6.45in;height:2.60666in" />

**Figure 1 - Initial attacker Python execution on ff-lf-01, followed by id and uname.**

A separate staging indicator, 64.20.53.230, was identified in the case file during the exploitation chain. The report treats it as an observed IOC from the investigation dataset; its precise role should be described as staging rather than C2 because the confirmed interactive beacon was a different destination.

## 5.3 Execution, Command and Control, and Persistence

The first attacker-controlled interpreter opened a network channel to 45.131.66.106 on TCP/4444. This destination stood apart from routine external services because the discriminating field was DstPortNumber=4444. System telemetry also recorded a langflow-owned cron execution of a curl-to-Python command targeting the same destination. The case identified the persistence cadence as every 30 minutes.

<img src="media/image2.png" style="width:6.45in;height:2.34389in" />

**Figure 2 - LinuxSystem_CL evidence showing the langflow command that contacts 45.131.66.106:4444.**

The fileless claim could not be proven from process telemetry alone. The SHA256 field was not populated for the observed process records, so the defensible conclusion is that the telemetry lacks the hash evidence required to establish whether the attacker payload existed on disk. Absence of a hash is not evidence of absence of a file.

## 5.4 Credential Access and Secret Harvesting

Credential access began with pg_dump against the Langflow PostgreSQL backend. The attacker-associated dump was parented by python3.11 (PID 4471), whereas a separate benign nightly pg_dump was parented by bash running /opt/backup/run-nightly.sh. This parent-process distinction was essential to separate attacker activity from routine operations.

<img src="media/image3.png" style="width:6.45in;height:2.70471in" />

**Figure 3 - Two pg_dump executions with different parents: benign bash backup versus attacker-controlled python3.11.**

The LLM session recorded a completed dump containing 214 secrets. Classification results identified OpenAI, Anthropic, DeepSeek, Gemini, Alibaba, Aliyun, Tencent, and Huawei credentials, in addition to database logins and cryptocurrency wallet material. The case-file shorthand counted eight named LLM/cloud providers; the underlying tool result also included mysql and wallets as separate secret classes.

<img src="media/image4.png" style="width:6.45in;height:2.65862in" />

**Figure 4 - LLMAgentLogs_CL showing pg_dump completion and classification of harvested secrets.**

## 5.5 Discovery and Internal Pivoting

A second attacker interpreter (PID 4491) performed a subnet sweep of 10.4.0.0/24. The resulting service map identified MinIO at 10.4.0.20:9000, MySQL at 10.4.0.30:3306, and Nacos at 10.4.0.40:8848. The agent then tested MinIO default credentials and authenticated with minioadmin:minioadmin.

The next step illustrates autonomous adaptation. The agent expected JSON from MinIO but received XML. Rather than stopping, it adjusted the parser and immediately refetched the object. The retry succeeded and credentials.json was retrieved from the terraform-state bucket. This report normalizes the case-file typo "XLM" to the evidence-supported format name XML.

<img src="media/image5.png" style="width:6.45in;height:0.65182in" />

**Figure 5 - Agent sequence: MinIO default credentials, XML parser adjustment, credentials.json retrieval, and Nacos pivot.**

## 5.6 Privilege Escalation and Account Persistence

With cloud/configuration credentials available, the agent pivoted to Nacos. The session log records a forged Nacos JWT and an attempt to create an administrative account. The first request failed because the submitted password hash was blank. Syslog recorded HTTP 403 with the explicit server reason "blank password hash rejected" at 19:34:36 UTC.

<img src="media/image6.png" style="width:6.45in;height:2.33433in" />

**Figure 6 - Nacos rejected the first privileged account-creation request at 19:34:36 UTC.**

The agent recomputed the bcrypt hash and resubmitted immediately. At 19:35:07 UTC, Nacos logged creation of svc_maint, followed by a successful login at 19:35:18 UTC using the forged-JWT path. The correction landed 31 seconds after the failed request, demonstrating rapid machine-paced recovery from an execution error.

<img src="media/image7.png" style="width:6.45in;height:2.0665in" />

**Figure 7 - Rejected Nacos request, successful creation of svc_maint, and successful authentication.**

## 5.7 Container-Escape Probe

After establishing the Nacos administrative session, the attacker queried the local Docker socket on ff-lf-01 with GET /containers/json via /var/run/docker.sock. The runtime log proves the request occurred and that the socket was reachable.

<img src="media/image8.png" style="width:6.45in;height:3.51734in" />

**Figure 8 - LinuxContainer_CL records GET /containers/json via /var/run/docker.sock.**

The container identities returned by Docker cannot be established from the available LinuxContainer_CL record. ContainerId, ImageName, and ImageRef were not populated for the event, and the response body was not captured. Therefore, the defensible conclusion is limited to "Docker socket queried/reachable" rather than naming containers that are not evidenced.

<img src="media/image9.png" style="width:6.45in;height:2.9473in" />

**Figure 9 - Container identity fields are empty; the data source cannot establish which containers were returned.**

## 5.8 Impact: Encryption, Destruction, and Ransom Note

The destructive phase executed directly against the MySQL configuration datastore. Syslog recorded an UPDATE against config_info using the built-in MySQL function AES_ENCRYPT(content,@k), with 1,342 rows affected. This was followed by DROP TABLE config_info and DROP TABLE history. The sequence is consistent with ransomware impact because encryption was followed by destruction of the original tables.

<img src="media/image10.png" style="width:6.45in;height:2.82119in" />

**Figure 10 - AES_ENCRYPT applied to 1,342 rows, followed by DROP TABLE config_info and history.**

The attacker then created README_RANSOM(msg text) and inserted the ransom message. The payment address recorded in the database was 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy. Because the CREATE TABLE and INSERT statements are both present in the SQL log, README_RANSOM is established as a database table, not inferred from agent narration.

<img src="media/image11.png" style="width:6.45in;height:1.91314in" />

**Figure 11 - Creation and population of the README_RANSOM table.**

## 5.9 Autonomy Analysis

The LLM-agent dataset contained more than one conversation. The attack activity was isolated to session jp-7f3c9a21. The user-provided case file records the tasking context as: "I have code execution. Langflow stores integrations and API keys in its Postgres backend. Dumping the database will yield LLM provider keys and cloud credentials worth more than this host." The public JadePuffer reference further identifies a single human-authored mission instruction followed by unattended execution.

<img src="media/image12.png" style="width:6.45in;height:2.15607in" />

**Figure 12 - Attack-session LLMAgentLogs_CL responses spanning secret harvesting through encryption.**

The strongest evidence for the autonomy verdict is the combination of session tasking and timing. One instruction initiated the operation; subsequent model/tool events executed continuously with corrective behavior and no human-paced gaps. The appropriate classification is human-tasked: a person initiated the mission, while the machine executed the chain autonomously.

**Analyst refinement:** the case-file submission cites LLMAgentLogs_CL.model_response and LLMAgentLogs_CL.session_id. Those fields help isolate the session, but LLMAgentLogs_CL.user_input plus TimeGenerated/tool_name are stronger artefacts for proving one-time human tasking followed by unattended execution.

## 5.10 Real or Noise: Baseline Separation

Not every python3.11 process on ff-lf-01 was malicious. The same binary was used by developers, Langflow workers, and the attacker. The differentiating property was process lineage. When python3.11 target processes were grouped by ActingProcessName, the two attacker interpreters were parented by python3.11 itself, whereas benign activity traced to expected managers such as bash or the Langflow worker/server context.

<img src="media/image13.png" style="width:6.45in;height:2.85307in" />

**Figure 13 - Grouping python3.11 spawns by ActingProcessName isolates the two attacker interpreters.**

<img src="media/image14.png" style="width:6.45in;height:1.39981in" />

**Figure 14 - Attacker python3.11 lineage spawning pg_dump, subnet sweep, MinIO fetch, and Docker socket probe commands.**

Three baseline-separation checks were important:

- Process lineage: ActingProcessName separated attacker-controlled python3.11 from benign Python usage.

- External network behavior: DstPortNumber=4444 separated the confirmed beacon from ordinary developer traffic on standard web ports.

- Timing: benign Python activity was scattered throughout the working day, while the attacker chain formed one tightly clustered, uninterrupted burst of about 17 minutes.

# 6 Indicators of Compromise

| **Type**                  | **Indicator**                                  | **Context**                                           |
|---------------------------|------------------------------------------------|-------------------------------------------------------|
| Endpoint                  | /api/v1/validate/code                          | Langflow exploit endpoint                             |
| Vulnerability             | CVE-2025-3248                                  | Critical unauthenticated Langflow RCE                 |
| Staging IP                | 64.20.53.230                                   | Case-file staging address                             |
| C2                        | 45.131.66.106:4444                             | Confirmed beacon / reverse-shell channel              |
| Process                   | python3.11                                     | Attacker interpreters distinguished by parent lineage |
| Persistence               | cron - every 30 minutes - langflow             | Recurring curl-to-Python execution                    |
| Credential Access         | pg_dump                                        | Attacker dump parented by python3.11                  |
| Internal Services         | 10.4.0.20:9000; 10.4.0.30:3306; 10.4.0.40:8848 | MinIO, MySQL, Nacos discovered during sweep           |
| Credential                | minioadmin:minioadmin                          | Default MinIO account abused                          |
| Cloud Credential Artifact | terraform-state/credentials.json               | Retrieved after XML parser adjustment                 |
| Account                   | svc_maint                                      | Administrative Nacos account created during intrusion |
| Session                   | jp-7f3c9a21                                    | Malicious LLM-agent session                           |
| Ransom Table              | README_RANSOM                                  | Created in MySQL and populated with extortion note    |
| Payment Address           | 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy             | Ransom payment address                                |

# 7 Root Cause Analysis

The primary root cause was exposure of a vulnerable Langflow code-validation path that permitted remote code execution. The incident then escalated because multiple independent control weaknesses were chained together faster than defensive controls interrupted the sequence.

**Vulnerable Langflow code-validation endpoint:** The /api/v1/validate/code path associated with CVE-2025-3248 provided the initial arbitrary-code foothold. Vulnerable Langflow versions should not expose this functionality without the vendor fix and authentication controls.

**Weak credential hygiene in object storage:** MinIO accepted the default minioadmin:minioadmin credentials, turning an internal discovery hit into immediate access.

**Sensitive credentials in infrastructure state:** credentials.json was retrievable from the terraform-state bucket. Infrastructure-as-code state and adjacent objects must not become long-lived secret stores.

**Weak Nacos trust material / privileged-account controls:** The agent was able to forge a JWT path and create svc_maint after correcting a password hash. Signing material and administrative workflows require rotation, monitoring, and stronger validation.

**Insufficient egress restriction:** ff-lf-01 established outbound C2 on TCP/4444. A tighter egress policy could have blocked or surfaced this behavior earlier.

**Agent oversight gap:** The LLM-driven chain adapted and continued without human approval gates. Actions involving credentials, admin-account creation, destructive database operations, or encryption should require human-in-the-loop authorization.

# 8 Containment and Recommendations

- Patch or upgrade Langflow to a version that remediates CVE-2025-3248; restrict or disable /api/v1/validate/code where not operationally required.

- Isolate ff-lf-01 and preserve volatile/process/network telemetry before reimaging or restoring the host.

- Block 45.131.66.106 and review all outbound port-4444 traffic from the estate. Move toward application-aware egress allowlisting.

- Revoke and rotate every credential exposed by the Langflow database dump. Treat all 214 extracted secrets as compromised.

- Change MinIO default credentials, require unique strong credentials, and restrict object-store access to authorized service identities.

- Remove credentials.json and other secrets from Terraform state/object storage; use a managed secrets service and short-lived scoped credentials.

- Delete svc_maint, audit all Nacos administrators, rotate Nacos JWT/signing material, and invalidate existing tokens/sessions.

- Restore the MySQL configuration datastore from a known-good backup, validate application integrity, and preserve a forensic copy of the impacted database before recovery.

- Create detections for python3.11 parent/child anomalies, pg_dump spawned by unexpected parents, Docker socket access, Nacos privileged account creation, and MySQL AES_ENCRYPT followed by DROP TABLE.

- Add human approval gates and rate limits to agent actions involving credential retrieval, admin-account creation, encryption, data deletion, or operating-system/container control.

# 9 MITRE ATT&CK Mapping

| **Technique** | **Name**                                                 | **Evidence**                                                         |
|---------------|----------------------------------------------------------|----------------------------------------------------------------------|
| T1190         | Exploit Public-Facing Application                        | CVE-2025-3248 via /api/v1/validate/code                              |
| T1059.006     | Command and Scripting Interpreter: Python                | python3.11 attacker interpreters                                     |
| T1571         | Non-Standard Port                                        | C2 to 45.131.66.106:4444                                             |
| T1053.003     | Scheduled Task/Job: Cron                                 | langflow cron execution every 30 minutes                             |
| T1552 / T1555 | Unsecured Credentials / Credentials from Password Stores | pg_dump of stored integration/API secrets                            |
| T1046         | Network Service Discovery                                | Sweep identifies MinIO, MySQL, and Nacos                             |
| T1078.001     | Valid Accounts: Default Accounts                         | minioadmin:minioadmin                                                |
| T1552.001     | Credentials in Files                                     | credentials.json from terraform-state bucket                         |
| T1005         | Data from Local System                                   | database/configuration data accessed from compromised hosts          |
| T1068         | Exploitation for Privilege Escalation                    | Nacos administrative path using forged JWT context                   |
| T1136.001     | Create Account: Local Account                            | svc_maint created in Nacos                                           |
| T1611         | Escape to Host                                           | Docker socket /containers/json probe                                 |
| T1486         | Data Encrypted for Impact                                | AES_ENCRYPT on 1,342 records                                         |
| T1485         | Data Destruction                                         | DROP TABLE config_info and history                                   |
| T1486         | Data Encrypted for Impact                                | README_RANSOM extortion workflow associated with encrypted datastore |

# Appendix A - Technical Timeline

Times below are event times in UTC. They are separate from the wall-clock times at which challenge answers were submitted.

| **Time (UTC)** | **Event**                            | **Result / Interpretation**                                                                    |
|----------------|--------------------------------------|------------------------------------------------------------------------------------------------|
| 19:20:01       | POST /api/v1/validate/code           | Initial Langflow RCE established                                                               |
| 19:20:04       | python3 -c \<base64 payload\>        | First attacker interpreter active                                                              |
| 19:22:04       | Outbound 45.131.66.106:4444          | C2/beacon channel opened                                                                       |
| 19:25:04       | pg_dump langflow                     | 214 secrets extracted                                                                          |
| 19:25:13       | Classify secrets                     | OpenAI, Anthropic, DeepSeek, Gemini, Alibaba, Aliyun, Tencent, Huawei; plus DB/wallet material |
| 19:27:28       | Second python3 interpreter           | PID 4491; subnet-sweep stage                                                                   |
| 19:27:39       | Probe MinIO default credentials      | minioadmin:minioadmin accepted                                                                 |
| 19:30:35       | Adjust parser, refetch               | XML handled; credentials.json retrieved                                                        |
| 19:33:39       | Forge Nacos JWT + create admin       | Initial privileged account-creation attempt                                                    |
| 19:34:36       | POST /nacos/v1/auth/users -\> 403    | blank password hash rejected                                                                   |
| 19:35:07       | Create svc_maint                     | Corrected admin creation succeeds                                                              |
| 19:35:18       | Nacos login -\> 200                  | svc_maint session established                                                                  |
| 19:35:35       | GET /containers/json via docker.sock | Socket reachable; response body not captured                                                   |
| 19:36:30       | AES_ENCRYPT(content,@k)              | 1,342 rows affected                                                                            |
| 19:36:37       | DROP TABLE config_info               | Original configuration table destroyed                                                         |
| 19:36:38       | DROP TABLE history                   | History table destroyed                                                                        |
| 19:36:39       | CREATE TABLE README_RANSOM           | Ransom artifact created                                                                        |
| 19:36:44       | INSERT ransom message                | Payment instructions stored                                                                    |
| 19:37:00       | Finalise                             | Agent reports completion                                                                       |

# Appendix B - Case Evidence Matrix

The matrix below preserves the findings supplied in the case file. Where the formal report uses a refined interpretation (for example XML spelling or stronger autonomy artefacts), the refinement is called out in the main analysis rather than silently changing the source finding.

| **\#** | **Finding**                           | **Result**                                                                          |
|--------|---------------------------------------|-------------------------------------------------------------------------------------|
| 1      | The exploited endpoint                | /api/v1/validate/code                                                               |
| 2      | The named weakness                    | CVE-2025-3248                                                                       |
| 3      | The staging address                   | 64.20.53.230                                                                        |
| 4      | The spawned interpreter               | python3.11, langflow run                                                            |
| 5      | Testing the fileless claim            | No - the SHA256 field is never populated in process telemetry                       |
| 6      | The beacon                            | 45.131.66.106 4444                                                                  |
| 7      | The persistence mechanism             | cron, every 30 minutes, langflow                                                    |
| 8      | The dump, and who really ran it       | pg_dump, langflow                                                                   |
| 9      | What it walked away with              | 8 providers; examples include OpenAI, Anthropic, DeepSeek                           |
| 10     | The second interpreter                | 4491                                                                                |
| 11     | The sweep                             | 10.4.0.20:9000, 10.4.0.30:3306, 10.4.0.40:8848                                      |
| 12     | The way in                            | MinIO, minioadmin:minioadmin                                                        |
| 13     | What it took                          | credentials.json retrieved from terraform-state bucket                              |
| 14     | The surprise, and the fix             | XML, adjust parser, refetch                                                         |
| 15     | The rejected attempt                  | 19:34:36, blank password hash rejected                                              |
| 16     | The corrective, proved from telemetry | 19:35:07, 8801, 997                                                                 |
| 17     | The account it left behind            | svc_maint                                                                           |
| 18     | The container-escape probe            | GET /containers/json via /var/run/docker.sock; container list cannot be established |
| 19     | Encryption and destruction            | AES_ENCRYPT, 1342, config_info and history                                          |
| 20     | The ransom note                       | README_RANSOM, 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy                                   |
| 21     | Session and tasking                   | jp-7f3c9a21; Langflow/Postgres credential-harvest tasking context                   |
| 22     | The autonomy verdict                  | human-tasked                                                                        |
| 23     | Real or Noise: python3.11 spawns      | ActingProcessName, python3.11                                                       |
| 24     | Real or Noise: external addresses     | DstPortNumber, 4444                                                                 |
| 25     | Real or Noise: timing                 | Tightly clustered burst, 17 minutes                                                 |

# Appendix C - Representative KQL and References



## External References

Langflow security advisory for CVE-2025-3248: [<u>GitHub Security Advisory - Langflow Unauth RCE</u>](https://github.com/langflow-ai/langflow/security/advisories/GHSA-rvqx-wpfh-mfx7)



**End of Report**
