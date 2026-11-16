# 📂 Ready-to-Use Forensic Sample Logs

This folder contains clean, well-documented, realistic sample logs designed for demonstrating and testing the **ARIXA Forensic Timeline Console**.

---

## 📋 Catalog of Sample Logs

| # | File Name | Type | Recommended Settings | What Happens / What to Expect |
|---|---|---|---|---|
| **01** | `01_SSH_BruteForce_and_AdminTakeover_auth.log` | Linux `auth.log` | Timezone: `Asia/Kolkata`<br>Skew: `0` | **Attacker:** `203.0.113.45`<br>15 failed password attempts on root/admin, successful login as `deploy`, dumps `/etc/shadow`, and creates backdoor user `support2`.<br>🎯 **Alerts:** R1 (Brute Force), R2 (Critical Break-in), R7 (Privilege Escalation), R8 (`/etc/shadow`), R8 (`useradd`). |
| **02** | `02_Web_VulnerabilityScan_and_WebShell_access.log` | Nginx `access.log` | Timezone: `Asia/Kolkata`<br>Skew: `0` | **Attacker:** `203.0.113.99`<br>Scanning 15 missing pages (burst of 404s), SQL injection (`' UNION SELECT`), file inclusion (`../../etc/passwd`), and web shell execution (`cmd.php?cmd=whoami`).<br>🎯 **Alerts:** R3 (Web Scan), R4 (Scan then Exploit), R5 (SQLi, LFI, Web Shell). |
| **03A**<br>&<br>**03B** | `03A_Web_Server_London_access.log`<br>+<br>`03B_Database_Server_NewYork_auth.log` | Nginx + Linux Auth<br>*(Multi-Server)* | `03A`: London (`Europe/London`, Skew `0`)<br>`03B`: New York (`America/New_York`, Skew `+180`) | **The Clock Skew Proof:**<br>Attacker executes web shell on London web server at `11:03:00`, then pivots via SSH to New York database server and dumps database (`mysqldump`).<br>🎯 **Alerts:** R6 (Lateral Movement across servers), R7 (Privilege Escalation), R8 (Database dumped). |
| **04** | `04_PasswordSpraying_and_SSHKey_Backdoor_auth.log` | Linux `auth.log` | Timezone: `Europe/London`<br>Skew: `-120` | **Attacker:** `198.51.100.23`<br>Low-and-slow password spraying testing 1 password across 8 users (anna, ben, carol...), logs in as `grace`, adds SSH backdoor key to root, and edits cron persistence.<br>🎯 **Alerts:** R1, R2, R8 (`authorized_keys`), R8 (`crontab`). |
| **05** | `05_WebShop_SQLInjection_and_PathTraversal_access.log` | Apache `access.log` | Timezone: `UTC`<br>Skew: `0` | **Attacker:** `192.0.2.66`<br>Web shop reconnaissance, directory traversal, SQL injection, and webshell upload (`/images/avatar_9.php?exec=...`).<br>🎯 **Alerts:** R3, R4, R5 (SQLi, LFI, Web Shell). |
| **06A**<br>&<br>**06B** | `06A_Full_Enterprise_Morning_auth.log`<br>+<br>`06B_Full_Enterprise_Morning_access.log` | Linux + Nginx<br>*(Full Incident)* | Timezone: `Asia/Kolkata`<br>Skew: `0`<br>*(Drop both files together)* | **Full Incident Morning (155 events):**<br>Combines normal staff traffic (cron jobs, developers alice/bob) with 3 simultaneous attacks: brute force, web scanning, SQL injection, webshell, and database exfiltration.<br>🎯 **Alerts:** 16 detections across CRITICAL, HIGH, and WARN! |
| **07** | `07_Firewall_Mixed_CEF_for_GapTesting.log` | Mixed Firewall (CEF/JSON) | Timezone: `UTC`<br>Skew: `0` | **Parsing Gap Demonstration:**<br>Unrecognized firewall and IDS log lines. Demonstrates that ARIXA never silently drops unparseable data, but records them in the **Parsing Gaps** tab. |
| **08** | `08_Benign_Normal_Company_Traffic_auth.log` | Linux `auth.log` | Timezone: `Asia/Kolkata`<br>Skew: `0` | **Zero False Alarms Test:**<br>Clean everyday corporate server logs: admins logging in with public keys, routine uptime/disk checks, cron sessions.<br>🎯 **Alerts: 0 (Proves zero false positives!)** |

---

## 🚀 How to Use in the Dashboard

1. Open the ARIXA console: **http://localhost:8585**
2. In the left sidebar under **"Add evidence"**:
   - Drag & drop any of the files above into the dropzone (or click to browse).
   - Set the corresponding **Server Time Zone** and **Clock Skew** from the table above.
   - Click **⚡ Analyse evidence**.
3. Watch the **Attack Graph**, **Kill Chain**, and **Timeline** populate instantly!

