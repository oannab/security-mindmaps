---
markmap:
  colorFreezeLevel: 2
  initialExpandLevel: 2
  maxWidth: 420
  zoom: true
  pan: true
---

# 🛡️ Security Operations — Domain 4.0 Master Map

## 🗝️ Legend — 8 Category System
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;">🗄️ Hw — Digital Hardware · Servers · Sensors · TPM · HSM · RFID · GPS Devices</span>
- <span style="background:#A1887F;color:#fff;padding:2px 10px;border-radius:5px;font-weight:600;">🪪 Ph — Physical Non-Digital · Shredding · Incineration · Degaussing · Guards · Facilities</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;">🚀 Sw — Software · SIEM · SOAR · EDR · AV · DLP · MDM · Scanners · SAST/DAST</span>
- <span style="background:#7986CB;color:#fff;padding:2px 10px;border-radius:5px;font-weight:600;">🌐 Ntw — Network Architecture · Segmentation · DMZ · VLAN · Zones · SD-WAN · SASE</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;">🔗 Pr — Protocols · SSH · HTTPS · SFTP · SNMPv3 · SAML · OAuth · Kerberos · DKIM · SPF</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;">📋 Gov — Governance · Policy · Compliance · Classification · CVSS · CVE · Chain of Custody</span>
- <span style="background:#80DEEA;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;">☁️ Cl — Cloud · Cloud Monitoring · CASB · Cloud-Native Tools · SaaS/IaaS/PaaS Security</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;">🛠️ M — Tech Methods · Hashing · Wiping · Sandboxing · Patching · Scanning · Code Signing</span>

---

## 🏷️ Enterprise Asset Management

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Acquisition & Procurement</span>
- Role: Secure intake of new assets into the organisation; ensures supply chain integrity

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Vendor Selection</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Security Protocols · Vendor must meet baseline security standards; questionnaires, third-party audits, ISO 27001 certs</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Financial Stability · Unstable vendor = supply chain risk; vendor insolvency = no patches/support</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Supply Chain Reliability · Verify no counterfeit components; hardware bill of materials (HBOM) review</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Change Management · Any asset change follows formal approval process; prevents unauthorised modifications</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Total Cost of Ownership (TCO) · Full lifecycle cost: purchase + maintenance + support + disposal; informs risk/investment decisions</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Assignment & Accounting</span>
- Role: Every asset tracked, named, classified, and owned — no shadow IT
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Asset Register · Central inventory of all hardware, software, and data assets; foundation for vuln management + IR</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Standard Naming Conventions · Consistent naming enables automated discovery and SIEM correlation</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Classification · Assets labelled by sensitivity and criticality; drives protection requirements</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Ownership & Accountability · Named owner per asset; accountable for patching, access control, and disposal</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Monitoring & Asset Tracking</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Inventory & Enumeration · Continuous automated discovery; identifies unmanaged/rogue devices on network</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Network Scanners · e.g. Nmap, Lansweeper, Qualys — enumerate IPs, open ports, OS fingerprints</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — CMDB (Config Management DB) · ServiceNow, Device42 — authoritative record of all assets and their relationships</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Tracking Technologies</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — RFID & Barcodes · Physical tags on hardware assets; scanned during audits; tamper-evident seals detect physical access</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — GPS Tracking · Embedded in laptops/vehicles/equipment; enables geolocation of stolen assets; remote wipe trigger</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — MDM (Mobile Device Management) · Centrally manages and enforces policy on mobile devices; enables remote wipe; enforces encryption + PIN</span>
  - <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — BYOD (Bring Your Own Device) · Employee-owned; MDM limited to work profile; data separation via containerisation</span>
  - <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — COPE (Corporate-Owned, Personally Enabled) · Corp device; full MDM control; employee can use for personal within policy</span>
  - <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — CYOD (Choose Your Own Device) · Employee picks from approved list; full corp control from day one</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Disposal & Decommissioning</span>
- Role: Prevent data recovery from retired assets; legally compliant destruction
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Sanitisation · Remove all data before disposal or reuse; method depends on media type and sensitivity</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Wiping & Overwriting · DoD 5220.22-M: multiple-pass overwrite; effective on HDDs; NOT effective on SSDs (use secure erase)</span>
  - <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Degaussing · Strong magnetic field destroys magnetic media (HDD, tape); renders platters unreadable; ineffective on SSDs</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Secure Erase (SSD) · ATA Secure Erase or Sanitize command; crypto-erase: destroy encryption key rendering data unrecoverable</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Physical Destruction · Last resort; ensures no data recovery even from damaged media</span>
  - <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Shredding · Industrial shredder reduces drives to metal fragments; NIST SP 800-88 compliant</span>
  - <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Incineration · Burns media to ash; used for classified material destruction</span>
  - <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Pulverisation · Crushes into particles; combined with shredding for highest assurance</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Certification of Destruction · Third-party certificate proving compliant destruction; required for compliance (HIPAA, PCI-DSS, GDPR)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Data Retention Requirements · Legal mandates on how long data must be kept before destruction; GDPR, HIPAA, SOX define periods</span>

---

## 🔍 Vulnerability Management Framework

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Identification Methods</span>

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Vulnerability Scans</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Credentialed Scans · Authenticated; deep assessment; sees patch levels, installed software, config details · e.g. Nessus, Qualys</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Non-Credentialed Scans · External view; no login; shows attacker's perspective; limited depth but realistic external view</span>

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Application Security Testing</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — SAST (Static Analysis) · Analyses source code without execution; finds SQLi, buffer overflows, hardcoded secrets at build time</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — DAST (Dynamic Analysis) · Tests running application; simulates real attacks; finds runtime vulns SAST misses · e.g. OWASP ZAP, Burp Suite</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Package Monitoring · Tracks third-party dependencies for known CVEs; e.g. Dependabot, Snyk, OWASP Dependency-Check</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Threat Intelligence Feeds</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — OSINT (Open Source Intelligence) · Public vuln databases, NVD, MITRE CVE, vendor advisories, GitHub PoC repos</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Dark Web Monitoring · Services scanning dark web for leaked credentials, org data, exploit chatter; e.g. Recorded Future, Digital Shadows</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Penetration Testing</span>
- Role: Authorised simulated attack; goes beyond scanning to actual exploitation
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Rules of Engagement · Defines scope, targets, methods, timing; legal protection for testers and org</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Responsible Disclosure · Structured process for reporting found vulns to vendors; CVD (Coordinated Vulnerability Disclosure)</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Analysis</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Confirmation</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — False Positive · Scanner reports vuln that doesn't actually exist; wastes remediation effort; requires manual verification</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — False Negative · Real vuln missed by scanner; most dangerous outcome; credentialed scans reduce FN rate</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Prioritisation</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — CVSS Scores · Common Vulnerability Scoring System; 0–10 scale; 9.0+ = Critical; scores base + temporal + environmental metrics</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — CVE Identifiers · CVE-YEAR-NUMBER; unique vuln ID from MITRE; links to NVD for full description and patches</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — EPSS (Exploit Prediction Scoring System) · Probability a vuln will be exploited in wild within 30 days; used alongside CVSS</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Contextual Factors</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Exposure Factor · Is the vulnerable system internet-facing? Internal? Air-gapped? Determines actual exploitability</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Environmental Variables · Compensating controls in place? Business criticality of asset? Data sensitivity? All modify effective risk</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Risk Tolerance · Organisation's accepted risk level; drives patch SLA targets (e.g. critical = 24h, high = 7 days)</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Response & Remediation</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Patching · Primary remediation; vendor-supplied fix closes the vulnerability; tested in staging before prod deployment</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Patch Management Tools · WSUS, SCCM, Ansible, Puppet — automate patch distribution across fleet</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Segmentation · Isolate vulnerable system; limit blast radius while patch is pending; VLAN change or firewall rule</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Virtual Patching · WAF/IPS rule blocks known exploit vector before patch available; compensating control for legacy systems</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Compensating Controls · Alternative security measure when patching is infeasible; must provide equivalent protection</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Exceptions / Exemptions · Formal risk acceptance for vulns that cannot be remediated; time-limited; reviewed periodically</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Cyber Insurance · Financial risk transfer; covers breach costs, notification, legal fees; does not eliminate technical risk</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Validation</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Rescanning · Run same scan post-remediation; confirm vuln no longer appears; close the remediation ticket</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Verification · Manual confirmation that patch applied correctly; may include functional testing</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Audit · Independent review of vuln management process; evidence for compliance frameworks</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Reporting</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Technical Reports · Detailed vuln list with CVSS, CVE, affected systems, remediation steps; for security/IT teams</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Executive Summaries · Risk posture overview; trend analysis; remediation % completed; for leadership/board</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — SLA Tracking · Measures compliance with patch SLA targets; drives accountability; input to risk management dashboard</span>

---

## 📡 Security Monitoring & Alerting Tools

### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Monitoring Computing Resources</span>

#### Systems Monitoring
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — CPU Usage · High CPU = cryptominer, DoS, runaway process; baseline + alerting threshold in monitoring tool</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Memory Utilisation · Memory exhaustion = DoS or memory injection attack; track via agent or SNMP</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Disk Space · Full disk = log suppression; attackers deliberately fill disks to blind SIEM; alerts on threshold</span>

#### Application Monitoring
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Availability · Uptime monitoring; SLA compliance; e.g. Nagios, Zabbix, Datadog, PagerDuty alerting</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Performance · Response time, error rates, throughput; degradation can indicate attack or compromise</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Error Logs · Application exceptions; repeated errors = exploitation attempt; fed into SIEM for correlation</span>

#### Infrastructure Monitoring
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Network Backbone · Interface utilisation, packet loss, BGP routing changes; abnormal traffic = DDoS or exfiltration</span>
- <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">☁️ Cl — Cloud Services · CloudWatch, Azure Monitor, GCP Ops Suite; monitors cloud resource health + security events</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Monitoring Activities</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Log Aggregation · Centralise all log sources into SIEM; normalise formats (syslog, CEF, JSON); enables correlation</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Alerting · Rule-based and ML-based alert generation; threshold, correlation, and behavioural rules</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Scanning · Continuous or scheduled vulnerability and configuration scans</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Credentialed Scans · Authenticated; full internal view; patch levels, installed packages, registry settings</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Non-Credentialed Scans · External view; attacker perspective; finds exposed services and banners</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Reporting · Scheduled compliance and security posture reports; dashboards for SOC and management</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Archiving · Log retention for compliance (GDPR, PCI-DSS, HIPAA); immutable storage; forensic readiness</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Alert Response & Remediation</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Quarantine · Isolate compromised host from network; automated via SOAR or EDR; preserves evidence</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Alert Tuning · Reduce false positives; refine rules; balance sensitivity vs specificity; ongoing SOC activity</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Monitoring Tools</span>

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — SIEM (Central Nervous System)</span>
- Role: Aggregates + correlates logs from all sources; real-time detection + historical investigation
- Used by: SOC analysts (L1 triage → L3 threat hunting); compliance teams; IR teams
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Log Sources: Firewalls, endpoints, AD, cloud, apps, network devices</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Correlation Rules · Match patterns across multiple log sources to detect multi-stage attacks</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — UEBA · ML detects insider threats via behavioural baseline deviation</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Examples: Splunk · Microsoft Sentinel · IBM QRadar · LogRhythm · Elastic SIEM</span>

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Data Collection Methods</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Agent-based · Software installed on endpoint; deep local telemetry; richer data; requires deployment/maintenance</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Agentless · Uses existing protocols (SSH, WMI, SNMP); no software installed; easier deployment; less detail</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — SCAP (Security Content Automation Protocol)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — OVAL · Open Vulnerability Assessment Language; machine-readable vuln definitions</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — XCCDF · Extensible Configuration Checklist Description Format; defines security config checklists</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — CIS Benchmarks · Prescriptive hardening guides for OS, cloud, network devices; industry standard baseline</span>

#### Other Monitoring Tools
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Antivirus / Anti-malware · Signature + heuristic endpoint protection; integrated into EDR platforms</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — DLP (Data Loss Prevention) · Monitors and blocks sensitive data leaving org (email, USB, web upload) · e.g. Symantec DLP, Microsoft Purview</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — SNMP Traps · Network devices send unsolicited alerts on state changes (link down, threshold exceeded) to NMS</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — NetFlow / sFlow · Network flow metadata (src/dst IP, port, bytes, duration); no payload; pattern analysis for anomalies</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Vulnerability Scanners · Continuous or scheduled; e.g. Nessus, Qualys, Rapid7 InsightVM, OpenVAS</span>

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Visualisation & Reporting</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Dashboards (Real-time Visuals) · SOC dashboards showing live threat status, open incidents, KPIs (MTTD, MTTR)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Automated Reports (Compliance) · Scheduled reports for PCI-DSS, SOC2, ISO 27001 evidence packages</span>

---

## 🏢 Enterprise Security Capabilities & Tools

### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Firewalls & Network Security</span>

#### Firewall Types
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — WAF (Layer 7) · Web Application Firewall; blocks OWASP Top 10; SQL injection, XSS, CSRF; used in DMZ or cloud</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — NGFW (DPI & Intelligence) · Deep Packet Inspection; application awareness; integrated IPS; SSL inspection; identity-based rules</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — UTM (All-in-one) · Firewall + IDS/IPS + AV + VPN + content filter in single appliance; typically SMB use</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Rules & ACLs</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Implicit Deny · Default-deny rule at end of every ACL; anything not explicitly permitted is blocked; defence fundamental</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Screened Subnet (DMZ) · Semi-trusted zone between WAN and LAN; hosts public-facing services; NGFW on both sides</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — IDS vs IPS</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — IDS (Passive Detection) · Monitors and alerts; out-of-band via TAP or SPAN port; no impact on traffic; forensic value</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — IPS (Active Prevention) · Inline; drops malicious packets in real-time; introduces latency risk; must tune to avoid blocking legit traffic</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Detection Methods</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Signature-based · Matches known attack patterns; low FP rate; cannot detect zero-days; requires frequent updates</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Behavioural / Heuristic · Detects deviations from normal baseline; catches zero-days; higher FP rate; ML-enhanced in modern tools</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Web Filtering</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Centralised Proxy · All web traffic routed through proxy; URL categorisation; SSL inspection; logs all requests · e.g. Zscaler, Squid</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Agent-based Filtering · Endpoint agent enforces policy even off-network; protects roaming users without VPN</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — DNS Filtering · Block malicious domains at DNS resolution; fastest control; works before TCP connection; e.g. Cisco Umbrella</span>

### <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Email Security</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — SPF (Sender Policy Framework) · DNS TXT record listing authorised sending IP addresses; receiving MTA rejects unauthorised senders</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — DKIM (DomainKeys Identified Mail) · Cryptographic signature on email headers; proves message unmodified in transit; uses public/private key pair</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — DMARC (Policy Enforcement) · Builds on SPF + DKIM; tells receivers what to do with failures (none/quarantine/reject); provides forensic reports</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Endpoint & System Security</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Group Policy (Windows) · Centrally enforces security config across AD domain; password policy, software restriction, firewall rules · via GPO</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — SELinux (Linux MAC) · Mandatory Access Control on Linux; labels every process + file; confines processes to minimum required access</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — EDR (Advanced Endpoint Detection) · Behavioural agent; process telemetry; memory analysis; automated response; e.g. CrowdStrike, SentinelOne, Defender ATP</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — XDR (Extended Detection & Response) · Cross-layer correlation: endpoint + network + cloud + email in single platform; reduces analyst context-switching</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — FIM (File Integrity Monitoring) · Detects unauthorised changes to critical files/configs; alerts on modification; e.g. Tripwire, OSSEC, Wazuh</span>

### <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Secure Protocol Replacements</span>
- Role: Replace legacy insecure protocols with encrypted equivalents
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — SSH (22) replaces Telnet (23) · Encrypts all admin traffic; Telnet sends credentials in cleartext</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — HTTPS (443) replaces HTTP (80) · TLS encrypts web traffic; HTTP = plaintext; HSTS enforces HTTPS-only</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — SFTP / FTPS (22/990) replaces FTP (21) · Encrypted file transfer; FTP sends credentials and data in cleartext</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — SNMPv3 (161/162) replaces SNMPv1/v2 · Adds authentication + encryption; v1/v2 use community strings in cleartext</span>
---

## 🔐 Identity & Access Management (IAM)

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Provisioning & Deprovisioning</span>
- Role: Joiner/Mover/Leaver lifecycle — right access at right time, revoked when no longer needed

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Provisioning</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Account Creation · HR-triggered; RBAC assigns minimum required access automatically; no manual over-provisioning</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Identity Proofing · Verify identity before issuing credentials; document check, HR validation, video verification</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Deprovisioning</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Offboarding · All access revoked on last day; ideally automated via HRMS → IAM integration; prevent insider threat post-departure</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Account Disabling · Disable before delete; preserves audit trail; reactivation possible for legal hold situations</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Business Continuity · Shared accounts / emergency break-glass accounts for critical systems; PAM-vaulted, audited</span>

### <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Identity Management & Federation</span>

#### <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Single Sign-On (SSO)</span>
- Role: One authentication event grants access to multiple systems; reduces password fatigue
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Kerberos (TGT) · Ticket-based auth; KDC issues TGT on login; TGT used to request service tickets without re-entering password · Active Directory</span>
  - <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — TGT (Ticket Granting Ticket) · Encrypted proof of authentication; presented to KDC to get service tickets; expires (default 10h)</span>
  - <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Golden Ticket Attack · Attacker forges TGT using stolen KRBTGT hash; persistent domain access; requires krbtgt password reset</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — LDAP (Lightweight Directory Access Protocol) · Query and authenticate against directory services (Active Directory, OpenLDAP); port 389 (636 TLS)</span>

#### <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Federation Standards</span>
- Role: Allow identity from one domain to access resources in another (cross-org, cloud)
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — SAML (XML-based) · Security Assertion Markup Language; web SSO between org IdP and SaaS; used by Okta, ADFS · XML assertions</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — OAuth 2.0 (Authorisation) · Delegates access without sharing password; issues access tokens; used by Google/Microsoft for API access</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — OIDC (OpenID Connect) · Authentication layer on top of OAuth 2.0; issues ID tokens (JWT); modern replacement for SAML in cloud</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Access Control Models</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — DAC (Discretionary Access Control) · Resource owner sets permissions; flexible but inconsistent; e.g. Windows NTFS file permissions</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — MAC (Mandatory Access Control) · System enforces labels (Top Secret, Secret); users cannot override; e.g. SELinux, military systems</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — RBAC (Role-Based Access Control) · Permissions assigned to roles, users assigned to roles; scalable; most common enterprise model</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — ABAC (Attribute-Based Access Control) · Policy evaluates attributes (user dept, resource classification, time, location); most granular; used in ZTA</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Rule-Based (Firewall ACLs) · Access based on predefined rules (IP, port, protocol); not user-aware; network-layer control</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Multifactor Authentication (MFA)</span>
- Role: Requires 2+ independent factors; credential theft alone insufficient to compromise account
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Something You Know · Password, PIN, security question; weakest factor; subject to phishing, brute force, password spray</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Something You Have · Smart card, hardware token (YubiKey/FIDO2), OTP device; possession-based; phishing-resistant when FIDO2</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Something You Are · Biometrics: fingerprint, face, iris, voice; inherence factor; spoofable with deepfakes; liveness detection mitigates</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Something You Do · Behavioural biometrics: typing rhythm, mouse movement; continuous authentication; transparent to user</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Somewhere You Are · Geolocation-based; restrict access to known locations; impossible travel detection flags anomalies</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Password Best Practices</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Complexity & Length · NIST SP 800-63B: length over complexity; 15+ chars; check against breached password lists (HaveIBeenPwned)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Rotation & History · Mandatory rotation now discouraged by NIST unless breach suspected; history prevents reuse of last N passwords</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Password Managers · Generates and stores unique complex passwords; eliminates password reuse; e.g. 1Password, Bitwarden, KeePass</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Passkeys / FIDO2 / WebAuthn · Passwordless; cryptographic key pair; private key never leaves device; phishing-resistant by design</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Hardware Security Key · YubiKey, Titan Key; FIDO2 hardware; strongest MFA available; no shared secret to steal</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Privileged Access Management (PAM)</span>
- Role: Secures, controls, monitors, and audits all privileged account activity
- Used by: IT admins, DevOps, DBAs, security teams, third-party vendors
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Just-in-Time (JIT) Permissions · Elevated access granted only when needed; auto-expires; no standing privilege; reduces attack window</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Password Vaulting · Privileged credentials stored encrypted in vault; auto-rotated; checked out per session; never seen by admin · e.g. CyberArk, BeyondTrust, HashiCorp Vault</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Ephemeral Credentials · One-time credentials generated per session; expire immediately after use; no persistent shared accounts</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Session Recording · Full video + keystroke log of every privileged session; forensic evidence; insider threat deterrent</span>

---

## ⚡ Automation & Orchestration (SOAR)

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — SOAR Components</span>

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Orchestration</span>
- Role: Connects disparate security tools into unified workflows via APIs; eliminates tool-switching
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Tool Integration · Connects SIEM, EDR, firewall, ticketing, threat intel, IAM — all in one workflow engine</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — API Connectivity · REST/SOAP APIs enable bidirectional data flow between tools; no manual copy-paste between systems</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Unified Workflows · Single pane of glass; analysts trigger multi-system actions from one interface</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Automation</span>
- Role: Execute security tasks without human intervention; speed = key advantage (seconds vs minutes)
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Repetitive Tasks · Alert triage, IOC lookup, ticket creation, user account disable; frees analysts for complex work</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — No Human Intervention · Fully automated playbooks execute in milliseconds; critical for high-volume alert environments</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Malware Scanning · Auto-submit suspicious files to sandbox; detonate; retrieve verdict; auto-block if malicious</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Response Playbooks</span>
- Role: Pre-defined decision trees for common incident types; ensure consistent, repeatable response
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Playbooks · Step-by-step automated workflows; e.g. phishing response: extract URLs → check TI → block domain → notify user → close ticket</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Predefined Workflows · Mapped to MITRE ATT&CK techniques; response action matched to tactic/technique observed</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Threat Execution · Automated threat containment: isolate host, block IP at NGFW, revoke token via IAM, push alert to Slack</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — SOAR Use Cases</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Provisioning Automation</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — User Account Provisioning · HR trigger → SOAR creates AD account, assigns RBAC role, sends welcome email, enables MFA</span>
- <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">☁️ Cl — Resource Scalability · Auto-provision cloud resources based on demand; auto-deprovision to reduce attack surface and cost</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Incident Management</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Ticket Creation · SIEM alert → SOAR creates ITSM ticket (ServiceNow, Jira) with full context; no manual data entry</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Automated Escalation · SLA breach triggers automatic escalation to Tier 2 / on-call; reduces MTTR</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Guard Rails</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Policy Enforcement · SOAR enforces security policies automatically; detects and remediates policy drift (e.g. S3 bucket made public → auto-remediate)</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — CI/CD Security Testing</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Security Gates in Pipeline · SAST, DAST, secret scanning run automatically on every code commit; block merge if critical vuln found</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — DevSecOps Integration · Security embedded in development pipeline; shift-left security; findings fed back to developer immediately</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Benefits & Challenges</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Efficiency & Time Saving · Reduces MTTD and MTTR dramatically; SOC handles 10x alert volume without staff increase</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Enforcing Baselines · Automated config checks ensure no drift from security baseline; continuous compliance</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Workforce Multiplier · Analysts focus on complex investigation; routine work automated; reduces analyst burnout</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Workflow Complexity · Poorly designed playbooks create false confidence; requires ongoing testing and maintenance</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Technical Debt · Automation built on fragile integrations; API changes break playbooks; requires dedicated maintenance</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Single Point of Failure · If SOAR platform fails, automated response stops; manual fallback procedures essential</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — High Initial Cost · Licensing, integration work, playbook development; ROI realised over 12-24 months</span>

---

## 🚨 Incident Response & Digital Forensics

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Incident Response Process (PICERL)</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — 1. Preparation</span>
- Role: Everything done BEFORE an incident; enables effective response
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — CSIRT Assembly · Computer Security Incident Response Team; defined roles, responsibilities, escalation paths, contact lists</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Communication Plans · Who to notify (internal, legal, regulators, customers); when; pre-approved messaging templates</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — System Baselining · Document normal system behaviour; enables anomaly detection; configuration snapshots for comparison</span>

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — 2. Detection</span>
- Role: Identify that an incident has occurred; faster detection = less damage
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — EDR Alerts · Endpoint agent detects malicious process/behaviour; auto-kills + alerts SOC; first detection in many breaches</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — SIEM Monitoring · Correlation rules match multi-source events into incident alert; analyst triages and escalates</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — IDS/IPS Alerts · Network-level detection of exploit attempts, C2 traffic, lateral movement indicators</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — User Reports · Employees reporting suspicious emails, unusual behaviour; often fastest initial detection signal</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — 3. Analysis</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Scope Determination · How many systems affected? What data accessed/exfiltrated? What is the blast radius?</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — True Positive Verification · Confirm alert is real incident not false positive before triggering full IR; saves wasted effort</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — IOC/IOA Analysis · Identify Indicators of Compromise (hashes, IPs, domains) and Indicators of Attack (TTPs) for attribution + containment</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — 4. Containment</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — System Isolation · Network disconnect compromised host; SOAR automates via EDR quarantine or VLAN change; prevent lateral spread</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Evidence Preservation · Image memory and disk before remediation; maintain chain of custody; enable forensic analysis and legal proceedings</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Short-term Containment · Immediate isolation; may impact business operations; acceptable trade-off to stop spread</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Long-term Containment · Stable controls allowing business to continue while full remediation is prepared; e.g. enhanced monitoring + access restrictions</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — 5. Eradication</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Malware Removal · Delete malicious files, kill persistence mechanisms (registry keys, scheduled tasks, services)</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Vulnerability Patching · Close the initial access vector; apply patches or compensating controls to prevent re-infection</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Account Remediation · Reset all compromised credentials; revoke tokens/sessions; disable attacker-created backdoor accounts</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — 6. Recovery</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Data Restoration · Restore from last known clean backup; validate integrity via hash verification before use</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — System Reinstatement · Return to production only after security validation; monitor closely for recurrence</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Business Validation · Confirm normal operations restored; user acceptance testing; stakeholder sign-off</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — 7. Lessons Learned</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Post-Incident Review · Within 2 weeks; what happened, how detected, how responded, what worked, what failed</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Improvement Identification · Update playbooks, patch gaps, add detections, improve training; close loop on control failures</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Attack Frameworks</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — MITRE ATT&CK</span>
- Role: Knowledge base of adversary Tactics, Techniques, and Procedures (TTPs) observed in real attacks
- Used by: Threat hunters, red teams, SOC for detection coverage mapping, IR for attribution
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Adversary Tactics · 14 high-level goals (Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defence Evasion, etc.)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Techniques & Sub-techniques · Specific methods to achieve each tactic; 600+ techniques; each mapped to detection opportunities + mitigations</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Cyber Kill Chain (Lockheed Martin)</span>
- Role: 7-stage model of attacker progression; detect or disrupt at any stage to prevent compromise
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — 1. Reconnaissance · Attacker researches target: OSINT, LinkedIn, Shodan, DNS enumeration</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — 2. Weaponisation · Creates malware or exploit payload; pairs with delivery mechanism (macro, PDF, dropper)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — 3. Delivery · Sends payload to target: phishing email, watering hole, USB drop, supply chain compromise</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — 4. Exploitation · Payload executes; exploits vulnerability; code execution achieved on target</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — 5. Installation · Malware installs; establishes persistence (registry, scheduled task, service, rootkit)</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — 6. Command & Control (C2) · Beacon to attacker-controlled server; encrypted channel (HTTPS, DNS, Slack); awaits instructions</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — 7. Actions on Objectives · Attacker achieves goal: exfiltration, ransomware, destruction, lateral movement to new targets</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Diamond Model of Intrusion Analysis</span>
- Role: Framework for understanding and attributing intrusions via 4 interconnected elements
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Adversary · Who is attacking; nation-state, criminal group, insider; TTP patterns enable attribution</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Capability · What tools/malware used; CVEs exploited; custom vs commodity tooling</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Infrastructure · Attacker's C2 servers, domains, IPs, hosting providers; pivot point for attribution + takedown</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Victim · Target of attack; understanding victim helps predict next target; informs defensive prioritisation</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Testing & Training</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Tabletop Exercises · Discussion-based; walk through scenario without live systems; identifies plan gaps and communication failures</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Red Team Simulation · Full adversary emulation; tests detection and response capabilities; uses real TTPs from MITRE ATT&CK</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Blue Team Defence · Detect, respond, and contain during Red Team exercise; measures MTTD and MTTR</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Failover Testing · Validates DR/BCP plans work under realistic conditions; tests RTO/RPO targets</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Digital Forensics</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Order of Volatility</span>
- Role: Collect most volatile (perishable) evidence first; defines forensic acquisition sequence
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — 1. CPU Cache / Registers · Most volatile; lost on power cycle; contains in-flight operations; nanosecond lifespan</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — 2. RAM (System Memory) · Running processes, decrypted data, network connections, encryption keys; lost on reboot; dump with Volatility, FTK Imager</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — 3. Swap / Page File · Virtual memory on disk; partial RAM contents; persists after reboot; examine with forensic tools</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — 4. Hard Drive (Least Volatile) · Files, logs, artefacts; persists; image with dd, FTK Imager, Autopsy; write-blocker essential</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Chain of Custody</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Documentation · Every person who handles evidence logged with timestamp, action, and signature; breaks = inadmissible in court</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Hashing for Integrity · SHA-256 hash of evidence image; proves evidence unmodified; rehash at every transfer to verify</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Physical Evidence Storage · Tamper-evident bags, locked evidence room, access log; prevents physical tampering</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Legal Hold</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Preservation Order · Legal instruction to preserve all relevant data; overrides normal deletion/retention schedules; litigation readiness</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — eDiscovery · Legal process of identifying, collecting, and producing electronically stored information (ESI) for legal proceedings</span>

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Forensic Data Sources</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Firewall Logs · IP addresses, ports, protocols, allowed/blocked traffic; timeline of network events</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Application Logs · DB queries, application errors, user interactions; reveals what attacker did within the app</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Endpoint Logs · User logins, file access, DNS lookups; Windows Event Logs (4624 logon, 4688 process create)</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — OS Security Logs · Authentication events, privilege changes, startups/shutdowns; Linux: /var/log/auth.log, /var/log/syslog</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Network & Security Logs · IPS/IDS signatures fired, data flow patterns, bandwidth usage anomalies</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Metadata · File creation times, authors, geolocation, event timeline; often missed by attackers who clean logs</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Packet Captures (PCAP) · Wireshark, tcpdump; full payload; payload analysis; protocol troubleshooting; definitive network evidence</span>

---

## 💻 Securing Computing Resources

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Secure Baselines</span>
- Role: Minimum security configuration standard; all systems deployed at or above baseline

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Baseline Establishment</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — CIS Benchmarks · Center for Internet Security; prescriptive config guides for Windows, Linux, cloud, network devices; Level 1 (basic) and Level 2 (hardened)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — STIGs (Security Technical Implementation Guides) · DoD standards; extremely detailed; mandatory for US government systems; more restrictive than CIS</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Baseline Deployment</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Microsoft Group Policy · Centrally deploys security config to all Windows domain members; enforces password policy, software restrictions, firewall rules</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Puppet / Chef / Ansible · Config management tools; enforce desired state across Linux/Windows; detect and remediate drift automatically</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Baseline Maintenance</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — SCAP Scanners · Automated compliance scanning against SCAP benchmarks; produces pass/fail per rule · e.g. OpenSCAP</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — CIS-CAT Tool · CIS Configuration Assessment Tool; scans against CIS Benchmarks; generates compliance report</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Hardening Targets</span>

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Mobile Devices</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — MDM Enforcement · Encrypt storage, enforce screen lock, disable camera in secure areas, remote wipe capability</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — App Whitelisting · Only approved apps install; prevent shadow IT and malware sideloading</span>

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Workstations & Servers</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Disable Unnecessary Services · Reduce attack surface; unused services = unused attack vectors; follow principle of least functionality</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Change Default Passwords · Default credentials are publicly known; first step in any attacker checklist</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Remove Unused Ports · Firewall or disable unused physical/logical ports; each open port = potential attack vector</span>

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Network Devices (Routers/Switches)</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Port Security · Limit MAC addresses per switch port; prevent rogue device connection; 802.1X for authentication</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Disable Telnet · Replace with SSH; Telnet sends all data including passwords in cleartext</span>

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Specialised Systems (ICS/SCADA/IoT)</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Physical Access Controls · Lock ICS panels; limit physical access to authorised personnel only</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Network Isolation · Air-gap or separate VLAN for OT network; no direct connectivity to IT network or internet</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Firmware Validation · Verify firmware signatures before update; prevent supply chain firmware attacks</span>

### <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Wireless Security</span>

#### <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Wireless Installation Planning</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Site Surveys · Physical survey to plan AP placement; identify interference sources; minimise signal bleed outside perimeter</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Heat Maps · Visual coverage maps; identify gaps and overlaps; ensure no dead zones or excessive external coverage</span>

#### <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Wireless Security Settings</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — WPA3 (SAE) · Simultaneous Authentication of Equals; replaces WPA2 PSK; prevents offline dictionary attacks; forward secrecy</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — RADIUS (AAA) · Centralised auth for wireless; 802.1X port-based access control; each user has unique credentials · no shared PSK</span>

#### <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — EAP Authentication Protocols</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — EAP-TLS · Mutual certificate auth; client + server both present certs; strongest EAP method; requires PKI</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — EAP-TTLS · Server cert only; client uses username/password inside TLS tunnel; easier than EAP-TLS (no client certs)</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — PEAP (Protected EAP) · Server cert + MS-CHAPv2 inside tunnel; most common in Windows environments; simpler than EAP-TLS</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Application Security</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Input Validation · Sanitise all user input server-side; prevents SQLi, XSS, command injection; whitelist not blacklist approach</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Secure Cookies · HttpOnly (no JS access), Secure (HTTPS only), SameSite (CSRF protection) flags on all session cookies</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Static Code Analysis (SAST) · Automated scan of source code; runs in CI/CD pipeline; finds vulns before deployment · e.g. SonarQube, Semgrep</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Sandboxing · Execute untrusted code in isolated environment; analyse behaviour; no access to production systems · e.g. Cuckoo Sandbox, ANY.RUN</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Code Signing · Cryptographic signature on executables; OS verifies signature before execution; prevents tampered/malicious software</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — HSM for Code Signing Keys · Private signing key stored in HSM; never exposed to developer workstations; FIPS 140-2 protection</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Application Monitoring · Runtime visibility into app behaviour; detect injection, auth bypass, data exfiltration in real-time · e.g. RASP (Runtime Application Self-Protection)</span>

---

## 🔁 Cross-Reference Index — Key Components in Multiple D4 Contexts

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — SIEM — All Contexts in D4</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Monitoring Tool · Core SOC platform; aggregates all log sources; real-time correlation and alerting</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — IR Detection Tool · Primary alert source triggering IR process; feeds Detection phase of PICERL</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Forensic Source · Historical log query during forensic investigation; timeline reconstruction; threat hunting</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — SOAR Input · SIEM alert triggers SOAR playbook execution; bidirectional: SOAR enriches SIEM with investigation results</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Vuln Management Input · Scan results + asset data ingested by SIEM for contextual alert enrichment</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — SOAR — All Contexts in D4</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Automation Platform · Core SecOps automation; playbooks for all common scenarios</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — IR Corrective Tool · Automated containment during IR; isolates hosts, blocks IPs, revokes tokens in seconds</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — IAM Integration · Auto-provisions/deprovisions accounts; auto-disables leaver accounts on HR trigger</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Vuln Management · Auto-creates tickets for critical vulns; escalates unpatched systems past SLA; triggers scan after change</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — CI/CD Security · Triggers SAST/DAST scans on commit; blocks pipeline on critical findings; notifies developers</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — EDR — All Contexts in D4</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Endpoint Security Tool · Continuous behavioural monitoring; process tree analysis; memory scanning</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — IR Detection Source · First alert in many breaches; process injection, lateral tool transfer, credential dumping detection</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — IR Containment Tool · Remote isolate host; kill process; quarantine file; initiated via SOAR or analyst console</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Forensic Source · Full telemetry timeline; process, network, file events; forensic artefact collection; memory dump</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Monitoring Integration · Feeds endpoint telemetry to SIEM; enriches alerts with process context</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — IDS/IPS — All Contexts in D4</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Network Monitoring · Signature + anomaly detection on network traffic; NIDS via TAP or SPAN port</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — Enterprise Capability · Core defensive tool; integrated into NGFW or standalone; feeds SIEM</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🚀 Sw — IR Detection Source · IPS alerts on exploit attempts; lateral movement patterns; C2 beaconing</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Virtual Patching · IPS rule blocks exploit for unpatched vuln; compensating control in vuln management</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Hashing — All Contexts in D4</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Forensic Integrity · SHA-256 hash of evidence; proves unmodified; chain of custody requirement</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Backup Verification · Hash backup before and after restore; confirms data integrity</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Malware Detection · IOC matching by file hash; known malware identified by hash in threat intel feeds</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — File Integrity Monitoring · FIM hashes critical system files; alerts on modification; detects rootkits and tampering</span>

### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — NGFW — All Contexts in D4</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Enterprise Capability · Primary network security device; DPI, App-ID, IPS, SSL inspection in one platform</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — IR Containment Tool · Block attacker IP/domain; isolate compromised VLAN; firewall rule pushed by SOAR during IR</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Vuln Management · Virtual patching via IPS signatures; protects unpatched systems at network layer</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🗄️ Hw — Monitoring Source · Firewall logs fed to SIEM; blocked traffic analysis reveals attacker reconnaissance patterns</span>
