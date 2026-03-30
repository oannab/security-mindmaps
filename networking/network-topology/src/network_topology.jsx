import { useState, useRef, useCallback, useEffect } from "react";

// ═══════════════════════════════════════════════════════════════════════════
// REAL-WORLD SCENARIOS - THE "DOMINO EFFECT" - v6 - SHOWN IN RIGHT INFO PANEL
// ═══════════════════════════════════════════════════════════════════════════

const SCENARIOS = {
  siem: {
    title: "Lateral Movement Detection",
    trigger: "Spike in failed logins + lateral movement detected",
    chain: [
      { actor: "fin_ws", event: "User workstation shows 15 failed SSH attempts in 30 seconds", data: "EventID 4625 × 15, Source: FIN-WS-012, Target: SQL01" },
      { actor: "edr_agents", event: "EDR agent detects process spawning SSH connections to multiple servers", data: "Process: powershell.exe, Parent: WINWORD.EXE, Targets: 5 different IPs" },
      { actor: "ids_int", event: "IDS sees SMB enumeration traffic to multiple hosts", data: "SMB NULL sessions, LDAP queries, NetBIOS name lookups" },
      { actor: "siem", event: "SIEM correlates all 3 events → flags as lateral movement attack", data: "Risk score: 95/100, Confidence: High, MITRE: T1021.001" },
      { actor: "siem", event: "SIEM generates critical alert", data: "Alert ID: INC-2024-0042, Priority: P1, Category: Lateral Movement" },
      { actor: "soar", event: "SOAR automatically triggered by SIEM alert (playbook: 'Contain-LatMov-v2')", data: "Playbook execution started at 14:32:18 UTC" },
      { actor: "soar", event: "Step 1: SOAR calls EDR API to isolate infected host", data: "API: POST /devices/FIN-WS-012/isolate, Status: 200 OK" },
      { actor: "edr_console", event: "EDR console executes isolation command", data: "Network adapter disabled, host cannot reach other machines" },
      { actor: "soar", event: "Step 2: SOAR calls firewall API to block source IP at perimeter", data: "Rule: DROP src=10.0.30.12 any, inserted at position 1" },
      { actor: "int_fw", event: "Internal firewall adds deny rule for compromised host", data: "Rule ID: TEMP-2024-0042, Expiry: Manual review required" },
      { actor: "soar", event: "Step 3: SOAR resets user AD password", data: "User: john.smith@corp, New password: [randomly generated], Force change at login" },
      { actor: "dc", event: "Domain controller processes password reset", data: "Account locked until manual unlock by IT security" },
      { actor: "soar", event: "Step 4: SOAR creates incident ticket with all forensic data", data: "ServiceNow INC0042, Assigned: SOC-Tier2, SLA: 2 hours" },
      { actor: "itsm", event: "Ticket opened with timeline, logs, IOCs attached", data: "Attachments: PCAP (15MB), EDR telemetry (2.3MB), SIEM query results" },
      { actor: "soar", event: "Step 5: SOAR sends alert to on-call SOC analyst", data: "PagerDuty alert sent, SMS + Push notification" },
      { actor: "analysts", event: "SOC analyst receives notification and begins investigation", data: "Analyst: Sarah Chen, Investigation started: 14:32:45 UTC (27 seconds after detection)" },
    ],
    outcome: "Attack contained in under 30 seconds. Zero lateral spread. Analyst has full context to investigate root cause.",
    prevented: "Without automation: 5-15 minutes response time, attacker could compromise 3-5 additional hosts"
  },
  email_gw: {
    title: "Phishing Email → Automated Response",
    trigger: "Malicious attachment detected in inbound email",
    chain: [
      { actor: "email_gw", event: "Inbound email with .zip attachment scanned", data: "From: accounts@paypai.com (typosquat), Subject: 'Invoice Overdue'" },
      { actor: "email_gw", event: "Sandbox detonates attachment in isolated environment", data: "File: invoice_8472.zip → invoice.exe (renamed .pdf.exe)" },
      { actor: "email_gw", event: "Sandbox detects malicious behavior: network beaconing + registry modification", data: "C2: 185.220.101.42:443, Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
      { actor: "email_gw", event: "Email quarantined before delivery", data: "Status: Quarantined, User notified: Phishing attempt blocked" },
      { actor: "email_gw", event: "Sends alert + file hash to SIEM", data: "SHA256: 8f3e9d2a..., Verdict: Malware, Family: AgentTesla" },
      { actor: "siem", event: "SIEM receives phishing alert", data: "Checks: Has anyone already received this email? Query last 7 days" },
      { actor: "siem", event: "SIEM finds 3 users received similar email 2 days ago (before signature was added)", data: "Recipients: alice@corp, bob@corp, charlie@corp" },
      { actor: "soar", event: "SOAR playbook triggered: 'Phishing-Remediation-v3'", data: "Goal: Hunt for infection across all 3 previous recipients" },
      { actor: "soar", event: "SOAR queries EDR for file hash on all 3 user machines", data: "EDR search: SHA256=8f3e9d2a... across endpoints" },
      { actor: "edr_console", event: "EDR finds match: charlie@corp opened the attachment", data: "Host: EMP-WS-089, File executed: 2024-01-15 09:23:14, Process: invoice.exe" },
      { actor: "soar", event: "SOAR isolates infected host immediately", data: "Network isolation applied to EMP-WS-089" },
      { actor: "soar", event: "SOAR deletes malicious file from mailboxes of alice + bob", data: "Exchange API: Remove-MailboxSearch -DeleteContent" },
      { actor: "soar", event: "SOAR updates threat intel with new IOCs", data: "IOCs added: File hash, C2 IP, sending domain" },
      { actor: "threat_intel", event: "Threat intel platform updates feeds", data: "MISP event created, shared with org security tools" },
      { actor: "edge_fw", event: "Firewall receives updated IOC feed, blocks C2 domain", data: "Rule: DROP dst=185.220.101.42 any, Category: Known malware C2" },
      { actor: "soar", event: "SOAR creates ticket, assigns to malware analyst", data: "Ticket: Full infection timeline, memory dump requested from infected host" },
    ],
    outcome: "1 infected host found retrospectively. Malware prevented from spreading. C2 blocked org-wide.",
    prevented: "Without automation: Infected host could operate for days/weeks, exfiltrating credentials"
  },
  vuln: {
    title: "Critical CVE Detection → Patch Priority",
    trigger: "Weekly vulnerability scan finds critical RCE",
    chain: [
      { actor: "vuln", event: "Scheduled scan runs against production servers", data: "Scan: Weekly-Prod-Scan-2024-W04, Targets: VLAN 60 (production)" },
      { actor: "vuln", event: "Scanner finds CVE-2024-1234 on SQL01", data: "CVE-2024-1234: SQL Server RCE, CVSS 9.8, Exploit public since Jan 10" },
      { actor: "vuln", event: "Scanner checks if server is exposed to internet", data: "SQL01 port 1433: NOT exposed externally (internal only), Risk: Medium-High" },
      { actor: "vuln", event: "Scanner sends findings to SIEM", data: "Asset: SQL01, CVE: CVE-2024-1234, Severity: Critical, Exploitable: Yes" },
      { actor: "siem", event: "SIEM correlates CVE with asset criticality database", data: "SQL01: Production database, PII=Yes, Financial data=Yes, Criticality=Tier1" },
      { actor: "siem", event: "SIEM checks: Any exploit attempts in logs for this CVE?", data: "Query firewall + IDS logs last 30 days for CVE-2024-1234 signatures" },
      { actor: "ids_srv", event: "IDS reports: No exploit attempts detected", data: "Signature ID: SID-502341, Matches: 0" },
      { actor: "soar", event: "SOAR creates high-priority patch ticket", data: "Ticket: PATCH-2024-0042, SLA: 48 hours (Tier1 asset + Critical CVE)" },
      { actor: "itsm", event: "Ticket auto-assigned to SQL DBA team", data: "Assigned: DBA-Team, CCed: IT Security, Patch available: KB5024298" },
      { actor: "soar", event: "SOAR adds compensating controls while patch is pending", data: "Temporary mitigation: Block external access to port 1433 (already blocked, verified)" },
      { actor: "soar", event: "SOAR schedules vulnerability re-scan post-patch", data: "Re-scan scheduled: 2024-01-20 after maintenance window" },
      { actor: "backup", event: "SOAR triggers pre-patch backup of SQL01", data: "Backup job: SQL01-PrePatch-20240117, Status: Completed, Size: 450GB" },
      { actor: "itsm", event: "DBA applies patch during maintenance window", data: "Patch applied, SQL Server restarted, Downtime: 8 minutes" },
      { actor: "vuln", event: "Post-patch scan confirms CVE remediated", data: "SQL01: CVE-2024-1234 = NOT VULNERABLE, Patch verification successful" },
      { actor: "itsm", event: "Ticket closed, metrics updated", data: "Resolution time: 36 hours, SLA met, Patch success rate: 100%" },
    ],
    outcome: "Critical vulnerability patched in 36 hours with zero downtime impact (maintenance window used)",
    prevented: "Without automation: Avg patch time 2-3 weeks, vulnerable window increased 5x"
  },
  jump1: {
    title: "Off-Hours Admin Access → UEBA Detection",
    trigger: "Admin connects to jump server at 3 AM",
    chain: [
      { actor: "jump1", event: "SSH connection established from VPN", data: "User: admin@corp, Source: VPN-pool 10.0.10.200, Time: 03:14:22 UTC" },
      { actor: "pam", event: "PAM vault provides credentials for SQL01 access", data: "Credential: SQL01\\sa, Valid for: 4 hours, Session ID: PAM-82471" },
      { actor: "sess_rec", event: "Session recording started", data: "Video + keystroke capture active, Storage: /sessions/2024/01/17/PAM-82471.rec" },
      { actor: "jump1", event: "Admin executes: SELECT * FROM Users WHERE Role='Admin'", data: "Database: ProductionDB, Query returned: 147 rows, Time: 2.3s" },
      { actor: "sess_rec", event: "Logs all commands to SIEM", data: "Commands captured: 8 total, Duration: 14 minutes" },
      { actor: "siem", event: "SIEM forwards session data to UEBA", data: "User: admin@corp, Session: Prod DB access at 03:14 AM" },
      { actor: "ueba", event: "UEBA calculates risk score based on baseline", data: "Normal login time: 09:00-18:00 weekdays, Current: 03:14 Sunday = ANOMALY" },
      { actor: "ueba", event: "UEBA checks other factors: location, device, privilege level", data: "VPN from home (normal), Device: Known laptop (normal), Privilege: Root DB (high)" },
      { actor: "ueba", event: "UEBA risk score: 68/100 (Medium-High anomaly)", data: "Factors: Off-hours (+30), Weekend (+10), Root DB (+20), Known device (-10)" },
      { actor: "ueba", event: "UEBA sends alert to SIEM for correlation", data: "Alert: Anomalous admin behavior, Recommended action: Manager notification" },
      { actor: "siem", event: "SIEM creates informational alert (not critical)", data: "Alert: INFO-2024-0051, Action: Notify IT Manager for review" },
      { actor: "soar", event: "SOAR sends email to IT Manager + user's direct manager", data: "Email: FYI - Off-hours admin access by admin@corp, Please confirm if authorized" },
      { actor: "itsm", event: "Ticket created for review", data: "Ticket: REVIEW-2024-0051, Priority: Low, Review by: Next business day" },
      { actor: "analysts", event: "Next day: Manager confirms it was authorized (on-call incident)", data: "Manager response: Authorized, Context: Emergency DB restore for customer issue" },
      { actor: "itsm", event: "Ticket closed, session marked as authorized", data: "Session recording retained for compliance (90 days)" },
    ],
    outcome: "Anomaly detected and reviewed. Confirmed authorized. Baseline updated with on-call context.",
    prevented: "If unauthorized: Compromised admin creds would be flagged within minutes, not days/weeks"
  },
  file_srv: {
    title: "Insider Threat → Mass Data Exfiltration Attempt",
    trigger: "Employee accessing 10x normal file volume",
    chain: [
      { actor: "hr_ws", event: "HR employee logs in normally at 9 AM", data: "User: jane.doe@corp, Workstation: HR-WS-007, Login: 09:02:14" },
      { actor: "file_srv", event: "User accesses employee records folder (normal daily activity)", data: "Path: \\\\FS01\\HR\\EmployeeRecords, Files accessed: 12, Time: 09:15-09:45" },
      { actor: "file_srv", event: "User begins accessing salary database folder (unusual)", data: "Path: \\\\FS01\\HR\\Confidential\\Salaries, Files: Copying entire folder" },
      { actor: "file_srv", event: "Windows file audit logs mass copy operation", data: "EventID 4663: 847 files READ in 8 minutes by jane.doe, Total: 2.3GB" },
      { actor: "dlp", event: "DLP agent detects sensitive data movement", data: "Data classification: PII + Financial, Destination: USB drive E:\\" },
      { actor: "dlp", event: "DLP analyzes content: SSNs, salary info, bank accounts detected", data: "Matches: 847 documents contain SSN pattern, 823 contain salary data" },
      { actor: "dlp", event: "DLP blocks USB write operation", data: "Action: BLOCKED, User notified: Policy violation, IT Security alerted" },
      { actor: "dlp", event: "DLP sends alert to SIEM", data: "Alert: Mass PII exfiltration attempt blocked, User: jane.doe, Confidence: High" },
      { actor: "ueba", event: "UEBA checks user baseline: Normal file access = 50-80 files/day", data: "Current: 847 files in 8 minutes = 12x baseline = CRITICAL ANOMALY" },
      { actor: "siem", event: "SIEM correlates: DLP block + UEBA anomaly + file audit logs", data: "Risk score: 98/100, Classification: Insider threat - data exfiltration" },
      { actor: "soar", event: "SOAR immediately executes 'Insider-Threat-Response' playbook", data: "Playbook: Suspend user, preserve evidence, escalate to legal" },
      { actor: "soar", event: "Step 1: Disable AD account immediately", data: "User: jane.doe, Status: Disabled, All sessions terminated" },
      { actor: "dc", event: "Account disabled, user logged out of all systems", data: "Active sessions: 3, All forcefully disconnected" },
      { actor: "soar", event: "Step 2: Isolate workstation via EDR", data: "Host: HR-WS-007, Network isolated, Preserve memory for forensics" },
      { actor: "edr_console", event: "Workstation isolated, screenshot taken, memory dump initiated", data: "Evidence: 16GB RAM dumped, Disk imaging scheduled" },
      { actor: "soar", event: "Step 3: Notify HR + Legal + CISO immediately", data: "Critical notification sent, Conference bridge opened" },
      { actor: "soar", event: "Step 4: Create P1 incident with full evidence package", data: "Incident: INS-2024-0001, Evidence: File audit logs, DLP logs, PCAP, memory dump" },
      { actor: "forensic_ws", event: "Security analyst begins forensic investigation", data: "Analyst: Forensics team, Evidence chain of custody initiated" },
      { actor: "case_mgmt", event: "Legal case opened, timeline documented", data: "Case: 2024-INS-001, Status: Active investigation, HR coordinating" },
    ],
    outcome: "Exfiltration blocked. User contained in real-time. Full evidence preserved for investigation.",
    prevented: "Without automation: Data copied to USB, employee walks out. Discovery: weeks later during audit"
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

const COMPTIA_CATEGORIES = {
  H: { label: "Hardware", color: "#F4A261", desc: "Devices · Servers · Routers · TPM · HSM" },
  Ph: { label: "Physical", color: "#A1887F", desc: "Facilities · Guards · Bollards · Sites" },
  S: { label: "Software", color: "#4FC3F7", desc: "SIEM · SOAR · IDS/IPS · Antivirus · Monitoring" },
  P: { label: "Protocols", color: "#CE93D8", desc: "Network Standards · Communication Frameworks" },
  G: { label: "Governance", color: "#81C784", desc: "Policy · Compliance · Risk · Classification" },
  C: { label: "Cloud", color: "#80DEEA", desc: "Serverless · Managed Services · Cloud-Native" },
  M: { label: "Methods", color: "#FF8A80", desc: "Techniques · Encryption · Segmentation · Backups" },
};

const PLANES = {
  management: { id: "management", label: "Management Plane", color: "#8b5cf6", description: "Configuration · Policy · Monitoring · Orchestration" },
  control: { id: "control", label: "Control Plane", color: "#ec4899", description: "Routing Decisions · ACL Enforcement · Policy Engines" },
  data: { id: "data", label: "Data Plane", color: "#73c9ff", description: "Packet Forwarding · Traffic Flow · Data Transmission" },
};

///////////////////////////////////////////////////////////////////////

// SECURITY BOUNDARIES 

// GENERAL Security Boundaries
const BOUNDARIES = {
  external: { label: "Outside Enterprise", color: "#dc2626", desc: "Public Internet" },
  dmz: { label: "DMZ / Perimeter", color: "#f97316", desc: "Screened Subnet" },
  internal: { label: "Inside Enterprise", color: "#10b981", desc: "Trusted Internal Network" },
};

// VLANs 
const ZONES = [
  { id: "internet", label: "INTERNET", sublabel: "External / Public", x: 620, y: 20, w: 260, h: 100, color: "#ef4444", tier: "external", boundary: "external" },
  { id: "dmz", label: "DMZ — VLAN 10", sublabel: "10.0.10.0/24", x: 440, y: 140, w: 620, h: 140, color: "#f97316", tier: "perimeter", boundary: "dmz" },
  { id: "core", label: "CORE — VLAN 1", sublabel: "10.0.1.0/24 · Management", x: 260, y: 320, w: 980, h: 160, color: "#eab308", tier: "core", boundary: "internal" },
  { id: "soc", label: "SOC — VLAN 25", sublabel: "10.0.25.0/24 · Security Operations", x: 20, y: 520, w: 420, h: 280, color: "#a855f7", tier: "security", boundary: "internal" },
  { id: "it", label: "IT DEPT — VLAN 20", sublabel: "10.0.20.0/24", x: 460, y: 520, w: 340, h: 280, color: "#3b82f6", tier: "privileged", boundary: "internal" },
  { id: "jump", label: "JUMP/BASTION — VLAN 55", sublabel: "10.0.55.0/28 · PAM Gateway", x: 820, y: 520, w: 420, h: 280, color: "#ec4899", tier: "bastion", boundary: "internal" },
  { id: "finance", label: "FINANCE — VLAN 30", sublabel: "10.0.30.0/24", x: 20, y: 840, w: 220, h: 140, color: "#10b981", tier: "user", boundary: "internal" },
  { id: "hr", label: "HR — VLAN 40", sublabel: "10.0.40.0/24", x: 260, y: 840, w: 200, h: 140, color: "#10b981", tier: "user", boundary: "internal" },
  { id: "employees", label: "EMPLOYEES — VLAN 50", sublabel: "10.0.50.0/24", x: 480, y: 840, w: 260, h: 140, color: "#10b981", tier: "user", boundary: "internal" },
  { id: "voip", label: "VoIP — VLAN 80", sublabel: "10.0.80.0/24", x: 760, y: 840, w: 200, h: 140, color: "#06b6d4", tier: "utility", boundary: "internal" },
  { id: "iot", label: "IoT/Print — VLAN 90", sublabel: "10.0.90.0/24", x: 980, y: 840, w: 260, h: 140, color: "#06b6d4", tier: "utility", boundary: "internal" },
  { id: "prod_srv", label: "PROD SERVERS — VLAN 60", sublabel: "10.0.60.0/24 · Access via VLAN 55 only", x: 20, y: 1020, w: 720, h: 180, color: "#f59e0b", tier: "server", boundary: "internal" },
  { id: "dev_srv", label: "DEV SERVERS — VLAN 70", sublabel: "10.0.70.0/24 · Access via JUMP03", x: 760, y: 1020, w: 480, h: 180, color: "#f59e0b", tier: "server", boundary: "internal" },
  { id: "guest", label: "GUEST — VLAN 100", sublabel: "10.0.100.0/24 · Internet only", x: 20, y: 1240, w: 220, h: 120, color: "#6b7280", tier: "untrusted", boundary: "internal" },
  { id: "byod_e", label: "BYOD ENROLLED — VLAN 110", sublabel: "10.0.110.0/24 · MDM required", x: 260, y: 1240, w: 280, h: 120, color: "#6b7280", tier: "untrusted", boundary: "internal" },
  { id: "byod_r", label: "BYOD RESTRICTED — VLAN 120", sublabel: "10.0.120.0/24 · Internet only", x: 560, y: 1240, w: 280, h: 120, color: "#6b7280", tier: "untrusted", boundary: "internal" },
  { id: "forensic", label: "FORENSICS LAB", sublabel: "Isolated · Triggered by incidents", x: 860, y: 1240, w: 380, h: 120, color: "#dc2626", tier: "forensic", boundary: "internal" },
];

/////////////////////////////////////////////

// Security Tiers 
const TIER_LABELS = {
  external: "External",
  perimeter: "Perimeter",
  core: "Core / Management",
  security: "Security Ops (SOC)",
  privileged: "Privileged IT",
  bastion: "Bastion / PAM",
  user: "User VLANs",
  utility: "Utility VLANs",
  server: "Server VLANs",
  untrusted: "Untrusted / BYOD",
  forensic: "Forensics Lab",
};

// Security Tiers colors
const TIER_COLORS = {
  external: "#ef4444", perimeter: "#f97316", core: "#eab308", security: "#a855f7",
  privileged: "#3b82f6", bastion: "#ec4899", user: "#10b981", utility: "#06b6d4",
  server: "#f59e0b", untrusted: "#6b7280", forensic: "#dc2626",
};

/////////////////////////////////////////////

// Components inside VLANs zones
const ALL_DEVICES = [
  { id: "isp", label: "ISP Dual WAN", cat: "P", zone: "internet", x: 750, y: 80, icon: "🌐", feeds: ["edge_fw"], plane: null, desc: "Primary 1Gbps + Backup 500Mbps · BGP failover", purpose: "Provides redundant internet connectivity with automatic failover" },
  { id: "edge_fw", label: "Edge Firewall", cat: "H", zone: "dmz", x: 520, y: 240, icon: "🔥", feeds: ["siem", "soar", "ids_edge", "int_fw"], plane: "control", desc: "Palo Alto PA-3260 · IPS/IDS inline · Threat prevention", purpose: "First line of defense - inspects all traffic entering/leaving network", triggers: ["Blocks malicious IPs", "Sends threat logs to SIEM", "Auto-updates from threat intel"] },
  { id: "ids_edge", label: "Edge IDS", cat: "S", zone: "dmz", x: 670, y: 240, icon: "👁️", feeds: ["siem"], plane: "data", desc: "Suricata inline · 10.0.10.2 · Signature detection", purpose: "Deep packet inspection for threats at network perimeter" },
  { id: "waf", label: "WAF", cat: "S", zone: "dmz", x: 820, y: 240, icon: "🛡️", feeds: ["siem"], plane: "data", desc: "Cloudflare / F5 · OWASP Top 10 · Rate limiting", purpose: "Protects web applications from SQL injection, XSS, etc" },
  { id: "vpn_gw", label: "VPN Gateway", cat: "P", zone: "dmz", x: 630, y: 200, icon: "🔑", feeds: ["siem", "nac"], plane: "control", desc: "GlobalProtect · MFA enforced · Certificate auth", purpose: "Secure remote access for employees" },
  { id: "email_gw", label: "Email Gateway", cat: "S", zone: "dmz", x: 980, y: 240, icon: "📧", feeds: ["siem", "soar"], plane: "data", desc: "Proofpoint · Sandboxing · DLP · Anti-phishing", purpose: "Scans all inbound/outbound email for threats", triggers: ["Quarantines malicious emails", "Sends alerts to SIEM", "Triggers SOAR playbooks for phishing"] },
  
  { id: "core_sw", label: "Core Switch L3", cat: "H", zone: "core", x: 380, y: 380, icon: "⚡", feeds: ["siem", "npm", "netflow"], plane: "control", desc: "Cisco 9500 · 10.0.1.5 · Inter-VLAN routing · ACLs", purpose: "Routes traffic between VLANs, enforces network segmentation" },
  { id: "int_fw", label: "Internal Firewall", cat: "H", zone: "core", x: 550, y: 380, icon: "🔥", feeds: ["siem", "soar"], plane: "control", desc: "FortiGate 400E · Inter-VLAN ACLs · Stateful inspection", purpose: "Controls traffic between internal network segments", triggers: ["Blocks unauthorized VLAN-to-VLAN traffic", "Logs all inter-VLAN connections"] },
  { id: "dist_sw", label: "Dist Switches ×4", cat: "H", zone: "core", x: 720, y: 380, icon: "🔀", feeds: ["siem", "nac", "npm"], plane: "data", desc: "Cisco 9300 · 802.1X · DHCP snooping · DAI · PoE", purpose: "Connects user devices, enforces 802.1X authentication" },
  { id: "nac", label: "NAC", cat: "S", zone: "core", x: 890, y: 380, icon: "🔐", feeds: ["siem", "soar"], plane: "control", desc: "Cisco ISE · 10.0.1.10 · Posture checks · Device profiling", purpose: "Decides which devices can connect to network and which VLAN they get", triggers: ["Quarantines non-compliant devices", "Enforces MDM policies", "Blocks rogue devices"] },
  { id: "wlc", label: "Wireless Controller", cat: "H", zone: "core", x: 1060, y: 380, icon: "📡", feeds: ["siem", "nac"], plane: "control", desc: "Cisco WLC 9800 · 10.0.1.20 · Centralized AP mgmt", purpose: "Manages all wireless access points, enforces SSID policies" },
  { id: "npm", label: "Network Monitor", cat: "S", zone: "core", x: 380, y: 430, icon: "📊", feeds: ["siem", "itsm"], plane: "management", desc: "SolarWinds NPM · 10.0.1.30 · SNMP · Alerts", purpose: "Monitors network health, creates tickets when devices go down" },
  { id: "netflow", label: "NetFlow Analyzer", cat: "S", zone: "core", x: 550, y: 430, icon: "📈", feeds: ["siem", "ueba"], plane: "data", desc: "Scrutinizer · 10.0.1.35 · Traffic analysis", purpose: "Analyzes traffic patterns for anomalies" },

  // SOC VLAN
  { id: "analysts", label: "SOC Analysts", cat: "G", zone: "soc", x: 100, y: 580, icon: "👨‍💻", feeds: [], plane: "management", desc: "Human analysts who review alerts, investigate incidents, close tickets", purpose: "THE HUMANS - Final decision makers, handle complex incidents automation can't" },
  { id: "edr_console", label: "EDR Console", cat: "S", zone: "soc", x: 370, y: 620, icon: "💻", feeds: ["siem", "soar"], plane: "control", desc: "CrowdStrike · 10.0.25.30 · Host isolation", purpose: "Manages EDR agents, can remotely isolate infected hosts", triggers: ["Receives commands from SOAR to isolate hosts", "Sends alerts to SIEM when malware detected"] },
  { id: "siem", label: "SIEM", cat: "S", zone: "soc", x: 100, y: 620, icon: "🧠", feeds: ["soar", "ueba", "itsm", "forensic_ws"], plane: "control", desc: "Splunk / QRadar · 10.0.25.10 · Correlation · 90d retention", purpose: "THE BRAIN - Correlates logs from everything, detects threats", triggers: ["Generates alerts when patterns match attack signatures", "Triggers SOAR playbooks automatically", "Sends high-priority alerts to analysts"] },
  { id: "soar", label: "SOAR", cat: "S", zone: "soc", x: 245, y: 620, icon: "⚙️", feeds: ["edge_fw", "int_fw", "edr_console", "dc", "itsm"], plane: "control", desc: "Cortex XSOAR · 10.0.25.15 · Automated playbooks", purpose: "THE RESPONDER - Executes automated response to SIEM alerts", triggers: ["Isolates infected hosts via EDR", "Blocks IPs on firewalls", "Resets user passwords", "Creates tickets", "Sends notifications"] },
  { id: "ids_int", label: "Internal IDS", cat: "S", zone: "soc", x: 100, y: 680, icon: "👁️", feeds: ["siem"], plane: "data", desc: "Zeek · 10.0.25.20 · SPAN from core · Lateral movement", purpose: "Watches for lateral movement between internal systems" },
  { id: "ids_srv", label: "Server IDS", cat: "S", zone: "soc", x: 245, y: 680, icon: "👁️", feeds: ["siem"], plane: "data", desc: "Zeek · 10.0.25.21 · SPAN VLAN 60 · Server traffic", purpose: "Monitors all traffic to/from production servers" },
  { id: "ids_byod", label: "BYOD IDS", cat: "S", zone: "soc", x: 100, y: 740, icon: "👁️", feeds: ["siem"], plane: "data", desc: "Zeek · 10.0.25.22 · SPAN wireless · Guest/BYOD", purpose: "Watches untrusted devices for suspicious activity" },
  { id: "pcap", label: "PCAP/Arkime", cat: "S", zone: "soc", x: 245, y: 740, icon: "🔬", feeds: ["forensic_ws"], plane: "data", desc: "Full packet capture · 10.0.25.25 · 30d retention", purpose: "Records ALL network traffic for forensic investigation" },
  { id: "ueba", label: "UEBA", cat: "S", zone: "soc", x: 370, y: 680, icon: "📉", feeds: ["siem", "soar"], plane: "control", desc: "Splunk UBA · 10.0.25.35 · Behavioral baselines", purpose: "Detects anomalies like off-hours access, unusual file access", triggers: ["Flags anomalous user behavior to SIEM", "Can trigger SOAR for high-risk anomalies"] },
  { id: "threat_intel", label: "Threat Intel", cat: "S", zone: "soc", x: 370, y: 740, icon: "🗺️", feeds: ["siem", "soar", "edr_console", "edge_fw"], plane: "management", desc: "MISP · IOC feeds · STIX/TAXII · OSINT", purpose: "Provides IOCs (bad IPs, file hashes, domains) to all security tools", triggers: ["Updates firewall block lists", "Feeds IOCs to EDR for hunting", "Enriches SIEM alerts with threat context"] },
  
  // IT Dept VLAN 50
  { id: "vuln", label: "Vuln Scanner", cat: "S", zone: "it", x: 540, y: 620, icon: "🔍", feeds: ["siem", "itsm", "soar"], plane: "management", desc: "Nessus Pro · 10.0.20.70 · Weekly scans · CVE tracking", purpose: "Scans for vulnerabilities, creates patch tickets", triggers: ["Creates critical tickets for high-risk CVEs", "Alerts SIEM when exploitable vuln found on critical asset"] },
  { id: "dns_filter", label: "DNS Filter", cat: "S", zone: "it", x: 690, y: 620, icon: "🌍", feeds: ["siem", "soar"], plane: "data", desc: "Cisco Umbrella · 10.0.20.75 · Malicious domain blocking", purpose: "Blocks access to known malicious domains via DNS", triggers: ["Blocks DNS queries to C2 domains", "Sends alerts to SIEM for blocked domains"] },
  { id: "cfg_mgmt", label: "Config Mgmt", cat: "S", zone: "it", x: 540, y: 680, icon: "🗂️", feeds: ["siem"], plane: "management", desc: "Oxidized · GitLab · 10.0.20.80 · Config backup · Version control", purpose: "Backs up network device configs, tracks unauthorized changes" },
  { id: "proxy", label: "Web Proxy", cat: "S", zone: "it", x: 690, y: 680, icon: "🌐", feeds: ["siem", "dlp"], plane: "data", desc: "Squid / Cisco WSA · 10.0.20.85 · URL filtering · SSL inspection", purpose: "All web traffic goes through here, blocks malicious URLs" },
  { id: "itsm", label: "ITSM/Ticketing", cat: "S", zone: "it", x: 540, y: 740, icon: "🎫", feeds: ["analysts"], plane: "management", desc: "ServiceNow · 10.0.20.90 · Incident tracking · SLA monitoring", purpose: "Where all security incidents become tickets for humans to work", triggers: ["SOAR creates tickets here automatically", "Analysts work tickets and close them"] },
  { id: "dlp", label: "DLP", cat: "S", zone: "it", x: 690, y: 740, icon: "🚫", feeds: ["siem", "soar"], plane: "data", desc: "Symantec DLP · Data classification · Exfiltration prevention", purpose: "Prevents sensitive data from leaving the company", triggers: ["Blocks USB file copies with PII/financial data", "Alerts SIEM on exfiltration attempts", "Can trigger SOAR for insider threat response"] },
  
  // Jump Server - ADMIN
  { id: "jump1", label: "Jump Servers 1+2", cat: "H", zone: "jump", x: 930, y: 600, icon: "🔏", feeds: ["siem", "sess_rec"], plane: "control", desc: "JUMP01/02 · 10.0.55.2/3 · Prod access · PAM-brokered", purpose: "ONLY way to access production servers - all admin access goes here" },
  { id: "jump3", label: "Jump Server 3", cat: "H", zone: "jump", x: 1100, y: 600, icon: "🔏", feeds: ["siem", "sess_rec"], plane: "control", desc: "JUMP03 · 10.0.55.4 · Dev-only access · Isolated from prod", purpose: "Separate jump server for dev environment access" },
  { id: "pam", label: "PAM Vault", cat: "S", zone: "jump", x: 930, y: 670, icon: "🗝️", feeds: ["siem", "jump1", "jump3"], plane: "control", desc: "CyberArk PSM · 10.0.55.5 · Credential injection · Zero standing privs", purpose: "Stores all admin passwords, injects them so admins never see them", triggers: ["Logs every credential access to SIEM", "Can deny access based on policy", "Sends alerts on unusual access patterns"] },
  { id: "sess_rec", label: "Session Recorder", cat: "S", zone: "jump", x: 1100, y: 670, icon: "🎞️", feeds: ["siem", "forensic_ws"], plane: "data", desc: "CyberArk · 10.0.55.6 · Video + keystroke · 12mo retention", purpose: "Records every admin session for audit/forensics" },
  
  // Finance
  { id: "fin_ws", label: "Finance Workstations ×25", cat: "H", zone: "finance", x: 130, y: 910, icon: "🖥️", feeds: ["siem", "edr_agents"], plane: "data", desc: "Dell OptiPlex · EDR agents · Full disk encryption · Finance apps only", purpose: "Finance department workstations with EDR monitoring" },
  { id: "hr_ws", label: "HR Workstations ×15", cat: "H", zone: "hr", x: 360, y: 910, icon: "🖥️", feeds: ["siem", "edr_agents"], plane: "data", desc: "Dell OptiPlex · EDR agents · PII access controls · HR systems only", purpose: "HR workstations with PII data access" },
  { id: "emp_ws", label: "Employee Workstations ×150", cat: "H", zone: "employees", x: 610, y: 890, icon: "🖥️", feeds: ["siem", "edr_agents"], plane: "data", desc: "OptiPlex/iMac · EDR agents · Standard user access · Internet allowed", purpose: "Standard employee workstations" },
  { id: "edr_agents", label: "EDR Agents (all endpoints)", cat: "S", zone: "employees", x: 610, y: 940, icon: "🛡️", feeds: ["edr_console", "siem"], plane: "data", desc: "CrowdStrike Falcon · Real-time protection · Process telemetry", purpose: "Runs on EVERY endpoint, detects malware/suspicious behavior", triggers: ["Sends alerts to EDR console and SIEM", "Can be commanded by SOAR to isolate host"] },
  
  { id: "phones", label: "IP Phones ×200", cat: "H", zone: "voip", x: 860, y: 890, icon: "📞", feeds: ["pbx"], plane: "data", desc: "Cisco 8800 series · QoS VLAN · CoS marking · Isolated", purpose: "VoIP phones on isolated VLAN" },
  { id: "pbx", label: "PBX", cat: "H", zone: "voip", x: 860, y: 940, icon: "📟", feeds: ["siem"], plane: "data", desc: "Cisco UCM / Asterisk · Call detail records · Voicemail", purpose: "Phone system - logs calls for compliance" },
  
  { id: "printers", label: "MFP Printers ×10", cat: "H", zone: "iot", x: 1030, y: 890, icon: "🖨️", feeds: ["siem"], plane: "data", desc: "HP LaserJet Enterprise · Print audit · Secure print · Firmware updates", purpose: "Network printers - isolated from user VLANs" },
  { id: "cameras", label: "IP Cameras ×30", cat: "H", zone: "iot", x: 1030, y: 940, icon: "📷", feeds: ["nvr"], plane: "data", desc: "Security cameras · Motion detect · 90d retention · VLAN 90 isolated", purpose: "Physical security cameras" },
  { id: "nvr", label: "NVR", cat: "H", zone: "iot", x: 1170, y: 915, icon: "📼", feeds: ["siem"], plane: "data", desc: "Network Video Recorder · 10TB storage · Event triggers · Remote viewing", purpose: "Records camera footage" },
  
  // Production Servers
  { id: "dc", label: "Domain Controllers ×2", cat: "H", zone: "prod_srv", x: 110, y: 1090, icon: "🏛️", feeds: ["siem", "ueba", "nac"], plane: "control", desc: "DC01/02 · 10.0.60.10/11 · AD DS · DNS · DHCP · Replication · Group policy", purpose: "THE AUTHORITY - Authenticates all users, enforces group policies", triggers: ["SOAR can lock user accounts here", "Sends all login events to SIEM", "Failed logins trigger SIEM alerts"] },
  { id: "sql", label: "SQL Server", cat: "H", zone: "prod_srv", x: 270, y: 1090, icon: "🗄️", feeds: ["siem"], plane: "data", desc: "SQL01 · 10.0.60.30 · Production DBs · AlwaysOn AG · Audit logs · TDE", purpose: "Production database with all customer/business data" },
  { id: "app_srv", label: "App Servers ×2", cat: "H", zone: "prod_srv", x: 430, y: 1090, icon: "⚙️", feeds: ["siem"], plane: "data", desc: "APP01/02 · 10.0.60.40/41 · Web/API backend · Load balanced · Session affinity", purpose: "Web application servers" },
  { id: "file_srv", label: "File Server", cat: "H", zone: "prod_srv", x: 590, y: 1090, icon: "📁", feeds: ["siem", "dlp"], plane: "data", desc: "FS01 · 10.0.60.20 · DFS namespace · File audit · Clustered · Daily backup", purpose: "File shares for departments - monitored by DLP", triggers: ["Windows logs all file access", "DLP scans for sensitive data movement", "UEBA watches for anomalous file access patterns"] },
  { id: "exch", label: "Email Server", cat: "H", zone: "prod_srv", x: 110, y: 1150, icon: "📬", feeds: ["siem"], plane: "data", desc: "EXCH01 · 10.0.60.50 · Exchange hybrid · Transport rules · Mailbox audit", purpose: "Internal email server" },
  { id: "backup", label: "Backup Server", cat: "H", zone: "prod_srv", x: 270, y: 1150, icon: "💾", feeds: ["siem"], plane: "data", desc: "BKP01 · 10.0.60.70 · Veeam Backup & Replication · 3-2-1 rule · Off-site replication", purpose: "Backs up everything - SOAR can trigger backups before risky changes" },
  
  { id: "dev_web", label: "Dev Web Server", cat: "H", zone: "dev_srv", x: 900, y: 1070, icon: "🌐", feeds: ["siem"], plane: "data", desc: "DEVWEB01 · 10.0.70.10 · Test environment · Non-prod data · Snapshot before tests", purpose: "Development web server" },
  { id: "dev_db", label: "Dev Database", cat: "H", zone: "dev_srv", x: 1080, y: 1070, icon: "🗄️", feeds: ["siem"], plane: "data", desc: "DEVSQL01 · 10.0.70.20 · Dev/test data · Anonymized PII · Daily refresh from prod", purpose: "Dev database with sanitized data" },
  { id: "cicd", label: "CI/CD Server", cat: "S", zone: "dev_srv", x: 900, y: 1140, icon: "🔄", feeds: ["siem", "itsm"], plane: "management", desc: "Jenkins / GitLab CI · 10.0.70.30 · Pipeline automation · SAST/DAST · Artifact signing", purpose: "Automated build/deploy pipeline" },
  
  { id: "guest_dev", label: "Guest Devices", cat: "H", zone: "guest", x: 130, y: 1300, icon: "📱", feeds: ["siem"], plane: "data", desc: "Visitor smartphones/laptops · Captive portal · ToS acceptance · Bandwidth cap · Isolated", purpose: "Guest WiFi - completely isolated" },
  { id: "byod_phones", label: "BYOD Devices ×300+", cat: "H", zone: "byod_e", x: 350, y: 1300, icon: "📱", feeds: ["mdm", "siem"], plane: "data", desc: "Personal phones/laptops · MDM-enrolled · Conditional access · Compliance checks", purpose: "Personal devices with MDM - can access email/apps" },
  { id: "mdm", label: "MDM Platform", cat: "S", zone: "byod_e", x: 470, y: 1300, icon: "📲", feeds: ["siem", "nac"], plane: "control", desc: "Intune / Workspace ONE · Device compliance · App mgmt · Remote wipe · Geofencing", purpose: "Manages personal devices, enforces security policies", triggers: ["Reports compliance status to NAC", "SOAR can remote wipe devices", "Blocks non-compliant devices from email"] },
  { id: "byod_unman", label: "Unmanaged Devices ×80+", cat: "H", zone: "byod_r", x: 700, y: 1300, icon: "📱", feeds: ["siem"], plane: "data", desc: "Personal devices · DNS-filtered internet only · No internal access · Bandwidth limited", purpose: "Unmanaged personal devices - internet only" },
  
  { id: "forensic_ws", label: "Forensic Workstation", cat: "H", zone: "forensic", x: 970, y: 1280, icon: "🔬", feeds: ["case_mgmt"], plane: "management", desc: "Isolated analysis station · FTK / EnCase · Write-blockers · Evidence preservation", purpose: "Analysts investigate incidents here with captured forensic data" },
  { id: "case_mgmt", label: "Case Management", cat: "S", zone: "forensic", x: 1130, y: 1280, icon: "📋", feeds: ["analysts"], plane: "management", desc: "Incident case tracking · Evidence chain of custody · Timeline reconstruction · Reporting", purpose: "Tracks investigation from detection to resolution" },
  
];

// ═══════════════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export default function EnterpriseTopologyFlexible() {
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [hoveredDevice, setHoveredDevice] = useState(null);
  const [transform, setTransform] = useState({ x: 90, y: 8, scale: 0.6 }); {/* Map position at loading time*/}
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState(null);
  const [showPlanes, setShowPlanes] = useState(true);
  const [filterTier, setFilterTier] = useState("all");
  const [showConnections, setShowConnections] = useState("selected");
  const [legendMode, setLegendMode] = useState("zones");
  const svgRef = useRef(null);
  const containerRef = useRef(null);

  const handleMouseDown = (e) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y });
    e.preventDefault();
  };

  const handleMouseMove = (e) => {
    if (isDragging && dragStart) {
      setTransform(t => ({ ...t, x: e.clientX - dragStart.x, y: e.clientY - dragStart.y }));
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
    setDragStart(null);
  };

  const handleWheel = (e) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setTransform(t => ({ ...t, scale: Math.min(2, Math.max(0.3, t.scale * delta)) }));
  };

  useEffect(() => {
    const el = containerRef.current;
    if (el) {
      el.addEventListener("wheel", handleWheel, { passive: false });
      return () => el.removeEventListener("wheel", handleWheel);
    }
  }, []);

  // Filter
  const filteredZones = filterTier === "all" ? ZONES : ZONES.filter(z => z.tier === filterTier);
  const filteredDevices = filterTier === "all" ? ALL_DEVICES : ALL_DEVICES.filter(d => {
    const zone = ZONES.find(z => z.id === d.zone);
    return zone?.tier === filterTier;
  });

  // Build connections
  const allConnections = [];
  ALL_DEVICES.forEach(dev => {
    if (dev.feeds) {
      dev.feeds.forEach(target => {
        const targetDev = ALL_DEVICES.find(d => d.id === target);
        if (targetDev) {
          allConnections.push({ from: dev.id, to: target, fromDev: dev, toDev: targetDev });
        }
      });
    }
  });

  let visibleConnections = [];
  if (showConnections === "all") {
    visibleConnections = allConnections;
  } else if (showConnections === "selected" && selectedDevice) {
    visibleConnections = allConnections.filter(c => 
      c.from === selectedDevice.id || c.to === selectedDevice.id
    );
  }

  const getDevice = (id) => ALL_DEVICES.find(d => d.id === id);
  const getCategory = (cat) => COMPTIA_CATEGORIES[cat] || COMPTIA_CATEGORIES.S;
  const getScenario = (deviceId) => SCENARIOS[deviceId];
  const getFeedsFrom = (deviceId) => ALL_DEVICES.filter(d => d.feeds?.includes(deviceId));

  const CANVAS_W = 1260;
  const CANVAS_H = 1900;

  return (
    <div style={{ background: "#171d2f", height: "100vh", width: "100vw", fontFamily: "'JetBrains Mono', 'Courier New', monospace", color: "#e2e8f0", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      
      {/* ================================================================= */}

      {/* Header */}
      <div style={{ padding: "10px 20px", borderBottom: "1px solid #1e293b", background: "#171d2f", display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", zIndex: 100, flexShrink: 1 }}>
        <div style={{ flex: "0 1 auto" }}>
          <div style={{ fontSize: 10, letterSpacing: 3, color: "#e855f7", textTransform: "uppercase" }}>Security Topology</div>
          <div style={{ fontSize: 17, fontWeight:600, color: "#f1f5f9", letterSpacing: 0.2 }}>Enterprise Office · Network Topology ·  v7 </div>
        </div>
        
        <div style={{ marginLeft: "auto", display: "flex", gap: 4, alignItems: "left", flexWrap: "wrap" }}> {/* Header Bar*/}
          {/* Planes */} {/* Header Bar*/}
          <button onClick={() => setShowPlanes(showPlanes)} style={{
            padding: "4px 10px", fontSize: 10, border: `1px solid ${showPlanes ? "#8b5cf6" : "#334155"}`,
            background: showPlanes ? "#8b5cf622" : "transparent", color: showPlanes ? "#8b5cf6" : "#64748b",
            borderRadius: 4, cursor: "pointer", textTransform: "uppercase", fontWeight: 800
          }}>
            {showPlanes ? "✓ Planes" : "Planes"}
          </button>
          
          {/* Connections */} {/* Header Bar*/}
          <span style={{ fontSize: 10, color: "#e4eaf5", marginLeft: 4 }}>Connections:</span>
          {["all", "selected", "none"].map(mode => (
            <button key={mode} onClick={() => setShowConnections(mode)} style={{
              padding: "4px 7px", fontSize: 10, border: `1px solid ${showConnections === mode ? "#4FC3F7" : "#115155"}`,
              background: showConnections === mode ? "#4FC3F722" : "transparent",
              color: showConnections === mode ? "#4FC3F7" : "#64748b",
              borderRadius: 4, cursor: "pointer", textTransform: "uppercase"
            }}>
              {mode.slice(0,9)}
            </button>
          ))}
          
          {/* Tier filter */} {/* Header Bar*/}
          <span style={{ fontSize: 10, color: "#e4eaf5", marginLeft: 4 }}>Filter:</span>
          {["all", "external", "perimeter", "core", "security", "privileged", "bastion", "user", "utility", "server", "untrusted", "forensic"].map(tier => (
            <button key={tier} onClick={() => setFilterTier(tier)} style={{
              padding: "3px 5px", fontSize: 10, border: `1px solid ${filterTier === tier ? TIER_COLORS[tier] || "#a855f7" : "#634155"}`,
              background: filterTier === tier ? `${TIER_COLORS[tier] || "#a855f7"}22` : "transparent",
              color: filterTier === tier ? (TIER_COLORS[tier] || "#e4eaf5") : "#e4eaf5",
              borderRadius: 3, cursor: "pointer", textTransform: "uppercase"
            }}>
              {tier === "all" ? "All" : (TIER_LABELS[tier]?.split(" ")[0] || tier).slice(0,9)}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        
        {/* =========================== MAIN CANVAS ========================================== */}

        {/* Main Canvas */}
        <div 
          ref={containerRef}
          style={{ 
            flex: 1, 
            overflow: "hidden", 
            cursor: isDragging ? "grabbing" : "grab", 
            position: "relative", 
            background: "#171d2f",
            userSelect: "none"
          }}
          onMouseDown={handleMouseDown} 
          onMouseMove={handleMouseMove} 
          onMouseUp={handleMouseUp} 
          onMouseLeave={handleMouseUp}>
          
          <svg ref={svgRef} width="100%" height="100%" style={{ display: "block" }}>
            <defs>
              <marker id="arrow" markerWidth="7" markerHeight="7" refX="5" refY="3" orient="auto">
                <path d="M0,0 L0,6 L7,3 z" fill="#4FC3F7" />
              </marker>
              <marker id="arrow-selected" markerWidth="9" markerHeight="9" refX="6" refY="4" orient="auto">
                <path d="M0,0 L0,8 L9,4 z" fill="#fbbf24" />
              </marker>
              <filter id="glow">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
              <filter id="glow-strong">
                <feGaussianBlur stdDeviation="5" result="blur" />
                <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            </defs>

            <g transform={`translate(${transform.x},${transform.y}) scale(${transform.scale})`}>
              
              {/* Background grid */}
              <rect x={0} y={0} width={CANVAS_W} height={CANVAS_H} fill="none" />
              {Array.from({ length: 64 }).map((_, i) => (
                <line key={`v${i}`} x1={i * 20} y1={0} x2={i * 20} y2={CANVAS_H} stroke="#0a0f1e" strokeWidth={1} opacity={0.9} />
              ))}
              {Array.from({ length: 71 }).map((_, i) => (
                <line key={`h${i}`} x1={0} y1={i * 20} x2={CANVAS_W} y2={i * 20} stroke="#0a0f1e" strokeWidth={1} opacity={0.9} />
              ))}

              {/* --------------------- ZONES / PERIMETERS --------------------- */}

              {/* Security Boundary Labels - (External/DMZ/Internal Perimeters) */}
              <g opacity={1.0}> 
                <text x={0} y={17} fill={BOUNDARIES.external.color} fontSize={19} fontWeight={600} letterSpacing={1}>
                ---------------------------------------------------------------------------------------------------------- 🌍 {BOUNDARIES.external.label} 
                </text>
                <text x={0} y={135} fill={BOUNDARIES.dmz.color} fontSize={19} fontWeight={600} letterSpacing={1}>
                ------------------------------------------------------------------------------------------------------------ 🛡️ {BOUNDARIES.dmz.label} 
                </text>
                <text x={0} y={312} fill={BOUNDARIES.internal.color} fontSize={19} fontWeight={600} letterSpacing={1}>
                ---------------------------------------------------------------------------------------------------------- 🏢 {BOUNDARIES.internal.label} 
                </text>
              </g>

              {/* CompTIA Planes overlay */}
              {showPlanes && (
                <g opacity={1.0}>
                  {[
                    { label: "Management Plane", y: -20, h: 490, color: "#8b5cf6" },
                    { label: "Control Plane", y: 490, h: 302, color: "#ec4899" },
                    { label: "Data Plane", y: 808, h: 555, color: "#73c9ff" },
                  ].map((plane, i) => (
                    <g key={i}>
                      <rect x={0} y={plane.y} width={CANVAS_W} height={plane.h}
                        fill={`${plane.color}09`} stroke={`${plane.color}95`} strokeWidth={3}
                        strokeDasharray="10 5" />
                      <text x={10} y={plane.y + 20} fill={plane.color} fontSize={22} fontWeight={800} opacity={0.99}>  {/* Plane(s) text specifics */}
                        {plane.label}
                      </text>
                    </g>
                  ))}
                </g>
              )}

              {/* ZONES with boundary markers */}
              {filteredZones.map(zone => {
                const isSelected = selectedDevice?.zone === zone.id;
                const boundaryColor = BOUNDARIES[zone.boundary]?.color || zone.color;
                
                return (
                  <g key={zone.id}>
                    {isSelected && (
                      <rect x={zone.x - 3} y={zone.y - 3} width={zone.w + 6} height={zone.h + 6} rx={10}
                        fill={zone.color} opacity={0.09} filter="url(#glow)" />
                    )}
                    
                    {/* Boundary marker on left edge */} {/* ZONES */}
                    <rect x={zone.x - 7} y={zone.y} width={7} height={zone.h-20} fill={boundaryColor} opacity={0.9} />
                    
                    <rect x={zone.x} y={zone.y} width={zone.w} height={zone.h - 14} rx={8}
                      fill={`${zone.color}09`} stroke={isSelected ? zone.color : `${zone.color}99`} 
                      strokeWidth={isSelected ? 1.9 : 1} /> {/* Zone Surface Area Hatch/Fill */}
                    <rect x={zone.x} y={zone.y} width={zone.w} height={26} rx={8} fill={`${zone.color}1a`} /> {/* Displacement of Surface Area Hatch/Fill */}
                    <rect x={zone.x} y={zone.y} width={zone.w} height={7} fill={`${zone.color}1a`} /> {/* Displacement of Zone Bar  Hatch/Fill */}
                    <rect x={zone.x + 7} y={zone.y + 7} width={7} height={7} rx={1.5} fill={zone.color} /> {/* Dot - Zone Surface Area Name */}
                    <text x={zone.x + 20} y={zone.y + 15} fill={zone.color} fontSize={17} fontWeight={700} letterSpacing={0.5}> {/* Zone Name */}
                      {zone.label}
                    </text>
                    <text x={zone.x + 12} y={zone.y + 36} fill={`${zone.color}99`} fontSize={9.5}> {/* Subnetting Address */}
                      {zone.sublabel}
                    </text>
                  </g>
                );
              })}

              {/* --------------------- Connections --------------------- */}

              {/* Connections */}
              {visibleConnections.map((conn, i) => {
                const from = conn.fromDev;
                const to = conn.toDev;
                if (!from || !to) return null;
                const isSelected = selectedDevice && (from.id === selectedDevice.id || to.id === selectedDevice.id);
                const color = isSelected ? "#fbbf24" : "#4FC3F7";
                const width = isSelected ? 2 : 1;
                const opacity = isSelected ? 1 : 0.3;
                
                const dx = to.x - from.x;
                const dy = to.y - from.y;
                const dist = Math.sqrt(dx*dx + dy*dy);
                const midX = (from.x + to.x) / 2;
                const midY = (from.y + to.y) / 2;
                const offsetX = -dy / dist * 15;
                const offsetY = dx / dist * 15;
                const ctrlX = midX + offsetX;
                const ctrlY = midY + offsetY;

                return (
                  <g key={i}>
                    <path
                      d={`M ${from.x} ${from.y} Q ${ctrlX} ${ctrlY} ${to.x} ${to.y}`}
                      stroke={color} strokeWidth={width} fill="none" opacity={opacity}
                      markerEnd={`url(#arrow${isSelected ? "-selected" : ""})`}
                      filter={isSelected ? "url(#glow)" : "none"}
                      style={{ pointerEvents: "none" }}
                    />
                  </g>
                );
              })}

              {/* Devices */}
              {filteredDevices.map(dev => {
                const cat = getCategory(dev.cat);
                const isSelected = selectedDevice?.id === dev.id;
                const isHovered = hoveredDevice?.id === dev.id;
                const isConnected = selectedDevice && visibleConnections.some(c => 
                  (c.from === dev.id && c.to === selectedDevice.id) || 
                  (c.to === dev.id && c.from === selectedDevice.id)
                );
                
                const hasScenario = !!SCENARIOS[dev.id];
                const labelWidth = Math.max(140, dev.label.length * 6.5 + 40);
                const boxW = labelWidth;
                const boxH = 35; {/* Devices Box height*/}

                return (
                  <g key={dev.id}
                    onClick={(e) => { e.stopPropagation(); setSelectedDevice(dev); }}
                    onMouseEnter={() => setHoveredDevice(dev)}
                    onMouseLeave={() => setHoveredDevice(null)}
                    style={{ cursor: "pointer" }}>
                    
                    {(isSelected || isConnected) && (
                      <rect x={dev.x - boxW/2 - 3} y={dev.y - boxH/2 - 3} width={boxW + 6} height={boxH + 6} rx={7}
                        fill={isSelected ? "#fbbf24" : "#4FC3F7"} opacity={0.512}
                        filter="url(#glow-strong)" />
                    )}

                    <rect x={dev.x - boxW/2} y={dev.y - boxH/2} width={boxW} height={boxH} rx={6}
                      fill={isSelected ? "#1a2332" : (isHovered ? "#141b28" : "#0f1621")}
                      stroke={isSelected ? "#fbbf24" : (isConnected ? "#4FC3F7" : `${cat.color}aa`)}
                      strokeWidth={isSelected ? 2 : (isConnected ? 1.5 : 1)} />
                    
                    <rect x={dev.x - boxW/2} y={dev.y - boxH/2} width={5} height={boxH} rx={6}
                      fill={cat.color} />
                    
                    <text x={dev.x - boxW/2 + 16} y={dev.y - 6} fontSize={16} textAnchor="middle">
                      {dev.icon}
                    </text>
                    
                    <text x={dev.x - boxW/2 + 28} y={dev.y - 4} fill="#f1f5f9" fontSize={9.5} fontWeight={600}>
                      {dev.label}
                    </text>
                    
                    <text x={dev.x - boxW/2 + 28} y={dev.y + 8} fill={cat.color} fontSize={7.5} fontWeight={600}>
                      [{dev.cat}] {cat.label}
                    </text>

                    {hasScenario && (
                      <circle cx={dev.x + boxW/2 - 7} cy={dev.y - boxH/2 + 7} r={3}
                        fill="#fbbf24" filter="url(#glow)" />
                    )}

                    {(isHovered || isSelected) && !hasScenario && (
                      <circle cx={dev.x + boxW/2 - 7} cy={dev.y - boxH/2 + 7} r={2.5}
                        fill={isSelected ? "#fbbf24" : "#4FC3F7"} filter="url(#glow)" />
                    )}
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Controls */} {/* "Click / Drag" box & "+/-" left Buttons */}
          <div style={{ position: "absolute", bottom: 24, right: 14, background: "#0f1621dd", border: "1px solid #1e3a5f", borderRadius: 6, padding: "7px 10px", fontSize: 9, color: "#e4eaf5", lineHeight: 1.4 }}>
            <div>🖱 Click & drag to pan · ⚲ Scroll to zoom</div>
            <div>💡 Yellow dot = Real-world scenario</div>
          </div>

          <div style={{ position: "absolute", bottom: 24, left: 14, display: "flex", flexDirection: "column", gap: 3 }}>
            {[["＋", 1.2], ["−", 0.8], ["⌂", null]].map(([label, factor]) => (
              <button key={label} onClick={(e) => {
                e.stopPropagation();
                if (factor) setTransform(t => ({ ...t, scale: Math.min(2, Math.max(0.3, t.scale * factor)) }));
                else setTransform({ x: 0, y: 0, scale: 0.68 });
              }} style={{
                width: 28, height: 28, background: "#0f1621", border: "1px solid #1e3a5f",
                color: "#94a3b8", borderRadius: 4, cursor: "pointer", fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center"
              }}>{label}</button>
            ))}
          </div>
        </div>
        
        {/* ============================ RIGHT PANEL ============================ */}
        
        {/* RIGHT PANEL */} {/* Key & Information */}
        <div style={{ width: 300, borderLeft: "1px solid #5e293b", background: "#202430", overflowY: "auto", padding: "14px", display: "flex", flexDirection: "column", gap: 12, flexShrink: 5 }}>
          
          {selectedDevice ? (
            <>
              {/* Device Header  ------- Right Panel -------*/}
              <div> {/* Selected Component / Device  */}
                <div style={{ fontSize: 11, letterSpacing: 2, color: "#e4eaf5", marginBottom: 6, textTransform: "uppercase" }}>Selected Component</div>
                <div style={{ border: `1px solid ${getCategory(selectedDevice.cat).color}44`, borderLeft: `3px solid ${getCategory(selectedDevice.cat).color}`, borderRadius: 6, padding: "9px", background: "#0a0f1e" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 6 }}>
                    <span style={{ fontSize: 16 }}>{selectedDevice.icon}</span>
                    <div>
                      <div style={{ color: "#e4eaf5", fontWeight: 800, fontSize: 13 }}>{selectedDevice.label}</div> {/* Selected Component Name  */}
                      <div style={{ color: getCategory(selectedDevice.cat).color, fontSize: 10, fontWeight: 700 }}> {/* Selected Component "Subtitle" Comptia Category  */}
                        [{selectedDevice.cat}] {getCategory(selectedDevice.cat).label}
                      </div>
                    </div>
                  </div>
                  <div style={{ fontSize: 10, color: "#e4eaf5", lineHeight: 1.4, marginBottom: 6 }}>
                    {selectedDevice.desc}
                  </div>
                </div>
              </div>

              {/* PURPOSE  ------- Right Panel ------- */}
              {selectedDevice.purpose && (
                <div>
                  <div style={{ fontSize: 11, letterSpacing: 2, color: "#e4eaf5", marginBottom: 5, textTransform: "uppercase" }}>⚙️ Purpose</div>
                  <div style={{ background: "#0a0f1e", border: "1px solid #1e293b", borderRadius: 5, padding: "7px 9px", fontSize: 11, color: "#e4eaf5", lineHeight: 1.4 }}>
                    {selectedDevice.purpose}
                  </div>
                </div>
              )}

              {/* DATA FLOWS ------- Right Panel ------- */}
              <div>
                <div style={{ fontSize: 11, letterSpacing: 2, color: "#e4eaf5", marginBottom: 5, textTransform: "uppercase" }}>⇅ Data Flows</div>
                <div style={{ background: "#0a0f1e", border: "1px solid #1e293b", borderRadius: 5, padding: "7px 9px" }}>
                  
                  {/* -------'SENDS TO ->' CONNECTED Component BOX ------- Right Panel ------- */}
                  {selectedDevice.feeds && selectedDevice.feeds.length > 0 && (
                    <div style={{ marginBottom: 6 }}>
                      <div style={{ fontSize: 10, color: "#e4eaf5", marginBottom: 3, letterSpacing: 0.5 }}>↓ SENDS DATA TO:</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                        {selectedDevice.feeds.map(targetId => {
                          const target = getDevice(targetId);
                          if (!target) return null;
                          return (
                            <div key={targetId} onClick={(e) => { e.stopPropagation(); setSelectedDevice(target); }} style={{
                              fontSize: 12, padding: "2px 6px", background: "#4FC3F711", border: "1.5px solid #4FC3F733",
                              borderRadius: 3, cursor: "pointer", color: "#4FC3F7", transition: "all 0.15s"
                            }}
                              onMouseEnter={e => e.currentTarget.style.background = "#4FC3F722"}
                              onMouseLeave={e => e.currentTarget.style.background = "#4FC3F711"}>
                              {target.label}
                            </div> 
                          );
                        })}
                      </div>
                    </div>
                  )}
                  {/* ------- '<- RECEIVES FROM' CONNECTED Component BOX ------- Right Panel ------- */}
                  {(() => {
                    const feeders = getFeedsFrom(selectedDevice.id);
                    if (feeders.length === 0) return null;
                    return (
                      <div>
                        <div style={{ fontSize: 10, color: "#e4eaf5", marginBottom: 3, letterSpacing: 0.5 }}>↑ RECEIVES FROM:</div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                          {feeders.map(feeder => (
                            <div key={feeder.id} onClick={(e) => { e.stopPropagation(); setSelectedDevice(feeder); }} style={{
                              fontSize: 12, padding: "2px 6px", background: "#10b98111", border: "1.5px solid #10b98133",
                              borderRadius: 3, cursor: "pointer", color: "#e4eaf5", transition: "all 0.15s"
                            }}
                              onMouseEnter={e => e.currentTarget.style.background = "#10b98122"}
                              onMouseLeave={e => e.currentTarget.style.background = "#10b98111"}>
                              {feeder.label}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })()}
                </div>
              </div>
             
              {/* ----------------------------- */}
              {/* TRIGGERS */}
              {selectedDevice.triggers && selectedDevice.triggers.length > 0 && (
                <div>
                  <div style={{ fontSize: 9, letterSpacing: 2, color: "#e4eaf5", marginBottom: 5, textTransform: "uppercase" }}>⚡ Triggers / Actions</div>
                  <div style={{ background: "#0a0f1e", border: "1px solid #1e293b", borderRadius: 5, padding: "7px 9px" }}>
                    {selectedDevice.triggers.map((trigger, i) => (
                      <div key={i} style={{ display: "flex", gap: 5, marginBottom: 4, alignItems: "flex-start" }}>
                        <span style={{ color: "#e4eaf5", fontSize: 9, flexShrink: 0 }}>▸</span>
                        <div style={{ fontSize: 9, color: "#e4eaf5", lineHeight: 1.4 }}>{trigger}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ----------------------------- */}
              {/* REAL-WORLD SCENARIO */}
              {(() => {
                const scenario = getScenario(selectedDevice.id);
                if (!scenario) return null;

                return (
                  <div> 
                    <div style={{ fontSize: 14, letterSpacing: 2, color: "#e4eaf5", marginBottom: 5, textTransform: "uppercase" }}>🎯 Real-World Scenario: The Domino Effect</div>
                    <div style={{ background: "#1a0f14", border: "1px solid #ff4d6d33", borderLeft: "3px solid #ff4d6d", borderRadius: 5, padding: "9px" }}>
                      
                      <div style={{ color: "#e4eaf5", fontWeight: 700, fontSize: 10, marginBottom: 4 }}>{scenario.title}</div>
                      <div style={{ fontSize: 10, color: "#e4eaf5", marginBottom: 8, padding: "4px 6px", background: "#ff4d6d11", borderRadius: 3 }}>
                        Trigger: {scenario.trigger}
                      </div>
                      {/* Event Chain Box */}
                      <div style={{ fontSize: 13, color: "#e4eaf5", marginBottom: 5, textTransform: "uppercase", letterSpacing: 1 }}>Event Chain:</div>
                      <div style={{ maxHeight: 400, overflowY: "auto", marginBottom: 8 }}>
                        {scenario.chain.map((step, i) => {
                          const actor = getDevice(step.actor);
                          const actorColor = actor ? getCategory(actor.cat).color : "#64748b";
                          return (
                            <div key={i} style={{ marginBottom: 6, paddingLeft: 6, borderLeft: `2px solid ${i === scenario.chain.length - 1 ? "#10b981" : "#1e3a5f"}` }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 2 }}>
                                <span style={{ fontSize: 10, color: "#e4eaf5", fontFamily: "monospace", minWidth: 16 }}>{i + 1}.</span>
                                {actor && (
                                  <span style={{ fontSize: 11, color: actorColor, fontWeight: 600, cursor: "pointer" }}
                                    onClick={() => setSelectedDevice(actor)}> {/* Event Chain - Step */}
                                    {actor.label}
                                  </span>
                                )}
                              </div>
                              {/* Event Chain - Each Step Description */}
                              <div style={{ fontSize: 11, color: "#e3e3e3", lineHeight: 1.4, marginBottom: 2 }}>
                                {step.event}
                              </div>
                              {/* Event Chain - Each Step "How/What/Where/Which (Device, Tool, Protocol, CVA, etc)" */}
                              <div style={{ fontSize: 8.5, color: "#54748b", fontFamily: "monospace", background: "#0a0f1e", padding: "3px 6px", borderRadius: 2 }}>
                                {step.data}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                      {/* Event Chain - Red/Green Outcome of Scenario */}
                      <div style={{ background: "#10b98111", border: "1px solid #10b981", borderRadius: 4, padding: "6px 8px", marginBottom: 6 }}>
                        <div style={{ fontSize: 9, color: "#e4eaf5", fontWeight: 600, marginBottom: 2 }}>✓ OUTCOME</div>
                        <div style={{ fontSize: 9, color: "#e4eaf5", lineHeight: 1.4 }}>{scenario.outcome}</div>
                      </div>

                      <div style={{ background: "#ef444411", border: "1px solid #ef4444", borderRadius: 4, padding: "6px 8px" }}>
                        <div style={{ fontSize: 9, color: "#e4eaf5", fontWeight: 600, marginBottom: 2 }}>⚠ WITHOUT AUTOMATION</div>
                        <div style={{ fontSize: 9, color: "#e4eaf5", lineHeight: 1.4 }}>{scenario.prevented}</div>
                      </div>
                    </div>
                  </div>
                );
              })()}

            </>
          ) : (
            <div> {/* Top Right Bar at Loading Time - Before Component Selected */}
              <div style={{ fontSize: 10, letterSpacing: 2, color: "#e4eaf5", marginBottom: 10, textTransform: "uppercase" }}>How It Actually Works</div>
              <div style={{ color: "#f9548b", fontSize: 9, lineHeight: 1.5, marginBottom: 5 }}>
                Click any device to see:
              </div>
              <div style={{ fontSize: 10, color: "#e4eaf5", lineHeight: 1.6, marginBottom: 3 }}>• What it does in the real world</div>
              <div style={{ fontSize: 10, color: "#e4eaf5", lineHeight: 1.6, marginBottom: 3 }}>• What data it sends/receives</div>
              <div style={{ fontSize: 10, color: "#e4eaf5", lineHeight: 1.6, marginBottom: 3 }}>• What actions it can trigger</div>
              <div style={{ fontSize: 10, color: "#e4eaf5", lineHeight: 1.6, marginBottom: 10 }}>• The complete "domino effect" of security events</div>
              <div style={{ fontSize: 10, color: "#e4eaf5", padding: "6px 8px", background: "#0a0f1e", border: "1px solid #1e293b", borderRadius: 4, lineHeight: 1.5 }}>
                💡 Devices with a yellow dot have detailed real-world scenarios
              </div>
            </div>
          )}

          {/* Legend Toggle */}
          <div>
            <div style={{ display: "flex", gap: 4, marginBottom: 8 }}>
              {["zones", "comptia"].map(mode => (
                <button key={mode} onClick={() => setLegendMode(mode)} style={{
                  flex: 1, padding: "5px", fontSize: 11, border: `1px solid ${legendMode === mode ? "#a855f7" : "#334155"}`,
                  background: legendMode === mode ? "#a855f722" : "transparent",
                  color: legendMode === mode ? "#a855f7" : "#64748b",
                  borderRadius: 4, cursor: "pointer", textTransform: "uppercase", fontWeight: 700
                }}>
                  {mode === "zones" ? "Zone Legend" : "CompTIA"}
                </button>
              ))}
            </div>

            {/* Zone Legend */}
            {legendMode === "zones" && (
              <div>
                <div style={{ fontSize: 10, letterSpacing: 2, color: "#e4eaf5", marginBottom: 5, textTransform: "uppercase" }}>Security Tiers</div>
                {Object.entries(TIER_LABELS).map(([tier, label]) => (
                  <div key={tier} style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 5, padding: "5px 7px", background: "#0a0f1e", borderRadius: 4, border: "1px solid #1e293b" }}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: TIER_COLORS[tier], flexShrink: 0 }} />
                    <div style={{ fontSize: 10, color: "#e4eaf5" }}>{label}</div>
                  </div>
                ))}
              </div>
            )}

            {/* CompTIA Legend */}
            {legendMode === "comptia" && (
              <div>
                <div style={{ fontSize: 10, letterSpacing: 2, color: "#e4eaf5", marginBottom: 5, textTransform: "uppercase" }}>CompTIA Categories</div>
                {Object.entries(COMPTIA_CATEGORIES).map(([key, cat]) => (
                  <div key={key} style={{ marginBottom: 6, padding: "6px 8px", background: "#0a0f1e", borderLeft: `3px solid ${cat.color}`, borderRadius: 4 }}>
                    <div style={{ fontSize: 10, color: cat.color, fontWeight: 700, marginBottom: 2 }}>[{key}] {cat.label}</div>
                    <div style={{ fontSize: 10, color: "#e4eaf5" }}>{cat.desc}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Security Boundaries */}
          <div>
            <div style={{ fontSize: 10, letterSpacing: 2, color: "#e4eaf5", marginBottom: 5, textTransform: "uppercase" }}>Security Boundaries</div>
            {Object.entries(BOUNDARIES).map(([key, boundary]) => (
              <div key={key} style={{ marginBottom: 5, padding: "6px 8px", background: "#0a0f1e", borderLeft: `3px solid ${boundary.color}`, borderRadius: 4 }}>
                <div style={{ fontSize: 10, color: boundary.color, fontWeight: 700, marginBottom: 2 }}>{boundary.label}</div>
                <div style={{ fontSize: 10, color: "#e4eaf5" }}>{boundary.desc}</div>
              </div>
            ))}
          </div>

          {showPlanes && (
            <div>
              <div style={{ fontSize: 10, letterSpacing: 2, color: "#e4eaf5", marginBottom: 5, textTransform: "uppercase" }}>CompTIA Planes</div>
              {Object.values(PLANES).map(plane => (
                <div key={plane.id} style={{ marginBottom: 7, padding: "7px", background: "#0a0f1e", borderLeft: `3px solid ${plane.color}`, borderRadius: 4 }}>
                  <div style={{ fontSize: 10, color: plane.color, fontWeight: 700, marginBottom: 2 }}>{plane.label}</div>
                  <div style={{ fontSize: 10, color: "#e4eaf5" }}>{plane.description}</div>
                </div>
              ))}
            </div>
          )}

          <div style={{ fontSize: 9, color: "#e4eaf5", textAlign: "center", paddingTop: 7, marginTop: "auto" }}>
            v6 · Security Boundaries
          </div>
        </div>
      </div>
    </div>
  );
}
