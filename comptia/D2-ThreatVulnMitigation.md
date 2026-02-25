---
markmap:
  colorFreezeLevel: 2
  maxWidth: 450
---

# 🛡️ Threats, Vulnerabilities & Mitigations — Domain 2.0

## 🗝️ Legend — Category System
- 🎯 **TA** — Threat Actors · Nation-State · Organised Crime · Hacktivists · Insiders · Script Kiddies
- 📡 **TV** — Threat Vectors & Attack Surfaces · Message-Based · Network · Social Engineering
- 🐛 **Vl** — Vulnerabilities · Technical · Infrastructure · Application · Web · Crypto · Zero-Day
- 🧹 **Ma** — Malware & Attack Types · Ransomware · Trojans · Worms · Rootkits · Logic Bombs
- 🌐 **NA** — Network Attacks · DDoS · DNS Attacks · On-Path · ARP Poisoning · Credential Replay
- 💻 **AA** — Application Attacks · Injection · Buffer Overflow · Forgery · Privilege Escalation · Race Conditions
- 🛡️ **Mt** — Mitigation Techniques · Architecture · Hardening · Operations · Encryption · Monitoring
- 📊 **IoC** — Indicators of Compromise · Impossible Travel · Account Lockouts · Missing Logs · Resource Spikes

## 🎯 Threat Actors

### 🎯 TA — Types of Threat Actors
- 🎯 TA — Nation-State · State-sponsored; highly sophisticated APT groups; targets critical infrastructure, espionage, IP theft; long dwell time; e.g. APT28, Lazarus Group
- 🎯 TA — Organised Crime · Financially motivated; ransomware-as-a-service; credential theft; business email compromise; operates like a business with specialised roles
- 🎯 TA — Hacktivist · Ideologically motivated; website defacement; DDoS campaigns; data leaks to embarrass targets; e.g. Anonymous; disruptive not destructive
- 🎯 TA — Insider Threat · Authorised access misused; disgruntled employees; negligent users; malicious insiders; hardest to detect; bypasses perimeter controls
- 🎯 TA — Script Kiddie · Low skill; uses existing tools/exploits; opportunistic; noisy; often caught easily; motivation is recognition or curiosity
- 🎯 TA — Shadow IT · Employees deploying unauthorised systems/cloud services; creates unmanaged attack surface; not malicious intent but serious risk

### 🎯 TA — Attributes of Threat Actors
- 🎯 TA — Internal vs External · Internal: authorised access, harder to detect, higher damage potential; External: must breach perimeter first; both require different controls
- 🎯 TA — Resources & Funding · Nation-state: near-unlimited; Organised crime: substantial; Hacktivist: limited; Script kiddie: minimal; Resources determine sophistication of tools used
- 🎯 TA — Level of Sophistication · APT (Advanced Persistent Threat): custom zero-days, long dwell time, multi-stage; Commodity: off-the-shelf tools; determines detection difficulty

### 🎯 TA — Motivations
- 🎯 TA — Data Exfiltration · Steal sensitive data (PII, IP, credentials, financial); sell on dark web or use for competitive advantage; primary goal of espionage actors
- 🎯 TA — Financial Gain · Ransomware payments; fraud; BEC scams; cryptojacking; primary driver for organised crime groups
- 🎯 TA — Service Disruption · DDoS to take down services; sabotage competitor operations; nation-state pre-conflict positioning; hacktivism targets
- 🎯 TA — Philosophical / Political Beliefs · Hacktivists driven by cause; nation-states by geopolitical goals; insiders by grievance; understanding motive aids attribution

## 📡 Threat Vectors & Attack Surfaces

### 📡 TV — Message-Based Vectors
- 📡 TV — Email Phishing · Mass phishing (broad targets); Spear phishing (targeted individual); Whaling (C-suite); BEC (Business Email Compromise); malicious links/attachments
- 📡 TV — Smishing (SMS) · Phishing via text message; fake delivery notifications; bank alerts with malicious links; harder to identify on mobile; growing attack vector
- 📡 TV — Instant Messaging · Malicious links via Slack, Teams, WhatsApp; attackers compromise accounts then target contacts; trusted channel exploited

### 📡 TV — Network & Hardware Vectors
- 📡 TV — Removable Devices · USB drives with malware (BadUSB); HID spoofing attacks; autorun exploits; physical delivery bypasses network controls entirely
- 📡 TV — Vulnerable Software · Unpatched applications; outdated libraries; default configurations; public-facing services with known CVEs; attack surface from software inventory
- 📡 TV — Wireless Attacks · Evil Twin AP; deauthentication attacks; WPA2 weaknesses; rogue access points in corporate environments; sniffing on open networks
- 📡 TV — Supply Chain · Compromised third-party software/hardware; malicious updates (SolarWinds); counterfeit hardware with backdoors; vendor access exploitation

### 📡 TV — Social Engineering
- 📡 TV — Vishing · Voice phishing; attacker calls posing as IT support, bank, or government; creates urgency; extracts credentials or authorises wire transfers
- 📡 TV — Watering Hole · Attacker compromises website frequently visited by target group; delivers malware to visitors; difficult to detect as legitimate site trusted
- 📡 TV — Typosquatting · Register domains resembling legitimate brands (g00gle.com); used for phishing or malware delivery; exploits user typing errors
- 📡 TV — Pretexting · Fabricated scenario to manipulate target; attacker assumes false identity (vendor, auditor, co-worker) to extract information or access

## 🐛 Vulnerabilities (Objective 2.3)

### 🐛 Vl — Technical Vulnerabilities
- 🐛 Vl — Buffer Overflow · Writing past allocated memory boundary; overwrites adjacent memory including return address; enables arbitrary code execution · Defences: ASLR, DEP, stack canaries
- 🐛 Vl — Memory Injection · Process Hollowing: replace legit process memory with malicious code; DLL Injection: force process to load malicious DLL; bypasses file-based AV
- 🐛 Vl — Race Conditions (TOC/TOU) · Time-of-Check vs Time-of-Use: gap between security check and resource access; attacker swaps resource in the gap; common in multi-threaded apps
- 🐛 Vl — Malicious Updates · Compromised software update mechanism delivers backdoored code; SolarWinds Orion example; signed code trusted by security tools

### 🐛 Vl — Web-Based Vulnerabilities
- 🐛 Vl — SQL Injection (SQLi)
  - 🐛 Vl — Input Validation · Attacker inserts SQL commands via unsanitised input fields; can dump entire database, bypass auth (1=1), delete data
  - 🐛 Vl — Stored Procedures · Use parameterised queries and stored procedures; input treated as data not SQL code; primary SQLi defence
- 🐛 Vl — Cross-Site Scripting (XSS)
  - 🐛 Vl — Stored (Persistent) · Malicious script saved in database; executes when victim loads page; targets all users of application; highest severity XSS
  - 🐛 Vl — Reflected (Non-persistent) · Script in URL parameter reflected back in response; victim must click malicious link; used in phishing campaigns
  - 🐛 Vl — DOM-Based (Client-side) · Manipulates DOM directly without server interaction; script executes in browser; harder to detect server-side; CSP mitigates
- 🐛 Vl — SSRF · Attacker causes server to make requests to internal resources; bypass firewall to reach internal APIs; AWS metadata endpoint exploitation

### 🐛 Vl — Hardware & OS Vulnerabilities
- 🐛 Vl — OS Flaws (BlueKeep) · Wormable RDP vulnerability (CVE-2019-0708); unauthenticated remote code execution; MS17-010 EternalBlue used in WannaCry/NotPetya
- 🐛 Vl — Firmware Vulnerabilities · Hard to patch; persists across OS reinstalls; BIOS/UEFI flaws; network device firmware; IoT devices with default/no update mechanism
- 🐛 Vl — End-of-Life / End-of-Support (EOL/EOS) · No patches available; known vulnerabilities never remediated; regulatory compliance risk; Windows XP / Server 2003 examples
- 🐛 Vl — Legacy Systems · Cannot be patched or replaced; industrial control systems; medical devices; compensating controls required (network isolation, virtual patching via IPS)

### 🐛 Vl — Cloud & Virtualisation Vulnerabilities
- 🐛 Vl — VM Escape · Attacker breaks out of VM to access hypervisor or other VMs; extremely rare but catastrophic; hypervisor vulnerabilities (VMware, Hyper-V CVEs)
- 🐛 Vl — Resource Reuse · Memory or storage not properly zeroed between tenant uses; cloud provider residual data; encryption at rest mitigates
- 🐛 Vl — VM Sprawl · Unmanaged VMs accumulate; unpatched, forgotten VMs become easy targets; asset management and automated lifecycle policies prevent this
- 🐛 Vl — Shared Tenancy Risks · Side-channel attacks between tenants; Spectre/Meltdown CPU vulnerabilities; co-location of sensitive workloads with untrusted tenants
- 🐛 Vl — Cloud Misconfiguration · Public S3 buckets; open security groups; no MFA on root; overly permissive IAM roles; #1 cause of cloud breaches; automated CSPM tools detect
- 🐛 Vl — IAM Flaws · Over-privileged service accounts; lack of MFA on cloud accounts; key exposure in code repos; federation misconfigurations granting excessive access

### 🐛 Vl — Mobile Device Vulnerabilities
- 🐛 Vl — Jailbreaking (iOS) · Removes Apple sandboxing; enables unsigned app installation; disables security controls; device no longer manageable by MDM; policy violation
- 🐛 Vl — Rooting (Android) · Gains superuser access; bypasses OS security model; enables malware persistence; MDM can detect via attestation APIs
- 🐛 Vl — Sideloading · Installing apps from outside official stores; bypasses vetting process; common malware delivery on Android; MDM policy can block

### 🐛 Vl — Cryptographic Vulnerabilities
- 🐛 Vl — Compromised Keys/CAs · Stolen private keys enable man-in-the-middle; rogue CA certificates allow trusted HTTPS interception; DigiNotar breach example
- 🐛 Vl — Outdated Algorithms · MD5/SHA-1: collision attacks demonstrated; DES: brute-forceable (56-bit); RC4: statistical biases; RSA-512: factorable; use SHA-256+, AES-256, RSA-2048+
- 🐛 Vl — Weak Random Number Generation · Predictable IVs or nonces; weak seed values; allows session token prediction; affects key generation security
- 🐛 Vl — Side-Channel Attacks · Timing attacks: measure processing time to infer key bits; power analysis; cache timing (Spectre/Meltdown); does not attack algorithm directly
- 🐛 Vl — Downgrade & Stripping Attacks · Force negotiation to weaker protocol (SSLv3, TLS 1.0); SSL stripping converts HTTPS to HTTP; HSTS and TLS min-version config prevents

### 🐛 Vl — Zero-Day Vulnerabilities
- 🐛 Vl — Undiscovered Flaws · Unknown to vendor and public; no patch exists; exploited in wild before disclosure; detected only by behaviour-based tools not signatures
- 🐛 Vl — No Available Patches · Vendor has no fix; mitigate via WAF virtual patching, network isolation, enhanced monitoring, disable affected feature if possible

## 🧹 Malware Types & Indicators (Objective 2.4)

### 🧹 Ma — Ransomware
- 🧹 Ma — File Encryption · Encrypts user files with attacker-controlled key; demands payment for decryption; Double extortion: also exfiltrates data and threatens publication
- 🧹 Ma — Double Extortion · Encrypt AND steal data; pay or stolen data published; RaaS (Ransomware-as-a-Service): criminal franchises; LockBit, REvil, ALPHV examples
- 🧹 Ma — Indicators · Mass file extension changes (.locked, .encrypted); high disk I/O; VSS deletion; ransom note creation; C2 beacon traffic spike
- 🧹 Ma — Offline Backup Defence · 3-2-1 rule: 3 copies, 2 media types, 1 offsite/offline; air-gapped backups cannot be encrypted; test restores regularly

### 🧹 Ma — Trojans & RATs
- 🧹 Ma — Disguised as Legitimate Software · Appears useful; malicious payload hidden inside; distributed via phishing, fake cracks, trojanised installers
- 🧹 Ma — Remote Access Trojan (RAT) · Full interactive remote control via hidden backdoor; keylogging, screenshot, file access, webcam; C2 beacon to attacker server
- 🧹 Ma — Indicators · C2 beacon traffic (regular intervals); new scheduled tasks; outbound connections to unusual IPs/domains; unexpected processes with network connections

### 🧹 Ma — Worms
- 🧹 Ma — Self-Replicating, Autonomous Spread · Spreads without user action via network shares, email, exploits; no host file needed; WannaCry used EternalBlue to spread automatically
- 🧹 Ma — Indicators · Bandwidth spikes; lateral scanning activity (port 445 SMB); increased failed connection attempts; new processes spawning network connections

### 🧹 Ma — Spyware & Keyloggers
- 🧹 Ma — Monitors Activity & Records Keystrokes · Captures passwords, PINs, credit card numbers; screenshots; clipboard monitoring; audio/video capture
- 🧹 Ma — Indicators · Battery drain; unexpected background processes; elevated data usage; device overheating; signs of persistent data exfiltration

### 🧹 Ma — Rootkits
- 🧹 Ma — Kernel-Level Persistence · Modifies OS kernel to hide processes, files, network connections; survives OS reinstall (firmware rootkit); intercepting system calls
- 🧹 Ma — Indicators · Survives OS reinstall; disables AV; system calls return inconsistent results; memory scanners (Volatility) detect hidden processes
- 🧹 Ma — Defence: Secure Boot + TPM · UEFI Secure Boot verifies bootloader integrity; TPM measures boot chain; hardware-level attestation detects kernel tampering

### 🧹 Ma — Logic Bombs
- 🧹 Ma — Triggers on Specific Conditions · Executes when date reached, file accessed, user logs in, or condition met; planted by insiders; delayed sabotage mechanism
- 🧹 Ma — Indicators · Suspicious scheduled tasks or cron jobs; code reviews revealing conditional destruction logic; unusual file monitoring triggers

### 🧹 Ma — Viruses & Other Malware
- 🧹 Ma — Viruses: Require User Action to Spread · Attach to files; spread when infected file shared/executed; polymorphic variants change signatures to evade detection
- 🧹 Ma — Bloatware/PUPs · Potentially Unwanted Programs; bundled with legitimate software; resource consumption; privacy risk; not always malicious but undesirable

## 🌐 Network Attacks (Objective 2.4)

### 🌐 NA — DDoS Attacks
- 🌐 NA — Amplified · Small request triggers massive response; DNS amplification (50x factor), NTP Monlist (500x); attacker spoofs victim IP as source; reflectors overwhelm target
- 🌐 NA — Reflected · Spoofs victim IP to reflectors (DNS/NTP servers); response traffic floods victim; attacker never directly contacts victim; hard to trace and block
- 🌐 NA — Mitigations · Anycast routing; CDN scrubbing centres; rate limiting; BCP38 (source IP validation); cloud DDoS protection (Cloudflare, AWS Shield)

### 🌐 NA — DNS Attacks
- 🌐 NA — Cache Poisoning · Fraudulent DNS records inserted into resolver cache; redirects users to attacker-controlled IP; DNSSEC with digital signatures prevents
- 🌐 NA — DNS Tunneling · Encodes data in DNS queries/responses; bypasses firewall allowing DNS; exfiltrates data via DNS traffic; C2 communication channel; detected by anomalous DNS query volume/length
- 🌐 NA — DNS Hijacking · Modifying DNS settings at registrar or resolver; redirects all users of a domain; requires registrar account compromise or ISP-level attack

### 🌐 NA — On-Path (MitM) Attack
- 🌐 NA — Interception & Modification · Attacker positions between two communicating parties; can read and modify traffic; requires ARP poisoning or rogue AP on LAN; TLS mitigates
- 🌐 NA — ARP Poisoning · MAC-to-IP spoofing on LAN; sends gratuitous ARP replies associating attacker MAC with victim IP; enables MitM on local segment; Dynamic ARP Inspection (DAI) prevents
- 🌐 NA — Credential Replay · Reusing captured authentication tokens without decrypting; Pass-the-Hash (NTLM); Kerberoasting; replay captured session cookies; MFA and short token lifetimes mitigate

### 🌐 NA — Wireless Attacks
- 🌐 NA — Evil Twin · Rogue AP mimicking legitimate SSID and BSSID; client auto-connects; attacker intercepts all traffic; WPA3 SAE prevents; certificate-based auth (EAP-TLS) detects
- 🌐 NA — Deauthentication · Forged 802.11 deauth frames kick clients; forces reconnection; combined with Evil Twin for credential capture; WPA3 Management Frame Protection (PMF) prevents
- 🌐 NA — Jamming · Radio frequency interference disrupts wireless communications; physical attack on availability; detection via RF monitoring; FCC regulations limit transmitter power
- 🌐 NA — WPA Cracking / MAC Spoofing · WPA2 PMKID capture without handshake; offline dictionary attack; WPA3 SAE prevents offline attacks; MAC spoofing bypasses basic filtering

## 💻 Application Attacks (Objective 2.4)

### 💻 AA — Injection Attacks
- 💻 AA — SQL Injection · Malicious SQL in input fields; bypass auth, dump DB; parameterised queries prevent; most exploited web vulnerability
- 💻 AA — OS Command Injection · System() calls with unsanitised input execute OS commands; full server compromise; avoid shell calls; use allowlisted commands only
- 💻 AA — LDAP Injection · Manipulate LDAP queries to bypass authentication or extract directory information; sanitise all LDAP filter characters
- 💻 AA — XML/XXE Injection · XML External Entity: malicious XML references external entities; reads local files, SSRF, DoS; disable external entity processing in XML parsers
- 💻 AA — Memory Injection / Process Hollowing · Injects code into legitimate process memory; evades file-based AV; no malicious file on disk; detected by EDR behavioural analysis

### 💻 AA — Buffer Overflow
- 💻 AA — Overwriting Memory Stack · Write beyond allocated buffer; overwrite return address with attacker-controlled pointer; shellcode injected in adjacent memory; enables arbitrary code execution
- 💻 AA — Defences · ASLR: randomises memory addresses; DEP/NX: non-executable stack; Stack Canaries: detect overwrites before return; Bounds Checking: compiler-level protection

### 💻 AA — Forgery Attacks
- 💻 AA — CSRF: Client-Side Browser Trickery · Cross-Site Request Forgery; tricks authenticated user browser into making unwanted requests to trusted site; anti-CSRF tokens and SameSite cookies prevent
- 💻 AA — SSRF: Server-Side Unauthorised Requests · Server-Side Request Forgery; server fetches attacker-specified URL; access internal metadata services (AWS 169.254.169.254); validate and allowlist URLs server-side

### 💻 AA — Privilege Escalation
- 💻 AA — Vertical: Standard to Admin · Low-privilege user gains admin/root; exploits kernel vulnerability, SUID binary, service misconfiguration; leads to full system compromise
- 💻 AA — Horizontal: User to User · Access another user's resources without privilege increase; IDOR (Insecure Direct Object Reference); access other users' data by changing ID parameter

### 💻 AA — Directory Traversal
- 💻 AA — Path Navigation (../) · Navigate outside intended web root using ../; read /etc/passwd, config files, private keys; canonicalise paths server-side; jail web server to document root

### 💻 AA — Race Conditions (TOC/TOU)
- 💻 AA — Time-of-Check vs Time-of-Use · Concurrent access to shared resource; attacker swaps file between security check and use; mutex/lock mechanisms and atomic operations prevent

## 🔑 Password & Physical Attacks (Objective 2.4)

### 🔑 PA — Password Attack Methods
- 🔑 PA — Password Spraying · One common password (Password1!) tried against many accounts; avoids lockout; detects by account lockout pattern; sign: many accounts with same failed password
- 🔑 PA — Brute Force · Exhaustive character combination attempt; online: rate limited and detectable; offline: against stolen hash file; fast GPU cracking; MFA and strong hashing (bcrypt) mitigate
- 🔑 PA — Dictionary Attack · Tries list of known words and common passwords; effective against weak passwords; combine with rules (l33tspeak); check against HaveIBeenPwned lists
- 🔑 PA — Hybrid Attack · Dictionary words + variations (appending numbers, symbols, l33tspeak); more effective than pure dictionary; covers common password creation patterns
- 🔑 PA — Offline Cracking · Steal password hash database; crack offline at high speed; Rainbow Tables: precomputed hash-to-plaintext; Salt prevents rainbow tables; bcrypt/Argon2 slow cracking

### 🔑 PA — Cryptographic Attacks
- 🔑 PA — Downgrade Attack · Forces negotiation to weaker protocol version (SSLv3, TLS 1.0, DES); TLS minimum version config and HSTS prevent; POODLE attack exploited SSLv3 downgrade
- 🔑 PA — Collision Attack · Find two inputs producing same hash; MD5 and SHA-1 vulnerable; collision found = digital signature forgery possible; use SHA-256 or stronger
- 🔑 PA — Birthday Attack · Probability-based collision finding; exploits birthday paradox; 50% collision probability at sqrt(hash-space); longer hash outputs (256-bit+) resist

### 🔑 PA — Physical Attacks
- 🔑 PA — Physical Brute Force · Lock picking; forced entry; bypass electronic locks with power cycling; anti-tailgating controls; mantrap entries; security guards
- 🔑 PA — RFID Cloning · Read RFID badge from proximity with concealed reader; clone to blank card; defeat with Faraday sleeve, challenge-response badges, multi-factor physical access
- 🔑 PA — Environmental Attacks · Power disruption; HVAC sabotage causing overheating; fire suppression system activation; physical security must consider environmental threats

## 📊 Indicators of Compromise (IoC)

### 📊 IoC — Behavioural Indicators
- 📊 IoC — Impossible Travel · Single account login from geographically distant locations within impossible timeframe; strong credential compromise indicator; trigger MFA step-up or block
- 📊 IoC — Concurrent Session Usage · Same account active from multiple IP addresses simultaneously; session token theft or sharing; UBA baseline detects anomaly
- 📊 IoC — Account Lockout · Multiple failed auth attempts across many accounts (spraying) or single account (targeted brute force); investigate source IPs; may indicate automated attack tool
- 📊 IoC — Resource Consumption Spikes · Unexplained CPU/memory/network spikes; active DDoS participation (bot); cryptojacking; worm propagation; establish baseline and alert on deviation
- 📊 IoC — Missing Logs · Attacker covering tracks by deleting audit logs; selective gaps in event timeline; log forwarding to immutable SIEM prevents tampering; integrity alerts on log gaps
- 📊 IoC — Out-of-Cycle Logging · Legitimate-looking activity at unusual hours (3AM admin logins); attacker operating in different timezone; SIEM time-based rules flag anomalous access patterns

### 📊 IoC — Network & System Indicators
- 📊 IoC — Unusual Outbound Traffic · Large data transfers to unknown external IPs; DNS tunneling; HTTPS to non-standard ports; C2 beacon (regular interval callback); DLP and NetFlow analysis detect
- 📊 IoC — Unusual File System Activity · Mass file access or modification; new executables in temp directories; files created with random names; scheduled task/registry run key added unexpectedly
- 📊 IoC — Lateral Movement Indicators · Port scanning from internal host; SMB traffic to many hosts; PsExec/WMI/RDP from unexpected sources; credential use on multiple systems in short time

## 🛡️ Mitigation Techniques (Objective 2.5)

### 🛡️ Mt — Architecture & Network Defences
- 🛡️ Mt — Segmentation · Physical separation; VLANs; subnetting; divides network into security zones; limits blast radius; prevents lateral movement across segments
  - 🛡️ Mt — Physical Segmentation · Separate physical network infrastructure; air-gapped OT/ICS networks; physically separate sensitive systems
  - 🛡️ Mt — VLANs · Virtual LAN isolation at Layer 2; separate user, server, guest, IoT segments; inter-VLAN routing controlled by firewall ACLs
  - 🛡️ Mt — Microsegmentation · Granular workload-level isolation; Zero Trust network architecture; each VM/container in its own security zone; east-west traffic controlled
- 🛡️ Mt — Access Control
  - 🛡️ Mt — Access Control Lists (ACLs) · Permit/deny rules on network devices; enforce which traffic traverses segment boundaries; implicit deny at end
  - 🛡️ Mt — OS Permissions · File/directory permissions; discretionary access control; least privilege principle; regular permission audits to remove unnecessary access
- 🛡️ Mt — Network Access Control (NAC) · 802.1X port-based authentication; health check before network admission; agents verify patch level, AV status; non-compliant devices quarantined
  - 🛡️ Mt — Agents (Permanent/Dissolvable) · Permanent agent for corporate devices; dissolvable (temporary) for guest/BYOD; assess device health before granting access
  - 🛡️ Mt — Health Authority (HAuth) · Evaluates device compliance (patch level, AV, encryption); grants or denies network access based on posture assessment
  - 🛡️ Mt — Remediation Server · Non-compliant devices redirected here; automatic patch/update delivery before network access granted; reduces security debt
- 🛡️ Mt — DNSSEC · Cryptographic signatures on DNS records; prevents cache poisoning; RRSIG resource records authenticate responses; validates chain from root to authoritative server
  - 🛡️ Mt — RRSIG Records · Resource Record Signatures; each DNS record signed with zone private key; resolver verifies with zone public key
  - 🛡️ Mt — Cache Poisoning Defence · Signed responses cannot be forged; resolver rejects unsigned or invalid records; chain of trust from root DNS to TLD to authoritative
- 🛡️ Mt — Isolation Techniques
  - 🛡️ Mt — Air-Gapping · Physical network isolation; no wired or wireless connection to external networks; used for ICS/SCADA, classified systems; Stuxnet showed even air-gaps can be bridged via USB
  - 🛡️ Mt — Sandboxing · Execute suspicious code in isolated environment; no access to production; analyse behaviour; Cuckoo, ANY.RUN, Bromium; malware analysis without risk
  - 🛡️ Mt — Quarantining · Isolate infected host from network while investigation continues; maintains evidence; automated via SOAR/EDR; restores after remediation confirmed

### 🛡️ Mt — System Hardening
- 🛡️ Mt — Hardening Techniques
  - 🛡️ Mt — Default Password Changes · Default credentials publicly known; change ALL defaults before deployment; automated credential scanners check for defaults in penetration tests
  - 🛡️ Mt — Removal of Unnecessary Software · Every installed package = attack surface; remove unused roles/features; container images: minimal base; server: no GUI if not needed
  - 🛡️ Mt — Disabling Unused Ports/Protocols · Each open port is potential attack vector; disable Telnet, FTP, unused services; block at host firewall and network ACL
  - 🛡️ Mt — Host-Based Firewalls · Local firewall rules independent of network; last line of defence against lateral movement; Windows Firewall, iptables/nftables; restrict inbound per application
  - 🛡️ Mt — HIPS · Monitors and blocks suspicious activity on host; process, registry, file system protection; more granular than network IPS
- 🛡️ Mt — Endpoint Protection
  - 🛡️ Mt — Antivirus (AV) · Signature-based malware detection; frequent definition updates; next-gen AV adds heuristic and ML detection; necessary but insufficient alone
  - 🛡️ Mt — EDR/XDR · Endpoint Detection & Response: behavioural monitoring, process trees, memory scanning, automated containment; XDR extends to network, cloud, email layers
- 🛡️ Mt — Hardware Security
  - 🛡️ Mt — Full Disk Encryption · BitLocker (Windows), FileVault (macOS), LUKS (Linux); protects data at rest on lost/stolen devices; TPM stores encryption key; pre-boot authentication
  - 🛡️ Mt — TPM (Trusted Platform Module) · Hardware chip storing keys, certs, measurements; enables Secure Boot integrity checking; key storage without software exposure
  - 🛡️ Mt — UEFI Secure Boot · Verifies bootloader digital signature; prevents unsigned bootloaders/rootkits; chain of trust from firmware through OS; defeats boot-level rootkits

### 🛡️ Mt — Operational Defences
- 🛡️ Mt — Patch Management · Regular patching cycle; prioritise by CVSS + EPSS + exposure; WSUS, SCCM, Ansible automate deployment; test in staging before production rollout
- 🛡️ Mt — Vulnerability Scanning · Regular credentialed and non-credentialed scans; Nessus, Qualys, OpenVAS; track vulnerability age and remediation SLAs; continuous scanning preferred
- 🛡️ Mt — Application Allow Listing · Only pre-approved executables can run; blocks unknown malware and shadow IT; AppLocker (Windows), WDAC; reduces attack surface dramatically
- 🛡️ Mt — Configuration Enforcement · Automated baseline compliance; Ansible, Puppet, Chef; SCAP scanners detect drift; prevent unauthorised configuration changes
- 🛡️ Mt — Monitoring Tools · SIEM for centralised log correlation and alerting; NetFlow analysers for traffic patterns; UBA for insider threat detection; continuous visibility required

### 🛡️ Mt — Data & Access Hardening
- 🛡️ Mt — Encryption States
  - 🛡️ Mt — Data At Rest · Encrypted storage: full disk encryption, database encryption, file-level encryption; protects against physical theft and storage provider breach
  - 🛡️ Mt — Data In Transit · TLS 1.2+; HTTPS; VPN tunnels; SSH; prevents interception and MitM; certificate validation required; HSTS prevents downgrade
  - 🛡️ Mt — Data In Use · Memory encryption; secure enclaves (Intel SGX); homomorphic encryption; protects data while being processed; emerging capability
- 🛡️ Mt — Least Privilege
  - 🛡️ Mt — Minimum Permissions · Grant only permissions required for job function; deny all others; reduces blast radius of compromised accounts; critical for service accounts
  - 🛡️ Mt — Privilege Reviews · Quarterly access reviews; remove stale permissions; identify privilege creep; manager attestation of access requirements
  - 🛡️ Mt — Just-In-Time (JIT) Access · Elevated access granted only when needed, for limited duration; auto-expires; PAM platforms implement JIT; no standing privilege reduces risk window
- 🛡️ Mt — Secure Baselines · CIS Benchmarks; STIGs for government systems; Level 1 (basic) and Level 2 (hardened); automated deployment via Group Policy / Ansible; drift detection
- 🛡️ Mt — Decommissioning
  - 🛡️ Mt — Asset Retirement · Formal process to remove from asset register; revoke certificates; disable all accounts; update CMDB; prevents orphaned attack surface
  - 🛡️ Mt — Data Sanitisation · Wipe (DoD 5220.22-M for HDDs); Secure Erase for SSDs; Degaussing for magnetic media; Shredding/Incineration for highest assurance; certificate of destruction

## 🔁 Cross-Reference — Key Attack Chains

### 📊 IoC — Ransomware Detection Chain
- 🧹 Ma — Initial Vector: Phishing email (TV) → malicious attachment → macro executes dropper
- 🧹 Ma — Exploitation: Unpatched software vuln (Vl) → code execution → privilege escalation (AA)
- 📊 IoC — IoC: Mass file extension changes + VSS deletion + high disk I/O → SIEM alert
- 🛡️ Mt — Mitigations: Email filtering + patch management + EDR + offline backups (3-2-1)

### 🌐 NA — DDoS Attack Chain
- 🎯 TA — Actor: Hacktivist or organised crime; financially or ideologically motivated
- 🌐 NA — Attack: Amplified DNS/NTP reflecting massive traffic to victim
- 📊 IoC — IoC: Traffic volume spike; many source IPs; UDP floods; service unavailability
- 🛡️ Mt — Mitigations: BCP38; rate limiting; anycast; CDN scrubbing; cloud DDoS protection

### 🐛 Vl — SQL Injection Defence Chain
- 📡 TV — Vector: Web application with unvalidated input fields accessible externally
- 🐛 Vl — Vulnerability: Unsanitised SQL input passed directly to database query
- 💻 AA — Attack: SQL injection dumps credentials; attacker gains authenticated access
- 🛡️ Mt — Mitigations: Parameterised queries + WAF + DAST scanning in CI/CD + least privilege DB accounts

### 🔑 PA — Credential Attack Chain
- 📡 TV — Vector: Phishing email harvests password; or breach database contains hashed passwords
- 🔑 PA — Attack: Offline hash cracking (dictionary + hybrid); or credential stuffing against other services
- 📊 IoC — IoC: Multiple failed logins; impossible travel; concurrent sessions from different IPs
- 🛡️ Mt — Mitigations: MFA; bcrypt/Argon2 password hashing; HaveIBeenPwned checks; account lockout policies
