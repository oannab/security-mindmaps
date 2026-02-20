---
markmap:
  colorFreezeLevel: 2
  initialExpandLevel: 2
  maxWidth: 420
  zoom: true
  pan: true
---

# 🔐 Security Architecture — Domain 3.0 Master Map

## 🗝️ Legend — 8 Category System
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Digital Hardware · Servers · Routers · Switches · TPM · HSM · Sensors</span>
- <span style="background:#A1887F;color:#fff;padding:2px 10px;border-radius:5px;font-weight:600;">🪪 Ph — Physical Non-Digital · Bollards · CCTV · Guards · UPS · Generators · Sites</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;"> 🚀 Sw — Software · SIEM · SOAR · IDS/IPS · AV · EDR · Monitoring Tools · OS</span>
- <span style="background:#7986CB;color:#fff;padding:2px 10px;border-radius:5px;font-weight:600;">🌐 Ntw — Network Architecture · SDN · VLANs · WAN/LAN · Air-Gap · Zero Trust · SASE</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;">🔗 Pr — Protocols · IPSec · TLS · AH · ESP · SSH · API Standards</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;">📋 Gov — Governance · Policy · Compliance · Classification · Risk · AUP · SOP</span>
- <span style="background:#80DEEA;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;"> ☁️ Cl — Cloud · Serverless · Multi-Cloud · Hybrid · Managed Services</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 10px;border-radius:5px;font-weight:600;">🛠️ M — Methods · Encryption · Clustering · Backups · Containerisation · Sandboxing</span>

---

## 🏗️ Architecture Models & Implications

###  ☁️ Cloud & Modern Infrastructure

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Shared Responsibility Matrix</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Shared Duties · Who is responsible for what between provider and customer</span>
- <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Provider Infrastructure · Cloud vendor secures hypervisor, physical DC, networking fabric</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Customer Data / Endpoints · Customer owns: data, IAM, app config, OS patches (IaaS)</span>

#### <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Hybrid & Third-Party Considerations</span>
- <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Data Sync Latency · Risk of inconsistency between on-prem and cloud during sync windows</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Third-Party Access Risks · Vendors with elevated access = expanded attack surface; requires vendor risk management</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Supply Chain Risk · Compromise of upstream dependency (e.g. SolarWinds-style attack)</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Infrastructure as Code (IaC)</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Automation · Infra provisioned via code (Terraform, Ansible, CloudFormation) — removes manual steps</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Human Error Reduction · Declarative configs enforced consistently across all environments</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Quick Recovery · Re-deploy entire env from code in minutes after incident</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Version-Controlled Policy · Security rules stored as code, auditable, peer-reviewed via Git</span>

#### <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Serverless Computing</span>
- <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Managed Infrastructure · Provider handles OS, runtime, scaling — customer only writes functions</span>
- <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Code Focus · Dev teams focus on logic; attack surface reduced (no exposed OS layer)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Ephemeral Risk · Functions spin up/down; traditional endpoint monitoring doesn't apply — requires cloud-native logging</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Microservices & Containers</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Containerisation · Docker/Kubernetes — isolates app dependencies; limits blast radius per service</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — API Communication · Services talk via REST/gRPC APIs; each API = potential attack surface requiring auth + rate limiting</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Fault Isolation · One failed service doesn't cascade — health checks + circuit breakers contain failure</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Container Orchestration Security · Kubernetes RBAC, network policies, image scanning (Trivy, Snyk)</span>

### 🌐 Network Infrastructure Design

#### <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Software-Defined Networking (SDN)</span>
- Role: Decouples network control logic from physical hardware; enables programmatic, centralised network management
- Used by: Enterprise data centres, cloud providers, telecoms
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Control Plane · The "brain" — makes routing/policy decisions; separated from data forwarding</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Policy Engine · Evaluates access requests against policy; grants/denies; integrates with SIEM + threat intel</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SIEM Integration · Real-time log/event correlation feeds into policy decisions · e.g. Splunk, Microsoft Sentinel</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SOAR Integration · Automated response actions triggered by policy engine · e.g. isolate host, block IP, revoke token</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Threat Intelligence Feeds · External IOC/IOA data enriches policy decisions · e.g. MISP, commercial TI platforms</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Policy Administrator · Translates Policy Engine decisions into commands; pushes rules to enforcement points</span>
    - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Policy Enforcement Points (PEP) · Routers, switches, firewalls that receive and apply the pushed rules</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — NGFW (as PEP) · Acts as enforcement point for SDN-pushed Layer 7 policies · e.g. Palo Alto, Fortinet</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Data Plane · The "muscle" — forwards actual packets per rules set by control plane</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Managed Switches · Execute forwarding rules; VLAN tagging; port security enforcement</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Routers · Inter-VLAN routing; ACL enforcement at Layer 3</span>
  - <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — OpenFlow Protocol · Standard protocol between SDN controller and forwarding devices</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Programmable Security · Dynamic rule updates via API; intent-based networking</span>
  - <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — API-Driven Configuration · RESTful APIs push security policy changes instantly across the fabric</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Microsegmentation · SDN enables per-workload isolation without physical VLAN changes</span>

#### <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Network Segmentation</span>
- Role: Divides network into zones to contain breaches and enforce least-privilege traffic flow
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Physical Isolation / Air-Gapping · No network connection; data transfer only via physical media (USB, sneakernet)</span>
  - <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Air-Gapped Systems · Used in: nuclear, military, SCADA — highest isolation; immune to remote attacks</span>
  - <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — High-Security Labs · Faraday cages, no wireless; physically enforced isolation</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Logical Segmentation (VLANs) · Layer 2 broadcast domain separation without physical rewiring</span>
  - <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — 802.1Q VLAN Tagging · IEEE standard; adds 4-byte tag to Ethernet frames to identify VLAN membership</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Blast Radius Reduction · Attacker in VLAN 10 cannot directly reach VLAN 20 without routing + firewall rules</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Managed Switches · Enforce VLAN membership per port; trunk links carry multiple VLANs</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Security Zones (LAN / DMZ / WAN)</span>
  - <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Trusted Zone (LAN) · Internal network; highest trust; enforces least privilege internally</span>
  - <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Screened Subnet (DMZ) · Semi-trusted buffer zone hosting public-facing services (web, mail, DNS)</span>
    - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — NGFW (perimeter) · Sits at DMZ boundary; inspects inbound/outbound traffic; DPI at Layer 7</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — WAF · Protects web apps in DMZ from SQLi, XSS, OWASP Top 10</span>
    - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Reverse Proxy / Load Balancer · Sits in DMZ; shields origin servers; terminates TLS</span>
  - <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Untrusted Zone (WAN/Internet) · Zero trust; all traffic assumed hostile; filtered at perimeter</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Microsegmentation · East-west traffic control within a zone; per-workload firewall rules</span>
  - Used by: Zero Trust architectures, cloud-native environments
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Host-based Firewall · Enforces microsegmentation rules at the OS level on each workload</span>

#### <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Zero Trust Architecture (ZTA)</span>
- Principle: "Never trust, always verify" — no implicit trust based on network location
- Used by: Modern enterprises, government (US EO 14028), cloud-native orgs
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Control Plane (ZTA)</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Policy Engine · Grants/denies access per request based on identity, device posture, context</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Identity Provider (IdP) · Authenticates users · e.g. Okta, Azure AD, Ping Identity</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — MFA · Required for every access request; second factor confirms identity</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Device Posture Assessment · Checks patch level, EDR status, compliance before granting access</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SIEM (ZTA context) · Feeds real-time risk signals into Policy Engine decisions</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SOAR (ZTA context) · Executes automated responses when Policy Engine detects anomaly</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Policy Administrator · Pushes Policy Engine decisions to PEPs; manages session tokens</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Data Plane (ZTA)</span>
  - <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Policy Enforcement Point (PEP) · Gateway that allows/blocks subject↔resource traffic per Policy Admin instruction</span>
    - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — NGFW (as PEP) · Enforces layer 7 rules at network boundary</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Proxy (as PEP) · Intercepts and inspects all subject requests before forwarding</span>
    - <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — SASE (as PEP) · Cloud-delivered PEP; enforces ZTA policy for remote/mobile users</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — SASE (Secure Access Service Edge)</span>
  - Role: Converges networking (SD-WAN) + security (CASB, FWaaS, ZTNA) delivered from the cloud edge
  - Used by: Distributed orgs, remote workforce, branch offices
  - <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Cloud Edge Security · Security controls enforced at cloud PoP close to user; reduces backhaul</span>
  - <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — SD-WAN (WAN component of SASE) · Intelligent routing; selects best path per app; encrypts WAN traffic</span>
    - <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — IPSec / TLS tunnels · All SD-WAN traffic encrypted in transit between sites and cloud PoPs</span>
    - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — SD-WAN Appliance (edge device) · CPE at branch; handles local traffic decision + tunnel termination</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — CASB (Cloud Access Security Broker) · Sits between users and cloud apps; enforces DLP, access policy</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — FWaaS (Firewall as a Service) · Cloud-hosted NGFW capabilities; no on-prem hardware needed</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — ZTNA (Zero Trust Network Access) · Replaces VPN; per-app access; identity-verified; never full tunnel</span>

### 🛠️ Specialised Systems

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — IoT (Internet of Things)</span>
- Role: Internet-connected embedded devices; often low-power, limited security capabilities
- Risk: Massive attack surface; rarely patched; often default credentials
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Botnet Vulnerability · Compromised IoT → recruited into botnets (Mirai) for DDoS attacks</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Firmware Management · Regular firmware updates essential; unsigned firmware = major risk vector</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — IoT Network Segmentation · Isolate IoT devices on dedicated VLAN; no lateral access to corporate LAN</span>

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — ICS / SCADA</span>
- Role: Industrial control systems; manage physical processes (power, water, manufacturing)
- Risk: Legacy protocols, always-on availability requirement, physical world consequences
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Legacy Software · Runs outdated OS (WinXP era); vendors won't support patches; air-gap is primary defence</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Availability Priority · Uptime &gt; Confidentiality (CIA triad inverted); patching windows are rare</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Physical Consequences · Stuxnet proved: cyberattack on SCADA = physical centrifuge destruction</span>

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — RTOS (Real-Time OS)</span>
- Role: OS guaranteeing deterministic response time; used in safety-critical hardware
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Zero Latency Requirement · Hard real-time deadlines; missed deadline = system failure (pacemaker, autopilot)</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Physical Safety Risks · Software vulnerability in RTOS can cause physical harm; requires certified secure RTOS</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Certification Requirements · IEC 61508, DO-178C for aviation; formal verification required</span>

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Embedded Systems</span>
- Role: Purpose-built hardware with fixed software; found in consumer electronics, medical, automotive
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Purpose-Built / Single Task · Limited OS exposure; but limited updateability increases long-term risk</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Hard to Patch · Requires physical access or proprietary tools; vulnerability may persist for device lifetime</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — TPM (Trusted Platform Module) · Hardware chip providing: secure key storage, measured boot, attestation</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Measured Boot · TPM records hash of each boot component; detects tampering</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Key Storage · Private keys stored in hardware; never exposed to software layer</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Infrastructure Design Trade-offs</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Availability vs. Cost · High availability = redundant hardware = higher cost; risk appetite determines investment level</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Resilience & Recovery Planning · RTO/RPO targets drive architecture decisions (active-active vs cold standby)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Patch Availability · Legacy/embedded systems may have no vendor patches; compensating controls required</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Power & Compute Resources · Cryptographic operations are CPU-intensive; HSMs offload crypto from servers</span>

---

## 🏢 Securing Enterprise Infrastructure

###  >_ Network Appliances

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Jump Servers (Bastion Hosts)</span>
- Role: Hardened intermediary that admins connect to before accessing internal systems
- Used by: SysAdmins, DevOps, Security teams accessing sensitive infrastructure
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Admin Access Control · Single controlled entry point; all admin sessions logged and auditable</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — PAM (Privileged Access Management) · Software layer managing jump server sessions · e.g. CyberArk, BeyondTrust</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — SSH / RDP over encrypted tunnel · All admin traffic encrypted; jump server terminates the external session</span>

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Proxy Servers</span>
- Role: Intermediary between client and destination; provides filtering, caching, anonymisation
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Forward Proxy (Outbound) · Intercepts user→internet traffic; enforces URL filtering, DLP, malware scanning</span>
  - Used by: Orgs controlling employee web access; logs all outbound URLs
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SSL Inspection · Decrypts HTTPS to inspect content; re-encrypts before forwarding</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Reverse Proxy (Inbound) · Sits in front of web servers; shields origin; handles TLS termination, load balancing</span>
  - Used by: Web hosting, API gateways, CDNs
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — WAF Integration · Reverse proxy + WAF = full L7 protection for inbound web traffic</span>

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Load Balancers</span>
- Role: Distributes traffic across multiple servers to prevent overload and ensure availability
- Used by: High-traffic web apps, APIs, enterprise data centres
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Scheduling: Round Robin · Requests distributed sequentially across servers; simple, equal distribution</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Scheduling: Least Utilized Host · Routes to server with lowest current load; better for unequal workloads</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Scheduling: Affinity / Persistence · Same client always hits same server (session stickiness); needed for stateful apps</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — DDoS Mitigation · Absorbs and distributes volumetric attack traffic; works with upstream scrubbing centres</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — TLS Termination · Decrypts HTTPS at load balancer; backend traffic may be HTTP (internal) or re-encrypted</span>

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Sensors & Taps (Network TAPs)</span>
- Role: Passive hardware that copies all network traffic to monitoring/analysis tools without disruption
- Used by: SOC teams, network forensics, IDS engines
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Passive Data Collection · Zero impact on production traffic; physically copies packets to out-of-band monitoring port</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — IDS Integration · TAP feeds raw traffic to IDS for anomaly/signature detection · e.g. Snort, Suricata</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SIEM Integration · Captured packet metadata + NetFlow fed into SIEM for correlation</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Network Monitoring Platform · e.g. Zeek (Bro), Wireshark, SolarWinds NTA</span>

### 🔥 Firewall Types

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — WAF (Web Application Firewall)</span>
- Role: Filters HTTP/HTTPS traffic at Layer 7; protects against web-specific attacks
- Used by: Any org with a public web app, API, or customer portal
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — OWASP Top 10 Protection · Blocks SQLi, XSS, CSRF, insecure deserialization, broken auth</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Rate Limiting · Throttles requests per IP; mitigates credential stuffing and scraping</span>
- <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Cloud WAF · e.g. AWS WAF, Cloudflare WAF, Akamai — no hardware; scales automatically</span>
- Used with: Reverse proxy, CDN, load balancer in DMZ

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — UTM (Unified Threat Management) Appliance</span>
- Role: All-in-one security appliance combining firewall, IDS/IPS, antivirus, VPN, content filtering
- Used by: SMBs needing consolidated security without dedicated tools for each function
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Integrated IDS/IPS · Signature + anomaly detection built into same box as firewall</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Integrated Antivirus / Anti-malware · Scans traffic at gateway level; catches known malware in transit</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — VPN Endpoint · UTM also terminates site-to-site and remote access VPN tunnels</span>

#### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — NGFW (Next-Generation Firewall)</span>
- Role: Stateful + Layer 7 DPI firewall; application awareness; integrated threat prevention
- Used by: Enterprise perimeters, data centre segmentation, ZTA enforcement points
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Deep Packet Inspection (DPI) · Reads payload content (not just headers); identifies apps regardless of port</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Integrated IDS/IPS · Inline threat detection and blocking; signature + behavioural</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SSL/TLS Inspection · Decrypts encrypted traffic to inspect for threats; re-encrypts outbound</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Application Awareness · Identifies and controls apps (Zoom, Torrent, Office365) regardless of port/protocol</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — User Identity Integration · Links firewall rules to Active Directory users/groups, not just IPs</span>
- Vendors: Palo Alto Networks, Fortinet FortiGate, Cisco Firepower, Check Point
- Also appears as: ZTA Policy Enforcement Point · SDN enforcement node · DMZ perimeter device

#### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Layer 4 Firewall (Stateful Packet Filter)</span>
- Role: Tracks TCP/UDP connection state; filters by IP, port, protocol
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Stateful Inspection · Tracks 5-tuple (src IP, dst IP, src port, dst port, protocol); blocks unsolicited inbound</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — ACL (Access Control Lists) · Rule-based allow/deny on IP ranges and ports; foundation of network policy</span>

### 🔒 Secure Communication

#### <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — VPN (Virtual Private Network)</span>
- Role: Encrypted tunnel over public network; creates private communication channel
- Used by: Remote workers, site-to-site branch connectivity, third-party access
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Site-to-Site VPN (IPSec) · Permanent encrypted tunnel between two network gateways; transparent to users</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Remote Access VPN (TLS/IPSec) · Individual user connects to corporate network; full tunnel or split tunnel</span>
  - <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Split Tunnelling Policy · Only corp traffic goes through VPN; internet direct; balances security vs performance</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — ZTNA as VPN Replacement · Per-app access; never grants full network; identity-verified per session</span>

#### <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — IPSec Protocol Suite</span>
- Role: Framework of protocols providing authentication, integrity, and encryption for IP traffic
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Transport Mode · Encrypts payload only; original IP header visible; used for host-to-host</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Tunnel Mode · Encrypts entire original packet + new IP header; used for VPN gateways</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — AH (Authentication Header) · Provides integrity + authentication; no encryption; detects tampering</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — ESP (Encapsulating Security Payload) · Provides encryption + integrity + auth; most commonly used component</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — IKE (Internet Key Exchange) · Negotiates and manages IPSec security associations; handles key exchange</span>
---

## 🛡️ Data Protection Strategies

### 📋 Data Types & Classification

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Regulated Data</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — PII (Personally Identifiable Information) · Name, SSN, DOB, address; regulated by GDPR, CCPA, HIPAA</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — PHI (Protected Health Information) · Medical records, diagnoses, insurance; regulated by HIPAA in US</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Financial Data / PCI-DSS · Card numbers, CVV, account data; PCI-DSS mandates encryption, access control, logging</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Intellectual Property</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Copyrights · Legal protection of creative works; automatic on creation; civil and criminal enforcement</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Patents · Protect inventions for 20 years; requires disclosure; enforceable by courts</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Trademarks · Brand identifiers (logos, names); indefinitely renewable; used to prevent brand impersonation</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Trade Secrets · Competitive advantage info (formulas, algorithms); protected by NDA + access restriction, not registration</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Data Classifications</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Government/Military: Top Secret · Unauthorised disclosure = exceptionally grave damage to national security</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Government/Military: Secret · Serious damage if disclosed; compartmentalised access</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Government/Military: Confidential · Lowest classified level; need-to-know basis</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Commercial: Critical · Business-stopping if disclosed; e.g. unreleased financial results, M&A plans</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Commercial: Confidential/Proprietary · Internal-only; NDA required for third parties</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Commercial: Private · Personal employee/customer data; GDPR-scope; limited internal distribution</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Commercial: Sensitive · Requires care but not formally restricted; internal distribution with awareness</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Commercial: Public · Intentionally published; no restriction; still verify for accuracy before release</span>

### 💡 Data States & Protection Methods

#### Data States
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Data at Rest · Stored on disk, DB, tape, cloud storage; protected by full-disk encryption (AES-256)</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — HSM (Hardware Security Module) · Stores encryption keys in tamper-resistant hardware; used for at-rest key management</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — TPM · Seals disk encryption key to platform; BitLocker/FileVault use TPM to unlock on boot</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Full Disk Encryption (FDE) · BitLocker (Windows), FileVault (macOS), LUKS (Linux)</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Database Encryption · TDE (Transparent Data Encryption) · SQL Server, Oracle, PostgreSQL</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Data in Transit · Moving across network; protected by TLS 1.3 / SSL; HTTPS, SFTP, SMTPS</span>
  - <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — TLS 1.3 · Current standard; forward secrecy; faster handshake; deprecated older ciphers</span>
  - <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Certificate Management · PKI, CA, X.509 certs; cert pinning prevents MITM; auto-renewal via ACME/Let's Encrypt</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — HSM (TLS offload) · Accelerates TLS handshakes; private key never leaves hardware</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Data in Use · Active in RAM/CPU; hardest to protect; protected by memory encryption + access control</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Secure Enclaves (Intel SGX, AMD SEV) · Hardware-isolated memory region; encrypted even from OS/hypervisor</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Memory Protection · ASLR, DEP/NX bit, stack canaries prevent memory exploitation</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Homomorphic Encryption (emerging) · Compute on encrypted data without decrypting; used in cloud analytics</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Methods to Secure Data</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Encryption · Converts plaintext to ciphertext; symmetric (AES) for bulk data; asymmetric (RSA/ECC) for key exchange</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Hashing · One-way transformation; verifies integrity (SHA-256, SHA-3); passwords stored as salted hashes (bcrypt, Argon2)</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Masking · Replaces real data with realistic fake data for non-prod environments (e.g. xxxx-xxxx-xxxx-1234)</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Tokenization · Replaces sensitive value with non-sensitive token; original stored in secure vault; used heavily in PCI-DSS</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Obfuscation · Makes data difficult to understand without destroying it; code obfuscation protects IP in binaries</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Geographic Restrictions · Data residency laws (GDPR Art.44) restrict cross-border data transfers; enforced via policy + cloud region config</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Segmentation · Separates data stores by classification; PII DB isolated from general app DB; separate access controls</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Permission Restrictions · Role-based (RBAC) / attribute-based (ABAC) access control; least-privilege principle</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Data Sovereignty · Data must reside and be processed within specific legal jurisdiction; impacts cloud provider selection</span>

---

## 🔄 Resilience and Recovery

### 📊 High Availability (HA)

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Load Balancing</span>
- Role: Distributes workload to prevent single point of failure and ensure response time SLAs
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Active/Active · All nodes handle live traffic simultaneously; instant failover; requires session synchronisation</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Active/Passive · Primary handles all traffic; secondary on hot standby; failover within seconds</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Round Robin · Sequential distribution; works for stateless services; simplest algorithm</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Least Connections · Routes to server with fewest active sessions; better for variable request duration</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Affinity / Session Persistence · Client always routed to same server; required for shopping carts, auth sessions</span>

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Clustering</span>
- Role: Groups servers to act as single logical system; provides redundancy and failover
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Heartbeat Signal · Periodic keep-alive between cluster nodes; missed heartbeat triggers failover</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Quorum Disk · Shared storage used as tiebreaker when cluster nodes disagree; prevents split-brain</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Witness Server · Third node in cluster providing quorum vote without running workloads; prevents split-brain</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Split-Brain Prevention · Quorum mechanism ensures only one node group becomes primary after network partition</span>

### 🏛️ Recovery Sites

#### <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Hot Site</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Fully mirrored data centre; all systems running; real-time data sync</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — RTO: Near-Instant · Failover in minutes; highest resilience; used for mission-critical systems</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Cost: Highest · Duplicate infrastructure running 24/7; justified for financial, healthcare, critical infrastructure</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Replication Method · Synchronous replication; every write confirmed on both sites before ack to client</span>

#### <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Warm Site</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Hardware installed and configured; data needs restoration from backup before going live</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — RTO: Hours to Days · Hardware ready; data restoration takes time; balance of cost vs recovery speed</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Cost: Moderate · Hardware costs without full operational duplication; most common DR choice</span>

#### <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Cold Site</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Empty facility with power and connectivity only; hardware must be procured and installed during disaster</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — RTO: Weeks · Slowest recovery; lowest cost; used when business can tolerate extended downtime</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Cost: Lowest · Rent/lease facility; no pre-deployed equipment; appropriate for non-critical systems</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Geographic Dispersion · Sites in different seismic zones, flood plains, power grids; protects against regional disaster</span>

### 🧠 Resilience Strategies
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Platform Diversity · Use different OS/hypervisors/vendors; single vendor vuln doesn't take down everything</span>
- <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Multi-Cloud Systems · Workloads span AWS + Azure + GCP; avoids cloud provider lock-in and outage dependency</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — COOP (Continuity of Operations Plan) · Documented plan for maintaining essential functions during disruption; tested regularly</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Capacity Planning · People: cross-training; Technology: headroom for surge; Infrastructure: N+1 redundancy</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — RTO (Recovery Time Objective) · Max acceptable downtime after incident; drives site type and HA investment</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — RPO (Recovery Point Objective) · Max acceptable data loss (time); drives backup frequency and replication choice</span>

### 🧪 Testing Plans
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Tabletop Exercises · Discussion-based; walk through disaster scenario without activating systems; identifies plan gaps</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Failover Testing · Actual failover triggered in controlled window; validates RTO targets; done during low-traffic periods</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Red/Blue Team Simulation · Red attacks, Blue defends; simulates real breach; identifies detection and response gaps</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Parallel Processing Test · Run DR environment alongside production; verify DR handles load before cutting over</span>

###  >_ Backups

#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Full Backup · Complete copy of all data; slowest to create, fastest to restore; weekly typical baseline</span>
#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Incremental Backup · Only data changed since last backup (any type); fastest to create; requires full + all incrementals to restore</span>
#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Differential Backup · Data changed since last FULL backup; larger than incremental; restore needs only full + latest differential</span>
#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Snapshots · Point-in-time copy at storage/VM level; near-instant; used for rapid rollback; not a substitute for offsite backup</span>
#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Replication · Continuous synchronisation to secondary storage/site; near-zero RPO for critical systems</span>
#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Journaling · File system logs every write; enables point-in-time recovery; used in databases (WAL in PostgreSQL)</span>
#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — 3-2-1 Rule · 3 copies of data · 2 different media types · 1 copy off-site or in cloud · industry gold standard</span>
#### <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Off-site / Cloud Storage · Protects against site-level disaster; S3, Azure Blob, Google Cloud Storage; geo-redundant options</span>
#### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Immutable Backups · Write-once storage; ransomware cannot encrypt or delete; critical for ransomware recovery</span>

### ⚡ Power Redundancy
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — UPS (Uninterruptible Power Supply) · Battery-backed power; provides seconds to minutes of power during outage; allows graceful shutdown or generator start</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Generators · Diesel/gas powered; sustains power for hours-days; kicks in after UPS; used in data centres + hospitals</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Managed PDUs (Power Distribution Units) · Intelligent power strips; remote monitoring + switching; alerts on overload; enables remote reboot</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Dual Power Feeds · Two independent utility feeds from different substations; protects against single grid failure</span>

---

## 🧩 Security Control Categories

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Technical Controls</span>
- Role: Hardware/software mechanisms that enforce security automatically without human action
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — TPM · Secure key storage, measured boot, platform attestation</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — HSM · Hardware crypto operations; key management; PKI root of trust</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Smart Cards / Hardware Tokens · Physical MFA factor; certificate-based auth; used in gov + banking</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SIEM (Security Information and Event Management) · Aggregates and correlates logs; real-time alerting; e.g. Splunk, Sentinel, IBM QRadar</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SOAR (Security Orchestration, Automation and Response) · Automates incident response playbooks; integrates SIEM alerts → automated actions; e.g. Palo Alto XSOAR, Splunk SOAR</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — IDS (Intrusion Detection System) · Monitors and alerts on suspicious activity; passive — does not block; e.g. Snort, Suricata (detect mode)</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — IPS (Intrusion Prevention System) · Inline blocking of detected threats; active — drops malicious packets; e.g. Suricata (inline), Cisco Firepower</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — EDR (Endpoint Detection and Response) · Agent on endpoint; behavioural detection; forensic telemetry; e.g. CrowdStrike Falcon, SentinelOne</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Antivirus / Anti-malware · Signature + heuristic detection; legacy but still effective for known malware; integrated into EDR platforms</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Encryption at rest + in transit · AES-256 for storage; TLS 1.3 for transport; enforced technically</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Access Control (RBAC/ABAC) · Technical enforcement of least-privilege; IAM systems assign roles automatically</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Managerial Controls</span>
- Role: Strategic oversight and governance; executed by management and documented in policy
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Risk Assessments · Identify, analyse, evaluate risks; quantitative (ALE=ARO×SLE) or qualitative; informs control selection</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Security Policies · Documented rules governing security behaviour; AUP, password policy, data classification policy</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Code of Conduct · Defines acceptable employee behaviour regarding information assets; legally binding via employment contract</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Vendor Risk Management · Third-party assessments, SLAs, right-to-audit clauses; supply chain risk mitigation</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Business Impact Analysis (BIA) · Identifies critical systems + quantifies financial/operational impact of downtime; drives RTO/RPO</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Operational Controls</span>
- Role: Day-to-day procedures executed by people to maintain security posture
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Security Awareness Training · Phishing simulation, policy training; humans = largest attack vector; mandatory and recurring</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Incident Response Procedures · Documented playbooks: Prepare → Identify → Contain → Eradicate → Recover → Lessons Learned (PICERL)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — User Access Management · Joiner/Mover/Leaver process; access reviews; PAM for privileged accounts</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Change Management · Controlled process for system changes; prevents unauthorised modifications; CAB approval</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Patch Management · Scheduled vulnerability remediation; critical patches within 24-72h; tracked via vulnerability scanner</span>

### <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Physical Controls</span>
- Role: Tangible barriers and personnel controlling physical access to assets
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Bollards · Reinforced posts preventing vehicle ramming; protects building entrances and data centre loading docks</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — CCTV / Surveillance · Continuous recording; deterrence + forensic evidence; feeds into SOC monitoring screens</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Video Analytics · AI-powered motion detection, facial recognition, anomaly alerts integrated with SIEM</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Security Guards · Human response capability; challenge unknown individuals; patrol; cannot be bypassed by software exploit</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Access Control Vestibules / Mantraps · Two-door airlock; prevents tailgating; one door must close before next opens</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Badge Readers / Biometric Scanners · Electronic access control at vestibule; logs every entry attempt</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Faraday Cage · Metal enclosure blocks electromagnetic signals; prevents wireless exfiltration from secured areas</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Cable Locks · Physical laptop locks; prevents opportunistic theft in shared workspaces</span>

---

## 🎯 Security Control Types

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Preventive Controls</span>
- Role: Stop incidents BEFORE they occur; reduce likelihood of a threat being realised
- Used by: Security architects, network engineers, policy makers
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Proactive Measures · Security by design; threat modelling (STRIDE, PASTA); secure SDLC; hardening baselines (CIS Benchmarks)</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Firewalls (as preventive) · Block unauthorised traffic before it reaches target; perimeter + internal enforcement</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — NGFW · DPI blocks known malicious payloads, C2 traffic, exploits at wire speed</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — WAF · Blocks OWASP Top 10 attacks before they reach the application</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Access Control Lists (ACLs) · Network ACLs: permit/deny by IP/port; OS ACLs: file/folder permission rules</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Principle of Least Privilege · Users/systems get minimum permissions needed; reduces blast radius of compromise</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — MFA (Multi-Factor Authentication) · Requires 2+ factors; prevents credential-only attacks; something you know + have + are</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Hardware Tokens (FIDO2/YubiKey) · Phishing-resistant MFA; cryptographic challenge-response; cannot be replayed</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Authenticator Apps (TOTP) · Time-based OTP; e.g. Google Authenticator, Microsoft Authenticator</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Employee Security Training · Reduces human error (phishing clicks, weak passwords, social engineering); recurring + role-specific</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — IPS (Intrusion Prevention System) · Inline blocking of exploit attempts, malicious patterns; preventive counterpart to IDS</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Encryption (preventive) · Prevents data exposure if storage/transit is compromised; pre-emptive data protection</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Network Segmentation (preventive) · Limits lateral movement if attacker gains initial access; contains blast radius</span>

### <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Deterrent Controls</span>
- Role: Discourage threat actors from attempting attacks; psychological or visible presence
- Note: Do not technically stop the attack — reduce probability of attempt
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Psychological Measures · Legal notices, warning banners on login screens, prosecution policies; signals monitoring is active</span>
  - <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Warning Banners · "Authorised users only — activity is monitored and logged"; establishes legal basis for prosecution</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Visible Warning Signs · "CCTV in operation", "Trespassers prosecuted"; visible deterrence reduces opportunistic physical intrusion</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Surveillance Cameras (CCTV as deterrent) · Visible camera presence deters bad actors; even dummy cameras have deterrent effect</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — MFA (as deterrent) · Visible MFA requirement discourages attackers who know credential theft alone won't suffice</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Security Guards (visible presence) · Uniformed personnel deters physical intrusion and social engineering attempts</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Prosecution / Legal Deterrence · Public disclosure of prosecutions signals that attacks have consequences; deters repeat actors</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Detective Controls</span>
- Role: Identify and alert on incidents WHILE or AFTER they occur; enable response
- Used by: SOC analysts, incident responders, auditors
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Identify Existing Incidents · Focus is detection speed (MTTD — Mean Time to Detect); faster detection = less damage</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Log Analysis · Centralised log aggregation; search for IOCs, anomalous patterns; SIEM is the primary tool</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SIEM (Detective) · Correlates events from firewalls, endpoints, AD, cloud; triggers alerts on anomalies · Splunk, Sentinel, QRadar</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — UEBA (User Entity Behaviour Analytics) · ML-based; detects insider threats via baseline deviation · integrated in modern SIEMs</span>
    - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Threat Hunting · Proactive analyst-driven search for hidden threats; uses SIEM + EDR telemetry</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Network TAPs / Sensors (detective) · Feed raw traffic to IDS and SIEM for analysis without impacting production</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — CCTV Monitoring (detective) · Recorded footage reviewed after incident; provides physical forensic timeline</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Video Analytics · Real-time motion/anomaly detection; alerts SOC to physical security events</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Financial / Compliance Audits · Independent review of transactions and controls; detects fraud, policy violations, misconfiguration</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — IDS (Intrusion Detection System) · Monitors network/host for attack signatures or anomalies; alerts but does not block</span>
  - <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — NGFW (with IDS module) · Hardware appliance performing deep packet inspection for detection purposes</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — HIDS (Host IDS) · Agent on endpoint; monitors file integrity, process anomalies, log tampering · e.g. OSSEC, Wazuh</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — NIDS (Network IDS) · Monitors network traffic; signature + anomaly · e.g. Snort, Suricata, Zeek</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Corrective Controls</span>
- Role: Minimise impact and restore operations AFTER an incident occurs; reactive
- Used by: IR teams, SysAdmins, SOC Level 2/3 analysts
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Reactive Measures · Triggered post-detection; contain damage, remove threat, restore service; follows IR playbook</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SOAR (Corrective) · Automates containment: isolates compromised host, blocks attacker IP, revokes tokens — seconds vs minutes</span>
  - <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — EDR Remediation · Kills malicious processes, quarantines files, rolls back ransomware changes at endpoint level</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Data Restoration · Restores from clean backup after malware/ransomware/corruption; tests backup integrity before incident</span>
  - <span style="background:#80DEEA;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> ☁️ Cl — Cloud Backup Restore · AWS Backup, Azure Recovery Services; automated restore to last known good state</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Immutable Backup Restore · Ransomware cannot delete/encrypt immutable copies; gold standard for ransomware recovery</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Software Patching (corrective) · Applies vendor patch to close exploited vulnerability after breach is confirmed</span>
  - <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Emergency Change Process · Expedited CAB approval for critical security patches; bypasses normal change window</span>
  - <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Virtual Patching · WAF/IPS rule blocks exploit while permanent patch is developed/tested; buys time for legacy systems</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Compensating Controls</span>
- Role: Alternative controls used when primary control cannot be implemented; maintains equivalent security
- Used by: Risk managers, compliance teams, orgs with legacy/unpatachable systems
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Alternative Measures · Accepted by compliance frameworks (PCI-DSS, HIPAA) when standard control is technically infeasible</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Human Approval Layers · Manual review step replaces automated control; e.g. 4-eyes approval for large financial transactions</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Physical Security Increase · Enhanced guards/cameras around unpatachable legacy system; physical access compensates for software weakness</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — Network Isolation · Air-gap or separate VLAN for system that cannot be patched; limits attack surface without patching</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Virtual Patching (compensating) · IPS/WAF rule blocks known exploit vector while patch is unavailable</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — Enhanced Monitoring · Increase logging verbosity + alerting sensitivity around unprotected system to detect exploitation faster</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Directive Controls</span>
- Role: Guide and mandate behaviour through documented rules; foundational to all other control types
- Used by: CISO, Compliance teams, Legal, HR
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Administrative Guidelines · High-level security direction from leadership; translated into specific policies and procedures</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Acceptable Use Policy (AUP) · Defines permitted/prohibited use of org IT systems; signed by all employees; legal basis for disciplinary action</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Standard Operating Procedures (SOPs) · Step-by-step instructions for security tasks; ensures consistency; e.g. onboarding, offboarding, incident escalation</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Codes of Conduct · Ethical and professional behaviour expectations; security-relevant: no sharing credentials, reporting incidents, clean desk</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Data Classification Policy · Mandatory labelling of data by sensitivity; triggers handling requirements (encryption, access logging, retention)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Regulatory Compliance Mandates · GDPR, HIPAA, PCI-DSS, ISO 27001, NIST CSF — external frameworks driving internal directive controls</span>

### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Contextual Framework</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — CIA Triad</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Confidentiality · Prevent unauthorised access; enforced by: encryption, access control, classification, MFA</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Integrity · Ensure data is accurate and unmodified; enforced by: hashing, digital signatures, version control, audit logs</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Availability · Ensure systems accessible when needed; enforced by: HA, backups, DR sites, DDoS mitigation, redundancy</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Control Categories (reminder mapping)</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Technical · Automated enforcement by hardware/software</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Managerial · Strategic governance and risk decisions</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Operational · Human-executed day-to-day procedures</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Physical · Tangible access barriers and environmental controls</span>

#### <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — General Security Concepts</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Defence in Depth · Multiple overlapping control layers; single control failure doesn't equal breach</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Least Privilege · Every user/system gets minimum permissions for their role; limits blast radius</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Separation of Duties · No single person controls entire critical process; prevents fraud and error</span>
- <span style="background:#81C784;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">📋 Gov — Zero Trust · Never trust, always verify; explicit verification for every access request regardless of location</span>

---

## 🔁 Cross-Reference Index — Key Components Appearing in Multiple Contexts

### <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — NGFW — All Contexts</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — As Network Appliance · Physical hardware at perimeter/internal boundary; DPI, App-ID, IPS integrated</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — As ZTA Policy Enforcement Point · Receives policy from Policy Administrator; enforces per-session access decisions</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — As SDN Enforcement Node · SDN controller pushes dynamic ACLs to NGFW; programmable security rules</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — As DMZ Perimeter Device · Sits between WAN and DMZ; inspects all inbound traffic to public-facing services</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — As Preventive Control · Blocks known malicious traffic, exploits, C2 before reaching target</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — As Detective Control · IDS module alerts on suspicious patterns; generates logs to SIEM</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SIEM — All Contexts</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — As Technical Control · Aggregates + correlates logs; automated alerting on rule matches</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — As Detective Control · Core tool for identifying incidents; SOC analysts triage SIEM alerts</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — As SDN Policy Engine Input · Real-time threat data feeds into SDN Policy Engine for dynamic rule adjustment</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — As ZTA Policy Engine Input · Risk signals (anomalous login, impossible travel) feed ZTA Policy Engine to revoke/step-up access</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — SOAR — All Contexts</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — As Technical Control · Automated playbook execution; integrates with 100s of security tools</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — As Corrective Control · Automates containment (isolate host, block IP, reset password) in seconds</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — As SDN Policy Engine Actuator · SOAR pushes dynamic firewall rules / VLAN changes through SDN controller</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — As ZTA Automated Response · SOAR revokes session tokens, triggers step-up MFA, alerts Policy Administrator</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — IDS/IPS — All Contexts</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — IDS as Detective Control · Passive monitoring; alerts on signatures and anomalies; no blocking</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — IPS as Preventive Control · Inline blocking; drops malicious packets before reaching target</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Integrated in NGFW · IDS/IPS modules embedded in next-gen firewall hardware</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Inline Appliance (dedicated) · Standalone IPS appliance inserted into traffic path</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — Network TAP → NIDS · TAP passively copies traffic to out-of-band IDS sensor</span>

### <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — MFA — All Contexts</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — As Preventive Control · Blocks credential-only attacks; required before granting any access</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — As Deterrent · Visible MFA requirement discourages phishing-focused attackers</span>
- <span style="background:#7986CB;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🌐 Ntw — As ZTA Policy Engine Input · Device + identity verified via MFA before Policy Engine grants session token</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — FIDO2 Hardware Key · Phishing-resistant; cryptographic proof of possession; YubiKey, Titan Key</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — Biometric (as factor) · Something you are; fingerprint, face, iris; used in high-security physical + logical access</span>

### <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — CCTV — All Contexts</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — As Deterrent Control · Visible cameras deter physical intrusion and insider theft</span>
- <span style="background:#4FC3F7;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🚀 Sw — As Detective Control · Recorded footage provides forensic evidence; video analytics trigger real-time alerts</span>
- <span style="background:#A1887F;color:#fff;padding:2px 8px;border-radius:5px;font-weight:600;">🪪 Ph — As Physical Control · Part of physical security layer; integrated with access control systems</span>

### <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Encryption — All Contexts</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Data at Rest · AES-256 full disk / database encryption; key managed by HSM/KMS</span>
- <span style="background:#CE93D8;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🔗 Pr — Data in Transit · TLS 1.3 for HTTPS; IPSec for VPN/SD-WAN; SSH for admin access</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — Backup Encryption · Protects backup data from theft; key must be stored separately from backup</span>
- <span style="background:#FF8A80;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;">🛠️ M — As Preventive Control · Pre-emptive protection; useless data to attacker without key</span>
- <span style="background:#F4A261;color:#1a1a1a;padding:2px 8px;border-radius:5px;font-weight:600;"> 🗄️ Hw — HSM performs crypto operations · Private keys never exposed to software; tamper-evident; FIPS 140-2 Level 3+</span>
