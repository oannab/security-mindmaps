## Protocol - for CompTIA Security+ - by OSI Layer (*v2*)

### 🔑 Category Key

| Code | Category |
|---|---|
| **WEB** | Web / HTTP |
| **EMAIL** | Email delivery & retrieval |
| **ESEC** | Email security (anti-spoofing) |
| **FILE** | File transfer |
| **REMOTE** | Remote access & shell |
| **DIR** | Generic directory access (LDAP-based) |
| **AD** | Active Directory & Windows identity |
| **AUTH** | Authentication & authorisation |
| **NAME** | Name & address resolution |
| **NET** | Core networking & routing |
| **VPN** | VPN & tunnelling |
| **TLS** | TLS / SSL transport encryption |
| **PKI** | Certificates, PKI & revocation |
| **MGMT** | Network management (config, polling) |
| **MON** | Monitoring, logging & telemetry |
| **SEC** | Security tooling (FW / IDS / SIEM / EDR) |
| **WIRELESS** | Wireless & radio security |
| **VOIP** | Voice & real-time comms |
| **DB** | Database protocols |

---

# Layer 7 — Application

#### 🌐 Web [L7]

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| HTTP | 80 | WEB | 🌐 Browsers, 🖥️ web servers (Apache, Nginx, IIS) | Cleartext — session hijacking, injection, sniffing |
| HTTPS | 443 | WEB | 🌐 Browsers, 🛡️ WAFs, ☁️ CDNs (Cloudflare, Akamai) | HTTP over TLS — SSL stripping, weak ciphers, cert errors |
| HTTP/2 | 443 | WEB | 🌐 Modern browsers, ☁️ CDNs | Rapid Reset DoS (CVE-2023-44487), stream abuse |
| HTTP/3 (QUIC) | 443 UDP | WEB | 🌐 Chrome/Firefox, ☁️ Cloudflare | Bypasses DPI — UDP 443 can evade inspection |

#### 📁 File Transfer [L7]

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| FTP | 20, 21 | FILE | 📂 FileZilla, WinSCP, 🖥️ web hosting | Cleartext creds + data — flag immediately |
| FTPS | 989, 990 | FILE | 📂 FileZilla, enterprise FTP systems | FTP + implicit TLS — secure alternative |
| SFTP | 22 | FILE | 📂 WinSCP, OpenSSH, 🐧 Linux/Unix | FTP over SSH — brute force, key compromise |
| TFTP | 69 | FILE | 🔌 Routers/switches, 🖥️ PXE boot servers | UDP, zero auth, zero encryption — firmware/boot only |
| SMB / CIFS | 445, 139 | FILE | 🪟 Windows file servers, 💾 NAS (Synology), 🐧 Samba | EternalBlue, pass-the-hash, ransomware propagation — disable SMBv1 |

#### 💻 Remote Access [L7]

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| SSH | 22 | REMOTE | 🐧 OpenSSH, PuTTY, 🔌 network devices | Encrypted shell — brute force, key theft, port forward abuse |
| Telnet | 23 | REMOTE | 🔌 Legacy routers/switches, ICS | Cleartext — **deprecated**, any usage is an IoC |
| RDP | 3389 | REMOTE | 🪟 Windows (all), Remote Desktop Gateway | BlueKeep, brute force, ransomware vector — never expose raw to internet |
| WinRM | 5985, 5986 | REMOTE | 🪟 Windows Server, PowerShell, Ansible | Lateral movement — PS remoting exploitation |

#### 📧 Email [L7]

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| SMTP | 25, 587 | EMAIL | 📧 Exchange, Postfix, Sendmail | 25 = server relay; 587 = client submission with auth |
| SMTPS | 465 | EMAIL | 📧 Email clients (Outlook, Thunderbird) | SMTP with implicit TLS |
| SMTP STARTTLS | 587 | EMAIL | 📧 Email clients, MTAs | Opportunistic TLS — STARTTLS stripping attack possible |
| POP3 | 110 | EMAIL | 📧 Outlook, Thunderbird, mobile apps | Cleartext retrieval — use POP3S |
| POP3S | 995 | EMAIL | 📧 Email clients | POP3 over TLS |
| IMAP | 143 | EMAIL | 📧 Webmail, mobile apps | Cleartext — use IMAPS; forwarding rule abuse |
| IMAPS | 993 | EMAIL | 📧 Email clients, webmail | IMAP over TLS |

#### 🛡️ Email Security (anti-spoofing triad — know all three)

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| SPF | DNS TXT | ESEC | 🌐 DNS servers, email gateways (Mimecast, Proofpoint) | Authorises sending IPs — **'+all' = anyone can send = broken** |
| DKIM | DNS TXT | ESEC | 🌐 DNS, mail servers | Signs message body — key < 1024-bit = weak |
| DMARC | DNS TXT | ESEC | 🌐 DNS, reporting tools (Dmarcian) | Enforces SPF+DKIM alignment — **'p=none' = no enforcement** |

> 💡 **Exam tip:** DMARC requires *both* SPF *and* DKIM to align. Without enforcement ('p=quarantine' or 'p=reject') DMARC reports but doesn't block.

#### 🔍 Name & Address Resolution [L7]

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| DNS | 53 UDP/TCP | NAME | 🌐 All hosts, 🔌 DNS servers (BIND, Windows DNS, Pi-hole) | Poisoning, tunnelling, DGA C2 — cornerstone of most attacks |
| DNSSEC | 53 | NAME | 🌐 DNS servers, resolvers | Authenticates DNS records — doesn't encrypt, just signs |
| DoH | 443 | NAME | 🌐 Firefox, Chrome, Cloudflare 1.1.1.1 | Encrypted DNS — bypasses corporate DNS filtering |
| DoT | 853 | NAME | 🌐 Resolvers, 🛡️ next-gen firewalls | DNS over TLS — encrypted, still fingerprintable |
| DHCP | 67, 68 | NAME | 🔌 Routers, DHCP servers (Windows DHCP, ISC DHCP) | Rogue DHCP server → redirect traffic, DHCP starvation DoS |
| mDNS | 5353 | NAME | 🍎 Apple devices, 🐧 Avahi, 📟 IoT | Zero-config local resolution — poisoning, enumeration |
| LLMNR | 5355 | NAME | 🪟 Windows hosts | **Poisoned by Responder tool** to capture NTLMv2 hashes — disable in AD environments |
| NetBIOS | 137–139 | NAME | 🪟 Windows (legacy), 🐧 Samba | Legacy name resolution — null sessions, enumeration |

#### 🔐 Directory & Identity [L7]

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| LDAP | 389 | DIR | 🗂️ OpenLDAP, 🪟 Active Directory, 📱 apps | Cleartext queries — anonymous bind, injection, enumeration |
| LDAPS | 636 | DIR | 🗂️ OpenLDAP, AD, 🔑 SSSD, FreeIPA | LDAP over TLS — always prefer over plain LDAP |
| LDAP STARTTLS | 389 | DIR | 🗂️ OpenLDAP, SSSD, app backends | Upgrade to TLS on same port — stripping attack possible |
| Kerberos | 88 | AD | 🪟 Active Directory DCs, 🐧 MIT KDC | Ticket-based — **Kerberoasting, AS-REP roasting, golden/silver ticket, pass-the-ticket** |
| NTLM / NTLMv2 | Various | AD | 🪟 Windows (all versions), SMB, IIS | Challenge-response — **pass-the-hash, NTLM relay** — prefer Kerberos |
| SMB (auth context) | 445 | AD | 🪟 Windows, 🐧 Samba | NTLM relay over SMB, credential capture |
| WMI / DCOM | 135, dynamic | AD | 🪟 Windows, SCCM, management tools | Lateral movement — attacker toolkits abuse WMI heavily |

#### 🔑 Authentication & Authorisation [L7]

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| RADIUS | 1812, 1813 | AUTH | 🔑 FreeRADIUS, 🪟 NPS, 🛡️ Cisco ISE, 🔌 APs, VPN gateways | AAA — shared secret + MD5; weak against sniff; use with 802.1X |
| TACACS+ | 49 | AUTH | 🔌 Cisco devices, 🔑 Cisco ISE, ACS | Device admin AAA — encrypts full packet (unlike RADIUS) |
| OAuth 2.0 | 443 | AUTH | 🌐 Google, Okta, Azure AD, web/mobile apps | Authorisation delegation — token theft, CSRF, open redirector |
| SAML 2.0 | 443 | AUTH | 🔑 Okta, ADFS, Azure AD, enterprise SaaS | XML SSO — **Golden SAML**, assertion replay, XML sig wrapping |
| OIDC | 443 | AUTH | 🔑 Okta, Google, Azure AD, mobile apps | Identity layer on OAuth 2.0 — ID token forgery, nonce reuse |
| FIDO2 / WebAuthn | 443 | AUTH | 🔑 YubiKey, Windows Hello, Touch ID, browsers | **Phishing-resistant MFA** — strongest available for Security+ |
| TOTP / HOTP | N/A | AUTH | 📱 Google Authenticator, Authy, RSA SecurID | Soft token MFA — OTP phishing (real-time relay), seed theft |

#### 📡 Network Management & Monitoring [L7]

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| SNMP v1/v2c | 161, 162 | MGMT | 🔌 Routers/switches, 🛡️ Nagios, PRTG, Zabbix | **Default 'public'/'private' community strings = critical vuln** |
| SNMP v3 | 161, 162 | MGMT | 🔌 Routers/switches, 🛡️ PRTG, SolarWinds | Adds auth + encryption — always prefer over v1/v2 |
| NTP | 123 | MGMT | 🔌 All network devices, 🕐 NTP servers (pool.ntp.org) | Amplification DDoS, time manipulation breaks Kerberos + TLS certs |
| Syslog | 514 UDP, 601 TCP, 6514 TLS | MON | 🛡️ Splunk, Graylog, rsyslog, syslog-ng | Log forwarding — UDP 514 is cleartext + tamperable; use TLS |
| NetFlow / IPFIX | 2055, 4739 | MON | 🔌 Cisco routers, 🛡️ ntopng, Elastic, StealthWatch | Traffic metadata — detects beaconing, exfil volume, lateral movement |
| NETCONF | 830 | MGMT | 🔌 Cisco/Juniper/Arista devices, Ansible, NSO | Automated device config — config injection if unprotected |

#### 📞 VoIP [L7]

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| SIP | 5060, 5061 | VOIP | 📞 VoIP phones, PBX (Asterisk, 3CX), softphones | Call signalling — toll fraud, INVITE floods, registration hijacking |
| RTP | Dynamic | VOIP | 📞 VoIP systems, video conferencing (Zoom, Teams infrastructure) | Media stream — **unencrypted by default**, eavesdropping |

#### 💬 Other Application Layer [L7]

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| IRC | 6667, 6697 | SEC | 💬 IRC clients — historically used by botnets | Classic botnet C2 channel — any corporate IRC traffic is suspicious |


### Cross-Layer: 💾 Database Protocols [L7]/[L4]

> Security+ increasingly includes database attack surface. SQL injection is a core topic.

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| MySQL / MariaDB | 3306 | DB | 💾 MySQL Server, MariaDB, phpMyAdmin, LAMP/WAMP stacks | Default root with no password, cleartext by default — **SQL injection** |
| PostgreSQL | 5432 | DB | 💾 PostgreSQL server, pgAdmin, Heroku, cloud RDS | Default 'postgres' superuser, md5 auth weak — SQL injection, COPY TO/FROM abuse |
| MSSQL | 1433 TCP, 1434 UDP | DB | 💾 SQL Server, SSMS, Azure SQL, 🪟 Windows servers | **xp_cmdshell** (OS command exec), SA account brute force, SQL injection |
| Oracle DB | 1521 | DB | 💾 Oracle Database, SQL*Plus, OEM | TNS listener attacks, default SYS/SYSTEM accounts, SQL injection |
| Redis | 6379 | DB | 💾 Redis server, Redis Sentinel, caching layers | **No auth by default** — RCE via config write (SSH key / cron injection), data exfil |
| MongoDB | 27017 | DB | 💾 MongoDB server, MongoDB Atlas, NoSQL apps | **No auth by default** — historically masses of exposed DBs on internet, data exfil |
| Memcached | 11211 | DB | 💾 Memcached, caching tier | No auth — **massive DDoS amplification factor** (51,000×), data exfil |
| Elasticsearch | 9200, 9300 | MON / DB | 🛡️ Elastic Stack (ELK), Kibana, SIEM backends | No auth by default — frequent mass data exposure; REST API = easily queried |


---

# Layer 6 — Presentation

#### 🔒 TLS / SSL — Know the Version History

| Protocol | Cat | Devices / Tools | Status & Key Notes |
|---|---|---|---|
| SSL 2.0 / 3.0 | TLS | 🌐 Legacy servers/browsers | ❌ **Completely broken** — POODLE, DROWN — any use = critical finding |
| TLS 1.0 | TLS | 🌐 Old browsers, legacy apps | ❌ **Deprecated** (RFC 8996) — BEAST attack, disable everywhere |
| TLS 1.1 | TLS | 🌐 Old browsers, legacy apps | ❌ **Deprecated** (RFC 8996) — disable everywhere |
| TLS 1.2 | TLS | 🌐 All browsers, 🖥️ servers, 📱 mobile apps | ✅ Current minimum — avoid RC4/3DES cipher suites |
| TLS 1.3 | TLS | 🌐 Modern browsers, 🖥️ modern servers | ✅ **Preferred** — removes all legacy ciphers, mandatory PFS, faster |
| MIME | EMAIL | 📧 Email systems, browsers | Encoding format — content-type spoofing, polyglot file attachments |

> 💡 **TLS 1.3 key improvements vs 1.2:** removed RSA key exchange (now always PFS), reduced handshake from 2 RTT → 1 RTT, eliminated RC4/3DES/MD5.

---

# Layer 5 — Session

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| PPTP | 1723 | VPN | 🪟 Windows built-in VPN, legacy clients | ❌ **Deprecated** — MS-CHAPv2 offline-crackable, no use today |
| L2TP (alone) | 1701 | VPN | 🔌 VPN concentrators, ISPs | ❌ **Insecure alone** — no encryption without IPSec |
| L2TP/IPSec | 1701 + 500/4500 | VPN | 🔌 VPN gateways, 🪟 Windows VPN client | ✅ Secure combination — weak PSK is the main risk |
| SOCKS5 | 1080 | NET | 🌐 Proxy servers, Tor, browsers | Proxy tunnelling — heavily abused for C2 traffic routing |

---

# Layer 4 — Transport

| Protocol | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|
| TCP | NET | 🔌 All hosts/devices | SYN flood, session hijacking, RST injection, port scanning (SYN scan) |
| UDP | NET | 🔌 All hosts/devices | No connection state — spoofing, **amplification/reflection DDoS** (DNS, NTP, Memcached) |

---

# Layer 3 — Network

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| IP | N/A | NET | 🔌 All hosts/routers | Spoofing, TTL manipulation, fragmentation-based IDS evasion |
| ICMP | N/A | NET | 🔌 All hosts — ping, traceroute, pathping | Ping flood, **ICMP tunnelling** (data exfil), ping of death, recon |
| ARP | N/A | NET | 🔌 All Ethernet hosts/switches | **ARP poisoning → MITM** — no auth by default; mitigate with DAI |
| BGP | 179 | NET | 🔌 Internet routers, ISP infrastructure | Route hijacking (prefix hijacking) — no auth by default in BGP |
| OSPF | 89 | NET | 🔌 Enterprise routers, L3 switches | Neighbour spoofing, route injection — enable MD5/SHA auth |
| IPSec | Proto 50/51 | VPN | 🔌 VPN gateways, 🪟🐧 OS IPSec stacks | **ESP** (Proto 50) = encrypt + auth; **AH** (Proto 51) = auth only, no encrypt |
| IKEv1 | 500 UDP | VPN | 🔌 Legacy VPN gateways | Aggressive mode → PSK crackable offline — use IKEv2 |
| IKEv2 | 500, 4500 UDP | VPN | 🔌 Modern VPN gateways, 📱 mobile VPN clients | Preferred IPSec key exchange — PSK or cert auth |
| GRE | Proto 47 | VPN | 🔌 Cisco routers, DMVPN | Encapsulation only — **no encryption** — attackers tunnel malicious traffic inside |

---

# Layer 2 — Data Link

#### 📶 Wireless Security — Ordered worst to best

| Standard | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|
| WEP | WIRELESS | 📡 Legacy APs | ❌ **Broken** — IV reuse + RC4 = cracked in minutes |
| WPA (TKIP) | WIRELESS | 📡 Older APs/clients | ❌ **Deprecated** — TKIP has known weaknesses |
| WPA2-Personal (PSK) | WIRELESS | 📡 Home routers, SMB APs | ⚠️ 4-way handshake capture → offline PSK crack; PMKID attack |
| WPA2-Enterprise | WIRELESS | 📡 Enterprise APs, 🔑 RADIUS/NPS | ✅ Better — 802.1X/EAP per-user auth; rogue AP attack if cert validation off |
| WPA3-Personal (SAE) | WIRELESS | 📡 WPA3 APs (2019+), modern clients | ✅ SAE replaces PSK — forward secrecy; Dragonblood side-channel |
| WPA3-Enterprise | WIRELESS | 📡 Enterprise APs, 🔑 RADIUS | ✅ Best — 192-bit suite option for high-security |
| 802.11w (PMF) | WIRELESS | 📡 WPA3 (mandatory), WPA2 (optional) | Protects mgmt frames — prevents **deauth attacks** |

#### 🔑 802.1X EAP Methods — Ordered strongest to weakest

| Method | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|
| EAP-TLS | AUTH | 📡 Enterprise APs, 🔑 RADIUS, managed endpoints | ✅ Strongest — mutual cert auth, no PSK |
| PEAP-MSCHAPv2 | AUTH | 📡 APs, 🪟 Windows, 📱 Android/iOS, 🔑 NPS | ⚠️ Most common enterprise Wi-Fi — **crackable if server cert validation disabled** |
| EAP-TTLS | AUTH | 📡 APs, 🐧 Linux (wpa_supplicant), 🔑 FreeRADIUS | ✅ Flexible — validate server cert to prevent MITM |
| EAP-FAST | AUTH | 📡 Cisco APs, 🔑 Cisco ISE | ⚠️ Cisco proprietary — PAC file compromise is main risk |
| PEAP-GTC | AUTH | 📡 APs, 🔑 RADIUS, RSA SecurID | OTP-based — GTC inner method; server cert validation critical |

#### 🔌 Other Layer 2

| Protocol | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|
| 802.1Q VLAN | NET | 🔌 Managed switches, enterprise routers | **VLAN hopping** via double-tagging — disable auto-trunk on access ports |
| STP / RSTP | NET | 🔌 Managed switches | **Root bridge hijacking** → traffic interception — use BPDU Guard + Root Guard |
| MACsec (802.1AE) | TLS | 🔌 Enterprise switches (Cisco, Aruba), NICs | Layer 2 encryption between switches — hop-by-hop, not end-to-end |
| PPP / PPPoE | NET | 🔌 DSL modems, broadband routers | **PAP = cleartext** (never use); CHAP = challenge-response (better) |
| CDP / LLDP | MGMT | 🔌 Cisco (CDP), all vendors (LLDP) | Topology discovery — **disable on untrusted/user ports** (leaks VLAN/device info) |
| Bluetooth Classic | WIRELESS | 📱 Phones, laptops, 🎧 headsets, keyboards | Bluejacking, bluesnarfing, **BlueBorne** — keep patched, disable discoverable mode |
| BLE | WIRELESS | 📟 Fitness bands, smart locks, beacons, medical devices | GATT enumeration, Just Works MITM, **beacon tracking**, replay attacks |

---

# Layer 1 — Physical

| Protocol / Medium | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|
| Ethernet (Cat5e/6/6A) | NET | 🔌 Switches, NICs, patch panels | Physical tapping, rogue device — **physical security = first line** |
| Fiber Optic | NET | 🔌 Core switches, data centre backbones, SFP modules | Harder to tap than copper — but splice taps exist |
| USB | SEC | 💻 Computers, peripherals | **BadUSB** (HID spoofing), juice jacking, malware via drop attacks |
| Bluetooth RF | WIRELESS | 📱 All BT devices | RF eavesdropping — extended-range antenna attacks |

---

---

# Other

### Cross-Layer: 🔐 PKI & Certificate Management

> These aren't protocols in themselves but underpin TLS, S/MIME, code signing — Security+ tests heavily.

| Concept | Cat | Devices / Tools | Key Notes |
|---|---|---|---|
| X.509 Certificates | PKI | 🔐 CAs (DigiCert, Let's Encrypt, internal MS CA/AD CS) | Format for TLS, email, code signing certs — CN, SAN, extensions |
| CA Hierarchy (Root → Intermediate → Leaf) | PKI | 🔐 CA servers, HSMs | Root CA should be **offline** — intermediate CA issues end-entity certs |
| CSR (Certificate Signing Request) | PKI | 🖥️ Servers, OpenSSL, certreq | Submitted to CA to request cert — contains public key + identity |
| CRL (Certificate Revocation List) | PKI | 🌐 CA servers, LDAP, browsers | Revoked cert list — can be slow/large; downloaded periodically |
| OCSP | 80, 443 | PKI | 🌐 OCSP responders, browsers | Real-time revocation check — **OCSP stapling** preferred (server caches response) |
| Certificate Pinning | PKI | 📱 Mobile apps, browsers (HPKP) | Bind cert/key to app — prevents MITM via rogue CA |
| Self-signed Certificate | PKI | 🖥️ Dev/test servers, internal tools | No third-party trust — **browsers warn**, MITM risk if accepted blindly |
| Wildcard Certificate | PKI | 🌐 Web servers, CDNs | Covers *.domain.com — compromise = affects all subdomains |
| SAN Certificate | PKI | 🌐 Web servers, Exchange, internal PKI | Multiple domains on one cert — verify all SANs are legit |
| PFS (Perfect Forward Secrecy) | PKI | 🌐 TLS 1.3 (mandatory), TLS 1.2 (ECDHE) | Past sessions can't be decrypted even if key later compromised |
| HSM (Hardware Security Module) | PKI | 🔐 Thales Luna, AWS CloudHSM, YubiHSM | Stores private keys in tamper-resistant hardware — CA root key protection |

---

### Cross-Layer: 🔒 Authentication Reference Card

| Protocol | Port(s) | Cat | Devices / Tools | Key Security Notes |
|---|---|---|---|---|
| NTLM / NTLMv2 | Various | AD | 🪟 Windows OS, SMB, IIS, legacy apps | **Pass-the-hash, NTLM relay** — NTLMv1 = broken; prefer Kerberos always |
| CHAP | PPP | AUTH | 🔌 PPP links, legacy VPN, L2TP | Challenge-response — better than PAP; **MS-CHAPv2 offline-crackable** |
| PAP | PPP | AUTH | 🔌 Legacy PPP | ❌ Cleartext password — never use |
| OAuth 2.0 | 443 | AUTH | 🌐 Google, GitHub, Okta, Azure AD | **Token theft**, open redirector, CSRF — not an auth protocol (authorisation only) |
| SAML 2.0 | 443 | AUTH | 🔑 Okta, ADFS, Azure AD | Enterprise SSO — **Golden SAML**, XML signature wrapping |
| FIDO2 / WebAuthn | 443 | AUTH | 🔑 YubiKey, Windows Hello, Touch ID | **Phishing-resistant** — no shared secret ever leaves device |
| TOTP / HOTP | N/A | AUTH | 📱 Authenticator apps, RSA tokens | Soft MFA — **real-time OTP phishing** is the main modern attack |

---

# 📋 Quick-Fire Exam Reminders

**Cleartext protocols — always flag as vulnerable:**
> Telnet · FTP · HTTP · LDAP · SMTP:25 · POP3 · IMAP · SNMPv1/v2 · Syslog UDP:514 · TFTP · PAP · Redis · MongoDB (no-auth defaults)

**Secure replacements:**
> Telnet → SSH | FTP → SFTP or FTPS | HTTP → HTTPS | LDAP → LDAPS | SNMPv1/v2 → SNMPv3 | Syslog UDP → Syslog TLS

**Port list you must know cold:**

| Port | Protocol | Port | Protocol |
|---|---|---|---|
| 21 | FTP | 443 | HTTPS / TLS |
| 22 | SSH / SFTP | 445 | SMB |
| 23 | Telnet | 465 | SMTPS |
| 25 | SMTP | 514 | Syslog UDP |
| 53 | DNS | 587 | SMTP Submission |
| 67/68 | DHCP | 636 | LDAPS |
| 69 | TFTP | 993 | IMAPS |
| 80 | HTTP | 995 | POP3S |
| 88 | Kerberos | 1433 | MSSQL |
| 110 | POP3 | 1812 | RADIUS |
| 143 | IMAP | 3306 | MySQL |
| 161/162 | SNMP | 3389 | RDP |
| 389 | LDAP | 5432 | PostgreSQL |



**IPSec — three things to know:**
> **ESP** (Proto 50) = encrypts + authenticates | **AH** (Proto 51) = authenticates only, no encryption | **IKE** = key exchange (IKEv2 preferred)

**WPA — encryption evolution:**
> WEP (RC4, broken) → WPA/TKIP (still RC4, weak) → WPA2/AES-CCMP (current minimum) → WPA3/SAE (current best, forward secrecy)

> WPA3 uses **SAE** (Simultaneous Authentication of Equals) — replaces PSK handshake

**DMARC only works if:**
> SPF *and* DKIM both pass + are aligned *and* policy is 'p=quarantine' or 'p=reject' — 'p=none' = monitoring only, no blocking

**Database quick flags:**
> Redis & MongoDB with no auth = exposed to internet = immediate critical | Memcached on UDP:11211 = massive DDoS amplifier | MSSQL xp_cmdshell = OS command execution from SQL | MySQL port 3306 public = never
