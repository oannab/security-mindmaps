# 🛡️ Security Mind Maps — Open Study Resources

> **One career changer's vault of free, interactive knowledge maps for cybersecurity, networking, and OS fundamentals.**  
> I built these because I learn best by seeing how things actually connect, not just by memorising what they mean.

---

## 🧭 Why This Exists

Most quality study materials are behind a paywall. The free ones rarely show the full picture.

As a non-CS major and career changer studying independently, I found that high-quality resources are consistently locked behind paywalls. I believe education should be free and accessible — not a socio-economic privilege.

These maps are my attempt to consolidate the notes I've accumulated from various sources into something visual and holistic. If you're starting from zero or switching fields, I hope these help.

> ⚠️ **Work in progress.** You might find content that's partially incomplete, slightly off, or just flat-out wrong. If you find an error or want to expand on something, jump in — see [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## 🗺️ What's in Here

```
📁 comptia/          → CompTIA Security+ SY0-701 domain maps
📁 os/               → Linux & Windows architecture interactive maps
📁 networking/       → Networking fundamentals, topology & encapsulation apps
📁 general-concepts/ → Core security concepts not tied to any cert [coming soon]
```

---

## 🚀 How to Use the Maps

The `.md` files use **[Markmap](https://markmap.js.org)** syntax — they render as interactive, collapsible mind maps. Zero cost, three ways to use them:

### Option 1 — In Your Browser (No Install)

1. Go to **[markmap.js.org/repl](https://markmap.js.org/repl)**
2. Delete the placeholder text on the left
3. Paste the full contents of any `.md` file from this repo
4. The interactive map renders instantly on the right
5. Click any node to expand/collapse — scroll to zoom, drag to pan

### Option 2 — Open the Static HTML Files Directly

Every map ships with a pre-built `.html` file. No Node, no terminal, no setup — just open the file in your browser.

| File | What it shows |
|------|--------------|
| `comptia/D3-Security-Architecture.html` | Security Architecture domain map |
| `comptia/D4-Security-Operations.html` | Security Operations domain map |
| `os/linux_architecture_mindmap.html` | Linux architecture deep dive |
| `networking/protocols_osi.html` | OSI protocols reference |

### Option 3 — VS Code Extension (Recommended for Studying)

1. Open VS Code
2. Install the **[Markmap extension](https://marketplace.visualstudio.com/items?itemName=gera2ld.markmap-vscode)** (`gera2ld.markmap-vscode`)
3. Open any `.md` file from this repo
4. Press `Ctrl+Shift+P` → type `Markmap: Open as Markmap`
5. The map opens in a live split panel — edits update in real time

> **Tip:** VS Code is better for continuous studying — map open on one side, notes on the other.

---

### ☁️ Alternative — View Live via GitHub Pages

The interactive React apps and standalone HTML maps are also hosted live. No cloning or setup required — open in any browser:

**Networking Interactive Apps:**
- [Network Topology Builder](https://your-username.github.io/security-mindmaps/networking/network-topology/dist/)
- [Packet Encapsulation Visualiser](https://your-username.github.io/security-mindmaps/networking/packet-encapsulation/dist/)
- [OSI Protocols Interactive Map](https://your-username.github.io/security-mindmaps/networking/protocols_osi.html)

**OS Architecture Maps:**
- [Linux Architecture Map](https://your-username.github.io/security-mindmaps/os/linux_architecture_mindmap.html)

> Replace `your-username` with your actual GitHub username, or update these links once GitHub Pages is configured.

---

## 📚 CompTIA Security+ SY0-701 Maps

These maps cover all 5 domains of the Security+ exam. Each uses a consistent **8-category colour system** so you always know what type of control or concept you're looking at:

| Colour | Category | Examples |
|--------|----------|---------|
| 🟠 Orange | 🗄️ Hardware | Servers, TPM, HSM, RFID, sensors |
| 🟤 Brown | 🪪 Physical | Guards, CCTV, shredding, facilities |
| 🔵 Light Blue | 🚀 Software | SIEM, SOAR, EDR, AV, DLP, MDM |
| 🟣 Indigo | 🌐 Network | VLANs, DMZ, SD-WAN, Zero Trust, SASE |
| 🟣 Lavender | 🔗 Protocols | TLS, SSH, SAML, OAuth, Kerberos, DKIM |
| 🟢 Green | 📋 Governance | Policy, compliance, CVSS, CVE, classification |
| 🩵 Cyan | ☁️ Cloud | CASB, cloud-native tools, SaaS/IaaS/PaaS |
| 🔴 Pink-Red | 🛠️ Methods | Hashing, sandboxing, patching, code signing |

### Domain Coverage

| File | Domain | Status |
|------|--------|--------|
| `D1-.md` | 1.0 — General Security Concepts | 🔜 Pending |
| `D2-ThreatVulnMitigation.md` | 2.0 — Threat, Vulnerabilities, Mitigation | ✅ Available |
| `D3-Security-Architecture.md` | 3.0 — Security Architecture | ✅ Available |
| `D4-Security-Operations.md` | 4.0 — Security Operations | ✅ Available |
| `D5-.md` | 5.0 — Security, Program Management & Oversight | 🔜 Pending |

> These maps are **consolidation tools** — they work best alongside your primary study material, not as a replacement. They're designed to help you see the full picture and retain connections between concepts.

---

## 🌐 Networking Maps

Interactive tools for core networking fundamentals — built as React apps with static HTML fallbacks.

| Tool | Description | Status |
|------|-------------|--------|
| `network-topology/` | Common topologies — star, mesh, bus, ring, hybrid | ✅ Available |
| `packet-encapsulation/` | OSI encapsulation walkthrough layer by layer | ✅ Available |
| `protocols_osi.html` | OSI protocols standalone reference | ✅ Available |

---

## 🖥️ OS Architecture Maps

Platform-level deep dives into how Linux and Windows actually work under the hood. Not cert-specific — these stay relevant regardless of what you're studying or working on.

| File | Description | Status |
|------|-------------|--------|
| `linux_architecture_mindmap.html` | Kernel, syscalls, filesystem hierarchy, process model, networking stack | ✅ Available |
| `windows-architecture` | NT kernel, registry, Active Directory, Win32 subsystem | 🔜 Pending |

---

## 🤝 Contributing

Found an error? Want to add a section? See [CONTRIBUTING.md](./CONTRIBUTING.md).

The maps are only as accurate as the people reviewing them — if you spot something wrong or outdated, a PR or Issue is very welcome.

---

## 📄 Licence

**[Creative Commons Attribution 4.0 (CC BY 4.0)](./LICENSE)** — use freely, share freely, adapt freely. Just credit the source.

---

## ⭐ If This Helped You

Star the repo — it helps other learners find it. That's the whole point.
