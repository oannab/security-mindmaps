# 🛡️ Security Mind Maps — Open Study Resources

> **One career changer's vault of free, interactive knowledge maps for cybersecurity, networking, and OS fundamentals.** 
I built these because I learn best by seeing how things actually connect, not just by memorizing what they mean.

---

## 🧭 Why This Exists

Most quality study materials are behind a paywall. The free ones rarely show the full picture. 
As a non Computer Science major (or minor) and a career changer, studying on my own, I found that most high-quality resources are locked behind paywalls. I believe education should be free and accessible to everyone, not a socio-economic privilege.

These maps are my attempt to consolidate the "massive pile" of notes I’ve accumulated from various sources. I needed to visualize how things actually connect and where they fit in the broader landscape, not just their definitions.

If you're also starting from zero or switching fields, I hope these help.

⚠️ A Note on Accuracy & Code
This is a work in progress. You might find info that is partially incomplete, slightly off, or just flat-out wrong. I'm open to improvement. If you find an error or want to expand on something, feel free to jump in and refine it.

---

## 🗺️ What's in Here


```

📁 comptia/         → CompTIA Security+ SY0-701 domain maps
📁 os/              → Linux & Windows architecture interactive maps
📁 networking/      → Networking fundamentals, interactive topology & encapsulation apps
📁 general-concepts/→ Core security concepts not tied to any cert

```

---

## 🚀 How to Use the Maps

The `.md` files use **[Markmap](https://markmap.js.org)** syntax — they render as interactive, collapsible mind maps. Zero cost, three ways to use them:

### Option 1 — In Your Browser (No Install)
To view the `.md` files (like the CompTIA maps):
1. Go to **[markmap.js.org/repl](https://markmap.js.org/repl)**
2. Delete the placeholder text on the left
3. Paste the full contents of any `.md` file from this repo
4. The interactive map renders instantly on the right
5. Click any node to expand/collapse — use scroll to zoom, drag to pan

### Option 3 — VS Code Extension (Recommended)
1. Open VS Code
2. Install the **[Markmap extension](https://marketplace.visualstudio.com/items?itemName=gera2ld.markmap-vscode)** by gera2ld (`gera2ld.markmap-vscode`)
3. Open any `.md` file from this repo
4. Press `Ctrl+Shift+P` → type `Markmap: Open as Markmap`
5. The map opens in a live split panel — edits update in real time

> **Tip:** VS Code is better for continous studying — you can have the map open on one side and take notes/ amend / add features on the other.

---

### Alternative Option — View Live Apps & HTML Maps (GitHub Pages)
You can view the interactive React applications and standalone HTML mind maps directly in your browser without any setup! 

**Networking Interactive Apps:**
* **[Network Topology Builder](https://<your-username>.github.io/security-mindmaps/networking/network-topology/dist/)**
* **[Packet Encapsulation Visualiser](https://<your-username>.github.io/security-mindmaps/networking/packet-encapsulation/dist/)**
* **[OSI Protocols Interactive Map](https://<your-username>.github.io/security-mindmaps/networking/osi_protocols_interactive.html)**

**OS Architecture Maps:**
* **[Linux Architecture Map](https://<your-username>.github.io/security-mindmaps/os/linux_architecture_mindmap.html)**

---



## 📚 CompTIA Security+ SY0-701 Maps

These maps cover all 5 domains of the Security+ exam. Each map uses a consistent **8-category colour system** so you always know what type of control or concept you're looking at:

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
| `D1-Threats-Attacks.md` | 1.0 — Threats, Attacks & Vulnerabilities | 🔜 Pending |
| `D2-Cryptography-PKI.md` | 2.0 — Cryptography & PKI | 🔜 Pending |
| `D3-Security-Architecture.md` | 3.0 — Security Architecture | ✅ Available |
| `D4-Security-Operations.md` | 4.0 — Security Operations | ✅ Available |
| `D5-Governance-Risk.md` | 5.0 — Governance, Risk & Compliance | 🔜 Pending |

> These maps are **consolidation tools** — they work best alongside your primary study material, not as a replacement. They're designed to help you see the full picture and retain connections between concepts.

---

## 🖥️ OS Architecture Maps

Platform-level deep dives — how Linux and Windows actually work under the hood. Not cert-specific, these stay relevant regardless of what you're studying or working on.

| File | Description |
|------|-------------|
| `linux-architecture.md` | Kernel, syscalls, filesystem hierarchy, process model, networking stack |
| `windows-architecture.md` | NT kernel, registry, Active Directory integration, Win32 subsystem |

---

## 🤝 Contributing

Found an error? Want to add a section? See [CONTRIBUTING.md](./CONTRIBUTING.md).

The maps are only as accurate as the people reviewing them — if you spot something wrong or outdated, a PR or Issue is very welcome.

---

## 📄 Licence

**[Creative Commons Attribution 4.0 (CC BY 4.0)](./LICENSE)** Use freely, share freely, adapt freely — just credit the source.

---

## ⭐ If This Helped You

Star the repo — it helps other learners find it. That's the whole point.