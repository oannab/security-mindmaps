# 📦 Packet Encapsulation — Interactive OSI Walkthrough

An interactive React diagram showing how data is encapsulated as it travels *down* the OSI stack from sender to wire, and de-encapsulated as it travels *up* the stack on the receiver side. Each layer adds (or strips) its own header, trailer, and metadata.

Built with React + Vite. Runs entirely in the browser, no backend needed.

> **No-install option:** open `osi-encapsulation.html` directly in your browser — no Node or npm required.

---

## What it covers

| OSI Layer | PDU Name | What gets added |
|-----------|----------|-----------------|
| 7 — Application | Data | Raw payload from the application |
| 4 — Transport | Segment | TCP/UDP header — ports, sequence numbers |
| 3 — Network | Packet | IP header — source & destination IP |
| 2 — Data Link | Frame | MAC header + trailer — local delivery + error check |
| 1 — Physical | Bits | Electrical/optical signal on the wire |

---

## Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Node.js | v18+ | `node -v` |
| npm | comes with Node | `npm -v` |

Download Node from [nodejs.org](https://nodejs.org) if you don't have it.

---

## Quick Start

### 1. Create a new Vite + React project

```bash
npm create vite@latest my-encapsulation -- --template react
cd my-encapsulation
```

### 2. Install dependencies

```bash
npm install
```

### 3. Add the component

Copy `packet_encapsulation.jsx` into the `src/` folder, then open `src/App.jsx` and replace everything with:

```jsx
import PacketEncapsulation from './packet_encapsulation.jsx'

export default function App() {
  return <PacketEncapsulation />
}
```

### 4. Run it

```bash
npm run dev
```

Open your browser at `http://localhost:5173`.

---

## Project Structure

```
packet-encapsulation/
├── src/
│   ├── App.jsx                    ← entry point (edit this)
│   ├── packet_encapsulation.jsx   ← main interactive component
│   ├── main.jsx
│   └── index.css
├── osi-encapsulation.html         ← static version, no setup needed
├── index.html
├── vite.config.js
└── package.json
```

---

## Part of

This tool lives inside [`networking/`](../) in the [security-mindmaps](../../) repo.  
See also: [`network-topology/`](../network-topology/) for the network topology diagram.
