# 🌐 Networking

Interactive visual tools and reference maps covering core networking concepts — OSI model, network topology, packet encapsulation, and protocols. Built for learners coming from non-CS backgrounds who need to *see* how things connect, not just read definitions.

All tools run in the browser. Most have a zero-install static HTML version alongside the interactive React build.

---

## What's in here

### [`network-topology/`](./network-topology/)
Interactive React diagram of common network topology. Shows device relationships, traffic flow, and failure impact per topology type.

→ [OSI Protocols reference](./protocols_osi.html) — standalone static file, open directly in browser.

### [`packet-encapsulation/`](./packet-encapsulation/)
Interactive React diagram walking through how data gets wrapped and unwrapped as it travels down and up the OSI stack — from application payload to physical bits and back. Includes a static `.html` version.

---

## No-install option

Every tool in this section ships with a pre-built `.html` file. If you don't want to deal with Node or npm, just open the HTML file directly in your browser — no setup, no terminal.

| File | What it shows |
|------|--------------|
| `network-topology/osi-encapsulation.html` | Network topology interactive view |
| `networking/protocols_osi.html` | OSI layer protocols reference |
| `packet-encapsulation/osi-encapsulation.html` | Packet encapsulation walkthrough |

---

## Part of

This section is part of the [security-mindmaps](../) repo — free, open study materials for anyone breaking into cybersecurity, networking, or IT from a non-traditional background.
