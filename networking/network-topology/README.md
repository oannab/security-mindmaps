# 🖧 Network Topology — Interactive Diagram

An interactive React diagram visualising common network topology.

Built with React + Vite. Runs entirely in the browser, no backend needed.

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
npm create vite@latest my-topology -- --template react
cd my-topology
```

### 2. Install dependencies

```bash
npm install
```

### 3. Add the component

Copy `network_topology.jsx` into the `src/` folder, then open `src/App.jsx` and replace everything with:

```jsx
import NetworkTopology from './network_topology.jsx'

export default function App() {
  return <NetworkTopology />
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
network-topology/
├── src/
│   ├── App.jsx               ← entry point (edit this)
│   ├── network_topology.jsx  ← main interactive component
│   ├── main.jsx
│   └── index.css
├── index.html
├── vite.config.js
└── package.json
```

---

## Part of

This tool lives inside [`networking/`](../) in the [security-mindmaps](../../) repo.  
See also: [`packet-encapsulation/`](../packet-encapsulation/) for the OSI encapsulation walkthrough.
