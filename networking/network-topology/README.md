# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Babel](https://babeljs.io/) (or [oxc](https://oxc.rs) when used in [rolldown-vite](https://vite.dev/guide/rolldown)) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.



# What you need installed first

- Node.js (v18+) — download from nodejs.org
- npm (comes with Node)

Check you have them: ```node -v``` and ```npm -v``` in your terminal.

# Steps

### 1. Create a new Vite + React project

```
npm create vite@latest my-topology -- --template react
cd my-topology
```

### 2. Install dependencies

```
npm install
```

### 3. Replace default code

Copy network_topology.jsx into the src/ folder, then open src/App.jsx and replace everything in it with:

```
import NetworkTopology from './network_topology.jsx'

export default function App() {
  return <NetworkTopology />
}
```

### 4. Run it

Copy network_topology.jsx into the src/ folder, then open src/App.jsx and replace everything in it with:

```
npm run dev
```