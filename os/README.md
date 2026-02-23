# 🖥️ OS Architecture Maps

Platform-level architecture maps for Linux and Windows. These are not cert-specific.

## Maps

| File | Description | Status |
|------|-------------|--------|
| `linux-architecture_mindmap.md` | Kernel, syscalls, filesystem hierarchy, process model, permissions, networking stack | ✅ Available |
| `windows-architecture.md` | NT kernel, Win32 subsystem, registry, services, Active Directory integration | ✅ Available |

## Why These Matter for Security

These maps were built to help understand the foundation for interpreting system behavior:
- Malware Analysis: Identifying where a process injects code (e.g., /proc/pid/mem in Linux or Object Handles in Windows). 
- Telemetry & Logs: Making sense of EDR output, Auditd events, or Windows Event Logs.
- Privilege Escalation: Understanding how attackers move from $Ring$ $3$ to $Ring$ $0$ through $Syscall$ vulnerabilities.
- Hardening: Implementing CIS Benchmarks by understanding what a specific registry key or sysctl parameter actually changes.

## How to Render

Open in any modern web browser
Interact:
- Windows: Use the "Expand All" button to see the full NT stack at once.
- Linux: Click on the 📁 FILESYSTEM PATHS section in the side panel to explore directory structures.

