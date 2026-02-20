import { useState, useRef, useCallback, useEffect } from "react";

const ZONES = [
  {
    id: "internet", label: "INTERNET", sublabel: "External / Public",
    x: 620, y: 20, w: 260, h: 70, color: "#ef4444", tier: "external",
    devices: [
      { id: "isp", label: "ISP Dual WAN", icon: "🌐", sub: "1Gbps + 500Mbps failover" },
    ],
    collapsed: false,
  },
  {
    id: "dmz", label: "DMZ — VLAN 10", sublabel: "10.0.10.0/24",
    x: 440, y: 150, w: 620, h: 120, color: "#f97316", tier: "perimeter",
    devices: [
      { id: "edge_fw", label: "Edge Firewall", icon: "🔥", sub: "Palo Alto PA-3260 / FortiGate 600E" },
      { id: "waf", label: "WAF", icon: "🛡️", sub: "Cloudflare / F5 BIG-IP ASM" },
      { id: "vpn_gw", label: "VPN Gateway", icon: "🔑", sub: "Cisco AnyConnect / GlobalProtect" },
      { id: "email_gw", label: "Email Gateway", icon: "📧", sub: "Proofpoint / Mimecast" },
    ],
    collapsed: false,
  },
  {
    id: "core", label: "CORE NETWORK — VLAN 1  /  Management", sublabel: "10.0.1.0/24",
    x: 260, y: 330, w: 980, h: 130, color: "#eab308", tier: "core",
    devices: [
      { id: "core_sw", label: "Core Switch L3", icon: "⚡", sub: "Cisco Catalyst 9500 / Arista 7050SX" },
      { id: "int_fw", label: "Internal Firewall", icon: "🔥", sub: "FortiGate 400E / Cisco Firepower 2130" },
      { id: "dist_sw", label: "Distribution Switches ×4", icon: "🔀", sub: "Cisco Catalyst 9300 — 802.1X / DAI" },
      { id: "nac", label: "NAC", icon: "🔐", sub: "Cisco ISE / Aruba ClearPass — 10.0.1.10" },
      { id: "wlc", label: "Wireless Controller", icon: "📡", sub: "Cisco WLC 9800 / Aruba 7200 — 10.0.1.20" },
      { id: "npm", label: "NPM / NetFlow", icon: "📊", sub: "SolarWinds / PRTG — 10.0.1.30 / .35" },
    ],
    collapsed: false,
  },
  {
    id: "soc", label: "SOC — VLAN 25", sublabel: "10.0.25.0/24  |  Security Operations",
    x: 20, y: 530, w: 380, h: 200, color: "#a855f7", tier: "security",
    devices: [
      { id: "siem", label: "SIEM", icon: "🧠", sub: "Splunk / QRadar / Sentinel — 10.0.25.10" },
      { id: "soar", label: "SOAR", icon: "⚙️", sub: "Cortex XSOAR / Splunk SOAR — 10.0.25.15" },
      { id: "ids_int", label: "IDS Sensors ×3", icon: "👁️", sub: "Zeek / Suricata — 10.0.25.20–22" },
      { id: "pcap", label: "PCAP / Arkime", icon: "🔬", sub: "Full packet capture — 10.0.25.25" },
      { id: "edr_con", label: "EDR Console", icon: "💻", sub: "CrowdStrike / Defender — 10.0.25.30" },
      { id: "ueba", label: "UEBA", icon: "📈", sub: "Splunk UBA / Varonis — 10.0.25.35" },
    ],
    collapsed: false,
  },
  {
    id: "it", label: "IT DEPT — VLAN 20", sublabel: "10.0.20.0/24",
    x: 420, y: 530, w: 300, h: 200, color: "#3b82f6", tier: "privileged",
    devices: [
      { id: "it_ws", label: "Admin Workstations ×10", icon: "🖥️", sub: "Dell Precision / MacBook Pro" },
      { id: "vuln", label: "Vuln Scanner", icon: "🔍", sub: "Nessus / Qualys — 10.0.20.70" },
      { id: "dns_filter", label: "DNS Filter", icon: "🌍", sub: "Cisco Umbrella / Infoblox — 10.0.20.75" },
      { id: "cfg_mgmt", label: "Config Mgmt", icon: "🗂️", sub: "Oxidized / Ansible / GitLab — 10.0.20.80" },
    ],
    collapsed: false,
  },
  {
    id: "jump", label: "JUMP / BASTION — VLAN 55", sublabel: "10.0.55.0/28  |  Privileged Access Gateway",
    x: 740, y: 530, w: 340, h: 200, color: "#ec4899", tier: "bastion",
    devices: [
      { id: "jump1", label: "Jump Server 1+2", icon: "🔏", sub: "JUMP01/02 — 10.0.55.2/3 (Prod)" },
      { id: "jump3", label: "Jump Server 3", icon: "🔏", sub: "JUMP03 — 10.0.55.4 (Dev access)" },
      { id: "pam", label: "PAM Vault", icon: "🗝️", sub: "CyberArk PSM / BeyondTrust — 10.0.55.5" },
      { id: "sess_rec", label: "Session Recorder", icon: "🎞️", sub: "CyberArk / Securonix — 10.0.55.6" },
    ],
    collapsed: false,
  },
  {
    id: "finance", label: "FINANCE — VLAN 30", sublabel: "10.0.30.0/24",
    x: 20, y: 800, w: 220, h: 130, color: "#10b981", tier: "user",
    devices: [
      { id: "fin_ws", label: "Workstations ×25", icon: "🖥️", sub: "Dell OptiPlex" },
      { id: "fin_lap", label: "Laptops ×5", icon: "💻", sub: "Dell Latitude" },
    ],
    collapsed: false,
  },
  {
    id: "hr", label: "HR — VLAN 40", sublabel: "10.0.40.0/24",
    x: 260, y: 800, w: 200, h: 130, color: "#10b981", tier: "user",
    devices: [
      { id: "hr_ws", label: "Workstations ×15", icon: "🖥️", sub: "Dell OptiPlex" },
      { id: "hr_lap", label: "Laptops ×3", icon: "💻", sub: "Dell Latitude" },
    ],
    collapsed: false,
  },
  {
    id: "employees", label: "EMPLOYEES — VLAN 50", sublabel: "10.0.50.0/24",
    x: 480, y: 800, w: 240, h: 130, color: "#10b981", tier: "user",
    devices: [
      { id: "emp_ws", label: "Workstations ×150", icon: "🖥️", sub: "Dell OptiPlex / iMac" },
      { id: "emp_lap", label: "Laptops ×100", icon: "💻", sub: "Dell Latitude / MacBook" },
      { id: "emp_tab", label: "Tablets ×20", icon: "📱", sub: "iPad Pro (MDM enrolled)" },
    ],
    collapsed: false,
  },
  {
    id: "voip", label: "VoIP — VLAN 80", sublabel: "10.0.80.0/24",
    x: 740, y: 800, w: 180, h: 130, color: "#06b6d4", tier: "utility",
    devices: [
      { id: "phones", label: "IP Phones", icon: "📞", sub: "Cisco IP Phones" },
      { id: "pbx", label: "PBX Server", icon: "📟", sub: "Asterisk / Cisco UCM" },
    ],
    collapsed: false,
  },
  {
    id: "iot", label: "IoT/Print — VLAN 90", sublabel: "10.0.90.0/24",
    x: 940, y: 800, w: 200, h: 130, color: "#06b6d4", tier: "utility",
    devices: [
      { id: "printers", label: "MFP Printers ×10", icon: "🖨️", sub: "HP LaserJet Enterprise" },
      { id: "cameras", label: "IP Cameras", icon: "📷", sub: "Security cameras / sensors" },
    ],
    collapsed: false,
  },
  {
    id: "prod_srv", label: "PROD SERVERS — VLAN 60", sublabel: "10.0.60.0/24  |  Access via VLAN 55 only",
    x: 20, y: 1000, w: 560, h: 160, color: "#f59e0b", tier: "server",
    devices: [
      { id: "dc", label: "Domain Controllers", icon: "🏛️", sub: "DC01/DC02 — 10.0.60.10/11 (AD DS, DNS)" },
      { id: "sql", label: "DB Server", icon: "🗄️", sub: "SQL01 — 10.0.60.30 (SQL Server)" },
      { id: "app_srv", label: "App Servers ×2", icon: "⚙️", sub: "APP01/02 — 10.0.60.40/41" },
      { id: "file_srv", label: "File Server", icon: "📁", sub: "FS01 — 10.0.60.20 (DFS)" },
      { id: "exch", label: "Email Server", icon: "📬", sub: "EXCH01 — 10.0.60.50 (Exchange)" },
      { id: "backup", label: "Backup Server", icon: "💾", sub: "BKP01 — 10.0.60.70 (Veeam)" },
    ],
    collapsed: false,
  },
  {
    id: "dev_srv", label: "DEV SERVERS — VLAN 70", sublabel: "10.0.70.0/24  |  Access via JUMP03",
    x: 600, y: 1000, w: 340, h: 160, color: "#f59e0b", tier: "server",
    devices: [
      { id: "dev_web", label: "Dev Web Server", icon: "🌐", sub: "DEVWEB01 — 10.0.70.10" },
      { id: "dev_db", label: "Dev Database", icon: "🗄️", sub: "DEVSQL01 — 10.0.70.20" },
      { id: "cicd", label: "CI/CD Server", icon: "🔄", sub: "JENKINS01 — 10.0.70.30" },
    ],
    collapsed: false,
  },
  {
    id: "guest", label: "GUEST — VLAN 100", sublabel: "10.0.100.0/24  |  Internet only",
    x: 20, y: 1220, w: 220, h: 110, color: "#6b7280", tier: "untrusted",
    devices: [
      { id: "guest_dev", label: "Guest Devices", icon: "📱", sub: "Visitor smartphones/laptops" },
    ],
    collapsed: false,
  },
  {
    id: "byod_e", label: "BYOD ENROLLED — VLAN 110", sublabel: "10.0.110.0/24  |  MDM required",
    x: 260, y: 1220, w: 260, h: 110, color: "#6b7280", tier: "untrusted",
    devices: [
      { id: "byod_phones", label: "Personal Phones 300+", icon: "📱", sub: "iPhone / Samsung (MDM enrolled)" },
      { id: "byod_lap", label: "Personal Laptops 50+", icon: "💻", sub: "Intune / Workspace ONE managed" },
    ],
    collapsed: false,
  },
  {
    id: "byod_r", label: "BYOD RESTRICTED — VLAN 120", sublabel: "10.0.120.0/24  |  Internet only",
    x: 540, y: 1220, w: 260, h: 110, color: "#6b7280", tier: "untrusted",
    devices: [
      { id: "byod_unman", label: "Unmanaged Devices 80+", icon: "📱", sub: "Personal devices — DNS filtered" },
    ],
    collapsed: false,
  },
];

const CONNECTIONS = [
  { from: "internet", to: "dmz", label: "Dual WAN" },
  { from: "dmz", to: "core", label: "Filtered traffic" },
  { from: "core", to: "soc", label: "SPAN / Syslog" },
  { from: "core", to: "it", label: "Admin access" },
  { from: "core", to: "jump", label: "Brokered sessions" },
  { from: "core", to: "finance", label: "VLAN trunk" },
  { from: "core", to: "hr", label: "VLAN trunk" },
  { from: "core", to: "employees", label: "VLAN trunk" },
  { from: "core", to: "voip", label: "QoS VLAN" },
  { from: "core", to: "iot", label: "Isolated VLAN" },
  { from: "jump", to: "prod_srv", label: "PAM-brokered only" },
  { from: "jump", to: "dev_srv", label: "JUMP03 only" },
  { from: "core", to: "guest", label: "VLAN trunk" },
  { from: "core", to: "byod_e", label: "VLAN trunk" },
  { from: "core", to: "byod_r", label: "VLAN trunk" },
];

const TIER_LABELS = {
  external: "External",
  perimeter: "Perimeter",
  core: "Core / Management",
  security: "Security Ops",
  privileged: "Privileged IT",
  bastion: "Bastion / PAM",
  user: "User VLANs",
  utility: "Utility VLANs",
  server: "Server VLANs",
  untrusted: "Untrusted / BYOD",
};

const TIER_COLORS = {
  external: "#ef4444",
  perimeter: "#f97316",
  core: "#eab308",
  security: "#a855f7",
  privileged: "#3b82f6",
  bastion: "#ec4899",
  user: "#10b981",
  utility: "#06b6d4",
  server: "#f59e0b",
  untrusted: "#6b7280",
};

function getZoneCenter(zone) {
  return { x: zone.x + zone.w / 2, y: zone.y + (zone.collapsed ? 30 : zone.h / 2) };
}

export default function NetworkTopology() {
  const [zones, setZones] = useState(ZONES);
  const [tooltip, setTooltip] = useState(null);
  const [selected, setSelected] = useState(null);
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 0.62 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState(null);
  const [filter, setFilter] = useState("all");
  const svgRef = useRef(null);
  const CANVAS_W = 1160;
  const CANVAS_H = 1380;

  const toggleZone = useCallback((id) => {
    setZones(prev => prev.map(z => z.id === id ? { ...z, collapsed: !z.collapsed } : z));
    setSelected(id);
  }, []);

  const handleMouseDown = (e) => {
    if (e.target === svgRef.current || e.target.closest(".pan-target")) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y });
    }
  };

  const handleMouseMove = (e) => {
    if (isDragging && dragStart) {
      setTransform(t => ({ ...t, x: e.clientX - dragStart.x, y: e.clientY - dragStart.y }));
    }
    if (tooltip) {
      setTooltip(prev => ({ ...prev, mx: e.clientX, my: e.clientY }));
    }
  };

  const handleMouseUp = () => { setIsDragging(false); setDragStart(null); };

  const handleWheel = (e) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setTransform(t => ({ ...t, scale: Math.min(2, Math.max(0.25, t.scale * delta)) }));
  };

  useEffect(() => {
    const el = document.getElementById("topo-wrapper");
    if (el) el.addEventListener("wheel", handleWheel, { passive: false });
    return () => { if (el) el.removeEventListener("wheel", handleWheel); };
  }, []);

  const filteredZones = filter === "all" ? zones : zones.filter(z => z.tier === filter || z.id === "core" || z.id === "dmz" || z.id === "internet");

  const visibleIds = new Set(filteredZones.map(z => z.id));
  const visibleConns = CONNECTIONS.filter(c => visibleIds.has(c.from) && visibleIds.has(c.to));

  const allDevices = zones.flatMap(z => (z.devices || []).map(d => ({ ...d, zoneTier: z.tier, zoneColor: z.color, zoneName: z.label })));
  const selectedZone = zones.find(z => z.id === selected);

  return (
    <div style={{ background: "#050811", minHeight: "100vh", fontFamily: "'JetBrains Mono', 'Courier New', monospace", color: "#e2e8f0", display: "flex", flexDirection: "column" }}>
      {/* Header */}
      <div style={{ padding: "14px 24px", borderBottom: "1px solid #1e2d47", background: "rgba(5,8,17,0.97)", display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap", zIndex: 100 }}>
        <div>
          <div style={{ fontSize: 13, letterSpacing: 4, color: "#a855f7", textTransform: "uppercase" }}>Network Topology</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: "#f1f5f9", letterSpacing: 1 }}>Enterprise Office — VLAN/WLAN Architecture</div>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontSize: 11, color: "#64748b", marginRight: 4 }}>FILTER:</span>
          {["all", ...Object.keys(TIER_COLORS)].map(tier => (
            <button key={tier} onClick={() => setFilter(tier)} style={{
              padding: "4px 10px", fontSize: 10, border: `1px solid ${filter === tier ? TIER_COLORS[tier] || "#a855f7" : "#1e2d47"}`,
              background: filter === tier ? `${TIER_COLORS[tier] || "#a855f7"}22` : "transparent",
              color: filter === tier ? (TIER_COLORS[tier] || "#a855f7") : "#64748b",
              borderRadius: 4, cursor: "pointer", textTransform: "uppercase", letterSpacing: 1,
            }}>
              {tier === "all" ? "All" : (TIER_LABELS[tier] || tier)}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* Main canvas */}
        <div id="topo-wrapper" style={{ flex: 1, overflow: "hidden", cursor: isDragging ? "grabbing" : "grab", position: "relative" }}
          onMouseDown={handleMouseDown} onMouseMove={handleMouseMove} onMouseUp={handleMouseUp} onMouseLeave={handleMouseUp}>
          <svg ref={svgRef} width="100%" height="100%" style={{ display: "block" }}>
            <defs>
              <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0,0 L0,6 L8,3 z" fill="#334155" />
              </marker>
              <marker id="arrow-jump" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0,0 L0,6 L8,3 z" fill="#ec4899" />
              </marker>
              <filter id="glow">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
              <filter id="softglow">
                <feGaussianBlur stdDeviation="6" result="blur" />
                <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            </defs>

            <g transform={`translate(${transform.x},${transform.y}) scale(${transform.scale})`}>
              {/* Grid */}
              <rect x={0} y={0} width={CANVAS_W} height={CANVAS_H} fill="none" />
              {Array.from({ length: 60 }).map((_, i) => (
                <line key={`v${i}`} x1={i * 20} y1={0} x2={i * 20} y2={CANVAS_H} stroke="#0f172a" strokeWidth={1} />
              ))}
              {Array.from({ length: 70 }).map((_, i) => (
                <line key={`h${i}`} x1={0} y1={i * 20} x2={CANVAS_W} y2={i * 20} stroke="#0f172a" strokeWidth={1} />
              ))}

              {/* Connections */}
              {visibleConns.map((conn, i) => {
                const fromZ = zones.find(z => z.id === conn.from);
                const toZ = zones.find(z => z.id === conn.to);
                if (!fromZ || !toZ) return null;
                const fc = getZoneCenter(fromZ);
                const tc = getZoneCenter(toZ);
                const isJump = conn.label.includes("PAM") || conn.label.includes("JUMP");
                const mx = (fc.x + tc.x) / 2;
                const my = (fc.y + tc.y) / 2;
                return (
                  <g key={i}>
                    <line x1={fc.x} y1={fc.y} x2={tc.x} y2={tc.y}
                      stroke={isJump ? "#ec498944" : "#1e3a5f"}
                      strokeWidth={isJump ? 2 : 1}
                      strokeDasharray={isJump ? "6 3" : "4 4"}
                      markerEnd={`url(#arrow${isJump ? "-jump" : ""})`}
                    />
                    <rect x={mx - 42} y={my - 8} width={84} height={16} rx={4} fill="#050811" opacity={0.85} />
                    <text x={mx} y={my + 4} textAnchor="middle" fill={isJump ? "#ec4899" : "#334155"} fontSize={9} fontFamily="monospace">{conn.label}</text>
                  </g>
                );
              })}

              {/* Zones */}
              {filteredZones.map(zone => {
                const h = zone.collapsed ? 44 : zone.h;
                const isSelected = selected === zone.id;
                return (
                  <g key={zone.id} className="pan-target"
                    style={{ cursor: "pointer" }}
                    onClick={(e) => { e.stopPropagation(); toggleZone(zone.id); }}>

                    {/* Zone glow */}
                    {isSelected && <rect x={zone.x - 4} y={zone.y - 4} width={zone.w + 8} height={h + 8} rx={14} fill={zone.color} opacity={0.07} filter="url(#softglow)" />}

                    {/* Zone body */}
                    <rect x={zone.x} y={zone.y} width={zone.w} height={h} rx={10}
                      fill={`${zone.color}0d`}
                      stroke={isSelected ? zone.color : `${zone.color}55`}
                      strokeWidth={isSelected ? 1.5 : 1}
                    />

                    {/* Zone header bar */}
                    <rect x={zone.x} y={zone.y} width={zone.w} height={32} rx={10} fill={`${zone.color}22`} />
                    <rect x={zone.x} y={zone.y + 22} width={zone.w} height={10} fill={`${zone.color}22`} />

                    {/* Tier badge */}
                    <rect x={zone.x + 8} y={zone.y + 8} width={8} height={8} rx={2} fill={zone.color} />

                    {/* Zone label */}
                    <text x={zone.x + 22} y={zone.y + 19} fill={zone.color} fontSize={11} fontWeight={700} fontFamily="monospace" letterSpacing={0.5}>{zone.label}</text>

                    {/* Sublabel */}
                    {!zone.collapsed && (
                      <text x={zone.x + 10} y={zone.y + 42} fill={`${zone.color}88`} fontSize={9} fontFamily="monospace">{zone.sublabel}</text>
                    )}

                    {/* Collapse toggle */}
                    <text x={zone.x + zone.w - 16} y={zone.y + 19} fill={zone.color} fontSize={12} textAnchor="middle" fontWeight={700}>
                      {zone.collapsed ? "+" : "−"}
                    </text>

                    {/* Devices */}
                    {!zone.collapsed && (zone.devices || []).map((dev, di) => {
                      const cols = Math.ceil(zone.w / 155);
                      const col = di % cols;
                      const row = Math.floor(di / cols);
                      const dx = zone.x + 12 + col * 150;
                      const dy = zone.y + 54 + row * 52;
                      return (
                        <g key={dev.id}
                          onMouseEnter={(e) => { e.stopPropagation(); setTooltip({ ...dev, mx: e.clientX, my: e.clientY, color: zone.color }); }}
                          onMouseLeave={() => setTooltip(null)}
                          onClick={(e) => e.stopPropagation()}
                          style={{ cursor: "default" }}>
                          <rect x={dx} y={dy} width={138} height={44} rx={6}
                            fill={`${zone.color}12`} stroke={`${zone.color}33`} strokeWidth={1} />
                          <text x={dx + 10} y={dy + 16} fontSize={14}>{dev.icon}</text>
                          <text x={dx + 30} y={dy + 15} fill="#e2e8f0" fontSize={9.5} fontWeight={600} fontFamily="monospace">{dev.label}</text>
                          <text x={dx + 30} y={dy + 27} fill="#64748b" fontSize={8} fontFamily="monospace"
                            style={{ maxWidth: 100 }}>{dev.sub.length > 28 ? dev.sub.slice(0, 28) + "…" : dev.sub}</text>
                        </g>
                      );
                    })}
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Tooltip */}
          {tooltip && (
            <div style={{
              position: "fixed", left: tooltip.mx + 14, top: tooltip.my - 10, zIndex: 9999,
              background: "#0f172a", border: `1px solid ${tooltip.color}66`,
              borderLeft: `3px solid ${tooltip.color}`,
              padding: "10px 14px", borderRadius: 8, maxWidth: 280, pointerEvents: "none",
              boxShadow: `0 0 20px ${tooltip.color}22`,
            }}>
              <div style={{ color: tooltip.color, fontSize: 13, fontWeight: 700 }}>{tooltip.icon} {tooltip.label}</div>
              <div style={{ color: "#94a3b8", fontSize: 11, marginTop: 4 }}>{tooltip.sub}</div>
              {tooltip.zoneName && <div style={{ color: "#475569", fontSize: 10, marginTop: 6, borderTop: "1px solid #1e293b", paddingTop: 4 }}>Zone: {tooltip.zoneName}</div>}
            </div>
          )}

          {/* Controls hint */}
          <div style={{ position: "absolute", bottom: 16, right: 16, background: "#0f172a99", border: "1px solid #1e2d47", borderRadius: 8, padding: "8px 12px", fontSize: 10, color: "#475569", lineHeight: 1.6 }}>
            <div>🖱 Drag to pan</div>
            <div>⚲ Scroll to zoom</div>
            <div>Click zone to expand/collapse</div>
            <div>Hover device for details</div>
          </div>

          {/* Zoom controls */}
          <div style={{ position: "absolute", bottom: 16, left: 16, display: "flex", flexDirection: "column", gap: 4 }}>
            {[["＋", 1.2], ["−", 0.8], ["⌂", null]].map(([label, factor]) => (
              <button key={label} onClick={() => {
                if (factor) setTransform(t => ({ ...t, scale: Math.min(2, Math.max(0.25, t.scale * factor)) }));
                else setTransform({ x: 0, y: 0, scale: 0.62 });
              }} style={{
                width: 32, height: 32, background: "#0f172a", border: "1px solid #1e2d47",
                color: "#94a3b8", borderRadius: 6, cursor: "pointer", fontSize: 16, display: "flex", alignItems: "center", justifyContent: "center"
              }}>{label}</button>
            ))}
          </div>
        </div>

        {/* Side panel */}
        <div style={{ width: 280, borderLeft: "1px solid #1e2d47", background: "#07101f", overflowY: "auto", padding: "16px", display: "flex", flexDirection: "column", gap: 16 }}>

          {/* Selected Zone Info */}
          {selectedZone ? (
            <div>
              <div style={{ fontSize: 10, letterSpacing: 3, color: "#475569", marginBottom: 8, textTransform: "uppercase" }}>Selected Zone</div>
              <div style={{ border: `1px solid ${selectedZone.color}44`, borderLeft: `3px solid ${selectedZone.color}`, borderRadius: 8, padding: "12px" }}>
                <div style={{ color: selectedZone.color, fontWeight: 700, fontSize: 13 }}>{selectedZone.label}</div>
                <div style={{ color: "#64748b", fontSize: 10, marginTop: 2 }}>{selectedZone.sublabel}</div>
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 10, color: "#475569", marginBottom: 4 }}>DEVICES / HARDWARE</div>
                  {(selectedZone.devices || []).map(d => (
                    <div key={d.id} style={{ display: "flex", gap: 8, padding: "6px 0", borderTop: "1px solid #0f172a", alignItems: "flex-start" }}>
                      <span style={{ fontSize: 16, flexShrink: 0 }}>{d.icon}</span>
                      <div>
                        <div style={{ fontSize: 11, color: "#e2e8f0", fontWeight: 600 }}>{d.label}</div>
                        <div style={{ fontSize: 10, color: "#64748b" }}>{d.sub}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div>
              <div style={{ fontSize: 10, letterSpacing: 3, color: "#475569", marginBottom: 8, textTransform: "uppercase" }}>Zones Overview</div>
              <div style={{ color: "#334155", fontSize: 11 }}>Click any zone on the map to view its devices and details here.</div>
            </div>
          )}

          {/* Legend */}
          <div>
            <div style={{ fontSize: 10, letterSpacing: 3, color: "#475569", marginBottom: 8, textTransform: "uppercase" }}>Legend — Security Tiers</div>
            {Object.entries(TIER_LABELS).map(([tier, label]) => (
              <div key={tier} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <div style={{ width: 10, height: 10, borderRadius: 2, background: TIER_COLORS[tier], flexShrink: 0 }} />
                <div style={{ fontSize: 10, color: "#64748b" }}>{label}</div>
              </div>
            ))}
          </div>

          {/* VLAN quick ref */}
          <div>
            <div style={{ fontSize: 10, letterSpacing: 3, color: "#475569", marginBottom: 8, textTransform: "uppercase" }}>VLAN Quick Ref</div>
            {[
              ["VLAN 1", "Management", "10.0.1.0/24"],
              ["VLAN 10", "DMZ", "10.0.10.0/24"],
              ["VLAN 20", "IT Dept", "10.0.20.0/24"],
              ["VLAN 25", "SOC", "10.0.25.0/24"],
              ["VLAN 30", "Finance", "10.0.30.0/24"],
              ["VLAN 40", "HR", "10.0.40.0/24"],
              ["VLAN 50", "Employees", "10.0.50.0/24"],
              ["VLAN 55", "Bastion", "10.0.55.0/28"],
              ["VLAN 60", "Prod Servers", "10.0.60.0/24"],
              ["VLAN 70", "Dev Servers", "10.0.70.0/24"],
              ["VLAN 80", "VoIP", "10.0.80.0/24"],
              ["VLAN 90", "IoT/Print", "10.0.90.0/24"],
              ["VLAN 100", "Guest", "10.0.100.0/24"],
              ["VLAN 110", "BYOD Enrolled", "10.0.110.0/24"],
              ["VLAN 120", "BYOD Restricted", "10.0.120.0/24"],
            ].map(([id, name, ip]) => (
              <div key={id} style={{ display: "flex", justifyContent: "space-between", padding: "3px 0", borderBottom: "1px solid #0f172a" }}>
                <span style={{ fontSize: 9, color: "#a855f7", fontWeight: 600 }}>{id}</span>
                <span style={{ fontSize: 9, color: "#94a3b8" }}>{name}</span>
                <span style={{ fontSize: 9, color: "#475569" }}>{ip}</span>
              </div>
            ))}
          </div>

          <div style={{ fontSize: 9, color: "#1e293b", textAlign: "center", paddingTop: 8 }}>
            v2 · Enterprise Office Topology
          </div>
        </div>
      </div>
    </div>
  );
}
