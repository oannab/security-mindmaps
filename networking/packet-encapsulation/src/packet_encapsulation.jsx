import { useState, useEffect } from "react";

const LAYERS = [
  {
    num: 7, name: "Application", color: "#ef4444", pdu: "Data",
    icon: "🌐", desc: "HTTP/HTTPS Request",
    fields: [
      { name: "Method", val: "GET", bytes: 3, desc: "HTTP method" },
      { name: "Path", val: "/api/users", bytes: 10, desc: "Resource path" },
      { name: "Version", val: "HTTP/1.1", bytes: 8, desc: "Protocol version" },
      { name: "Host", val: "api.example.com", bytes: 15, desc: "Target hostname" },
      { name: "Accept", val: "application/json", bytes: 16, desc: "MIME types" },
      { name: "User-Agent", val: "Mozilla/5.0...", bytes: 78, desc: "Client info" },
    ],
    action: "Application constructs HTTP request",
    adds: ["HTTP Method", "URI", "Headers", "Body (if POST/PUT)"],
    totalSize: 130,
  },
  {
    num: 6, name: "Presentation", color: "#f97316", pdu: "Encoded Data",
    icon: "🔐", desc: "TLS Encryption & Encoding",
    fields: [
      { name: "TLS Record Type", val: "0x17 (App Data)", bytes: 1, desc: "Content type", isHeader: true },
      { name: "TLS Version", val: "0x0303 (TLS 1.2)", bytes: 2, desc: "Protocol version", isHeader: true },
      { name: "Length", val: "0x00C8 (200B)", bytes: 2, desc: "Payload length", isHeader: true },
      { name: "Encrypted Data", val: "[...HTTP payload...]", bytes: 130, desc: "AES-GCM encrypted" },
      { name: "Auth Tag", val: "0x3F2A...BC7D", bytes: 16, desc: "AEAD authentication", isHeader: true },
    ],
    action: "TLS encrypts & wraps in record",
    adds: ["TLS Record Header (5B)", "Encrypted Payload", "Auth Tag (16B)"],
    totalSize: 151,
    overhead: 21,
  },
  {
    num: 5, name: "Session", color: "#eab308", pdu: "Session Data",
    icon: "🔗", desc: "Session Management",
    fields: [
      { name: "Session ID", val: "0xA3F2...CC01", bytes: 32, desc: "Unique session identifier", isHeader: true },
      { name: "Sequence", val: "0x000007B2", bytes: 4, desc: "Message ordering", isHeader: true },
      { name: "Flags", val: "0x02 (ESTABLISHED)", bytes: 1, desc: "Session state", isHeader: true },
      { name: "TLS Data", val: "[...TLS record...]", bytes: 151, desc: "Payload from L6" },
    ],
    action: "Session context & synchronization",
    adds: ["Session ID (32B)", "Sequence Number", "State Flags"],
    totalSize: 188,
    overhead: 37,
  },
  {
    num: 4, name: "Transport", color: "#22c55e", pdu: "Segment",
    icon: "🚚", desc: "TCP Segment with Port Numbers",
    fields: [
      { name: "Src Port", val: "54321", bytes: 2, desc: "Ephemeral port", isHeader: true },
      { name: "Dst Port", val: "443 (HTTPS)", bytes: 2, desc: "Service port", isHeader: true },
      { name: "Sequence #", val: "0x1A2B3C4D", bytes: 4, desc: "Byte position", isHeader: true },
      { name: "Ack #", val: "0x5E6F7A8B", bytes: 4, desc: "Next expected byte", isHeader: true },
      { name: "Data Offset", val: "5 (20 bytes)", bytes: 0.5, desc: "Header length", isHeader: true },
      { name: "Flags", val: "PSH, ACK", bytes: 1.5, desc: "Control flags", isHeader: true },
      { name: "Window", val: "65535", bytes: 2, desc: "Flow control", isHeader: true },
      { name: "Checksum", val: "0xF3A1", bytes: 2, desc: "Error detection", isHeader: true },
      { name: "Urgent Ptr", val: "0x0000", bytes: 2, desc: "Urgent data offset", isHeader: true },
      { name: "Payload", val: "[...Session data...]", bytes: 188, desc: "Data from L5" },
    ],
    action: "TCP adds reliability & port addressing",
    adds: ["Src/Dst Ports", "Seq/Ack Numbers", "Flags", "Window", "Checksum"],
    totalSize: 208,
    overhead: 20,
  },
  {
    num: 3, name: "Network", color: "#3b82f6", pdu: "Packet",
    icon: "🗺️", desc: "IP Packet with Routing Info",
    fields: [
      { name: "Version", val: "4 (IPv4)", bytes: 0.5, desc: "IP version", isHeader: true },
      { name: "IHL", val: "5 (20 bytes)", bytes: 0.5, desc: "Header length", isHeader: true },
      { name: "DSCP/ECN", val: "0x00", bytes: 1, desc: "QoS & congestion", isHeader: true },
      { name: "Total Length", val: "228 bytes", bytes: 2, desc: "Entire packet size", isHeader: true },
      { name: "Identification", val: "0x4E7A", bytes: 2, desc: "Fragment ID", isHeader: true },
      { name: "Flags/Offset", val: "DF, Offset=0", bytes: 2, desc: "Fragmentation", isHeader: true },
      { name: "TTL", val: "64 hops", bytes: 1, desc: "Time to live", isHeader: true },
      { name: "Protocol", val: "6 (TCP)", bytes: 1, desc: "Upper layer protocol", isHeader: true },
      { name: "Header Checksum", val: "0x3B2F", bytes: 2, desc: "Header integrity", isHeader: true },
      { name: "Source IP", val: "192.168.1.10", bytes: 4, desc: "Source address", isHeader: true },
      { name: "Dest IP", val: "93.184.216.34", bytes: 4, desc: "Destination address", isHeader: true },
      { name: "Payload", val: "[...TCP segment...]", bytes: 208, desc: "Data from L4" },
    ],
    action: "IP adds logical addressing for routing",
    adds: ["Src/Dst IP Addresses", "TTL", "Protocol ID", "Checksum"],
    totalSize: 228,
    overhead: 20,
  },
  {
    num: 2, name: "Data Link", color: "#8b5cf6", pdu: "Frame",
    icon: "🔌", desc: "Ethernet Frame with MAC Addresses",
    fields: [
      { name: "Dst MAC", val: "AA:BB:CC:DD:EE:FF", bytes: 6, desc: "Destination hardware", isHeader: true },
      { name: "Src MAC", val: "11:22:33:44:55:66", bytes: 6, desc: "Source hardware", isHeader: true },
      { name: "EtherType", val: "0x0800 (IPv4)", bytes: 2, desc: "Protocol indicator", isHeader: true },
      { name: "Payload", val: "[...IP packet...]", bytes: 228, desc: "Data from L3" },
      { name: "FCS", val: "0x1A2B3C4D", bytes: 4, desc: "CRC-32 checksum", isTrailer: true },
    ],
    action: "Ethernet frames for local delivery",
    adds: ["Src/Dst MAC (12B)", "EtherType (2B)", "FCS Trailer (4B)"],
    totalSize: 246,
    overhead: 18,
  },
  {
    num: 1, name: "Physical", color: "#ec4899", pdu: "Bits",
    icon: "⚡", desc: "Physical Signal on Wire/Fiber",
    fields: [
      { name: "Preamble", val: "10101010 × 7 bytes", bytes: 7, desc: "Clock sync pattern", isHeader: true },
      { name: "SFD", val: "10101011 (1 byte)", bytes: 1, desc: "Start frame delimiter", isHeader: true },
      { name: "Frame Data", val: "[...Ethernet frame...]", bytes: 246, desc: "Encoded bits from L2" },
      { name: "Encoding", val: "Manchester / 4B5B", bytes: 0, desc: "Line encoding scheme" },
      { name: "Medium", val: "Electrical / Optical", bytes: 0, desc: "Physical transmission" },
    ],
    action: "Bits transmitted as physical signals",
    adds: ["Preamble (7B)", "SFD (1B)", "Physical Encoding"],
    totalSize: 254,
    overhead: 8,
  },
];

export default function PacketEncapsulation() {
  const [currentStep, setCurrentStep] = useState(0);
  const [selectedLayer, setSelectedLayer] = useState(null);
  const [mode, setMode] = useState("encapsulation"); // encapsulation | decapsulation
  const [autoPlay, setAutoPlay] = useState(false);
  const [showFields, setShowFields] = useState(true);

  // Auto-play through layers
  useEffect(() => {
    if (!autoPlay) return;
    const timer = setInterval(() => {
      setCurrentStep(prev => {
        if (mode === "encapsulation") {
          return prev >= LAYERS.length - 1 ? 0 : prev + 1;
        } else {
          return prev >= LAYERS.length - 1 ? 0 : prev + 1;
        }
      });
    }, 2500);
    return () => clearInterval(timer);
  }, [autoPlay, mode]);

  const displayLayers = mode === "encapsulation" 
    ? LAYERS.slice(0, currentStep + 1)
    : LAYERS.slice(LAYERS.length - 1 - currentStep);

  const activeLayer = LAYERS[mode === "encapsulation" ? currentStep : LAYERS.length - 1 - currentStep];

  return (
    <div style={{
      width: "100vw", height: "100vh", background: "#0a0e1a",
      color: "#e2e8f0", fontFamily: "system-ui, -apple-system, sans-serif",
      display: "flex", overflow: "hidden"
    }}>
      {/* Main visualization area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", position: "relative" }}>
        
        {/* Header */}
        <div style={{
          padding: "20px 32px", borderBottom: "1px solid #1e293b",
          background: "#0f1629", display: "flex", alignItems: "center", justifyContent: "space-between"
        }}>
          <div>
            <h1 style={{ fontSize: 24, fontWeight: 700, margin: 0, letterSpacing: "-0.02em" }}>
              OSI Packet Encapsulation
              <span style={{ color: "#64748b", fontWeight: 400, fontSize: 16, marginLeft: 12 }}>
                // HTTP Request Lifecycle
              </span>
            </h1>
            <p style={{ fontSize: 12, color: "#64748b", margin: "4px 0 0", letterSpacing: "0.05em" }}>
              {mode === "encapsulation" ? "SENDER SIDE: Layer 7 → 1" : "RECEIVER SIDE: Layer 1 → 7"}
            </p>
          </div>
          
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <button
              onClick={() => setMode(m => m === "encapsulation" ? "decapsulation" : "encapsulation")}
              style={{
                padding: "8px 16px", background: "#1e293b", border: "1px solid #334155",
                color: "#e2e8f0", borderRadius: 6, cursor: "pointer", fontSize: 13,
                display: "flex", alignItems: "center", gap: 8
              }}>
              {mode === "encapsulation" ? "📤 Encapsulation" : "📥 Decapsulation"}
            </button>
            <button
              onClick={() => setAutoPlay(!autoPlay)}
              style={{
                padding: "8px 16px", background: autoPlay ? "#22c55e22" : "#1e293b",
                border: `1px solid ${autoPlay ? "#22c55e" : "#334155"}`,
                color: autoPlay ? "#22c55e" : "#e2e8f0",
                borderRadius: 6, cursor: "pointer", fontSize: 13
              }}>
              {autoPlay ? "⏸ Pause" : "▶ Auto-play"}
            </button>
          </div>
        </div>

        {/* Main content */}
        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
          
          {/* Left: Onion visualization */}
          <div style={{
            flex: 1, display: "flex", flexDirection: "column",
            alignItems: "center", justifyContent: "center", padding: 40,
            background: "radial-gradient(circle at 50% 50%, #0f1629 0%, #0a0e1a 100%)",
            position: "relative"
          }}>
            
            {/* Current layer badge */}
            <div style={{
              position: "absolute", top: 24, left: 24,
              background: `${activeLayer.color}22`, border: `1px solid ${activeLayer.color}`,
              padding: "8px 16px", borderRadius: 8, display: "flex", alignItems: "center", gap: 10
            }}>
              <span style={{ fontSize: 24 }}>{activeLayer.icon}</span>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: activeLayer.color }}>
                  Layer {activeLayer.num} — {activeLayer.name}
                </div>
                <div style={{ fontSize: 11, color: "#64748b" }}>
                  {activeLayer.totalSize} bytes total • +{activeLayer.overhead || 0}B overhead
                </div>
              </div>
            </div>

            {/* Packet size indicator */}
            <div style={{
              position: "absolute", top: 24, right: 24,
              background: "#1e293b", border: "1px solid #334155",
              padding: "10px 16px", borderRadius: 8, textAlign: "right"
            }}>
              <div style={{ fontSize: 11, color: "#64748b", marginBottom: 4 }}>TOTAL PACKET SIZE</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: "#22c55e" }}>
                {activeLayer.totalSize}
                <span style={{ fontSize: 14, color: "#64748b", marginLeft: 4 }}>bytes</span>
              </div>
              <div style={{ fontSize: 10, color: "#64748b", marginTop: 4 }}>
                {activeLayer.overhead ? `Original: ${LAYERS[0].totalSize}B + ${activeLayer.totalSize - LAYERS[0].totalSize}B headers/trailers` : "Application payload"}
              </div>
            </div>

            {/* Onion layers */}
            <div style={{
              position: "relative", display: "flex", flexDirection: "column",
              alignItems: "center", gap: 0, minWidth: 600, maxWidth: "90%"
            }}>
              {displayLayers.map((layer, idx) => {
                const isActive = layer.num === activeLayer.num;
                const size = 100 - (displayLayers.length - idx - 1) * 8;
                const isNew = idx === displayLayers.length - 1;
                
                return (
                  <div
                    key={layer.num}
                    onClick={() => setSelectedLayer(layer)}
                    style={{
                      width: `${size}%`,
                      background: `${layer.color}${isActive ? "33" : "11"}`,
                      border: `2px solid ${layer.color}${isActive ? "" : "44"}`,
                      borderRadius: 12,
                      padding: 16,
                      marginTop: idx > 0 ? -8 : 0,
                      cursor: "pointer",
                      transition: "all 0.3s ease",
                      boxShadow: isActive ? `0 0 30px ${layer.color}44` : "none",
                      transform: isNew ? "scale(0.95)" : "scale(1)",
                      animation: isNew ? "slideIn 0.4s ease forwards" : "none",
                      position: "relative",
                      zIndex: displayLayers.length - idx,
                    }}>
                    
                    {/* Layer header */}
                    <div style={{
                      display: "flex", alignItems: "center", justifyContent: "space-between",
                      marginBottom: 8
                    }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <span style={{ fontSize: 20 }}>{layer.icon}</span>
                        <div>
                          <div style={{ fontSize: 13, fontWeight: 700, color: layer.color }}>
                            L{layer.num}: {layer.name}
                          </div>
                          <div style={{ fontSize: 10, color: "#64748b" }}>{layer.pdu}</div>
                        </div>
                      </div>
                      <div style={{
                        fontSize: 11, color: "#64748b",
                        background: "#0f162966", padding: "3px 8px", borderRadius: 4
                      }}>
                        {layer.totalSize}B
                      </div>
                    </div>

                    {/* Fields preview (when active) */}
                    {isActive && showFields && (
                      <div style={{
                        display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
                        gap: 6, marginTop: 10, fontSize: 10
                      }}>
                        {layer.fields.filter(f => f.isHeader || f.isTrailer).slice(0, 4).map((field, fi) => (
                          <div key={fi} style={{
                            background: "#0f162999", padding: "6px 8px", borderRadius: 4,
                            border: "1px solid #1e293b"
                          }}>
                            <div style={{ color: "#64748b", fontSize: 9 }}>{field.name}</div>
                            <div style={{ color: "#e2e8f0", fontWeight: 600, fontSize: 10 }}>
                              {field.val}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Inner payload indicator */}
                    {idx < displayLayers.length - 1 && (
                      <div style={{
                        marginTop: 8, padding: "6px 10px", background: "#0f162944",
                        borderRadius: 6, border: "1px dashed #334155",
                        fontSize: 10, color: "#64748b", textAlign: "center"
                      }}>
                        ▸ Contains: {displayLayers[idx + 1].pdu} from Layer {displayLayers[idx + 1].num}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Progress controls */}
            <div style={{
              position: "absolute", bottom: 32, left: "50%", transform: "translateX(-50%)",
              display: "flex", gap: 12, alignItems: "center",
              background: "#1e293b", padding: "12px 20px", borderRadius: 12,
              border: "1px solid #334155"
            }}>
              <button
                onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
                disabled={currentStep === 0}
                style={{
                  padding: "6px 12px", background: "#0f1629", border: "1px solid #334155",
                  color: currentStep === 0 ? "#475569" : "#e2e8f0",
                  borderRadius: 6, cursor: currentStep === 0 ? "not-allowed" : "pointer", fontSize: 16
                }}>
                ◀
              </button>

              <div style={{ display: "flex", gap: 4 }}>
                {LAYERS.map((_, i) => (
                  <div
                    key={i}
                    onClick={() => setCurrentStep(i)}
                    style={{
                      width: 8, height: 8, borderRadius: "50%",
                      background: i === currentStep ? "#22c55e" : "#334155",
                      cursor: "pointer", transition: "all 0.2s"
                    }}
                  />
                ))}
              </div>

              <button
                onClick={() => setCurrentStep(Math.min(LAYERS.length - 1, currentStep + 1))}
                disabled={currentStep === LAYERS.length - 1}
                style={{
                  padding: "6px 12px", background: "#0f1629", border: "1px solid #334155",
                  color: currentStep === LAYERS.length - 1 ? "#475569" : "#e2e8f0",
                  borderRadius: 6, cursor: currentStep === LAYERS.length - 1 ? "not-allowed" : "pointer", fontSize: 16
                }}>
                ▶
              </button>
            </div>

            <style>{`
              @keyframes slideIn {
                from { transform: scale(0.9); opacity: 0; }
                to { transform: scale(1); opacity: 1; }
              }
            `}</style>
          </div>

          {/* Right: Details panel */}
          <div style={{
            width: 380, background: "#0f1629", borderLeft: "1px solid #1e293b",
            overflowY: "auto", display: "flex", flexDirection: "column"
          }}>
            
            {/* Layer info */}
            <div style={{ padding: 20, borderBottom: "1px solid #1e293b" }}>
              <div style={{
                fontSize: 10, letterSpacing: 2, color: "#475569",
                textTransform: "uppercase", marginBottom: 12
              }}>
                Current Layer
              </div>
              
              <div style={{
                background: `${activeLayer.color}11`, border: `1px solid ${activeLayer.color}44`,
                borderLeft: `3px solid ${activeLayer.color}`, borderRadius: 8, padding: 16
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <span style={{ fontSize: 28 }}>{activeLayer.icon}</span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 15, fontWeight: 700, color: activeLayer.color }}>
                      Layer {activeLayer.num}: {activeLayer.name}
                    </div>
                    <div style={{ fontSize: 11, color: "#64748b" }}>{activeLayer.desc}</div>
                  </div>
                </div>

                <div style={{ fontSize: 12, color: "#94a3b8", lineHeight: 1.6, marginTop: 12 }}>
                  <strong style={{ color: activeLayer.color }}>Action:</strong> {activeLayer.action}
                </div>

                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: 10, color: "#64748b", marginBottom: 6 }}>ADDS TO PACKET:</div>
                  {activeLayer.adds.map((item, i) => (
                    <div key={i} style={{
                      fontSize: 11, color: "#e2e8f0", padding: "4px 8px",
                      background: "#0f162966", borderRadius: 4, marginBottom: 4,
                      border: "1px solid #1e293b"
                    }}>
                      ✓ {item}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Fields breakdown */}
            <div style={{ padding: 20, flex: 1 }}>
              <div style={{
                fontSize: 10, letterSpacing: 2, color: "#475569",
                textTransform: "uppercase", marginBottom: 12,
                display: "flex", alignItems: "center", justifyContent: "space-between"
              }}>
                <span>Field Breakdown</span>
                <button
                  onClick={() => setShowFields(!showFields)}
                  style={{
                    padding: "4px 8px", background: "#1e293b", border: "1px solid #334155",
                    color: "#94a3b8", borderRadius: 4, cursor: "pointer", fontSize: 9
                  }}>
                  {showFields ? "Hide in Onion" : "Show in Onion"}
                </button>
              </div>

              {activeLayer.fields.map((field, i) => (
                <div key={i} style={{
                  background: field.isHeader || field.isTrailer ? `${activeLayer.color}11` : "#1e293b",
                  border: `1px solid ${field.isHeader || field.isTrailer ? `${activeLayer.color}33` : "#334155"}`,
                  borderRadius: 6, padding: 12, marginBottom: 8,
                  borderLeft: field.isHeader || field.isTrailer ? `3px solid ${activeLayer.color}` : "none"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", marginBottom: 4 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: "#e2e8f0" }}>
                      {field.name}
                      {field.isHeader && <span style={{ marginLeft: 6, fontSize: 9, color: activeLayer.color }}>[ HEADER ]</span>}
                      {field.isTrailer && <span style={{ marginLeft: 6, fontSize: 9, color: activeLayer.color }}>[ TRAILER ]</span>}
                    </div>
                    <div style={{ fontSize: 10, color: "#64748b", fontWeight: 600 }}>
                      {field.bytes}B
                    </div>
                  </div>
                  <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 4, fontFamily: "monospace" }}>
                    {field.val}
                  </div>
                  <div style={{ fontSize: 10, color: "#64748b" }}>
                    {field.desc}
                  </div>
                </div>
              ))}
            </div>

            {/* Quick nav */}
            <div style={{ padding: 20, borderTop: "1px solid #1e293b" }}>
              <div style={{
                fontSize: 10, letterSpacing: 2, color: "#475569",
                textTransform: "uppercase", marginBottom: 12
              }}>
                Quick Navigation
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {LAYERS.map((layer, i) => (
                  <button
                    key={layer.num}
                    onClick={() => setCurrentStep(mode === "encapsulation" ? i : LAYERS.length - 1 - i)}
                    style={{
                      padding: "8px 12px", background: i === currentStep ? `${layer.color}22` : "#1e293b",
                      border: `1px solid ${i === currentStep ? layer.color : "#334155"}`,
                      borderRadius: 6, cursor: "pointer", textAlign: "left",
                      color: "#e2e8f0", fontSize: 12, display: "flex",
                      alignItems: "center", gap: 8, transition: "all 0.2s"
                    }}>
                    <span>{layer.icon}</span>
                    <span style={{ flex: 1 }}>L{layer.num}: {layer.name}</span>
                    <span style={{ fontSize: 10, color: "#64748b" }}>{layer.totalSize}B</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
