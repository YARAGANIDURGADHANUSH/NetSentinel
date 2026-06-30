import React, { useState, useEffect, useRef } from 'react';
import * as d3 from 'd3';

export default function App() {
  // Reconciled Metrics States
  const [metrics, setMetrics] = useState({
    total: 0,
    http: 0,
    dns: 0,
    raw: 0
  });

  const [packetLogs, setPacketLogs] = useState([]);
  const [threatAlerts, setThreatAlerts] = useState([]);
  const [wsStatus, setWsStatus] = useState('OFFLINE (CLICK TEST FOR TRAFFIC)');
  const [currentFilter, setCurrentFilter] = useState('ALL');

  const topologyRef = useRef(null);
  const terminalEndRef = useRef(null);
  const sessionLogRef = useRef([]);

  // Node Infrastructure Framework for Topology Canvas Data Mapping
  const topologyData = {
    nodes: [
      { id: "Gateway", type: "router", label: "Core Gateway (10.0.0.1)" },
      { id: "Server-Alpha", type: "server", label: "App Node A (10.0.0.12)" },
      { id: "Server-Beta", type: "server", label: "DB Cluster B (192.168.1.50)" },
      { id: "External-DNS", type: "external", label: "Ext Router (8.8.8.8)" }
    ],
    links: [
      { source: "Gateway", target: "Server-Alpha" },
      { source: "Gateway", target: "Server-Beta" },
      { source: "Gateway", target: "External-DNS" }
    ]
  };

  // Node Visual Intercept Pulsing Animation
  const triggerInfiltrationFlash = (sourceIp) => {
    let targetNodeId = "Gateway";
    if (sourceIp?.includes("10.0.0.12")) targetNodeId = "Server-Alpha";
    else if (sourceIp?.includes("192.168.1.50") || sourceIp?.includes("192.168.1.105")) targetNodeId = "Server-Beta";
    else if (sourceIp?.includes("8.8.8.8")) targetNodeId = "External-DNS";

    const circle = d3.select(`#react-node-${targetNodeId} circle`);
    if (!circle.empty()) {
      circle.attr("fill", "#ef4444").attr("r", 16);
      setTimeout(() => {
        const baseColor = targetNodeId === "Gateway" ? "#06b6d4" : (targetNodeId.includes("Server") ? "#10b981" : "#475569");
        circle.transition().duration(400).attr("fill", baseColor).attr("r", 10);
      }, 800);
    }
  };

  // 1. Initialize D3 Topography Graph Layout Engine (Bound within safe dimensions)
  useEffect(() => {
    if (!topologyRef.current) return;
    d3.select(topologyRef.current).selectAll("*").remove();

    const width = topologyRef.current.clientWidth || 300;
    const height = topologyRef.current.clientHeight || 200;

    const svg = d3.select(topologyRef.current)
      .append("svg")
      .attr("width", "100%")
      .attr("height", "100%")
      .attr("viewBox", `0 0 ${width} ${height}`);

    const linkSelection = svg.append("g")
      .selectAll("line")
      .data(topologyData.links)
      .enter().append("line")
      .attr("stroke", "#334155")
      .attr("stroke-width", 1.5);

    const nodeSelection = svg.append("g")
      .selectAll("g")
      .data(topologyData.nodes)
      .enter().append("g")
      .attr("id", d => `react-node-${d.id}`);

    nodeSelection.append("circle")
      .attr("r", 10)
      .attr("fill", d => d.type === "router" ? "#06b6d4" : (d.type === "server" ? "#10b981" : "#475569"))
      .attr("stroke", "#020617")
      .attr("stroke-width", 2)
      .style("transition", "all 250ms ease");

    nodeSelection.append("text")
      .text(d => d.id)
      .attr("dy", 20)
      .attr("text-anchor", "middle")
      .attr("fill", "#64748b")
      .attr("font-size", "9px")
      .attr("font-weight", "bold");

    const simulation = d3.forceSimulation(topologyData.nodes)
      .force("link", d3.forceLink(topologyData.links).id(d => d.id).distance(55))
      .force("charge", d3.forceManyBody().strength(-150))
      .force("center", d3.forceCenter(width / 2, height / 2));

    simulation.on("tick", () => {
      linkSelection
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);

      nodeSelection.attr("transform", d => `translate(${d.x},${d.y})`);
    });

    return () => simulation.stop();
  }, []);

  // 2. Real-time Pipeline Stream WebSocket Loop Receiver
  useEffect(() => {
    const wsUrl = `ws://${window.location.hostname || 'localhost'}:8000/api/packets/stream`;
    let socket;

    const connect = () => {
      socket = new WebSocket(wsUrl);
      socket.onopen = () => setWsStatus("ONLINE");
      socket.onmessage = (event) => {
        try {
          const packet = JSON.parse(event.data);
          processIncomingPacket(packet);
        } catch (err) { console.error("Stream parse loop fault: ", err); }
      };
      socket.onclose = () => {
        setTimeout(connect, 5000);
      };
    };

    connect();
    return () => socket?.close();
  }, []);

  // Shared processor logic for both real-time stream frames and manual diagnostic pushes
  const processIncomingPacket = (packet) => {
    sessionLogRef.current.push(packet);
    const l7Protocol = packet.application_layer?.protocol_parsed || "RAW";

    setMetrics(prev => ({
      total: prev.total + 1,
      http: l7Protocol === "HTTP" ? prev.http + 1 : prev.http,
      dns: l7Protocol === "DNS" ? prev.dns + 1 : prev.dns,
      raw: l7Protocol === "RAW" ? prev.raw + 1 : prev.raw
    }));

    setPacketLogs(prev => [...prev.slice(-25), packet]);

    if (packet.is_anomaly || packet.ai_analyzed) {
      const newAlert = {
        id: Date.now() + Math.random(),
        type: packet.anomaly_metadata?.threat_type || "VECTOR EXPLOIT PROBE DETECTED",
        desc: packet.anomaly_metadata?.flagged_feature || `Unencrypted target path intercept monitored from resource node.`
      };
      setThreatAlerts(prev => [newAlert, ...prev.slice(0, 5)]);
      triggerInfiltrationFlash(packet.network_layer?.source_ip || "");
    }
  };

  // 3. COMPLETE PIPELINE SIMULATION / TESTING ENGINE
  const injectTestTelemetryFrame = () => {
    if (wsStatus.includes("OFFLINE")) setWsStatus("ONLINE (MOCK ACTIVE)");
    
    const targetProtocols = ["HTTP", "DNS", "RAW"];
    const chosenProto = targetProtocols[Math.floor(Math.random() * targetProtocols.length)];
    
    const sourceIps = ["192.168.1.50", "10.0.0.12", "8.8.8.8", "184.22.109.5"];
    const destIps = ["142.250.190.46", "34.117.230.8", "192.168.1.105"];
    
    const isAnomalyTest = Math.random() > 0.65; // ~35% chance for threat triggers

    const mockPacket = {
      timestamp: new Date().toISOString(),
      size: Math.floor(Math.random() * 1200) + 64,
      is_anomaly: isAnomalyTest,
      ai_analyzed: isAnomalyTest,
      transport_layer: {
        protocol: chosenProto === "DNS" ? "UDP" : "TCP",
        source_port: chosenProto === "DNS" ? 53 : Math.floor(Math.random() * 4000) + 1024,
        destination_port: chosenProto === "DNS" ? 53 : (chosenProto === "HTTP" ? 80 : 443)
      },
      network_layer: {
        source_ip: sourceIps[Math.floor(Math.random() * sourceIps.length)],
        destination_ip: destIps[Math.floor(Math.random() * destIps.length)]
      },
      application_layer: {
        protocol_parsed: chosenProto
      },
      ...(isAnomalyTest && {
        anomaly_metadata: {
          threat_type: chosenProto === "HTTP" ? "UNENCRYPTED CREDENTIAL LEAK" : "MALICIOUS INTERCEPT / BEACONING",
          flagged_feature: chosenProto === "HTTP" 
            ? "Cleartext payload target target parameters matched signature isolation forest metrics."
            : "High-frequency iterative connection sequence outside established system bounds."
        }
      })
    };

    processIncomingPacket(mockPacket);
  };

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [packetLogs]);

  const filteredLogs = packetLogs.filter(p => 
    currentFilter === "ALL" || (p.application_layer?.protocol_parsed || "RAW") === currentFilter
  );

  return (
    <div className="bg-slate-950 text-slate-100 font-mono h-screen flex flex-col overflow-hidden text-xs selection:bg-cyan-500 selection:text-slate-950">
      
      {/* HUD TERMINAL TOP STATUS HEADER */}
      <header className="border-b border-slate-800 bg-slate-900/40 px-6 py-3 flex items-center justify-between shrink-0">
        <div className="flex items-center space-x-3">
          <div className={`w-2.5 h-2.5 rounded-full ${wsStatus.includes("ONLINE") ? 'bg-emerald-400 animate-pulse' : 'bg-amber-500'}`}></div>
          <h1 className="text-base font-black tracking-wider">
            NETSENTINEL <span className="text-[10px] text-slate-500 px-1 border border-slate-800 rounded bg-slate-950 ml-1">v1.0.0</span>
          </h1>
        </div>
        
        {/* INTERACTION TESTING SUITE PANEL */}
        <div className="flex items-center space-x-4">
          <button 
            onClick={injectTestTelemetryFrame}
            className="bg-gradient-to-r from-amber-600 to-amber-700 hover:from-amber-500 hover:to-amber-600 text-slate-950 font-bold px-4 py-1.5 rounded border border-amber-400/30 cursor-pointer transition shadow-md shadow-amber-950/20 text-[11px]"
          >
            🧪 RUN DIAGNOSTIC TEST FRAME
          </button>
          <div className="text-[11px] text-slate-400 border-l border-slate-800 pl-4 flex space-x-4">
            <div>HOST IP: <span className="text-slate-200">127.0.0.1</span></div>
            <div>WS STREAM: <span className={`font-bold ${wsStatus.includes("ONLINE") ? 'text-emerald-400' : 'text-amber-500'}`}>{wsStatus}</span></div>
          </div>
        </div>
      </header>

      {/* RECONCILED VIEWPORT EXPANSION GRID (Zero Scrolling Framework) */}
      <main className="flex-1 p-4 grid grid-cols-1 lg:grid-cols-12 gap-4 overflow-hidden min-h-0">
        
        {/* LEFT COLUMN INTERFACE (4 OF 12 SECTIONS) */}
        <div className="lg:col-span-4 flex flex-col space-y-3 min-h-0">
          
          {/* HIGH-DENSITY METRIC COUNTERS GRID */}
          <div className="grid grid-cols-2 gap-2.5 shrink-0">
            <div className="bg-slate-900/40 border border-slate-800/60 p-3 rounded-lg">
              <div className="text-[9px] font-bold uppercase tracking-wider text-slate-400 mb-0.5">Total Packets</div>
              <div className="text-xl font-black text-cyan-400">{metrics.total}</div>
            </div>
            <div className="bg-slate-900/40 border border-slate-800/60 p-3 rounded-lg">
              <div className="text-[9px] font-bold uppercase tracking-wider text-slate-400 mb-0.5">HTTP Intercepts</div>
              <div className="text-xl font-black text-emerald-400">{metrics.http}</div>
            </div>
            <div className="bg-slate-900/40 border border-slate-800/60 p-3 rounded-lg">
              <div className="text-[9px] font-bold uppercase tracking-wider text-slate-400 mb-0.5">DNS Resolves</div>
              <div className="text-xl font-black text-purple-400">{metrics.dns}</div>
            </div>
            <div className="bg-slate-900/40 border border-slate-800/60 p-3 rounded-lg">
              <div className="text-[9px] font-bold uppercase tracking-wider text-slate-400 mb-0.5">RAW / L4 Frames</div>
              <div className="text-xl font-black text-rose-400">{metrics.raw}</div>
            </div>
          </div>

          {/* AI THREAT SEVERITY CRITICAL INCIDENT LOGGER */}
          <div className="bg-slate-900/40 border border-slate-800/60 p-3 rounded-lg flex flex-col h-[150px] shrink-0">
            <div className="text-[11px] font-bold uppercase tracking-wider text-rose-400 border-b border-slate-900 pb-1.5 mb-1.5 flex items-center justify-between">
              <span>⚠️ Threat Intelligence Feed</span>
              <span className="bg-rose-950 text-rose-400 border border-rose-800/40 px-1.5 py-0.2 rounded text-[9px]">
                {threatAlerts.length} ALERTS
              </span>
            </div>
            <div className="flex-1 overflow-y-auto space-y-1.5 text-[10px] text-slate-400 pr-0.5 scrollbar-thin">
              {threatAlerts.length === 0 ? (
                <div className="text-slate-600 italic">No threat traces logged. Trigger diagnostic test to verify.</div>
              ) : (
                threatAlerts.map(alert => (
                  <div key={alert.id} className="p-2 bg-rose-950/20 border-l-2 border-rose-500 rounded text-rose-200 leading-tight">
                    <strong>[{alert.type}]</strong> {alert.desc}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* SAFELY BOUND D3 TOPOLOGY CONTAINER (Fits side-by-side) */}
          <div className="bg-slate-900/40 border border-slate-800/60 p-3 rounded-lg flex-1 flex flex-col min-h-0">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 border-b border-slate-900 pb-1.5 mb-2">
              🌐 Live Infrastructure Topology Map
            </div>
            <div ref={topologyRef} className="flex-1 w-full bg-slate-950/50 rounded border border-slate-900/60 overflow-hidden relative"></div>
          </div>
        </div>

        {/* RIGHT PIPELINE TRIAGE TERM STREAM (8 OF 12 SECTIONS) */}
        <div className="lg:col-span-8 bg-slate-900/40 border border-slate-800/60 rounded-lg flex flex-col min-h-0">
          
          {/* RUNTIME OPTION INTERFACES */}
          <div className="px-4 py-2.5 border-b border-slate-800/60 bg-slate-900/20 flex items-center justify-between shrink-0">
            <div className="flex items-center space-x-2 text-[11px] font-bold uppercase tracking-wider text-slate-300">
              <span className={`w-2 h-2 rounded-full ${packetLogs.length > 0 ? 'bg-cyan-400 animate-ping' : 'bg-slate-600'}`}></span>
              <span>Live Pipeline Packet Triage Feed</span>
            </div>

            {/* QUICK PROTOCOL FILTER SELECTOR TOGGLES */}
            <div className="flex items-center space-x-1 bg-slate-950 p-0.5 rounded border border-slate-900 text-[10px]">
              {['ALL', 'HTTP', 'DNS'].map(proto => (
                <button
                  key={proto}
                  onClick={() => setCurrentFilter(proto)}
                  className={`px-2.5 py-0.5 rounded font-bold cursor-pointer transition ${
                    currentFilter === proto ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {proto}
                </button>
              ))}
            </div>

            <button 
              onClick={() => setPacketLogs([])} 
              className="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-400 px-2 py-0.5 rounded transition border border-slate-700/60 cursor-pointer"
            >
              Clear View
            </button>
          </div>

          {/* UNIFIED SCROLLABLE FEED TERMINAL CONTAINER */}
          <div className="flex-1 p-3.5 overflow-y-auto space-y-1.5 bg-slate-950/40 text-[11px] scrollbar-thin select-text">
            {filteredLogs.length === 0 ? (
              <div className="text-slate-500 italic">[Awaiting packet matrix traffic context stream records...]</div>
            ) : (
              filteredLogs.map((pkt, i) => {
                const isAnomaly = pkt.is_anomaly || pkt.ai_analyzed;
                const timeStr = pkt.timestamp ? pkt.timestamp.slice(11, 19) : new Date().toLocaleTimeString();
                return (
                  <div key={i} className={`p-2 border rounded font-mono w-full transition-all duration-100 ${
                    isAnomaly ? 'border-rose-900/70 bg-rose-950/10 text-rose-200' : 'border-slate-800/60 text-slate-300 bg-slate-900/5'
                  }`}>
                    <div className="flex items-center justify-between text-[9px] text-slate-500 mb-0.5 pb-0.5 border-b border-slate-900/40">
                      <span>SIZE: {pkt.size || 64}B | L4: {pkt.transport_layer?.protocol || 'TCP'} (Ports: {pkt.transport_layer?.source_port} ➔ {pkt.transport_layer?.destination_port})</span>
                      <span>{timeStr}</span>
                    </div>
                    <div className="text-xs">
                      <span className="text-cyan-400 font-bold">{pkt.network_layer?.source_ip}</span> ➔ <span className="text-indigo-400 font-bold">{pkt.network_layer?.destination_ip}</span>
                    </div>
                  </div>
                );
              })
            )}
            <div ref={terminalEndRef} />
          </div>
        </div>
      </main>
    </div>
  );
}
