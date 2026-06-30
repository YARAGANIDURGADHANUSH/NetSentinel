import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

function TopologyMap({ packetStream }) {
  const containerRef = useRef(null);
  const svgRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return;

    d3.select(containerRef.current).selectAll("svg").remove();

    const width = containerRef.current.clientWidth || 500;
    const height = containerRef.current.clientHeight || 300;

    const svg = d3.select(containerRef.current)
      .append("svg")
      .attr("width", "100%")
      .attr("height", "100%")
      .attr("viewBox", `0 0 ${width} ${height}`)
      .attr("preserveAspectRatio", "xMidYMid meet");

    svgRef.current = svg;

    const nodes = [
      { id: "Gateway", group: 1, type: "core" },
      { id: "Server-Alpha", group: 2, type: "internal" },
      { id: "Server-Beta", group: 2, type: "internal" },
      { id: "External-DNS", group: 3, type: "external" }
    ];

    const links = [
      { source: "Gateway", target: "Server-Alpha" },
      { source: "Gateway", target: "Server-Beta" },
      { source: "External-DNS", target: "Gateway" }
    ];

    const simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id(d => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2));

    const link = svg.append("g")
      .attr("stroke", "#334155")
      .attr("stroke-width", 2)
      .selectAll("line")
      .data(links)
      .join("line");

    const node = svg.append("g")
      .selectAll("circle")
      .data(nodes)
      .join("circle")
      .attr("r", 14)
      .attr("fill", d => {
        if (d.id === "Gateway") return "#06b6d4";
        if (d.type === "external") return "#64748b";
        return "#10b981";
      })
      .attr("stroke", "#0f172a")
      .attr("stroke-width", 2);

    const label = svg.append("g")
      .selectAll("text")
      .data(nodes)
      .join("text")
      .text(d => d.id)
      .attr("font-size", "11px")
      .attr("fill", "#94a3b8")
      .attr("text-anchor", "middle")
      .attr("dy", 26);

    simulation.on("tick", () => {
      link
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);

      node
        .attr("cx", d => d.x)
        .attr("cy", d => d.y);

      label
        .attr("x", d => d.x)
        .attr("y", d => d.y);
    });

    return () => simulation.stop();
  }, []);

  useEffect(() => {
    if (!packetStream || !svgRef.current) return;

    const targetNodeId = packetStream.is_anomaly ? "Server-Beta" : "Server-Alpha";

    svgRef.current.selectAll("circle")
      .filter(d => d.id === targetNodeId)
      .transition()
      .duration(200)
      .attr("fill", packetStream.is_anomaly ? "#f43f5e" : "#34d399")
      .attr("r", 20)
      .transition()
      .duration(800)
      .attr("fill", d => d.id === "Gateway" ? "#06b6d4" : (d.type === "external" ? "#64748b" : "#10b981"))
      .attr("r", 14);

  }, [packetStream]);

  return (
    <div ref={containerRef} className="w-full h-full min-h-[300px] bg-slate-950/40 rounded-xl relative overflow-hidden" />
  );
}

export default TopologyMap;
