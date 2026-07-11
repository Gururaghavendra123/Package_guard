/* PackageGuard HUD — dependency graph panel (Sem 8).
   Renders /api/graph as a layered SVG: nodes coloured by GNN risk, edges pulsing where risk
   propagates. No external libraries — vanilla SVG so it works offline. */

(function () {
  const SVG_NS = "http://www.w3.org/2000/svg";
  const W = 640, H = 460;

  const form = document.getElementById("graph-form");
  if (!form) return;

  form.addEventListener("submit", (e) => { e.preventDefault(); runGraph(document.getElementById("graph-input").value.trim()); });
  document.querySelectorAll(".chip[data-graph]").forEach((c) =>
    c.addEventListener("click", () => { document.getElementById("graph-input").value = c.dataset.graph; runGraph(c.dataset.graph); }));

  function riskColor(v) {
    if (v == null) return "var(--ink-dim)";
    if (v >= 0.6) return "var(--crit)";
    if (v >= 0.3) return "var(--warn)";
    return "var(--ok)";
  }

  async function runGraph(pkg) {
    if (!pkg) return;
    document.getElementById("graph-error").classList.add("hidden");
    const btn = form.querySelector(".run-btn"); btn.textContent = "···"; btn.classList.add("loading");
    try {
      const r = await fetch("/api/graph", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: pkg }),
      });
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
      render(await r.json());
    } catch (err) {
      document.getElementById("graph-result").classList.add("hidden");
      const b = document.getElementById("graph-error"); b.textContent = "⚠ " + err.message; b.classList.remove("hidden");
    } finally { btn.textContent = "MAP ▸"; btn.classList.remove("loading"); }
  }

  function render(d) {
    document.getElementById("graph-result").classList.remove("hidden");
    document.getElementById("graph-mode").textContent =
      d.demo ? "· curated poisoned-chain demo" : (d.gnn_available ? "· live" : "· GNN model not trained");

    // layout: group nodes by depth into horizontal bands
    const byDepth = {};
    d.nodes.forEach((n) => { (byDepth[n.depth] = byDepth[n.depth] || []).push(n); });
    const depths = Object.keys(byDepth).map(Number).sort((a, b) => a - b);
    const pos = {};
    const bandH = H / (depths.length + 1);
    depths.forEach((dep, di) => {
      const row = byDepth[dep];
      row.forEach((n, i) => {
        pos[n.id] = { x: (W / (row.length + 1)) * (i + 1), y: bandH * (di + 1) };
      });
    });

    const svg = document.getElementById("graph-svg");
    svg.innerHTML = "";

    // edges first (under nodes); pulse edges pointing at a malicious node
    d.edges.forEach((e) => {
      const a = pos[e.source], b = pos[e.target];
      if (!a || !b) return;
      const target = d.nodes.find((n) => n.id === e.target);
      const risky = target && (target.gnn_score != null ? target.gnn_score : target.xgb_score) >= 0.6;
      const line = document.createElementNS(SVG_NS, "line");
      line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
      line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
      line.setAttribute("stroke", risky ? "var(--crit)" : "var(--line-hot)");
      line.setAttribute("stroke-width", risky ? "2.5" : "1.2");
      line.setAttribute("opacity", risky ? "0.9" : "0.4");
      if (risky) line.setAttribute("class", "edge-pulse");
      svg.appendChild(line);
    });

    // nodes
    d.nodes.forEach((n) => {
      const p = pos[n.id];
      const risk = n.gnn_score != null ? n.gnn_score : n.xgb_score;
      const g = document.createElementNS(SVG_NS, "g");
      const c = document.createElementNS(SVG_NS, "circle");
      c.setAttribute("cx", p.x); c.setAttribute("cy", p.y);
      c.setAttribute("r", n.depth === 0 ? 16 : 11);
      c.setAttribute("fill", "var(--panel)");
      c.setAttribute("stroke", riskColor(risk));
      c.setAttribute("stroke-width", "3");
      if (risk >= 0.6) c.setAttribute("class", "node-pulse");
      g.appendChild(c);
      const label = document.createElementNS(SVG_NS, "text");
      label.setAttribute("x", p.x); label.setAttribute("y", p.y + (n.depth === 0 ? 30 : 24));
      label.setAttribute("text-anchor", "middle");
      label.setAttribute("fill", risk >= 0.6 ? "var(--crit)" : "var(--ink)");
      label.setAttribute("font-size", "11");
      label.setAttribute("font-family", "JetBrains Mono, monospace");
      label.textContent = n.id.length > 18 ? n.id.slice(0, 16) + "…" : n.id;
      g.appendChild(label);
      svg.appendChild(g);
    });

    // side panel
    const v = document.getElementById("graph-verdict");
    v.textContent = d.verdict; v.className = "verdict " + d.level;
    document.getElementById("graph-scores").innerHTML = `
      <div class="row"><span class="dot">📦</span> per-package (XGBoost): <b>${d.xgb_score}</b></div>
      <div class="row"><span class="dot">🕸️</span> dependency graph (GNN): <b>${d.graph_score}</b></div>
      <div class="row"><span class="dot">➕</span> graph contribution: <b>${d.graph_contribution >= 0 ? "+" : ""}${d.graph_contribution}</b> (log-odds)</div>
      <div class="row"><span class="dot">🎯</span> combined: <b style="color:${riskColor(d.combined_score)}">${d.combined_score}</b></div>`;
    const why = document.getElementById("graph-why");
    if (d.graph_score >= 0.6 && d.worst_dependency) {
      why.innerHTML = `<div class="row critical">🔴 Dependency <b>${d.worst_dependency}</b> scores ${d.graph_score} — the chain is compromised even though <b>${d.root}</b> itself looks clean (XGBoost ${d.xgb_score}). This is what per-package scoring misses.</div>`;
    } else if (!d.gnn_available) {
      why.innerHTML = `<div class="row">Train the GNN (<code>training/train_gnn.py</code>) to enable graph scoring. Showing per-package scores only.</div>`;
    } else {
      why.innerHTML = `<div class="row ok">🟢 No malicious dependencies detected in the neighbourhood.</div>`;
    }
  }
})();
