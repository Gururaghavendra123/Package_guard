/* PackageGuard HUD — dependency graph panel (Sem 8).
   Radial layout: root at centre, dependencies on rings by depth. Nodes coloured by GNN risk;
   the poisoned node pulses and its chain to the root glows. Labels appear on hover (plus a
   permanent label on the root and any malicious node) so a big tree never turns into a wall of
   overlapping text. Pure SVG — no external libraries, works offline. */

(function () {
  const NS = "http://www.w3.org/2000/svg";
  const W = 720, H = 560, CX = 360, CY = 275;
  const RINGS = [0, 130, 235];  // radius per depth

  const form = document.getElementById("graph-form");
  if (!form) return;
  const input = document.getElementById("graph-input");

  form.addEventListener("submit", (e) => { e.preventDefault(); runGraph(input.value.trim()); });
  window.__graphRun = runGraph;  // let app.js example chips trigger a graph run

  function color(v) {
    if (v == null) return "var(--ink-dim)";
    if (v >= 0.8) return "var(--crit)";
    if (v >= 0.5) return "var(--warn)";
    return "var(--ok)";
  }

  async function runGraph(pkg) {
    if (!pkg) return;
    document.getElementById("graph-error").classList.add("hidden");
    const btn = form.querySelector(".run-btn"); btn.textContent = "···"; btn.classList.add("loading");
    const steps = ["FETCHING 2-HOP NEIGHBOURHOOD", "BUILDING DEPENDENCY SUBGRAPH",
      "COMPUTING NODE FEATURES", "GRAPHSAGE MESSAGE PASSING", "PROPAGATING RISK",
      "STACKING XGBOOST + GNN"];
    const work = async () => {
      const r = await fetch("/api/graph", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: pkg }),
      });
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
      return r.json();
    };
    try {
      const data = window.withLoader ? await window.withLoader("MAPPING DEPENDENCY GRAPH", steps, work) : await work();
      render(data);
    } catch (err) {
      document.getElementById("graph-result").classList.add("hidden");
      const b = document.getElementById("graph-error"); b.textContent = "⚠ " + err.message; b.classList.remove("hidden");
    } finally { btn.textContent = "MAP ▸"; btn.classList.remove("loading"); }
  }

  function layout(nodes) {
    // group by depth, order depth>0 nodes so children sit near their parent's angle
    const pos = {};
    const byDepth = {};
    nodes.forEach((n) => { (byDepth[n.depth] = byDepth[n.depth] || []).push(n); });
    (byDepth[0] || []).forEach((n) => { pos[n.id] = { x: CX, y: CY }; });
    Object.keys(byDepth).map(Number).filter((d) => d > 0).sort().forEach((d) => {
      const row = byDepth[d];
      const R = RINGS[Math.min(d, RINGS.length - 1)];
      row.forEach((n, i) => {
        const a = (i / row.length) * Math.PI * 2 - Math.PI / 2;
        pos[n.id] = { x: CX + R * Math.cos(a), y: CY + R * Math.sin(a), a };
      });
    });
    return pos;
  }

  function render(d) {
    document.getElementById("graph-result").classList.remove("hidden");

    if (d.not_found) {
      document.getElementById("graph-svg").innerHTML =
        `<text x="360" y="270" text-anchor="middle" fill="var(--ink-dim)" font-size="14" font-family="Chakra Petch, monospace">✕ NOT FOUND ON NPM REGISTRY</text>`;
      document.getElementById("graph-mode").textContent = "· no such package";
      const v = document.getElementById("graph-verdict");
      v.textContent = "NOT FOUND"; v.className = "verdict low";
      document.getElementById("graph-story")?.classList.add("hidden");
      document.getElementById("graph-scores").innerHTML =
        `<div class="row dim">The package <b>${d.root}</b> does not exist on the npm registry, so there is no dependency graph to analyse.</div>`;
      document.getElementById("graph-why").innerHTML =
        `<div class="row">Try a real package (e.g. <code>express</code>) or a curated demo above.</div>`;
      return;
    }

    document.getElementById("graph-mode").textContent =
      d.demo ? "· curated poisoned-chain demo" : (d.gnn_available ? `· live · ${d.node_count} nodes` : "· GNN model not trained");

    const svg = document.getElementById("graph-svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.innerHTML = "";
    const pos = layout(d.nodes);
    const byId = Object.fromEntries(d.nodes.map((n) => [n.id, n]));
    const riskOf = (n) => (n.gnn_score != null ? n.gnn_score : n.xgb_score);

    // edges (curved toward centre); highlight the chain leading to a malicious node
    d.edges.forEach((e) => {
      const a = pos[e.source], b = pos[e.target];
      if (!a || !b) return;
      const risky = riskOf(byId[e.target]) >= 0.8 || riskOf(byId[e.source]) >= 0.8;
      const mx = (a.x + b.x) / 2 + (CX - (a.x + b.x) / 2) * 0.18;
      const my = (a.y + b.y) / 2 + (CY - (a.y + b.y) / 2) * 0.18;
      const path = document.createElementNS(NS, "path");
      path.setAttribute("d", `M${a.x} ${a.y} Q${mx} ${my} ${b.x} ${b.y}`);
      path.setAttribute("fill", "none");
      path.setAttribute("stroke", risky ? "var(--crit)" : "var(--line-hot)");
      path.setAttribute("stroke-width", risky ? "2.5" : "1");
      path.setAttribute("opacity", risky ? "0.9" : "0.25");
      if (risky) path.setAttribute("class", "edge-pulse");
      svg.appendChild(path);
    });

    // nodes
    d.nodes.forEach((n) => {
      const p = pos[n.id];
      const risk = riskOf(n);
      const isRoot = n.depth === 0;
      const mal = risk >= 0.8;
      const g = document.createElementNS(NS, "g");
      g.setAttribute("class", "gnode");
      g.style.cursor = "pointer";

      const c = document.createElementNS(NS, "circle");
      c.setAttribute("cx", p.x); c.setAttribute("cy", p.y);
      c.setAttribute("r", isRoot ? 20 : 9);
      c.setAttribute("fill", isRoot ? "var(--panel-2)" : "var(--panel)");
      c.setAttribute("stroke", color(risk));
      c.setAttribute("stroke-width", isRoot ? 3.5 : 2.5);
      if (mal) c.setAttribute("class", "node-pulse");
      g.appendChild(c);

      if (isRoot) {  // small shield glyph in the root
        const t = document.createElementNS(NS, "text");
        t.setAttribute("x", p.x); t.setAttribute("y", p.y + 6);
        t.setAttribute("text-anchor", "middle"); t.setAttribute("font-size", "16");
        t.textContent = "🛡"; g.appendChild(t);
      }

      // permanent label only for root + malicious nodes (avoids the wall of text)
      if (isRoot || mal) {
        const lbl = document.createElementNS(NS, "text");
        const dy = p.y > CY ? 34 : -18;
        lbl.setAttribute("x", p.x); lbl.setAttribute("y", p.y + (isRoot ? 40 : dy));
        lbl.setAttribute("text-anchor", "middle");
        lbl.setAttribute("fill", mal ? "var(--crit)" : "var(--cyan)");
        lbl.setAttribute("font-size", isRoot ? "13" : "11");
        lbl.setAttribute("font-family", "Chakra Petch, monospace");
        lbl.setAttribute("font-weight", "600");
        lbl.textContent = n.id.length > 22 ? n.id.slice(0, 20) + "…" : n.id;
        g.appendChild(lbl);
      }

      g.addEventListener("mouseenter", () => showTip(n, risk, p));
      g.addEventListener("mouseleave", hideTip);
      svg.appendChild(g);
    });

    // side panel
    const v = document.getElementById("graph-verdict");
    v.textContent = d.verdict; v.className = "verdict " + d.level;
    const story = document.getElementById("graph-story");
    if (story) {
      if (d.story) { story.textContent = "▸ " + d.story; story.classList.remove("hidden"); }
      else story.classList.add("hidden");
    }
    window.bumpMetrics && window.bumpMetrics(d.node_count || 1, d.poisoned ? 1 : 0);
    if (d.poisoned) window.flashThreat && window.flashThreat();
    document.getElementById("graph-scores").innerHTML = `
      <div class="row"><span class="dot">📦</span> per-package (XGBoost): <b>${d.xgb_score}</b></div>
      <div class="row"><span class="dot">🕸️</span> dependency graph (GNN): <b>${d.graph_score}</b></div>
      <div class="row"><span class="dot">➕</span> graph contribution: <b>${d.graph_contribution >= 0 ? "+" : ""}${d.graph_contribution}</b> <span class="dim">log-odds</span></div>
      <div class="row"><span class="dot">🎯</span> combined: <b style="color:${color(d.combined_score)}">${d.combined_score}</b></div>`;
    const why = document.getElementById("graph-why");
    if (d.poisoned && d.worst_dependency) {
      why.innerHTML = `<div class="row critical">🔴 Dependency <b>${d.worst_dependency}</b> scores ${d.worst_score} — the chain is compromised even though <b>${d.root}</b> itself looks clean (XGBoost ${d.xgb_score}). <span class="dim">This is exactly what per-package scoring misses.</span></div>`;
    } else if (!d.gnn_available) {
      why.innerHTML = `<div class="row">Train the GNN (<code>training/train_gnn.py</code>) to enable graph scoring. Showing per-package scores only.</div>`;
    } else {
      why.innerHTML = `<div class="row ok">🟢 No malicious dependencies in the neighbourhood. Hover any node to inspect it.</div>`;
    }
  }

  // ---- hover tooltip ----
  let tip;
  function ensureTip() {
    if (tip) return tip;
    tip = document.createElement("div");
    tip.className = "graph-tip hidden";
    document.getElementById("graph-result").appendChild(tip);
    return tip;
  }
  function showTip(n, risk, p) {
    const el = ensureTip();
    const svg = document.getElementById("graph-svg");
    const rect = svg.getBoundingClientRect();
    const sx = rect.left + (p.x / W) * rect.width;
    const sy = rect.top + (p.y / H) * rect.height;
    el.innerHTML = `<b>${n.id}</b><br>depth ${n.depth}${n.allowlisted ? " · allowlisted" : ""}<br>
      xgb ${n.xgb_score}${n.gnn_score != null ? ` · gnn <span style="color:${color(risk)}">${n.gnn_score}</span>` : ""}`;
    el.style.left = (sx - document.getElementById("graph-result").getBoundingClientRect().left) + "px";
    el.style.top = (sy - document.getElementById("graph-result").getBoundingClientRect().top - 12) + "px";
    el.classList.remove("hidden");
  }
  function hideTip() { if (tip) tip.classList.add("hidden"); }
})();
