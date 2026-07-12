/* PackageGuard HUD — talks to /api/check and /api/scan, renders the console. */

const $ = (sel) => document.querySelector(sel);
const ARC_LEN = Math.PI * 80; // gauge arc length
const NEEDLE_R = 66;

/* ---------- chrome: clock, tabs, health ---------- */
function tickClock() {
  $("#clock").textContent = new Date().toLocaleTimeString("en-GB");
}
setInterval(tickClock, 1000); tickClock();

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    tab.classList.add("active");
    $("#" + tab.dataset.tab).classList.add("active");
  });
});

fetch("/api/health").then((r) => r.ok ? r.json() : Promise.reject())
  .then(() => { $("#net-led").className = "led led-ok"; })
  .catch(() => { $("#net-led").className = "led led-warn"; });

/* ---------- CHECK ---------- */
const form = $("#check-form");
form.addEventListener("submit", (e) => { e.preventDefault(); runCheck($("#pkg-input").value.trim()); });
document.querySelectorAll(".chip[data-pkg]").forEach((c) =>
  c.addEventListener("click", () => { $("#pkg-input").value = c.dataset.pkg; runCheck(c.dataset.pkg); }));

async function runCheck(pkg) {
  if (!pkg) return;
  $("#check-error").classList.add("hidden");
  const btn = $(".run-btn"); btn.textContent = "···"; btn.classList.add("loading");
  try {
    const data = await withLoader(
      "SCANNING PACKAGE",
      ["QUERYING NPM REGISTRY", "EXTRACTING 5 FEATURES", "XGBOOST INFERENCE",
       "SHAP ATTRIBUTION", "CROSS-CHECK MALWARE DB", "COMPILING VERDICT"],
      async () => {
        const resp = await fetch("/api/check", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ package: pkg }),
        });
        if (!resp.ok) throw new Error((await resp.json()).detail || resp.statusText);
        return resp.json();
      });
    renderCheck(data);
  } catch (err) {
    $("#check-result").classList.add("hidden");
    const box = $("#check-error");
    box.textContent = "⚠ " + err.message; box.classList.remove("hidden");
  } finally {
    btn.textContent = "RUN ▸"; btn.classList.remove("loading");
  }
}

function renderCheck(d) {
  $("#check-result").classList.remove("hidden");

  if (d.not_found) {
    $("#arc-fg").style.strokeDashoffset = ARC_LEN;   // empty gauge
    $("#needle").setAttribute("x2", "100"); $("#needle").setAttribute("y2", "100");
    $("#score-num").textContent = "—";
    const v0 = $("#verdict"); v0.textContent = "NOT FOUND"; v0.className = "verdict low";
    $("#source-badge").textContent = `${d.name} — not on npm registry`;
    $("#bars").innerHTML = `<div class="row dim" style="padding:20px 0">Package <b>${d.name}</b> does not exist on the npm registry, so there is nothing to score. Try a real package name.</div>`;
    $("#signal-feed").innerHTML = `<div class="row"><span class="dot">✕</span> <span class="ok">${d.signals[0].text}</span></div>`;
    window.bumpMetrics && window.bumpMetrics(1, 0);
    return;
  }

  // gauge arc + needle + score count-up
  $("#arc-fg").style.strokeDashoffset = ARC_LEN * (1 - d.score);
  tweenNeedle(d.score);

  const verdict = $("#verdict");
  verdict.textContent = d.verdict;
  verdict.className = "verdict " + d.level;
  $("#source-badge").textContent = `SOURCE: ${d.source.toUpperCase()} · ${d.name}@${d.version}`;

  // attribution bars
  const bars = $("#bars"); bars.innerHTML = "";
  d.features.forEach((f) => {
    const risk = f.contribution >= 0;
    const width = Math.min(50, (Math.abs(f.contribution) / 3) * 50);
    const row = document.createElement("div");
    row.className = "bar-row";
    row.innerHTML = `
      <div class="bar-head"><span class="lbl">${f.label}</span>
        <span class="val">${f.contribution >= 0 ? "+" : ""}${f.contribution.toFixed(2)}</span></div>
      <div class="bar-track"><div class="bar-fill ${risk ? "risk" : "safe"}"></div></div>`;
    bars.appendChild(row);
    requestAnimationFrame(() => { row.querySelector(".bar-fill").style.width = width + "%"; });
  });

  // signal feed
  const feed = $("#signal-feed"); feed.innerHTML = "";
  d.signals.forEach((s, i) => {
    const dot = { critical: "🔴", warn: "🟡", ok: "🟢" }[s.level] || "•";
    const row = document.createElement("div");
    row.className = "row";
    row.style.animationDelay = i * 0.08 + "s";
    row.innerHTML = `<span class="dot">${dot}</span> <span class="${s.level}">${s.text}</span>`;
    feed.appendChild(row);
  });

  const danger = d.level === "critical" || d.level === "high";
  window.bumpMetrics && window.bumpMetrics(1, danger ? 1 : 0);
  if (danger) window.flashThreat && window.flashThreat();
}

function tweenNeedle(target) {
  const needle = $("#needle"), num = $("#score-num");
  const start = performance.now(), dur = 1100;
  function frame(now) {
    const t = Math.min(1, (now - start) / dur);
    const e = 1 - Math.pow(1 - t, 3);            // easeOutCubic
    const s = e * target;
    const a = Math.PI * (1 - s);
    needle.setAttribute("x2", (100 + NEEDLE_R * Math.cos(a)).toFixed(2));
    needle.setAttribute("y2", (100 - NEEDLE_R * Math.sin(a)).toFixed(2));
    num.textContent = s.toFixed(2);
    if (t < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

/* ---------- SCAN ---------- */
const dz = $("#dropzone"), fileInput = $("#file-input");
dz.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => fileInput.files[0] && runScan(fileInput.files[0]));
["dragover", "dragenter"].forEach((ev) =>
  dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
["dragleave", "drop"].forEach((ev) =>
  dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
dz.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) runScan(f); });

const SCAN_STEPS = ["PARSING LOCKFILE", "ENUMERATING DEPENDENCIES", "RESOLVING TRANSITIVE TREE",
  "CROSS-REFERENCING MALWARE DB", "SCORING SEVERITY", "GENERATING REMEDIATION"];

async function runScan(file) {
  const fd = new FormData(); fd.append("file", file);
  try {
    const data = await withLoader("SCANNING PROJECT", SCAN_STEPS, async () => {
      const resp = await fetch("/api/scan", { method: "POST", body: fd });
      if (!resp.ok) throw new Error((await resp.json()).detail || resp.statusText);
      return resp.json();
    });
    renderScan(data);
  } catch (err) {
    $("#scan-issues").innerHTML = `<div class="errline">⚠ ${err.message}</div>`;
  }
}

function renderScan(d) {
  const sum = $("#scan-summary"); sum.classList.remove("hidden");
  sum.innerHTML = `
    <div class="stat total"><div class="n">${d.total_dependencies}</div><div class="k">DEPENDENCIES</div></div>
    <div class="stat crit"><div class="n">${d.summary.critical}</div><div class="k">CRITICAL</div></div>
    <div class="stat high"><div class="n">${d.summary.high}</div><div class="k">HIGH</div></div>`;

  window.bumpMetrics && window.bumpMetrics(d.total_dependencies, d.issue_count);
  if (d.issue_count > 0) window.flashThreat && window.flashThreat();
  const box = $("#scan-issues");
  if (!d.issues.length) {
    box.innerHTML = `<div class="ok-line">✓ No known-malicious dependencies found in ${d.total_dependencies} packages.</div>`;
    return;
  }
  box.innerHTML = d.issues.map((i) => `
    <div class="issue ${i.severity}">
      <div class="sev">${i.severity.toUpperCase()}</div>
      <h4>${i.name}@${i.version}</h4>
      <div class="path">↳ ${i.path}</div>
      <div>${i.reason}</div>
      ${i.replacement ? `<div class="repl">→ replace with: ${i.replacement}</div>` : ""}
      <ol>${i.remediation.map((s) => `<li>${s}</li>`).join("")}</ol>
    </div>`).join("");
}

/* ---------- dynamic examples (generated by the backend, fresh each load) ---------- */
const KIND_CLASS = { clean: "chip-clean", typosquat: "chip-bad", malware: "chip-bad", demo: "chip-demo" };

function fillChips(id, items, onClick, labelFn) {
  const box = $("#" + id);
  if (!box) return;
  box.innerHTML = "";
  items.forEach((e) => {
    const b = document.createElement("button");
    b.className = "chip " + (KIND_CLASS[e.kind] || "");
    b.textContent = labelFn(e);
    b.addEventListener("click", () => onClick(e));
    box.appendChild(b);
  });
}

async function loadExamples() {
  try {
    const ex = await (await fetch("/api/examples")).json();
    fillChips("check-chips", ex.check, (e) => { $("#pkg-input").value = e.pkg; runCheck(e.pkg); }, (e) => e.pkg);
    fillChips("graph-chips", ex.graph, (e) => { $("#graph-input").value = e.pkg; window.__graphRun && window.__graphRun(e.pkg); }, (e) => e.label || e.pkg);
    fillChips("scan-chips", ex.scan, (e) => runScanSample(e.path), (e) => e.label || e.path);
  } catch { /* offline / no server — chips just stay empty */ }
}

async function runScanSample(name) {
  try {
    const data = await withLoader("SCANNING PROJECT", SCAN_STEPS, async () => {
      const r = await fetch("/api/scan-sample?name=" + encodeURIComponent(name));
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
      return r.json();
    });
    renderScan(data);
  } catch (err) {
    $("#scan-issues").innerHTML = `<div class="errline">⚠ ${err.message}</div>`;
  }
}

document.getElementById("check-shuffle")?.addEventListener("click", loadExamples);
document.getElementById("graph-shuffle")?.addEventListener("click", loadExamples);
loadExamples();

/* ---------- living HUD atmosphere ---------- */
// drifting particles
(function particles() {
  const box = document.getElementById("particles");
  if (!box) return;
  for (let i = 0; i < 30; i++) {
    const p = document.createElement("i");
    p.style.left = Math.random() * 100 + "%";
    const s = 1 + Math.random() * 2;
    p.style.width = p.style.height = s + "px";
    p.style.animationDuration = 9 + Math.random() * 15 + "s";
    p.style.animationDelay = -Math.random() * 22 + "s";
    if (Math.random() < 0.22) { p.style.background = "var(--ok)"; p.style.boxShadow = "0 0 6px var(--ok)"; }
    else if (Math.random() < 0.12) { p.style.background = "var(--crit)"; p.style.boxShadow = "0 0 6px var(--crit)"; }
    box.appendChild(p);
  }
})();

// scrolling threat-intel ticker (real incidents)
(function ticker() {
  const track = document.getElementById("ticker-track");
  if (!track) return;
  const facts = [
    "SUPPLY-CHAIN THREAT INTEL",
    "<b>event-stream</b> compromised — bitcoin wallet theft, 2018",
    "<b>ua-parser-js</b> hijacked — cryptominer + password stealer, 2021",
    "450K+ malicious packages published last year",
    "<b>coa</b> &amp; <b>rc</b> maintainer accounts hijacked, Nov 2021",
    "self-propagating <b>Shai-Hulud</b> worm spreads through poisoned chains",
    "<b>node-ipc</b> protestware wiped files by geolocation, 2022",
    "typosquatting = 60%+ of historical npm supply-chain attacks",
    "<span class='tk-ok'>PackageGuard flags the danger before you install</span>",
  ];
  const line = facts.map((f) => `<span>◦&nbsp;&nbsp;${f}</span>`).join("");
  track.innerHTML = line + line; // duplicated for a seamless loop
})();

// animated metric counters
let _scanned = 0, _threats = 0;
function animCount(id, from, to) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = performance.now();
  (function f(now) {
    const t = Math.min(1, (now - start) / 550);
    el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - t, 3)));
    if (t < 1) requestAnimationFrame(f);
  })(performance.now());
}
window.bumpMetrics = function (scanned, threats) {
  animCount("m-scanned", _scanned, _scanned + scanned); _scanned += scanned;
  if (threats > 0) {
    animCount("m-threats", _threats, _threats + threats); _threats += threats;
    const m = document.querySelector(".metric.threat");
    if (m) { m.classList.add("flash"); setTimeout(() => m.classList.remove("flash"), 500); }
  }
};

// GNN status LED
fetch("/api/health").then((r) => r.json())
  .then((h) => { if (!h.gnn) { const l = document.getElementById("gnn-led"); if (l) l.className = "led led-warn"; } })
  .catch(() => {});

// ---------- military boot sequence (~3.8s) ----------
(function boot() {
  const el = document.getElementById("boot");
  if (!el) return;
  const log = document.getElementById("boot-log");
  const bar = document.getElementById("boot-bar-fill");
  const pct = document.getElementById("boot-pct");
  const msg = document.getElementById("boot-msg");
  const steps = [
    "POWER-ON SELF TEST", "LOADING THREAT DATABASE",
    "MOUNTING KNOWN-MALWARE SIGNATURES", "CALIBRATING XGBOOST SCORER",
    "INITIALIZING GRAPHSAGE NEURAL NET", "ESTABLISHING NPM REGISTRY UPLINK",
    "ARMING THREAT CONSOLE",
  ];
  let i = 0;
  const iv = setInterval(() => {
    if (i < steps.length) {
      const r = document.createElement("div");
      r.className = "row";
      r.innerHTML = `&gt; ${steps[i]} <span class="bl-ok">[OK]</span>`;
      log.appendChild(r);
      const p = Math.round(((i + 1) / steps.length) * 100);
      bar.style.width = p + "%"; pct.textContent = p; msg.textContent = steps[i];
      i++;
    } else {
      clearInterval(iv);
      msg.textContent = "SYSTEM READY";
      setTimeout(() => {
        el.classList.add("gone");
        setTimeout(() => { el.remove(); const inp = document.getElementById("pkg-input"); if (inp) inp.focus(); }, 700);
      }, 550);
    }
  }, 470);
})();

// ---------- reusable action loading sequence ----------
async function withLoader(title, steps, work) {
  const ov = document.getElementById("action-loader");
  const stepsEl = document.getElementById("loader-steps");
  const bar = document.getElementById("al-bar");
  if (!ov) return work();
  document.getElementById("loader-title").textContent = title;
  stepsEl.innerHTML = ""; bar.style.width = "0";
  ov.classList.remove("hidden");
  let i = 0;
  const iv = setInterval(() => {
    if (i < steps.length) {
      const d = document.createElement("div");
      d.className = "lstep";
      d.innerHTML = `&gt; ${steps[i]} <span class="lstep-ok">[OK]</span>`;
      stepsEl.appendChild(d);
      bar.style.width = Math.round(((i + 1) / steps.length) * 100) + "%";
      i++;
    }
  }, 2200 / steps.length);
  try {
    const [res] = await Promise.all([work(), new Promise((r) => setTimeout(r, 2350))]);
    return res;
  } finally {
    clearInterval(iv);
    ov.classList.add("hidden");
  }
}
window.withLoader = withLoader;

// red threat-flash vignette
window.flashThreat = function () {
  let v = document.getElementById("threat-vignette");
  if (!v) { v = document.createElement("div"); v.id = "threat-vignette"; v.className = "threat-vignette"; document.body.appendChild(v); }
  v.classList.remove("on"); void v.offsetWidth; v.classList.add("on");
};

// ---------- ambient widgets: status meters + drifting coords ----------
document.querySelectorAll(".hud-meter").forEach((m) => m.style.setProperty("--w", (m.dataset.v || 60) + "%"));
setInterval(() => {
  const c = document.getElementById("hud-coord");
  if (c) c.textContent = `${(Math.random() * 89).toFixed(4)}N · ${(Math.random() * 179).toFixed(4)}W`;
}, 2600);

// ---------- QoL: keyboard tab shortcuts + auto-focus the active tab's input ----------
const TAB_INPUT = { check: "#pkg-input", graph: "#graph-input" };
function focusTab(name) {
  const sel = TAB_INPUT[name];
  if (sel) { const el = document.querySelector(sel); if (el) setTimeout(() => el.focus(), 60); }
}
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => focusTab(t.dataset.tab)));
document.addEventListener("keydown", (e) => {
  if (["INPUT", "TEXTAREA"].includes(e.target.tagName)) return;
  const map = { 1: "check", 2: "scan", 3: "graph" };
  const target = map[e.key];
  if (target) { const tab = document.querySelector(`.tab[data-tab="${target}"]`); if (tab) tab.click(); }
});
