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
document.querySelectorAll(".chip").forEach((c) =>
  c.addEventListener("click", () => { $("#pkg-input").value = c.dataset.pkg; runCheck(c.dataset.pkg); }));

async function runCheck(pkg) {
  if (!pkg) return;
  $("#check-error").classList.add("hidden");
  const btn = $(".run-btn"); btn.textContent = "···"; btn.classList.add("loading");
  try {
    const resp = await fetch("/api/check", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: pkg }),
    });
    if (!resp.ok) throw new Error((await resp.json()).detail || resp.statusText);
    renderCheck(await resp.json());
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

async function runScan(file) {
  const fd = new FormData(); fd.append("file", file);
  try {
    const resp = await fetch("/api/scan", { method: "POST", body: fd });
    if (!resp.ok) throw new Error((await resp.json()).detail || resp.statusText);
    renderScan(await resp.json());
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
