/* PackageGuard HUD — awareness page interactivity (Sem 8 redesign).
   Three self-contained bits: a scrolling incident ticker, an expandable incident
   timeline (accordion), a "spot the typosquat" mini-game, and flippable protocol
   cards. No dependencies, no fetches — everything here is static/curated content
   already reviewed for accuracy, wired up for interaction only. */

(function () {
  const view = document.getElementById("awareness");
  if (!view) return;

  // ---- ticker: cycles through real incident names in the banner ----
  const track = document.getElementById("aw-ticker-track");
  if (track) {
    const items = [
      "2018 · event-stream · maintainer handoff",
      "2021 · ua-parser-js · account takeover",
      "2021 · coa & rc · account takeover",
      "2022 · node-ipc · protestware",
      "2025 · chalk / debug / ansi-styles · phishing",
      "2025 · nx · credential exfiltration",
    ];
    const line = items.concat(items).map((t) => `<span>▸ ${t}</span>`).join("");
    track.innerHTML = line;
  }

  // ---- incident timeline accordion ----
  const cards = view.querySelectorAll(".tl2");
  cards.forEach((card) => {
    card.addEventListener("click", () => {
      const isOpen = card.getAttribute("data-open") === "true";
      cards.forEach((c) => c.setAttribute("data-open", "false"));
      card.setAttribute("data-open", isOpen ? "false" : "true");
    });
  });

  // ---- protocol flip cards ----
  const protos = view.querySelectorAll(".proto");
  protos.forEach((p) => {
    p.addEventListener("click", (e) => {
      if (e.target.closest(".proto-link[data-goto]")) return; // let nav links work
      const flipped = p.getAttribute("data-flip") === "true";
      p.setAttribute("data-flip", flipped ? "false" : "true");
    });
  });
  // (tab-navigation for .proto-link[data-goto] is already wired globally by app.js)

  // ---- spot-the-typosquat mini-game ----
  // Pairs mined from PackageGuard's own known_malware.json — every "fake" name here
  // is a real, historically-confirmed malicious package on npm.
  const PAIRS = [
    { real: "colors", fake: "co1ors", tell: "the letter L was swapped for the digit 1 — nearly invisible in most fonts." },
    { real: "cross-env", fake: "crossenv", tell: "the hyphen was simply dropped — a name a tired dev types from memory." },
    { real: "lodash", fake: "loadsh", tell: "two letters swapped (loadsh vs lodash) — a one-key typo away from the real thing." },
    { real: "twilio", fake: "twilio-npm", tell: "a plausible-sounding suffix tacked onto a trusted brand name." },
  ];

  let order = [];
  let round = 0;
  let score = 0;
  let locked = false;

  const roundEl = document.getElementById("tsq-round-n");
  const scoreEl = document.getElementById("tsq-score");
  const pairEl = document.getElementById("tsq-pair");
  const fbEl = document.getElementById("tsq-feedback");

  function shuffle(arr) {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  function renderRound() {
    if (!pairEl) return;
    locked = false;
    fbEl.textContent = "";
    fbEl.className = "tsq-feedback";
    if (round >= order.length) {
      pairEl.innerHTML = `<div class="tsq-done">DEBRIEF COMPLETE — <b>${score}/${order.length}</b> correct.
        ${score === order.length ? "Perfect scan. You'd have caught every one of these live." : "Re-run the drill any time — pattern recognition is a muscle."}
        </div><button type="button" class="tsq-again" id="tsq-again">▸ RUN IT AGAIN</button>`;
      roundEl.textContent = String(order.length);
      const again = document.getElementById("tsq-again");
      again && again.addEventListener("click", startGame);
      return;
    }
    roundEl.textContent = String(round + 1);
    const pair = order[round];
    const left = Math.random() < 0.5;
    const a = left ? pair.real : pair.fake;
    const b = left ? pair.fake : pair.real;
    pairEl.innerHTML = `
      <button type="button" class="tsq-opt" data-answer="${a === pair.real}">${a}</button>
      <span class="tsq-vs">vs</span>
      <button type="button" class="tsq-opt" data-answer="${b === pair.real}">${b}</button>
    `;
    pairEl.querySelectorAll(".tsq-opt").forEach((btn) => {
      btn.addEventListener("click", () => pick(btn, pair));
    });
  }

  function pick(btn, pair) {
    if (locked) return;
    locked = true;
    const correct = btn.getAttribute("data-answer") === "true";
    pairEl.querySelectorAll(".tsq-opt").forEach((b) => {
      b.classList.add(b.getAttribute("data-answer") === "true" ? "tsq-right" : "tsq-wrong");
      b.disabled = true;
    });
    if (correct) {
      score++;
      scoreEl.textContent = String(score);
      fbEl.textContent = `✓ CORRECT — ${pair.tell}`;
      fbEl.className = "tsq-feedback tsq-ok";
    } else {
      fbEl.textContent = `✕ THAT WAS THE ATTACK — ${pair.tell}`;
      fbEl.className = "tsq-feedback tsq-bad";
    }
    setTimeout(() => { round++; renderRound(); }, 1600);
  }

  function startGame() {
    order = shuffle(PAIRS);
    round = 0;
    score = 0;
    scoreEl.textContent = "0";
    renderRound();
  }

  if (pairEl) startGame();
})();
