# PackageGuard — How to Present (Review Guide)

Everything you need to walk in confident. Read this once, rehearse the demo twice.

---

## 1. The 30-second pitch (memorize this)

> "Every app today is built from thousands of small code packages downloaded off the internet.
> Attackers sneak *malicious* packages in — and developers install them by accident. This causes
> real breaches every week. **PackageGuard** is like a metal detector for those packages: before
> you install one, it tells you how dangerous it is and *why*; and it can scan your whole project
> to find compromised packages already inside, with exact steps to fix them. It runs as a command
> line tool for developers and as this security dashboard for everyone else."

Then open the dashboard. **Let the demo do the talking.**

---

## 2. The live demo (this is what wins the room)

Open a terminal:

```
cd C:\Users\pguru\Desktop\final_year_project\packageguard
.venv\Scripts\activate
packageguard serve
```

Browser opens the HUD. Do these **four** things, in order, narrating one line each:

1. **Type `co1ors` → RUN.**
   Say: *"This is a fake version of the popular 'colors' package — a classic trick."*
   → Gauge swings red, **DO NOT INSTALL**, reasons light up.

2. **Type `express` → RUN.**
   Say: *"A real, trusted package — the tool should stay calm."*
   → Gauge green, **LIKELY SAFE**. (Contrast sells it.)

3. **Type `loadash` → RUN.**
   Say: *"A typo of 'lodash'. This one is NOT in any database — the machine-learning model
   catches it on its own."*
   → Red, **DO NOT INSTALL**. (This proves the ML actually works, not just a lookup.)

4. **Click the SCAN tab → drop `packageguard/sample/package-lock.json`.**
   Say: *"Now scanning a whole project."*
   → 3 malware cards (event-stream, flatmap-stream, malicious-logger) with severity + fix steps.

5. **(Optional strong contrast) Drop `packageguard/sample_clean/package-lock.json`.**
   Say: *"And a clean project — no false alarms."*
   → "✓ No known-malicious dependencies found." (Shows it doesn't just cry wolf.)

**That's the whole demo.** Red for bad, green for good, a network scan, and a clear "here's how to
fix it." Non-technical people understand it instantly.

### Verified demo inputs (all tested — use these exact ones)
- **Clean → SAFE (green):** `express`, `lodash`, `react`, `chalk`, `axios`
- **Typosquat caught by the ML model → DO NOT INSTALL (red):** `loadash`, `expres`, `axioss`, `reactt`
  (pick any; if one is slow to load, use the next — that's why there are four)
- **Known malware from the database → DO NOT INSTALL:** `co1ors`, `event-stream@3.3.6`, `eslint-scope@3.7.2`
- **Legit scoped packages (proves no false alarms):** `@types/node`, `@babel/core` → SAFE
- **Scan dirty project:** `sample/` → 3 issues · **Scan clean project:** `sample_clean/` → 0 issues

**If the internet dies during the demo:** the tool still runs offline (it falls back gracefully).
`co1ors` and the scan still work. Just say *"it's running in offline mode right now."*

---

## 3. Slide structure (6 slides)

1. **Problem** — supply-chain attacks; one real headline (e.g. the event-stream incident). "Existing
   tools only catch already-known threats."
2. **Solution** — what PackageGuard does (check + scan), one screenshot of the HUD.
3. **How it works** — the one-diagram architecture (engine → CLI + web; features → model → verdict).
4. **The data + model** — real datasets, 5 features, XGBoost + SHAP explainability.
5. **Results — honestly** — the confounder table (0.987 → 0.90). *This slide makes you look like a
   real researcher.* (See §5 for why.)
6. **Live demo + roadmap** — do the demo; then "Sem 8 adds a graph AI for the hardest cases."

---

## 4. Answering questions (including the BS ones)

Keep answers **short and plain**. You don't need to out-jargon anyone.

**"Does it actually work / is it real?"**
> "Yes — live demo, and it's a real trained model on real malware data, not hardcoded."

**"How accurate is it?"**
> "About 90% on our headline metric. And I can tell you exactly *why* it's 90 and not a fake 99 —
> which is actually the interesting part." (Then pivot to the confounder story — it impresses.)

**"Why isn't it 99%? / That seems low."** (This is the key BS-question judo move.)
> "We could have shown 98%, but it would have been fake. Our first model scored 98% by cheating —
> it had learned 'new package = dangerous' instead of actually detecting malware. We caught that,
> fixed it, and the honest number is ~90%. A model that admits its real accuracy is more
> trustworthy than one that inflates it." — **Faculty respect this enormously.**

**"What's the machine learning doing exactly?"** (for the ML-literate)
> "XGBoost, gradient-boosted trees, on 5 metadata features per package, with SHAP for per-prediction
> explanations. Headline metric is PR-AUC because the classes are imbalanced."

**"What about typosquatting?"** (someone read one article)
> "Good question — we found typosquats are actually rare in modern malware, only about 44 in 51,000
> samples. The bulk is brand-new malware with made-up names. So we handle typosquats but don't
> over-rely on them — the data told us where the real threat is."

**"Is this safe to run? Did you download malware?"**
> "No. We only downloaded the *list of names* of malicious packages, never the actual malicious
> code. That was a deliberate safety decision."

**"What's novel / what's your contribution?"**
> "Two things: an honest, confounder-controlled evaluation of metadata-based detection — showing
> what it can and can't do — and, in Sem 8, a graph neural network for the hijacked-package case
> that metadata alone can't catch."

**"Why should anyone use this over npm audit?"**
> "`npm audit` only knows about *already-disclosed* vulnerabilities. We score *unknown* packages
> before they're ever reported. Different job."

**"What's left / what's next?"**
> "Semester 8: a graph-based AI model for the hardest 3% of attacks — hijacked popular packages —
> plus a live dependency-graph visualization in the dashboard."

**If you genuinely don't know an answer:**
> "That's a fair question — I'd want to check before giving you a wrong answer." (Never bluff. It's
> safer than a made-up answer they can poke holes in.)

---

## 5. Why the "honest 90%" story is your secret weapon

Non-technical faculty can't judge your code. But they *can* judge whether you sound credible. A
student who says "98%, it's great!" invites "prove it" and collapses under one hard question. A
student who says "it looked like 98% but that was a confounder, the real number is 90% and here's
why" sounds like a *scientist*. You control the narrative — and you'll have the answer ready for the
follow-up, because you understand it. That's the whole game with a non-technical panel.

---

## 6. One-line summary for your report cover

> "PackageGuard: a machine-learning tool that flags dangerous software packages before installation
> and scans projects for compromised dependencies — delivered as a developer CLI and a security
> dashboard, with an honest, confounder-controlled evaluation."
