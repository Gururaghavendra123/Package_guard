"""Phase 6 — held-out-unknown poisoned-chain benchmark.

Builds a benchmark of REAL (not synthetic) poisoned-chain cases from the registry cache: a
clean-looking parent package that has a transitive dependency which is (a) labeled malicious
in BKC/Datadog, and (b) still scores suspicious on its OWN current metadata (filters out
package *names* that were briefly compromised long ago but are now safe, thriving, hugely
popular packages — e.g. the real Sept-2025 chalk/debug/ansi-styles incident; BKC's flat name
list has no version info, so it labels the *name* forever, not just the bad version).

Critically: none of the malicious dependency names found here are in our own
`known_malware.json` — they were never manually curated in. That makes this a genuine
**held-out-unknown** simulation: a deterministic DB-lookup baseline cannot know about them,
exactly like it wouldn't know about a real zero-day. This is the fair test of whether the GNN
generalizes beyond "does the DB already know this name" — the concern flagged since the
original project plan.

Usage: python training/build_heldout_benchmark.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from packageguard.core.engine import _POPULAR  # noqa: E402

GRAPH = Path(__file__).resolve().parent / "graph_dataset.npz"
XGB_MODEL = Path(__file__).resolve().parent.parent / "src" / "packageguard" / "models" / "xgboost_model.joblib"
OUT = Path(__file__).resolve().parent / "heldout_benchmark.json"
SUSPICION_THRESHOLD = 0.5  # the malicious dep must still look risky on its OWN current metadata


def main() -> None:
    d = np.load(GRAPH, allow_pickle=True)
    ids, y, x, ei = d["ids"], d["y"], d["x"], d["edge_index"]
    xgb = joblib.load(XGB_MODEL)
    xgb_score = xgb.predict_proba(x)[:, 1]
    idx = {name: i for i, name in enumerate(ids)}
    src, dst = ei[0], ei[1]

    # Positive cases: clean parent -> genuinely-suspicious malicious-labeled dependency.
    seen = set()
    positives = []
    for a, b in zip(src, dst):
        if y[a] == 0 and y[b] == 1 and ids[a] not in _POPULAR and xgb_score[b] >= SUSPICION_THRESHOLD:
            pair = (str(ids[a]), str(ids[b]))
            if pair not in seen:
                seen.add(pair)
                positives.append({
                    "parent": pair[0], "malicious_dep": pair[1],
                    "parent_own_xgb": round(float(xgb_score[a]), 3),
                    "dep_own_xgb": round(float(xgb_score[b]), 3),
                })

    poisoned_parents = {p["parent"] for p in positives}
    # Negative controls: clean parents with NO malicious neighbour at all.
    mal_neighbours: dict[str, bool] = {}
    for a, b in zip(src, dst):
        if y[b] == 1:
            mal_neighbours[str(ids[a])] = True

    negatives = []
    rng = np.random.RandomState(42)
    clean_idx = [i for i in range(len(ids)) if y[i] == 0 and str(ids[i]) not in mal_neighbours
                and str(ids[i]) not in poisoned_parents]
    rng.shuffle(clean_idx)
    for i in clean_idx[: len(positives)]:
        negatives.append({"parent": str(ids[i]), "own_xgb": round(float(xgb_score[i]), 3)})

    print(f"Positive (real poisoned-chain) cases: {len(positives)}")
    print(f"Negative (clean, no malicious neighbour) controls: {len(negatives)}")

    from packageguard.core.remediation import find_issues
    from packageguard.core.lockfile import Dependency
    db_hits = [p for p in positives if find_issues([Dependency(p["malicious_dep"], "*", p["malicious_dep"])])]
    print(f"Of the {len(positives)} positive cases, {len(db_hits)} malicious deps are already "
          f"in known_malware.json (should be 0 — confirms held-out-unknown status).")

    OUT.write_text(json.dumps({"positives": positives, "negatives": negatives,
                               "suspicion_threshold": SUSPICION_THRESHOLD}, indent=2), encoding="utf-8")
    print(f"\nSaved -> {OUT}")


if __name__ == "__main__":
    main()
