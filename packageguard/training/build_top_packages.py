"""Build a real top-~1000 npm package list for the name-similarity (typosquat) feature.

`core/features.py` shipped with a ~40-name stub ("A tiny stand-in for 'top-1000 npm
packages'"). That stub is too small to catch most real typosquats — confirmed by Phase 2
training, where 0 of 98 real labeled malicious packages had name_similarity >= 0.5 even
after fixing sampling bias, because they typosquat popular packages outside the stub's 40.

This pulls real popularity-ranked names from npm's live search API across a broad spread
of generic search terms, dedupes, sorts by npm's own popularity score, and writes the
result to `src/packageguard/data/top_packages.json`. `features.py` loads this file if
present, falling back to the small embedded list otherwise (keeps cold-start/offline safe).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx

OUT_PATH = Path(__file__).resolve().parent.parent / "src" / "packageguard" / "data" / "top_packages.json"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"

# Seed with real, well-known package names (not generic dictionary words). Verified this
# matters: searching text="http" does NOT reliably surface "express" even with popularity
# weighting — relevance still requires a real text match. Searching text="express" does
# return "express" plus its real neighbors (swagger-ui-express, express-session, ...),
# which is exactly the breadth we want. Seeds below are common-knowledge, widely-known
# open-source project names (this is prior knowledge about POPULAR packages, not a claim
# about malicious data, so no fabrication risk).
SEARCH_TERMS = [
    "react", "vue", "angular", "svelte", "express", "koa", "fastify", "nestjs",
    "lodash", "underscore", "ramda", "chalk", "colors", "commander", "yargs", "inquirer",
    "axios", "request", "node-fetch", "got", "webpack", "babel", "rollup", "vite",
    "esbuild", "eslint", "prettier", "jest", "mocha", "chai", "typescript", "moment",
    "dayjs", "dotenv", "cors", "body-parser", "mongoose", "sequelize", "socket.io",
    "redux", "next", "nuxt", "gatsby", "graphql", "apollo", "prisma", "knex", "pg",
    "mysql", "redis", "rimraf", "glob", "semver", "uuid", "nanoid", "ws", "nodemon",
    "ts-node", "concurrently", "cross-env", "husky", "lint-staged", "jsonwebtoken",
    "bcrypt", "passport", "helmet", "multer", "sharp", "puppeteer", "playwright",
    "cheerio", "jsdom", "lodash.debounce", "classnames", "styled-components", "tailwindcss",
    "sass", "postcss", "autoprefixer", "npm", "yarn", "pnpm", "turbo",
]


def main() -> None:
    ranked: dict[str, float] = {}
    for term in SEARCH_TERMS:
        try:
            # Force ranking by raw popularity (downloads/stars), not blended relevance —
            # unweighted search buries famous root packages under keyword-matching noise
            # (verified: default search missed lodash/express/chalk entirely).
            resp = httpx.get(NPM_SEARCH, params={
                "text": term, "size": 100,
                "popularity": 1.0, "quality": 0.0, "maintenance": 0.0,
            }, timeout=10)
            resp.raise_for_status()
            for obj in resp.json().get("objects", []):
                name = obj["package"]["name"]
                score = obj.get("score", {}).get("detail", {}).get("popularity", 0.0)
                # keep the highest observed popularity score per name across search terms
                ranked[name] = max(ranked.get(name, 0.0), score)
        except httpx.HTTPError as e:
            print(f"  [warn] search '{term}' failed: {e}")
        time.sleep(0.4)  # bumped again after still hitting 429s at 0.25s

    # No artificial cap: many results tie at popularity==1.0 (npm's score is coarse), so a
    # fixed slice silently drops real matches depending on stable-sort tie order (confirmed
    # — "chalk" was dropped this way despite matching its own search). Membership lookup at
    # runtime is O(1) regardless of set size, so keep everything collected.
    names = [name for name, _ in sorted(ranked.items(), key=lambda kv: kv[1], reverse=True)]

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(names, indent=2), encoding="utf-8")
    print(f"Wrote {len(names)} real npm package names (union across {len(SEARCH_TERMS)} "
          f"searches) -> {OUT_PATH}")
    print(f"Sample (top 15): {names[:15]}")


if __name__ == "__main__":
    main()
