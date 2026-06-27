#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const sourcePath = path.join(repoRoot, "vyql/bindings/packages/top1000.sources.json");
const outPath = path.join(repoRoot, "vyql/bindings/packages/top1000.snapshot.json");

const sources = JSON.parse(await fs.readFile(sourcePath, "utf8"));
const baseUrl = sources.source.base_url.replace(/\/$/, "");
const target = Number(sources.source.target_per_language || 1000);
const perPage = 100;
const mailto = process.env.VYQL_ECOSYSTEMS_MAILTO || "";

function apiUrl(registry, page) {
  const url = new URL(`${baseUrl}/registries/${encodeURIComponent(registry)}/packages`);
  url.searchParams.set("sort", sources.source.rank_by || "dependent_repos_count");
  url.searchParams.set("order", sources.source.order || "desc");
  url.searchParams.set("per_page", String(perPage));
  url.searchParams.set("page", String(page));
  if (mailto) url.searchParams.set("mailto", mailto);
  return url;
}

async function fetchJson(url) {
  const res = await fetch(url, {
    headers: {
      "accept": "application/json",
      "user-agent": mailto ? `vyql-package-coverage (mailto:${mailto})` : "vyql-package-coverage"
    }
  });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText} for ${url}`);
  }
  return await res.json();
}

function includePackage(pkg, cfg) {
  const name = String(pkg.name || "");
  if (!name) return false;
  if (!cfg.name_prefixes || cfg.name_prefixes.length === 0) return true;
  const lower = name.toLowerCase();
  return cfg.name_prefixes.some((prefix) => lower.startsWith(String(prefix).toLowerCase()));
}

function packageRow(pkg, registry, rank) {
  return {
    rank,
    name: String(pkg.name || ""),
    registry,
    ecosystem: String(pkg.ecosystem || pkg.registry?.ecosystem || ""),
    dependent_repos_count: Number(pkg.dependent_repos_count || 0),
    downloads: Number(pkg.downloads || 0)
  };
}

async function collectLanguage(language, cfg) {
  const byName = new Map();
  const errors = [];
  for (const registry of cfg.registries || []) {
    let fetched = 0;
    const maxPages = Math.max(10, Math.ceil((target * 4) / perPage));
    for (let page = 1; page <= maxPages && byName.size < target; page++) {
      try {
        const rows = await fetchJson(apiUrl(registry, page));
        if (!Array.isArray(rows) || rows.length === 0) break;
        fetched += rows.length;
        for (const pkg of rows) {
          if (!includePackage(pkg, cfg)) continue;
          const name = String(pkg.name || "");
          const score = Number(pkg.dependent_repos_count || pkg.downloads || 0);
          const prev = byName.get(name);
          if (!prev || score > prev.score) {
            byName.set(name, { score, pkg, registry });
          }
          if (byName.size >= target) break;
        }
      } catch (err) {
        errors.push({ registry, page, error: String(err.message || err) });
        break;
      }
    }
    if (fetched === 0 && !errors.some((e) => e.registry === registry)) {
      errors.push({ registry, page: 1, error: "no packages returned" });
    }
  }
  const ranked = [...byName.values()]
    .sort((a, b) => {
      const aDep = Number(a.pkg.dependent_repos_count || 0);
      const bDep = Number(b.pkg.dependent_repos_count || 0);
      if (bDep !== aDep) return bDep - aDep;
      const aDownloads = Number(a.pkg.downloads || 0);
      const bDownloads = Number(b.pkg.downloads || 0);
      if (bDownloads !== aDownloads) return bDownloads - aDownloads;
      return String(a.pkg.name || "").localeCompare(String(b.pkg.name || ""));
    })
    .slice(0, target)
    .map((entry, i) => packageRow(entry.pkg, entry.registry, i + 1));
  return {
    registries: cfg.registries || [],
    project_types: cfg.project_types || [],
    target,
    count: ranked.length,
    complete: ranked.length >= target,
    errors,
    packages: ranked
  };
}

const languages = {};
for (const [language, cfg] of Object.entries(sources.languages || {})) {
  console.error(`fetching ${language}...`);
  languages[language] = await collectLanguage(language, cfg);
}

const snapshot = {
  schema: 1,
  generated_at: new Date().toISOString(),
  source: sources.source,
  project_types: sources.project_types,
  languages
};

await fs.writeFile(outPath, JSON.stringify(snapshot, null, 2) + "\n");
console.error(`wrote ${path.relative(repoRoot, outPath)}`);
