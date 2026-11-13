/* ============================================
   Programs — card grid with per-program stats
   ============================================ */

const state = {
  all: [],
  filtered: [],
  sortField: "name",
  sortAsc: true,
  filters: { q: "", onlyWithData: false },
};

// ---------- Data loading ----------

async function loadProgramsData() {
  const [programs, stats] = await Promise.all([
    apiFetch("/api/programs"),
    apiFetch("/api/stats"),
  ]);

  const detail = (stats && stats.programs_detail) || {};
  const items = [];

  for (const [dir, prog] of Object.entries(programs)) {
    const d = detail[dir] || {};
    items.push({
      dir: dir,
      name: dir,
      scopes: Array.isArray(prog.scopes) ? prog.scopes : [],
      ooscope: Array.isArray(prog.ooscope) ? prog.ooscope : [],
      cidr: Array.isArray(prog.cidr) ? prog.cidr : [],
      asn: Array.isArray(prog.asn) ? prog.asn : [],
      ips: Array.isArray(prog.ip) ? prog.ip : [],
      stats: {
        subdomains: d.subdomains || 0,
        lives: d.lives || 0,
        http: d.http || 0,
        portscan: d.portscan || 0,
        nuclei: d.nuclei || 0,
      },
      sources: d.sources || {},
      totalCount:
        (d.subdomains || 0) +
        (d.lives || 0) +
        (d.http || 0) +
        (d.nuclei || 0),
    });
  }

  return items;
}

// ---------- Filter / sort ----------

function applyFiltersAndSort() {
  const ql = state.filters.q.trim().toLowerCase();
  const onlyWithData = state.filters.onlyWithData;

  state.filtered = state.all.filter((it) => {
    if (onlyWithData && it.totalCount === 0) return false;

    if (ql) {
      const hay = [
        it.name,
        ...it.scopes,
        ...it.ooscope,
        ...it.cidr,
        ...it.asn,
        ...it.ips,
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(ql)) return false;
    }
    return true;
  });

  const { sortField, sortAsc } = state;
  state.filtered.sort((a, b) => {
    if (sortField === "total") {
      return sortAsc ? a.totalCount - b.totalCount : b.totalCount - a.totalCount;
    }
    if (sortField === "subdomains") {
      return sortAsc
        ? a.stats.subdomains - b.stats.subdomains
        : b.stats.subdomains - a.stats.subdomains;
    }
    const va = String(a[sortField] || "").toLowerCase();
    const vb = String(b[sortField] || "").toLowerCase();
    return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
}

// ---------- Rendering ----------

function makeTag(text, cls) {
  const el = document.createElement("span");
  el.className = cls;
  el.textContent = text;
  return el;
}

function buildSection(label, tags, emptyText) {
  if (!tags || tags.length === 0) {
    if (!emptyText) return null;
    const sec = document.createElement("div");
    sec.className = "program-section";
    const lbl = document.createElement("div");
    lbl.className = "program-section-label";
    lbl.textContent = label;
    sec.appendChild(lbl);
    const empty = document.createElement("span");
    empty.className = "cell-muted";
    empty.textContent = emptyText;
    sec.appendChild(empty);
    return sec;
  }

  const sec = document.createElement("div");
  sec.className = "program-section";

  const lbl = document.createElement("div");
  lbl.className = "program-section-label";
  lbl.textContent = label;
  sec.appendChild(lbl);

  const list = document.createElement("div");
  list.className = "scope-tag-list";
  for (const [text, cls] of tags) {
    list.appendChild(makeTag(text, cls));
  }
  sec.appendChild(list);

  return sec;
}

function buildSourcesSection(sources) {
  const entries = Object.entries(sources).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return null;

  const sec = document.createElement("div");
  sec.className = "program-section";

  const lbl = document.createElement("div");
  lbl.className = "program-section-label";
  lbl.textContent = "Sources";
  sec.appendChild(lbl);

  const list = document.createElement("div");
  list.className = "program-sources";
  for (const [src, count] of entries) {
    const t = document.createElement("span");
    t.className = "program-source";
    t.textContent = src;
    const c = document.createElement("span");
    c.className = "program-source-count";
    c.textContent = String(count);
    t.appendChild(c);
    list.appendChild(t);
  }
  sec.appendChild(list);

  return sec;
}

function buildStat(value, label) {
  const wrap = document.createElement("div");
  wrap.className = "program-stat";

  const v = document.createElement("div");
  v.className = "program-stat-value" + (value === 0 ? " zero" : "");
  v.textContent = Number(value).toLocaleString();
  wrap.appendChild(v);

  const l = document.createElement("div");
  l.className = "program-stat-label";
  l.textContent = label;
  wrap.appendChild(l);

  return wrap;
}

function buildCard(it) {
  const card = document.createElement("div");
  card.className = "program-card";

  // Header
  const header = document.createElement("div");
  header.className = "program-card-header";

  const nameGroup = document.createElement("div");
  nameGroup.className = "program-name-group";
  const nameEl = document.createElement("div");
  nameEl.className = "program-name";
  nameEl.textContent = it.name;
  nameEl.title = it.name;
  nameGroup.appendChild(nameEl);
  header.appendChild(nameGroup);

  const dirBadge = document.createElement("span");
  dirBadge.className = "program-dir-badge";
  dirBadge.textContent = it.dir;
  dirBadge.title = `database/${it.dir}/`;
  header.appendChild(dirBadge);

  card.appendChild(header);

  // Stats
  const stats = document.createElement("div");
  stats.className = "program-stats";
  stats.appendChild(buildStat(it.stats.subdomains, "Subs"));
  stats.appendChild(buildStat(it.stats.lives, "Live"));
  stats.appendChild(buildStat(it.stats.http, "HTTP"));
  stats.appendChild(buildStat(it.stats.portscan, "Ports"));
  stats.appendChild(buildStat(it.stats.nuclei, "Nuclei"));
  card.appendChild(stats);

  // Scopes
  const scopeSection = buildSection(
    "In Scope",
    it.scopes.map((s) => [s, "scope-tag"]),
    it.scopes.length === 0 ? "—" : null
  );
  if (scopeSection) card.appendChild(scopeSection);

  // OOS
  if (it.ooscope.length > 0) {
    const oosSection = buildSection(
      "Out of Scope",
      it.ooscope.map((s) => [s, "oos-tag"]),
      null
    );
    if (oosSection) card.appendChild(oosSection);
  }

  // CIDRs
  if (it.cidr.length > 0) {
    const cidrSection = buildSection(
      "CIDRs",
      it.cidr.map((s) => [s, "cidr-tag"]),
      null
    );
    if (cidrSection) card.appendChild(cidrSection);
  }

  // ASNs
  if (it.asn.length > 0) {
    const asnSection = buildSection(
      "ASNs",
      it.asn.map((s) => [s, "asn-tag"]),
      null
    );
    if (asnSection) card.appendChild(asnSection);
  }

  // IPs
  if (it.ips.length > 0) {
    const ipSection = buildSection(
      "IPs",
      it.ips.map((s) => [s, "ip-tag-sm"]),
      null
    );
    if (ipSection) card.appendChild(ipSection);
  }

  // Sources
  const srcSection = buildSourcesSection(it.sources);
  if (srcSection) card.appendChild(srcSection);

  return card;
}

function render() {
  const grid = document.getElementById("programs-grid");
  const countEl = document.getElementById("count-badge");
  const emptyEl = document.getElementById("empty-state");

  grid.innerHTML = "";

  if (state.filtered.length === 0) {
    emptyEl.style.display = "block";
    if (countEl) countEl.textContent = "0";
    return;
  }

  emptyEl.style.display = "none";
  for (const it of state.filtered) grid.appendChild(buildCard(it));

  if (countEl) countEl.textContent = state.filtered.length.toLocaleString();
}

// ---------- Controls ----------

function bindControls() {
  document.getElementById("filter-search").addEventListener(
    "input",
    debounce((e) => {
      state.filters.q = e.target.value;
      applyFiltersAndSort();
      render();
    }, 200)
  );

  document.getElementById("filter-has-data").addEventListener("change", (e) => {
    state.filters.onlyWithData = e.target.checked;
    applyFiltersAndSort();
    render();
  });

  document.getElementById("sort-field").addEventListener("change", (e) => {
    const [field, dir] = e.target.value.split("-");
    state.sortField = field;
    state.sortAsc = dir === "asc";
    applyFiltersAndSort();
    render();
  });
}

async function boot() {
  bindControls();

  try {
    const items = await loadProgramsData();
    state.all = items;
    state.filtered = items;
    applyFiltersAndSort();

    const loadingEl = document.getElementById("loading-state");
    if (loadingEl) loadingEl.remove();

    render();
  } catch (e) {
    console.error("Programs load failed:", e);
    document.getElementById("programs-grid").innerHTML = "";
    const emptyEl = document.getElementById("empty-state");
    emptyEl.innerHTML = `
      <div class="empty-state-icon">⚠️</div>
      <div class="empty-state-title">Failed to load programs</div>
      <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
    `;
    emptyEl.style.display = "block";
  }
}

document.addEventListener("DOMContentLoaded", boot);