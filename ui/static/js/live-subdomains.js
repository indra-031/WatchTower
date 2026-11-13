/* ============================================
   Live Subdomains — DNS-resolved hosts with IPs
   ============================================ */

const FRESH_WINDOW_MS = 24 * 60 * 60 * 1000;

const state = {
  all: [],
  filtered: [],
  page: 1,
  perPage: 50,
  sortField: "host",
  sortAsc: true,
  filters: { program: "", q: "", freshOnly: false },
};

// ---------- Helpers ----------

function isFreshTs(ts) {
  if (!ts) return false;
  const t = new Date(String(ts).replace(" ", "T")).getTime();
  if (isNaN(t)) return false;
  return Date.now() - t <= FRESH_WINDOW_MS;
}

// ---------- Data loading ----------

async function loadLiveData() {
  const programs = await apiFetch("/api/programs");
  const programList = Object.keys(programs).sort();

  const perProgram = await Promise.all(
    programList.map(async (pn) => {
      const safe = encodeURIComponent(pn);
      const [livesRes, subsRes] = await Promise.all([
        apiFetch(`/api/lives/${safe}`).catch(() => ({ lives: [] })),
        apiFetch(`/api/subdomains/${safe}`).catch(() => ({ subdomains: [] })),
      ]);

      const subMap = {};
      for (const s of subsRes.subdomains || []) {
        subMap[s.subdomain] = s;
      }

      const rows = [];
      for (const l of livesRes.lives || []) {
        const sd = subMap[l.host] || {};
        const ips = Array.isArray(l.ips) ? l.ips : [];
        rows.push({
          program: pn,
          host: l.host || "",
          domain: l.domain || "",
          ips: ips,
          ipCount: ips.length,
          cname: l.cname || "",
          first_seen: sd.first_seen || "",
          last_seen: l.last_seen || "",
          sources: Array.isArray(sd.sources) ? sd.sources : [],
        });
      }
      return rows;
    })
  );

  return perProgram.flat();
}

// ---------- Filter / sort ----------

function applyFiltersAndSort() {
  const { program, q, freshOnly } = state.filters;
  const ql = q.trim().toLowerCase();

  state.filtered = state.all.filter((it) => {
    if (program && it.program !== program) return false;
    if (freshOnly && !isFreshTs(it.last_seen)) return false;

    if (ql) {
      const hay = [it.host, it.domain, it.cname, ...it.ips, ...it.sources]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(ql)) return false;
    }
    return true;
  });

  const { sortField, sortAsc } = state;
  state.filtered.sort((a, b) => {
    if (sortField === "ipCount") {
      return sortAsc ? a.ipCount - b.ipCount : b.ipCount - a.ipCount;
    }

    if (sortField === "ip") {
      // Sort by first IP (numeric)
      const toInt = (ip) =>
        String(ip || "")
          .split(".")
          .reduce((acc, n) => (acc << 8) + (parseInt(n, 10) || 0), 0) >>> 0;
      const va = toInt(a.ips[0]);
      const vb = toInt(b.ips[0]);
      return sortAsc ? va - vb : vb - va;
    }

    if (sortField === "last_seen") {
      const va = a.last_seen || "";
      const vb = b.last_seen || "";
      return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    }

    const va = String(a[sortField] || "").toLowerCase();
    const vb = String(b[sortField] || "").toLowerCase();
    return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
}

// ---------- Rendering ----------

function buildIpsCell(it) {
  const td = document.createElement("td");
  td.style.whiteSpace = "normal";
  td.style.padding = "10px 14px";

  const wrap = document.createElement("div");
  wrap.className = "source-list";

  if (it.ips.length === 0) {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    wrap.appendChild(em);
    td.appendChild(wrap);
    return td;
  }

  const MAX_VISIBLE = 4;
  const visible = it.ips.slice(0, MAX_VISIBLE);
  const hidden = it.ips.slice(MAX_VISIBLE);

  for (const ip of visible) {
    const tag = document.createElement("span");
    tag.className = "ip-tag";
    tag.textContent = ip;
    wrap.appendChild(tag);
  }

  if (hidden.length) {
    const more = document.createElement("button");
    more.type = "button";
    more.className = "source-more";
    more.textContent = `+${hidden.length}`;
    more.title = hidden.join(", ");
    more.addEventListener("click", (e) => {
      e.stopPropagation();
      for (const ip of hidden) {
        const tag = document.createElement("span");
        tag.className = "ip-tag";
        tag.textContent = ip;
        wrap.insertBefore(tag, more);
      }
      more.remove();
    });
    wrap.appendChild(more);
  }

  td.appendChild(wrap);
  return td;
}

function buildSourcesCell(it) {
  const td = document.createElement("td");
  td.style.whiteSpace = "normal";
  td.style.padding = "10px 14px";

  const wrap = document.createElement("div");
  wrap.className = "source-list";

  if (it.sources.length === 0) {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    wrap.appendChild(em);
    td.appendChild(wrap);
    return td;
  }

  const MAX_VISIBLE = 2;
  const visible = it.sources.slice(0, MAX_VISIBLE);
  const hidden = it.sources.slice(MAX_VISIBLE);

  for (const s of visible) {
    const t = document.createElement("span");
    const cls = String(s).toLowerCase().replace(/[^a-z0-9_-]/g, "_");
    t.className = `source-tag source-${cls}`;
    t.textContent = s;
    wrap.appendChild(t);
  }

  if (hidden.length) {
    const more = document.createElement("button");
    more.type = "button";
    more.className = "source-more";
    more.textContent = `+${hidden.length}`;
    more.title = hidden.join(", ");
    more.addEventListener("click", (e) => {
      e.stopPropagation();
      for (const s of hidden) {
        const t = document.createElement("span");
        const cls = String(s).toLowerCase().replace(/[^a-z0-9_-]/g, "_");
        t.className = `source-tag source-${cls}`;
        t.textContent = s;
        wrap.insertBefore(t, more);
      }
      more.remove();
    });
    wrap.appendChild(more);
  }

  td.appendChild(wrap);
  return td;
}

function buildRow(it) {
  const tr = document.createElement("tr");

  // Host
  const tdHost = document.createElement("td");
  tdHost.className = "cell-host";
  const a = document.createElement("a");
  a.href = `https://${it.host}`;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  a.textContent = it.host;
  a.title = it.host;
  tdHost.appendChild(a);

  if (isFreshTs(it.last_seen)) {
    const dot = document.createElement("span");
    dot.className = "fresh-dot";
    dot.title = "Fresh (last 24h)";
    tdHost.appendChild(dot);
  }
  tr.appendChild(tdHost);

  // Program
  const tdProg = document.createElement("td");
  const progSpan = document.createElement("span");
  progSpan.className = "program-tag";
  progSpan.textContent = it.program;
  tdProg.appendChild(progSpan);
  tr.appendChild(tdProg);

  // IPs
  tr.appendChild(buildIpsCell(it));

  // IP count
  const tdCount = document.createElement("td");
  tdCount.style.textAlign = "center";
  const sc = document.createElement("span");
  sc.className = "source-count";
  sc.textContent = String(it.ipCount);
  tdCount.appendChild(sc);
  tr.appendChild(tdCount);

  // CNAME
  const tdCname = document.createElement("td");
  tdCname.className = "cell-muted";
  tdCname.textContent = it.cname || "—";
  tdCname.title = it.cname || "";
  tdCname.style.maxWidth = "220px";
  tdCname.style.overflow = "hidden";
  tdCname.style.textOverflow = "ellipsis";
  tr.appendChild(tdCname);

  // Sources
  tr.appendChild(buildSourcesCell(it));

  // First seen
  const tdFirst = document.createElement("td");
  tdFirst.className = "cell-muted";
  tdFirst.textContent = relativeTime(it.first_seen);
  tdFirst.title = it.first_seen || "";
  tr.appendChild(tdFirst);

  // Last seen
  const tdLast = document.createElement("td");
  tdLast.className = "cell-muted";
  tdLast.textContent = relativeTime(it.last_seen);
  tdLast.title = it.last_seen || "";
  tr.appendChild(tdLast);

  return tr;
}

function syncSortIndicators() {
  document.querySelectorAll("th.sortable").forEach((th) => {
    const arrow = th.querySelector(".sort-arrow");
    if (!arrow) return;
    if (th.dataset.sort === state.sortField) {
      arrow.textContent = state.sortAsc ? "↑" : "↓";
      arrow.classList.add("active");
    } else {
      arrow.textContent = "⇅";
      arrow.classList.remove("active");
    }
  });
}

function render() {
  const tbody = document.getElementById("tbody");
  const paginContainer = document.getElementById("pagination-container");
  const countEl = document.getElementById("count-badge");
  const tableWrap = document.getElementById("table-wrapper");
  const emptyEl = document.getElementById("empty-state");

  tbody.innerHTML = "";
  paginContainer.innerHTML = "";

  syncSortIndicators();

  if (state.filtered.length === 0) {
    tableWrap.style.display = "none";
    emptyEl.style.display = "block";
    if (countEl) countEl.textContent = "0";
    return;
  }

  tableWrap.style.display = "block";
  emptyEl.style.display = "none";

  const start = (state.page - 1) * state.perPage;
  const slice = state.filtered.slice(start, start + state.perPage);
  for (const it of slice) tbody.appendChild(buildRow(it));

  const totalPages = Math.ceil(state.filtered.length / state.perPage);
  const pager = renderPagination(
    state.page,
    totalPages,
    state.filtered.length,
    state.perPage,
    (p) => {
      state.page = p;
      render();
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  );
  paginContainer.appendChild(pager);

  if (countEl) countEl.textContent = state.filtered.length.toLocaleString();
}

// ---------- Controls ----------

function populateProgramSelect(programs) {
  const sel = document.getElementById("filter-program");
  for (const pn of Object.keys(programs).sort()) {
    const opt = document.createElement("option");
    opt.value = pn;
    opt.textContent = pn;
    sel.appendChild(opt);
  }
}

function bindControls() {
  document.getElementById("filter-program").addEventListener("change", (e) => {
    state.filters.program = e.target.value;
    state.page = 1;
    applyFiltersAndSort();
    render();
  });

  document.getElementById("filter-search").addEventListener(
    "input",
    debounce((e) => {
      state.filters.q = e.target.value;
      state.page = 1;
      applyFiltersAndSort();
      render();
    }, 200)
  );

  document.getElementById("filter-fresh").addEventListener("change", (e) => {
    state.filters.freshOnly = e.target.checked;
    state.page = 1;
    applyFiltersAndSort();
    render();
  });

  document.getElementById("sort-field").addEventListener("change", (e) => {
    const [field, dir] = e.target.value.split("-");
    state.sortField = field;
    state.sortAsc = dir === "asc";
    state.page = 1;
    applyFiltersAndSort();
    render();
  });

  document.getElementById("page-size").addEventListener("change", (e) => {
    state.perPage = parseInt(e.target.value, 10);
    state.page = 1;
    render();
  });

  document.querySelectorAll("th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const field = th.dataset.sort;
      if (state.sortField === field) {
        state.sortAsc = !state.sortAsc;
      } else {
        state.sortField = field;
        state.sortAsc = field === "last_seen" ? false : true;
      }
      const sel = document.getElementById("sort-field");
      if (sel) sel.value = `${state.sortField}-${state.sortAsc ? "asc" : "desc"}`;
      state.page = 1;
      applyFiltersAndSort();
      render();
    });
  });
}

async function boot() {
  bindControls();

  try {
    const programs = await apiFetch("/api/programs");
    populateProgramSelect(programs);

    const items = await loadLiveData();
    state.all = items;
    state.filtered = items;
    applyFiltersAndSort();

    const loadingEl = document.getElementById("loading-state");
    if (loadingEl) loadingEl.remove();

    render();
  } catch (e) {
    console.error("Live subdomains load failed:", e);
    document.getElementById("table-wrapper").style.display = "none";
    const emptyEl = document.getElementById("empty-state");
    emptyEl.innerHTML = `
      <div class="empty-state-icon">⚠️</div>
      <div class="empty-state-title">Failed to load live subdomains</div>
      <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
    `;
    emptyEl.style.display = "block";
  }
}

document.addEventListener("DOMContentLoaded", boot);