/* ============================================
   Advanced Search — unified view across all data
   ============================================ */

const state = {
  all: [],
  filtered: [],
  page: 1,
  perPage: 50,
  sortField: "time",
  sortAsc: false,
  filters: {
    types: new Set(["subdomain", "http", "cdn", "portscan", "vhost", "nuclei"]),
    program: "",
    cdn: "all",       // all | cdn | direct
    severity: "all",  // all | critical | high | medium | low
    statusClass: "all", // all | 2xx | 3xx | 4xx | 5xx
    fresh: false,     // last 24h
    q: "",
  },
};

const FRESH_WINDOW_MS = 24 * 60 * 60 * 1000;

// ---------- Helpers ----------

function isFresh(ts) {
  if (!ts) return false;
  const t = new Date(ts.replace(" ", "T")).getTime();
  if (isNaN(t)) return false;
  return Date.now() - t <= FRESH_WINDOW_MS;
}

function statusClassOf(code) {
  const s = String(code || "");
  if (s.startsWith("2")) return "2xx";
  if (s.startsWith("3")) return "3xx";
  if (s.startsWith("4")) return "4xx";
  if (s.startsWith("5")) return "5xx";
  return "na";
}

function severityBadgeClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(s)) {
    return `badge-sev-${s}`;
  }
  return "badge-sev-info";
}

// ---------- Data loading ----------

async function loadAll() {
  const programs = await apiFetch("/api/programs");
  const rows = [];

  for (const pn of Object.keys(programs).sort()) {
    const safe = encodeURIComponent(pn);

    // Subdomains
    try {
      const d = await apiFetch(`/api/subdomains/${safe}`);
      for (const s of d.subdomains || []) {
        const sources = Array.isArray(s.sources) ? s.sources : [];
        rows.push({
          type: "subdomain",
          host: s.subdomain || "",
          program: pn,
          status: "",
          details: `Sources: ${sources.join(", ") || "—"}`,
          url: `https://${s.subdomain || ""}`,
          time: s.first_seen || s.last_seen || "",
          raw: s,
        });
      }
    } catch (_) {}

    // HTTP
    try {
      const d = await apiFetch(`/api/http/${safe}`);
      for (const h of d.http_services || []) {
        const techs = Array.isArray(h.tech) ? h.tech : [];
        rows.push({
          type: "http",
          host: h.host || "",
          program: pn,
          status: h.status_code != null ? String(h.status_code) : "",
          details: [h.title, techs.slice(0, 3).join(", ")]
            .filter(Boolean)
            .join(" · ") || "—",
          url: h.url || "",
          time: h.last_seen || "",
          raw: h,
        });
      }
    } catch (_) {}

    // CDN
    try {
      const d = await apiFetch(`/api/cdn/${safe}`);
      for (const [host, info] of Object.entries(d.hosts || {})) {
        const provider = info.provider || "None";
        const isCdn = !!info.cdn;
        rows.push({
          type: "cdn",
          host,
          program: pn,
          status: isCdn ? "proxied" : "direct",
          details: isCdn
            ? `Provider: ${provider}`
            : `Direct · ${(info.ips || []).slice(0, 2).join(", ")}`,
          url: info.url || `https://${host}`,
          time: info.last_seen || "",
          raw: info,
        });
      }
    } catch (_) {}

    // Portscan
    try {
      const d = await apiFetch(`/api/portscan/${safe}`);
      for (const h of d.hosts || []) {
        const ports = Array.isArray(h.ports) ? h.ports : [];
        rows.push({
          type: "portscan",
          host: h.host || "",
          program: pn,
          status: String(ports.length),
          details: ports.slice(0, 8).join(", ") +
                   (ports.length > 8 ? ` +${ports.length - 8}` : ""),
          url: "",
          time: h.last_seen || "",
          raw: h,
        });
      }
    } catch (_) {}

    // VHost
    try {
      const d = await apiFetch(`/api/vhost/${safe}`);
      for (const info of Object.values(d.vhosts || {})) {
        rows.push({
          type: "vhost",
          host: info.vhost || "",
          program: pn,
          status: info.status != null ? String(info.status) : "",
          details: `via ${info.host || "?"}@${info.ip || "?"}${
            info.title ? " · " + info.title.slice(0, 50) : ""
          }`,
          url: `https://${info.vhost || ""}`,
          time: info.last_seen || "",
          raw: info,
        });
      }
    } catch (_) {}

    // Nuclei
    try {
      const d = await apiFetch(`/api/nuclei/${safe}`);
      for (const f of d.findings || []) {
        rows.push({
          type: "nuclei",
          host: f.host || "",
          program: pn,
          status: f.severity || "",
          details: `[${f.template || "?"}] ${f.name || ""}`,
          url: f.matched_at || "",
          time: f.timestamp || f.first_seen || "",
          raw: f,
        });
      }
    } catch (_) {}
  }

  return rows;
}

// ---------- Filter / sort ----------

function applyFiltersAndSort() {
  const f = state.filters;
  const ql = f.q.trim().toLowerCase();

  state.filtered = state.all.filter((r) => {
    if (!f.types.has(r.type)) return false;
    if (f.program && r.program !== f.program) return false;

    if (f.cdn !== "all") {
      if (r.type !== "cdn") {
        // for other types, we can't know CDN status here, so keep them
        // unless user explicitly wants only CDN — then drop non-cdn rows
        if (f.cdn === "cdn") return false;
      } else if (f.cdn === "cdn" && r.status !== "proxied") {
        return false;
      } else if (f.cdn === "direct" && r.status !== "direct") {
        return false;
      }
    }

    if (f.severity !== "all") {
      if (r.type !== "nuclei") return false;
      if (String(r.status).toLowerCase() !== f.severity) return false;
    }

    if (f.statusClass !== "all") {
      if (r.type !== "http" && r.type !== "vhost") return false;
      if (statusClassOf(r.status) !== f.statusClass) return false;
    }

    if (f.fresh && !isFresh(r.time)) return false;

    if (ql) {
      const hay = [r.host, r.program, r.details, r.status, r.url]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(ql)) return false;
    }

    return true;
  });

  const { sortField, sortAsc } = state;
  state.filtered.sort((a, b) => {
    if (sortField === "time") {
      const va = a.time || "";
      const vb = b.time || "";
      return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    }
    if (sortField === "type") {
      const va = a.type;
      const vb = b.type;
      return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    }
    const va = String(a[sortField] || "").toLowerCase();
    const vb = String(b[sortField] || "").toLowerCase();
    return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
}

// ---------- Rendering ----------

function buildStatusCell(r) {
  const td = document.createElement("td");

  if (r.type === "http") {
    if (r.status) {
      const b = document.createElement("span");
      b.className = `badge-status ${statusBadgeClass(r.status)}`;
      b.textContent = r.status;
      td.appendChild(b);
    } else {
      const em = document.createElement("span");
      em.className = "cell-muted";
      em.textContent = "—";
      td.appendChild(em);
    }
  } else if (r.type === "cdn") {
    const b = document.createElement("span");
    b.className = r.status === "proxied" ? "badge-cdn" : "badge-direct";
    b.textContent = r.status === "proxied" ? "Proxied" : "Direct";
    td.appendChild(b);
  } else if (r.type === "nuclei") {
    const b = document.createElement("span");
    b.className = `badge-sev ${severityBadgeClass(r.status)}`;
    b.textContent = r.status || "info";
    td.appendChild(b);
  } else if (r.type === "vhost") {
    if (r.status) {
      const b = document.createElement("span");
      b.className = `badge-status ${statusBadgeClass(r.status)}`;
      b.textContent = r.status;
      td.appendChild(b);
    } else {
      const em = document.createElement("span");
      em.className = "cell-muted";
      em.textContent = "—";
      td.appendChild(em);
    }
  } else if (r.type === "portscan") {
    const b = document.createElement("span");
    b.className = "type-tag type-tag-portscan";
    b.textContent = `${r.status} port${r.status === "1" ? "" : "s"}`;
    td.appendChild(b);
  } else {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    td.appendChild(em);
  }

  return td;
}

function buildRow(r, index) {
  const tr = document.createElement("tr");

  // #
  const tdI = document.createElement("td");
  tdI.className = "cell-faint";
  tdI.textContent = String(index);
  tr.appendChild(tdI);

  // Type
  const tdType = document.createElement("td");
  const typeTag = document.createElement("span");
  typeTag.className = `type-tag type-tag-${r.type}`;
  typeTag.textContent = r.type;
  tdType.appendChild(typeTag);
  tr.appendChild(tdType);

  // Host
  const tdHost = document.createElement("td");
  tdHost.className = "cell-host";
  if (r.url) {
    const a = document.createElement("a");
    a.href = r.url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = r.host;
    tdHost.appendChild(a);
  } else {
    tdHost.textContent = r.host;
  }
  tdHost.title = r.host;
  tr.appendChild(tdHost);

  // Program
  const tdProg = document.createElement("td");
  const progSpan = document.createElement("span");
  progSpan.className = "program-tag";
  progSpan.textContent = r.program;
  tdProg.appendChild(progSpan);
  tr.appendChild(tdProg);

  // Status
  tr.appendChild(buildStatusCell(r));

  // Details
  const tdDet = document.createElement("td");
  tdDet.className = "cell-details";
  tdDet.textContent = r.details || "—";
  tdDet.title = r.details || "";
  tr.appendChild(tdDet);

  // Time
  const tdTime = document.createElement("td");
  tdTime.className = "cell-muted";
  const timeSpan = document.createElement("span");
  timeSpan.textContent = relativeTime(r.time);
  tdTime.appendChild(timeSpan);
  if (isFresh(r.time)) {
    const dot = document.createElement("span");
    dot.className = "fresh-dot";
    dot.title = "Fresh (last 24h)";
    tdTime.appendChild(dot);
  }
  tdTime.title = r.time || "";
  tr.appendChild(tdTime);

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

function updateMiniStats() {
  const counts = { total: state.filtered.length, http: 0, findings: 0, fresh: 0 };
  for (const r of state.filtered) {
    if (r.type === "http") counts.http++;
    if (r.type === "nuclei") counts.findings++;
    if (isFresh(r.time)) counts.fresh++;
  }
  document.getElementById("stat-total").textContent = counts.total.toLocaleString();
  document.getElementById("stat-http").textContent = counts.http.toLocaleString();
  document.getElementById("stat-findings").textContent = counts.findings.toLocaleString();
  document.getElementById("stat-fresh").textContent = counts.fresh.toLocaleString();
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
  updateMiniStats();

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
  slice.forEach((r, i) => tbody.appendChild(buildRow(r, start + i + 1)));

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

function bindTypePills() {
  document.querySelectorAll(".filter-pill").forEach((pill) => {
    const type = pill.dataset.type;
    if (state.filters.types.has(type)) pill.classList.add("active");

    pill.addEventListener("click", () => {
      if (state.filters.types.has(type)) {
        state.filters.types.delete(type);
        pill.classList.remove("active");
      } else {
        state.filters.types.add(type);
        pill.classList.add("active");
      }
      state.page = 1;
      applyFiltersAndSort();
      render();
    });
  });
}

function bindControls() {
  document.getElementById("filter-program").addEventListener("change", (e) => {
    state.filters.program = e.target.value;
    state.page = 1;
    applyFiltersAndSort();
    render();
  });

  document.getElementById("filter-cdn").addEventListener("change", (e) => {
    state.filters.cdn = e.target.value;
    state.page = 1;
    applyFiltersAndSort();
    render();
  });

  document.getElementById("filter-severity").addEventListener("change", (e) => {
    state.filters.severity = e.target.value;
    state.page = 1;
    applyFiltersAndSort();
    render();
  });

  document.getElementById("filter-status").addEventListener("change", (e) => {
    state.filters.statusClass = e.target.value;
    state.page = 1;
    applyFiltersAndSort();
    render();
  });

  document.getElementById("filter-fresh").addEventListener("change", (e) => {
    state.filters.fresh = e.target.checked;
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
        state.sortAsc = field === "time" ? false : true;
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
  bindTypePills();
  bindControls();

  try {
    const programs = await apiFetch("/api/programs");
    populateProgramSelect(programs);

    const items = await loadAll();
    state.all = items;
    state.filtered = items;
    applyFiltersAndSort();

    const loadingEl = document.getElementById("loading-state");
    if (loadingEl) loadingEl.remove();

    render();
  } catch (e) {
    console.error("Advanced search load failed:", e);
    document.getElementById("table-wrapper").style.display = "none";
    const emptyEl = document.getElementById("empty-state");
    emptyEl.innerHTML = `
      <div class="empty-state-icon">⚠️</div>
      <div class="empty-state-title">Failed to load data</div>
      <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
    `;
    emptyEl.style.display = "block";
  }
}

document.addEventListener("DOMContentLoaded", boot);