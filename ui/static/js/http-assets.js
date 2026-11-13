/* ============================================
   HTTP Assets — all HTTP services across programs
   ============================================ */

const state = {
  all: [],
  filtered: [],
  page: 1,
  perPage: 50,
  sortField: "host",
  sortAsc: true,
  filters: {
    program: "",
    statusClass: "all",
    cdn: "all",
    tech: "all",
    q: "",
  },
};

let modal = null;

// ---------- Helpers ----------

function statusClassOf(code) {
  const s = String(code || "");
  if (s.startsWith("2")) return "2xx";
  if (s.startsWith("3")) return "3xx";
  if (s.startsWith("4")) return "4xx";
  if (s.startsWith("5")) return "5xx";
  return "na";
}

// ---------- Data loading ----------

async function loadHttpData() {
  const programs = await apiFetch("/api/programs");
  const items = [];

  for (const pn of Object.keys(programs).sort()) {
    const safe = encodeURIComponent(pn);

    const [httpRes, cdnRes] = await Promise.all([
      apiFetch(`/api/http/${safe}`).catch(() => ({ http_services: [] })),
      apiFetch(`/api/cdn/${safe}`).catch(() => ({ hosts: {} })),
    ]);

    const cdnMap = cdnRes.hosts || {};

    for (const h of httpRes.http_services || []) {
      const tech = Array.isArray(h.tech) ? h.tech : [];
      const ips = Array.isArray(h.ips) ? h.ips : [];
      const cdn = cdnMap[h.host] || {};

      items.push({
        program: pn,
        host: h.host || "",
        url: h.url || "",
        status: h.status_code != null ? String(h.status_code) : "",
        title: h.title || "",
        tech: tech,
        techCount: tech.length,
        ips: ips,
        webserver: h.webserver || "",
        last_seen: h.last_seen || "",
        cdnKind:
          cdn.cdn === true ? "cdn" : cdn.cdn === false ? "direct" : "unknown",
        provider: cdn.provider || "None",
      });
    }
  }

  return items;
}

// ---------- Filter / sort ----------

function applyFiltersAndSort() {
  const { program, statusClass, cdn, tech, q } = state.filters;
  const ql = q.trim().toLowerCase();

  state.filtered = state.all.filter((it) => {
    if (program && it.program !== program) return false;

    if (statusClass !== "all" && statusClassOf(it.status) !== statusClass) {
      return false;
    }

    if (cdn === "cdn" && it.cdnKind !== "cdn") return false;
    if (cdn === "direct" && it.cdnKind !== "direct") return false;
    if (cdn === "unknown" && it.cdnKind !== "unknown") return false;

    if (tech !== "all" && !it.tech.includes(tech)) return false;

    if (ql) {
      const hay = [
        it.host,
        it.url,
        it.title,
        it.webserver,
        ...it.tech,
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
    if (sortField === "status") {
      const va = parseInt(a.status, 10);
      const vb = parseInt(b.status, 10);
      const na = isNaN(va) ? 9999 : va;
      const nb = isNaN(vb) ? 9999 : vb;
      return sortAsc ? na - nb : nb - na;
    }
    if (sortField === "techCount") {
      return sortAsc ? a.techCount - b.techCount : b.techCount - a.techCount;
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

function buildTechCell(it) {
  const td = document.createElement("td");
  td.style.whiteSpace = "normal";
  td.style.padding = "10px 14px";

  const wrap = document.createElement("div");
  wrap.className = "tech-list";

  if (it.tech.length === 0) {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    wrap.appendChild(em);
    td.appendChild(wrap);
    return td;
  }

  const MAX_VISIBLE = 3;
  const visible = it.tech.slice(0, MAX_VISIBLE);
  const hidden = it.tech.slice(MAX_VISIBLE);

  for (const t of visible) {
    const tag = document.createElement("span");
    tag.className = "tech-tag-cell";
    tag.textContent = t;
    wrap.appendChild(tag);
  }

  if (hidden.length) {
    const more = document.createElement("button");
    more.type = "button";
    more.className = "tech-tag-more";
    more.textContent = `+${hidden.length}`;
    more.title = hidden.join(", ");
    more.addEventListener("click", (e) => {
      e.stopPropagation();
      for (const t of hidden) {
        const tag = document.createElement("span");
        tag.className = "tech-tag-cell";
        tag.textContent = t;
        wrap.insertBefore(tag, more);
      }
      more.remove();
    });
    wrap.appendChild(more);
  }

  td.appendChild(wrap);
  return td;
}

function buildScreenshotCell(it) {
  const td = document.createElement("td");
  td.style.textAlign = "center";

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "screenshot-btn";
  btn.title = "View screenshot";
  btn.textContent = "📸";

  const url = `/screenshots/${encodeURIComponent(it.program)}/${encodeURIComponent(
    it.host
  )}.png`;

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (modal) modal.open(url, `${it.host} — ${it.url}`);
  });

  td.appendChild(btn);
  return td;
}

function buildCdnBadge(it) {
  const span = document.createElement("span");
  if (it.cdnKind === "cdn") {
    span.className = "badge-cdn";
    span.textContent =
      it.provider && it.provider !== "None" ? it.provider : "CDN";
  } else if (it.cdnKind === "direct") {
    span.className = "badge-direct";
    span.textContent = "Direct";
  } else {
    span.className = "badge-unknown";
    span.textContent = "?";
  }
  return span;
}

function buildRow(it) {
  const tr = document.createElement("tr");

  // Host
  const tdHost = document.createElement("td");
  tdHost.className = "cell-host";
  const a = document.createElement("a");
  a.href = it.url || `https://${it.host}`;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  a.textContent = it.host;
  a.title = it.host;
  tdHost.appendChild(a);
  tr.appendChild(tdHost);

  // Program
  const tdProg = document.createElement("td");
  const progSpan = document.createElement("span");
  progSpan.className = "program-tag";
  progSpan.textContent = it.program;
  tdProg.appendChild(progSpan);
  tr.appendChild(tdProg);

  // Status
  const tdStatus = document.createElement("td");
  if (it.status) {
    const badge = document.createElement("span");
    badge.className = `status-badge-lg ${statusBadgeClass(it.status)}`;
    badge.textContent = it.status;
    tdStatus.appendChild(badge);
  } else {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    tdStatus.appendChild(em);
  }
  tr.appendChild(tdStatus);

  // CDN
  const tdCdn = document.createElement("td");
  tdCdn.appendChild(buildCdnBadge(it));
  tr.appendChild(tdCdn);

  // Title
  const tdTitle = document.createElement("td");
  tdTitle.className = "cell-title" + (it.title ? "" : " empty");
  tdTitle.textContent = it.title || "—";
  tdTitle.title = it.title || "";
  tr.appendChild(tdTitle);

  // URL
  const tdUrl = document.createElement("td");
  tdUrl.className = "cell-url";
  const urlLink = document.createElement("a");
  urlLink.href = it.url || `https://${it.host}`;
  urlLink.target = "_blank";
  urlLink.rel = "noopener noreferrer";
  urlLink.textContent = it.url || `https://${it.host}`;
  urlLink.title = it.url || "";
  tdUrl.appendChild(urlLink);
  tr.appendChild(tdUrl);

  // Tech
  tr.appendChild(buildTechCell(it));

  // Webserver
  const tdServer = document.createElement("td");
  tdServer.className = "cell-muted";
  tdServer.textContent = it.webserver || "—";
  tdServer.title = it.webserver || "";
  tr.appendChild(tdServer);

  // Last seen
  const tdLast = document.createElement("td");
  tdLast.className = "cell-muted";
  tdLast.textContent = relativeTime(it.last_seen);
  tdLast.title = it.last_seen || "";
  tr.appendChild(tdLast);

  // Screenshot
  tr.appendChild(buildScreenshotCell(it));

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

function populateTechSelect(items) {
  const sel = document.getElementById("filter-tech");
  const all = new Set();
  for (const it of items) {
    for (const t of it.tech) all.add(t);
  }
  for (const t of [...all].sort()) {
    const opt = document.createElement("option");
    opt.value = t;
    opt.textContent = t;
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

  document.getElementById("filter-status").addEventListener("change", (e) => {
    state.filters.statusClass = e.target.value;
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

  document.getElementById("filter-tech").addEventListener("change", (e) => {
    state.filters.tech = e.target.value;
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
  modal = initModal("screenshot-modal");
  bindControls();

  try {
    const programs = await apiFetch("/api/programs");
    populateProgramSelect(programs);

    const items = await loadHttpData();
    populateTechSelect(items);

    state.all = items;
    state.filtered = items;
    applyFiltersAndSort();

    const loadingEl = document.getElementById("loading-state");
    if (loadingEl) loadingEl.remove();

    render();
  } catch (e) {
    console.error("HTTP assets load failed:", e);
    document.getElementById("table-wrapper").style.display = "none";
    const emptyEl = document.getElementById("empty-state");
    emptyEl.innerHTML = `
      <div class="empty-state-icon">⚠️</div>
      <div class="empty-state-title">Failed to load HTTP assets</div>
      <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
    `;
    emptyEl.style.display = "block";
  }
}

document.addEventListener("DOMContentLoaded", boot);