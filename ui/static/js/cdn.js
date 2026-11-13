/* ============================================
   CDN / Cloud / WAF — list page
   ============================================ */

const state = {
  all: [],
  filtered: [],
  page: 1,
  perPage: 50,
  sortField: "host",
  sortAsc: true,
  filters: { program: "", status: "all", type: "all", q: "" },
};

// ---------- Data loading ----------

async function loadCdnData() {
  const programs = await apiFetch("/api/programs");
  const items = [];

  for (const pn of Object.keys(programs).sort()) {
    try {
      const data = await apiFetch(`/api/cdn/${encodeURIComponent(pn)}`);
      const hosts = data.hosts || {};
      for (const [host, info] of Object.entries(hosts)) {
        items.push({
          program: pn,
          host: host,
          url: info.url || `https://${host}`,
          domain: info.domain || "",
          ips: Array.isArray(info.ips) ? info.ips : [],
          cdn: !!info.cdn,
          provider: info.provider || "None",
          cdn_names: Array.isArray(info.cdn_names) ? info.cdn_names : [],
          cloud_names: Array.isArray(info.cloud_names) ? info.cloud_names : [],
          waf_names: Array.isArray(info.waf_names) ? info.waf_names : [],
          last_seen: info.last_seen || "",
        });
      }
    } catch (_) {}
  }

  return items;
}

// ---------- Filter / sort ----------

function applyFiltersAndSort() {
  const { program, status, type, q } = state.filters;
  const ql = q.trim().toLowerCase();

  state.filtered = state.all.filter((it) => {
    if (program && it.program !== program) return false;

    if (status === "proxied" && !it.cdn) return false;
    if (status === "direct" && it.cdn) return false;

    if (type === "cdn" && it.cdn_names.length === 0) return false;
    if (type === "cloud" && it.cloud_names.length === 0) return false;
    if (type === "waf" && it.waf_names.length === 0) return false;

    if (ql) {
      const hay = [
        it.host,
        it.url,
        it.provider,
        ...it.cdn_names,
        ...it.cloud_names,
        ...it.waf_names,
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
    if (sortField === "cdn") {
      const va = a.cdn ? 1 : 0;
      const vb = b.cdn ? 1 : 0;
      return sortAsc ? va - vb : vb - va;
    }
    const va = String(a[sortField] || "").toLowerCase();
    const vb = String(b[sortField] || "").toLowerCase();
    return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
}

// ---------- Rendering ----------

function typeTags(names, cls) {
  if (!names.length) {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    return em;
  }
  const wrap = document.createElement("span");
  for (const n of names) {
    const t = document.createElement("span");
    t.className = `type-tag ${cls}`;
    t.textContent = n;
    wrap.appendChild(t);
    wrap.appendChild(document.createTextNode(" "));
  }
  return wrap;
}

function buildRow(it) {
  const tr = document.createElement("tr");

  const tdHost = document.createElement("td");
  tdHost.className = "cell-host";
  tdHost.textContent = it.host;
  tdHost.title = it.url;
  tr.appendChild(tdHost);

  const tdProg = document.createElement("td");
  const progSpan = document.createElement("span");
  progSpan.className = "program-tag";
  progSpan.textContent = it.program;
  tdProg.appendChild(progSpan);
  tr.appendChild(tdProg);

  const tdStatus = document.createElement("td");
  const statusBadge = document.createElement("span");
  if (it.cdn) {
    statusBadge.className = "badge-cdn";
    statusBadge.textContent = "Proxied";
  } else {
    statusBadge.className = "badge-direct";
    statusBadge.textContent = "Direct";
  }
  tdStatus.appendChild(statusBadge);
  tr.appendChild(tdStatus);

  const tdProvider = document.createElement("td");
  if (it.provider && it.provider !== "None") {
    const t = document.createElement("span");
    t.className = "type-tag type-tag-provider";
    t.textContent = it.provider;
    tdProvider.appendChild(t);
  } else {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    tdProvider.appendChild(em);
  }
  tr.appendChild(tdProvider);

  const tdCdn = document.createElement("td");
  tdCdn.appendChild(typeTags(it.cdn_names, "type-tag-cdn"));
  tr.appendChild(tdCdn);

  const tdCloud = document.createElement("td");
  tdCloud.appendChild(typeTags(it.cloud_names, "type-tag-cloud"));
  tr.appendChild(tdCloud);

  const tdWaf = document.createElement("td");
  tdWaf.appendChild(typeTags(it.waf_names, "type-tag-waf"));
  tr.appendChild(tdWaf);

  const tdIps = document.createElement("td");
  if (it.ips.length) {
    for (const ip of it.ips.slice(0, 3)) {
      const t = document.createElement("span");
      t.className = "ip-tag";
      t.textContent = ip;
      tdIps.appendChild(t);
      tdIps.appendChild(document.createTextNode(" "));
    }
    if (it.ips.length > 3) {
      const more = document.createElement("span");
      more.className = "cell-muted";
      more.textContent = `+${it.ips.length - 3}`;
      tdIps.appendChild(more);
    }
  } else {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    tdIps.appendChild(em);
  }
  tr.appendChild(tdIps);

  const tdTime = document.createElement("td");
  tdTime.className = "cell-muted";
  tdTime.textContent = relativeTime(it.last_seen);
  tdTime.title = it.last_seen || "";
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

  document.getElementById("filter-status").addEventListener("change", (e) => {
    state.filters.status = e.target.value;
    state.page = 1;
    applyFiltersAndSort();
    render();
  });

  document.getElementById("filter-type").addEventListener("change", (e) => {
    state.filters.type = e.target.value;
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

  // Clickable column headers
  document.querySelectorAll("th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const field = th.dataset.sort;
      if (state.sortField === field) {
        state.sortAsc = !state.sortAsc;
      } else {
        state.sortField = field;
        state.sortAsc = field === "last_seen" ? false : true;
      }
      const sortSelect = document.getElementById("sort-field");
      if (sortSelect) {
        sortSelect.value = `${state.sortField}-${state.sortAsc ? "asc" : "desc"}`;
      }
      state.page = 1;
      applyFiltersAndSort();
      render();
    });
  });
}

async function boot() {
  bindControls();

  try {
    const [programs, items] = await Promise.all([
      apiFetch("/api/programs"),
      loadCdnData(),
    ]);
    populateProgramSelect(programs);
    state.all = items;
    state.filtered = items;
    applyFiltersAndSort();

    const loadingEl = document.getElementById("loading-state");
    if (loadingEl) loadingEl.remove();

    render();
  } catch (e) {
    console.error("CDN load failed:", e);
    document.getElementById("table-wrapper").style.display = "none";
    const emptyEl = document.getElementById("empty-state");
    emptyEl.innerHTML = `
      <div class="empty-state-icon">⚠️</div>
      <div class="empty-state-title">Failed to load CDN data</div>
      <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
    `;
    emptyEl.style.display = "block";
  }
}

document.addEventListener("DOMContentLoaded", boot);