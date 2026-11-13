/* ============================================
   Subdomains — list page
   ============================================ */

const state = {
  all: [],
  filtered: [],
  page: 1,
  perPage: 50,
  sortField: "subdomain",
  sortAsc: true,
  filters: { program: "", source: "all", q: "" },
};

// ---------- Data loading ----------

async function loadSubdomainsData() {
  const programs = await apiFetch("/api/programs");
  const items = [];

  for (const pn of Object.keys(programs).sort()) {
    try {
      const data = await apiFetch(`/api/subdomains/${encodeURIComponent(pn)}`);
      const subs = data.subdomains || [];
      for (const s of subs) {
        const sources = Array.isArray(s.sources) ? s.sources : [];
        items.push({
          program: pn,
          subdomain: s.subdomain || "",
          first_seen: s.first_seen || "",
          last_seen: s.last_seen || "",
          sources: sources,
          sourceCount: sources.length,
          sourceDetails: s.source_details || {},
        });
      }
    } catch (_) {}
  }

  return items;
}

// ---------- Filter / sort ----------

function applyFiltersAndSort() {
  const { program, source, q } = state.filters;
  const ql = q.trim().toLowerCase();

  state.filtered = state.all.filter((it) => {
    if (program && it.program !== program) return false;

    if (source !== "all" && !it.sources.includes(source)) return false;

    if (ql && !it.subdomain.toLowerCase().includes(ql)) return false;

    return true;
  });

  const { sortField, sortAsc } = state;
  state.filtered.sort((a, b) => {
    if (sortField === "sourceCount") {
      return sortAsc
        ? a.sourceCount - b.sourceCount
        : b.sourceCount - a.sourceCount;
    }

    if (sortField === "first_seen" || sortField === "last_seen") {
      const va = a[sortField] || "";
      const vb = b[sortField] || "";
      // ISO-like timestamps sort lexically = chronologically
      return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    }

    const va = String(a[sortField] || "").toLowerCase();
    const vb = String(b[sortField] || "").toLowerCase();
    return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
}

// ---------- Rendering ----------

function sourceTag(name) {
  const tag = document.createElement("span");
  const safeClass = String(name)
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "_");
  tag.className = `source-tag source-${safeClass}`;
  tag.textContent = name;
  tag.title = name;
  return tag;
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

  const MAX_VISIBLE = 3;
  const visible = it.sources.slice(0, MAX_VISIBLE);
  const hidden = it.sources.slice(MAX_VISIBLE);

  for (const s of visible) wrap.appendChild(sourceTag(s));

  if (hidden.length) {
    const moreBtn = document.createElement("button");
    moreBtn.type = "button";
    moreBtn.className = "source-more";
    moreBtn.textContent = `+${hidden.length}`;
    moreBtn.title = hidden.join(", ");
    moreBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      for (const s of hidden) {
        wrap.insertBefore(sourceTag(s), moreBtn);
      }
      moreBtn.remove();
    });
    wrap.appendChild(moreBtn);
  }

  td.appendChild(wrap);
  return td;
}

function buildRow(it) {
  const tr = document.createElement("tr");

  // Subdomain
  const tdSub = document.createElement("td");
  tdSub.className = "cell-subdomain";

  const a = document.createElement("a");
  a.href = `https://${it.subdomain}`;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  a.textContent = it.subdomain;
  a.title = it.subdomain;
  tdSub.appendChild(a);
  tr.appendChild(tdSub);

  // Program
  const tdProg = document.createElement("td");
  const progSpan = document.createElement("span");
  progSpan.className = "program-tag";
  progSpan.textContent = it.program;
  tdProg.appendChild(progSpan);
  tr.appendChild(tdProg);

  // Sources
  tr.appendChild(buildSourcesCell(it));

  // Source count
  const tdCount = document.createElement("td");
  tdCount.style.textAlign = "center";
  const sc = document.createElement("span");
  sc.className = "source-count";
  sc.textContent = String(it.sourceCount);
  tdCount.appendChild(sc);
  tr.appendChild(tdCount);

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

function populateSourceSelect(items) {
  const sel = document.getElementById("filter-source");
  const all = new Set();
  for (const it of items) {
    for (const s of it.sources) all.add(s);
  }
  for (const s of [...all].sort()) {
    const opt = document.createElement("option");
    opt.value = s;
    opt.textContent = s;
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

  document.getElementById("filter-source").addEventListener("change", (e) => {
    state.filters.source = e.target.value;
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
        state.sortAsc = field.endsWith("_seen") ? false : true;
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
    const [programs, items] = await Promise.all([
      apiFetch("/api/programs"),
      loadSubdomainsData(),
    ]);
    populateProgramSelect(programs);
    populateSourceSelect(items);
    state.all = items;
    state.filtered = items;
    applyFiltersAndSort();

    const loadingEl = document.getElementById("loading-state");
    if (loadingEl) loadingEl.remove();

    render();
  } catch (e) {
    console.error("Subdomains load failed:", e);
    document.getElementById("table-wrapper").style.display = "none";
    const emptyEl = document.getElementById("empty-state");
    emptyEl.innerHTML = `
      <div class="empty-state-icon">⚠️</div>
      <div class="empty-state-title">Failed to load subdomain data</div>
      <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
    `;
    emptyEl.style.display = "block";
  }
}

document.addEventListener("DOMContentLoaded", boot);