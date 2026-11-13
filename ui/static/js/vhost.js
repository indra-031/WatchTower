/* ============================================
   Virtual Hosts — list page
   ============================================ */

const state = {
  all: [],
  filtered: [],
  page: 1,
  perPage: 50,
  sortField: "vhost",
  sortAsc: true,
  filters: { program: "", statusClass: "all", q: "" },
};

// ---------- Data loading ----------

async function loadVhostData() {
  const programs = await apiFetch("/api/programs");
  const items = [];

  for (const pn of Object.keys(programs).sort()) {
    try {
      const data = await apiFetch(`/api/vhost/${encodeURIComponent(pn)}`);
      const vhosts = data.vhosts || {};
      for (const [key, info] of Object.entries(vhosts)) {
        items.push({
          program: pn,
          key: key,
          vhost: info.vhost || "",
          host: info.host || "",
          ip: info.ip || "",
          domain: info.domain || "",
          status: info.status != null ? String(info.status) : "",
          length: typeof info.length === "number" ? info.length : null,
          title: info.title || "",
          last_seen: info.last_seen || "",
        });
      }
    } catch (_) {}
  }

  return items;
}

// ---------- Filter / sort ----------

function statusClassOf(code) {
  const s = String(code || "");
  if (s.startsWith("2")) return "2xx";
  if (s.startsWith("3")) return "3xx";
  if (s.startsWith("4")) return "4xx";
  if (s.startsWith("5")) return "5xx";
  return "na";
}

function applyFiltersAndSort() {
  const { program, statusClass, q } = state.filters;
  const ql = q.trim().toLowerCase();

  state.filtered = state.all.filter((it) => {
    if (program && it.program !== program) return false;
    if (statusClass !== "all" && statusClassOf(it.status) !== statusClass) return false;

    if (ql) {
      const hay = [it.vhost, it.host, it.ip, it.title, it.domain]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(ql)) return false;
    }
    return true;
  });

  const { sortField, sortAsc } = state;
  state.filtered.sort((a, b) => {
    let va, vb;

    if (sortField === "status") {
      va = parseInt(a.status, 10);
      vb = parseInt(b.status, 10);
      va = isNaN(va) ? 9999 : va;
      vb = isNaN(vb) ? 9999 : vb;
      return sortAsc ? va - vb : vb - va;
    }

    if (sortField === "length") {
      va = a.length == null ? -1 : a.length;
      vb = b.length == null ? -1 : b.length;
      return sortAsc ? va - vb : vb - va;
    }

    if (sortField === "ip") {
      // Compare IP octets numerically
      const toInt = (ip) =>
        ip.split(".").reduce((acc, n) => (acc << 8) + (parseInt(n, 10) || 0), 0) >>> 0;
      va = toInt(a.ip);
      vb = toInt(b.ip);
      return sortAsc ? va - vb : vb - va;
    }

    va = String(a[sortField] || "").toLowerCase();
    vb = String(b[sortField] || "").toLowerCase();
    return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
}

// ---------- Rendering ----------

function buildRow(it, index) {
  const tr = document.createElement("tr");

  const tdIndex = document.createElement("td");
  tdIndex.className = "cell-faint";
  tdIndex.textContent = String(index);
  tr.appendChild(tdIndex);

  const tdVhost = document.createElement("td");
  tdVhost.className = "cell-host";
  tdVhost.textContent = it.vhost;
  tdVhost.title = it.vhost;
  tr.appendChild(tdVhost);

  const tdHost = document.createElement("td");
  tdHost.className = "cell-muted";
  tdHost.textContent = it.host || "—";
  tdHost.title = it.host || "";
  tr.appendChild(tdHost);

  const tdIp = document.createElement("td");
  if (it.ip) {
    const t = document.createElement("span");
    t.className = "ip-tag";
    t.textContent = it.ip;
    tdIp.appendChild(t);
  } else {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    tdIp.appendChild(em);
  }
  tr.appendChild(tdIp);

  const tdStatus = document.createElement("td");
  if (it.status) {
    const badge = document.createElement("span");
    badge.className = `badge-status ${statusBadgeClass(it.status)}`;
    badge.textContent = it.status;
    tdStatus.appendChild(badge);
  } else {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    tdStatus.appendChild(em);
  }
  tr.appendChild(tdStatus);

  const tdLength = document.createElement("td");
  tdLength.className = "cell-muted";
  tdLength.textContent = it.length == null ? "—" : it.length.toLocaleString();
  tr.appendChild(tdLength);

  const tdTitle = document.createElement("td");
  tdTitle.className = "cell-muted";
  if (it.title) {
    tdTitle.textContent = it.title;
    tdTitle.title = it.title;
    tdTitle.style.maxWidth = "280px";
    tdTitle.style.overflow = "hidden";
    tdTitle.style.textOverflow = "ellipsis";
  } else {
    tdTitle.textContent = "—";
  }
  tr.appendChild(tdTitle);

  const tdProg = document.createElement("td");
  const progSpan = document.createElement("span");
  progSpan.className = "program-tag";
  progSpan.textContent = it.program;
  tdProg.appendChild(progSpan);
  tr.appendChild(tdProg);

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
  slice.forEach((it, i) => tbody.appendChild(buildRow(it, start + i + 1)));

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
    state.filters.statusClass = e.target.value;
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
        state.sortAsc = true;
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
      loadVhostData(),
    ]);
    populateProgramSelect(programs);
    state.all = items;
    state.filtered = items;
    applyFiltersAndSort();

    const loadingEl = document.getElementById("loading-state");
    if (loadingEl) loadingEl.remove();

    render();
  } catch (e) {
    console.error("VHost load failed:", e);
    document.getElementById("table-wrapper").style.display = "none";
    const emptyEl = document.getElementById("empty-state");
    emptyEl.innerHTML = `
      <div class="empty-state-icon">⚠️</div>
      <div class="empty-state-title">Failed to load virtual host data</div>
      <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
    `;
    emptyEl.style.display = "block";
  }
}

document.addEventListener("DOMContentLoaded", boot);