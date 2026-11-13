/* ============================================
   Port Scan — list page
   ============================================ */

const state = {
  all: [],
  filtered: [],
  page: 1,
  perPage: 50,
  sortField: "host",
  sortAsc: true,
  filters: { program: "", service: "all", q: "" },
};

// Service → color class mapping (for port tags)
function serviceClass(service, tls) {
  if (!service) return "";
  const s = service.toLowerCase();
  if (["http", "https", "http-proxy", "http-alt", "https-alt"].includes(s)) {
    return "port-tag-http";
  }
  if (["mysql", "postgres", "redis", "mongodb", "mssql", "oracle", "cassandra",
       "elasticsearch", "memcached", "couchdb", "influxdb"].includes(s)) {
    return "port-tag-db";
  }
  if (["ssh", "telnet", "rdp", "vnc", "docker", "docker-tls", "kubernetes-api"].includes(s)) {
    return "port-tag-remote";
  }
  if (["smtp", "smtps", "pop3", "pop3s", "imap", "imaps", "smtp-submission"].includes(s)) {
    return "port-tag-mail";
  }
  return "";
}

// ---------- Data loading ----------

async function loadPortscanData() {
  const programs = await apiFetch("/api/programs");
  const items = [];

  for (const pn of Object.keys(programs).sort()) {
    try {
      const data = await apiFetch(`/api/portscan/${encodeURIComponent(pn)}`);
      const hosts = data.hosts || [];

      for (const h of hosts) {
        // API shape we expect after app.py update:
        //   ports: string[]
        //   services: {port: service}
        //   products: {port: product}
        //   tls: {port: bool}
        // Fallbacks handle the current (partial) shape gracefully.
        const ports = Array.isArray(h.ports) ? h.ports : [];
        const services = h.services || {};
        const products = h.products || {};
        const tls = h.tls || {};

        items.push({
          program: pn,
          host: h.host || "",
          domain: h.domain || "",
          ports: ports.map(String),
          services: services,
          products: products,
          tls: tls,
          portCount: ports.length,
          last_seen: h.last_seen || "",
        });
      }
    } catch (_) {}
  }

  return items;
}

// ---------- Filter / sort ----------

function applyFiltersAndSort() {
  const { program, service, q } = state.filters;
  const ql = q.trim().toLowerCase();

  state.filtered = state.all.filter((it) => {
    if (program && it.program !== program) return false;

    if (service !== "all") {
      const svcList = Object.values(it.services || {}).map((s) => String(s || "").toLowerCase());
      if (!svcList.includes(service)) return false;
    }

    if (ql) {
      const hay = [
        it.host,
        it.domain,
        ...it.ports,
        ...Object.values(it.services || {}),
        ...Object.values(it.products || {}),
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(ql)) return false;
    }

    return true;
  });

  const { sortField, sortAsc } = state;
  state.filtered.sort((a, b) => {
    if (sortField === "portCount") {
      return sortAsc
        ? a.portCount - b.portCount
        : b.portCount - a.portCount;
    }
    const va = String(a[sortField] || "").toLowerCase();
    const vb = String(b[sortField] || "").toLowerCase();
    return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
}

// ---------- Rendering ----------

function makePortTag(port, service, product, tls) {
  const tag = document.createElement("span");
  tag.className = "port-tag " + serviceClass(service, tls);
  if (tls) tag.classList.add("port-tag-tls");

  let label = port;
  if (service) label += `(${service})`;
  tag.textContent = label;

  // Tooltip: port • service • product
  const tipParts = [port];
  if (service) tipParts.push(service);
  if (product) tipParts.push(product);
  if (tls) tipParts.push("TLS");
  tag.title = tipParts.join(" • ");

  return tag;
}

function buildPortsCell(it) {
  const td = document.createElement("td");
  td.style.whiteSpace = "normal";
  td.style.padding = "10px 14px";

  const wrap = document.createElement("div");
  wrap.className = "port-list";

  const MAX_VISIBLE = 8;
  const visible = it.ports.slice(0, MAX_VISIBLE);
  const hidden = it.ports.slice(MAX_VISIBLE);

  for (const p of visible) {
    wrap.appendChild(
      makePortTag(p, it.services[p], it.products[p], it.tls[p])
    );
  }

  if (hidden.length) {
    const moreBtn = document.createElement("button");
    moreBtn.type = "button";
    moreBtn.className = "port-tag port-tag-more";
    moreBtn.textContent = `+${hidden.length}`;
    moreBtn.title = "Click to reveal all ports";
    moreBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      for (const p of hidden) {
        wrap.insertBefore(
          makePortTag(p, it.services[p], it.products[p], it.tls[p]),
          moreBtn
        );
      }
      moreBtn.remove();
    });
    wrap.appendChild(moreBtn);
  }

  if (it.ports.length === 0) {
    const em = document.createElement("span");
    em.className = "cell-muted";
    em.textContent = "—";
    wrap.appendChild(em);
  }

  td.appendChild(wrap);
  return td;
}

function buildRow(it) {
  const tr = document.createElement("tr");

  // Host
  const tdHost = document.createElement("td");
  tdHost.className = "cell-host";
  tdHost.textContent = it.host;
  tdHost.title = it.host;
  tr.appendChild(tdHost);

  // Program
  const tdProg = document.createElement("td");
  const progSpan = document.createElement("span");
  progSpan.className = "program-tag";
  progSpan.textContent = it.program;
  tdProg.appendChild(progSpan);
  tr.appendChild(tdProg);

  // Ports (main content)
  tr.appendChild(buildPortsCell(it));

  // Count
  const tdCount = document.createElement("td");
  tdCount.className = "cell-muted";
  tdCount.textContent = String(it.portCount);
  tr.appendChild(tdCount);

  // Last seen
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

function populateServiceSelect(items) {
  const sel = document.getElementById("filter-service");
  const all = new Set();
  for (const it of items) {
    for (const svc of Object.values(it.services || {})) {
      const s = String(svc || "").toLowerCase();
      if (s) all.add(s);
    }
  }
  for (const svc of [...all].sort()) {
    const opt = document.createElement("option");
    opt.value = svc;
    opt.textContent = svc;
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

  document.getElementById("filter-service").addEventListener("change", (e) => {
    state.filters.service = e.target.value;
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
  bindControls();

  try {
    const [programs, items] = await Promise.all([
      apiFetch("/api/programs"),
      loadPortscanData(),
    ]);
    populateProgramSelect(programs);
    populateServiceSelect(items);
    state.all = items;
    state.filtered = items;
    applyFiltersAndSort();

    const loadingEl = document.getElementById("loading-state");
    if (loadingEl) loadingEl.remove();

    render();
  } catch (e) {
    console.error("Portscan load failed:", e);
    document.getElementById("table-wrapper").style.display = "none";
    const emptyEl = document.getElementById("empty-state");
    emptyEl.innerHTML = `
      <div class="empty-state-icon">⚠️</div>
      <div class="empty-state-title">Failed to load port scan data</div>
      <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
    `;
    emptyEl.style.display = "block";
  }
}

document.addEventListener("DOMContentLoaded", boot);