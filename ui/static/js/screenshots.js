/* ============================================
   Screenshots — list page
   ============================================ */

const state = {
  all: [],
  filtered: [],
  page: 1,
  perPage: 24,
  sortField: "host",
  sortAsc: true,
  filters: { program: "", cdn: "all", q: "" },
};

let modal;

// ---------- Data loading ----------

async function loadScreenshotsData() {
  const programs = await apiFetch("/api/programs");
  const items = [];

  for (const pn of Object.keys(programs).sort()) {
    let ssData = { files: [] };
    let httpData = { http_services: [] };
    let cdnData = { hosts: {} };

    try {
      ssData = await apiFetch(`/api/screenshots/${encodeURIComponent(pn)}`);
    } catch (_) {}
    try {
      httpData = await apiFetch(`/api/http/${encodeURIComponent(pn)}`);
    } catch (_) {}
    try {
      cdnData = await apiFetch(`/api/cdn/${encodeURIComponent(pn)}`);
    } catch (_) {}

    const httpByHost = {};
    for (const h of httpData.http_services || []) {
      httpByHost[h.host] = h;
    }
    const cdnByHost = cdnData.hosts || {};

    for (const file of ssData.files || []) {
      const host = file.replace(/\.png$/i, "");
      const http = httpByHost[host] || {};
      const cdn = cdnByHost[host] || {};

      let cdnKind = "unknown";
      if (cdn.cdn === true) cdnKind = "cdn";
      else if (cdn.cdn === false) cdnKind = "direct";

      items.push({
        program: pn,
        filename: file,
        host: host,
        url: http.url || `https://${host}`,
        status_code: http.status_code != null ? String(http.status_code) : "",
        title: http.title || "",
        tech: Array.isArray(http.tech) ? http.tech : [],
        webserver: http.webserver || "",
        cdnKind: cdnKind,
        provider: cdn.provider || "None",
        last_seen: http.last_seen || "",
        thumb_url: `/screenshots/${encodeURIComponent(pn)}/${encodeURIComponent(file)}`,
      });
    }
  }

  return items;
}

// ---------- Filter / sort ----------

function applyFiltersAndSort() {
  const { program, cdn, q } = state.filters;
  const ql = q.trim().toLowerCase();

  state.filtered = state.all.filter((it) => {
    if (program && it.program !== program) return false;
    if (cdn === "cdn" && it.cdnKind !== "cdn") return false;
    if (cdn === "direct" && it.cdnKind !== "direct") return false;
    if (cdn === "unknown" && it.cdnKind !== "unknown") return false;

    if (ql) {
      const hay = [
        it.host,
        it.url,
        it.title,
        it.provider,
        it.webserver,
        it.tech.join(" "),
      ].join(" ").toLowerCase();
      if (!hay.includes(ql)) return false;
    }
    return true;
  });

  const { sortField, sortAsc } = state;
  state.filtered.sort((a, b) => {
    let va, vb;
    if (sortField === "status_code") {
      va = parseInt(a[sortField], 10);
      vb = parseInt(b[sortField], 10);
      va = isNaN(va) ? 9999 : va;
      vb = isNaN(vb) ? 9999 : vb;
      return sortAsc ? va - vb : vb - va;
    }
    va = String(a[sortField] || "").toLowerCase();
    vb = String(b[sortField] || "").toLowerCase();
    return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
}

// ---------- Rendering ----------

function buildCard(it) {
  const card = document.createElement("div");
  card.className = "screenshot-card";

  // Thumbnail
  const thumbWrap = document.createElement("div");
  thumbWrap.className = "screenshot-thumb-wrap";

  const img = document.createElement("img");
  img.className = "screenshot-thumb";
  img.loading = "lazy";
  img.alt = it.host;
  img.src = it.thumb_url;
  img.addEventListener("error", () => thumbWrap.classList.add("img-failed"));
  thumbWrap.appendChild(img);

  // Info
  const info = document.createElement("div");
  info.className = "screenshot-info";

  const hostRow = document.createElement("div");
  hostRow.className = "screenshot-host-row";
  const hostEl = document.createElement("div");
  hostEl.className = "screenshot-host";
  hostEl.textContent = it.host;
  hostEl.title = it.host;
  hostRow.appendChild(hostEl);
  const progTag = document.createElement("span");
  progTag.className = "program-tag";
  progTag.textContent = it.program;
  hostRow.appendChild(progTag);
  info.appendChild(hostRow);

  const urlEl = document.createElement("div");
  urlEl.className = "screenshot-url";
  urlEl.textContent = it.url;
  urlEl.title = it.url;
  info.appendChild(urlEl);

  const meta = document.createElement("div");
  meta.className = "screenshot-meta";

  if (it.status_code) {
    const sc = document.createElement("span");
    sc.className = `badge-status ${statusBadgeClass(it.status_code)}`;
    sc.textContent = it.status_code;
    meta.appendChild(sc);
  }

  const cdnEl = document.createElement("span");
  if (it.cdnKind === "cdn") {
    cdnEl.className = "badge-cdn";
    cdnEl.textContent = it.provider && it.provider !== "None" ? it.provider : "CDN";
  } else if (it.cdnKind === "direct") {
    cdnEl.className = "badge-direct";
    cdnEl.textContent = "Direct";
  } else {
    cdnEl.className = "badge-unknown";
    cdnEl.textContent = "?";
  }
  meta.appendChild(cdnEl);

  for (const t of it.tech.slice(0, 2)) {
    const tt = document.createElement("span");
    tt.className = "tech-tag";
    tt.textContent = t;
    meta.appendChild(tt);
  }

  if (it.last_seen) {
    const t = document.createElement("span");
    t.className = "text-muted";
    t.style.fontSize = "0.72em";
    t.textContent = relativeTime(it.last_seen);
    t.title = it.last_seen;
    meta.appendChild(t);
  }

  info.appendChild(meta);
  card.appendChild(thumbWrap);
  card.appendChild(info);

  card.addEventListener("click", () => {
    modal.open(it.thumb_url, `${it.host} — ${it.url}`);
  });

  return card;
}

function render() {
  const gallery = document.getElementById("gallery");
  const paginContainer = document.getElementById("pagination-container");
  const countEl = document.getElementById("count-badge");

  gallery.innerHTML = "";
  paginContainer.innerHTML = "";

  if (state.filtered.length === 0) {
    gallery.innerHTML = `
      <div class="empty-state" style="grid-column: 1 / -1;">
        <div class="empty-state-icon">📷</div>
        <div class="empty-state-title">No screenshots match your filters</div>
        <div class="empty-state-desc">Try changing the filters above, or run <code>watch_screenshot_all.py</code> to capture screenshots.</div>
      </div>
    `;
    if (countEl) countEl.textContent = "0";
    return;
  }

  const start = (state.page - 1) * state.perPage;
  const slice = state.filtered.slice(start, start + state.perPage);
  for (const it of slice) gallery.appendChild(buildCard(it));

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

// ---------- Wiring ----------

function populateProgramSelect(programs) {
  const sel = document.getElementById("filter-program");
  if (!sel) return;
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

  document.getElementById("filter-cdn").addEventListener("change", (e) => {
    state.filters.cdn = e.target.value;
    state.page = 1;
    applyFiltersAndSort();
    render();
  });

  const search = document.getElementById("filter-search");
  search.addEventListener(
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
}

async function boot() {
  modal = initModal("screenshot-modal");
  bindControls();

  try {
    const [programs, items] = await Promise.all([
      apiFetch("/api/programs"),
      loadScreenshotsData(),
    ]);
    populateProgramSelect(programs);
    state.all = items;
    state.filtered = items;
    applyFiltersAndSort();

    const loadingEl = document.getElementById("loading-state");
    if (loadingEl) loadingEl.remove();

    render();
  } catch (e) {
    console.error("Screenshots load failed:", e);
    document.getElementById("gallery").innerHTML = `
      <div class="empty-state" style="grid-column: 1 / -1;">
        <div class="empty-state-icon">⚠️</div>
        <div class="empty-state-title">Failed to load screenshots</div>
        <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
      </div>
    `;
  }
}

document.addEventListener("DOMContentLoaded", boot);