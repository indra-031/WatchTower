/* ============================================
   WatchTower — Bruteforce Subdomains Page
   Fetches /api/bruteforce (which returns only subdomains
   discovered exclusively via DNS brute-force) and displays
   them with source attribution, filtering, and detail modal.
   ============================================ */

(function () {
  "use strict";

  const PER_PAGE = 100;

  // Handle both legacy "ns_brute_*" and current "dns_brute_*" labels
  const STATIC_LABELS  = new Set(["ns_brute_static",  "dns_brute_static"]);
  const DYNAMIC_LABELS = new Set(["ns_brute_dynamic", "dns_brute_dynamic"]);

  let allItems = [];   // [{ program, subdomain, sources, source_details, first_seen, last_seen }]
  let filtered = [];
  let currentPage = 1;

  const filters = { source: "all", program: "all", search: "" };
  const sort = { field: "subdomain", dir: "asc" };

  // ---------- Helpers ----------

  function hasStatic(sources) {
    return sources.some((s) => STATIC_LABELS.has(s));
  }

  function hasDynamic(sources) {
    return sources.some((s) => DYNAMIC_LABELS.has(s));
  }

  function sourceTagClass(s) {
    if (STATIC_LABELS.has(s))  return "source-tag source-ns_brute_static";
    if (DYNAMIC_LABELS.has(s)) return "source-tag source-ns_brute_dynamic";
    return "source-tag source-default";
  }

  function sourceDisplayName(s) {
    if (STATIC_LABELS.has(s))  return "static";
    if (DYNAMIC_LABELS.has(s)) return "dynamic";
    return s;
  }

  // ---------- Load ----------

  async function load() {
    const tbody = document.getElementById("bruteforce-tbody");
    try {
      const data = await apiFetch("/api/bruteforce");
      const programs = data.programs || {};

      allItems = [];
      for (const [prog, items] of Object.entries(programs)) {
        if (!Array.isArray(items)) continue;
        for (const it of items) {
          allItems.push({
            program: prog,
            subdomain: it.subdomain || "",
            sources: Array.isArray(it.sources) ? it.sources : [],
            source_details: it.source_details || {},
            first_seen: it.first_seen || "",
            last_seen: it.last_seen || "",
          });
        }
      }

      document.getElementById("item-count").textContent = allItems.length;
      updateMiniStats();
      populateProgramFilter();
      applyFilters();
    } catch (e) {
      console.error("Bruteforce load failed:", e);
      tbody.innerHTML = `
        <tr><td colspan="5" style="text-align:center;padding:32px;color:var(--red)">
          Failed to load items: ${escapeHTML(e.message || String(e))}
        </td></tr>
      `;
    }
  }

  function updateMiniStats() {
    let s = 0, d = 0;
    for (const it of allItems) {
      if (hasStatic(it.sources))  s++;
      if (hasDynamic(it.sources)) d++;
    }
    document.getElementById("stat-total").textContent   = allItems.length;
    document.getElementById("stat-static").textContent  = s;
    document.getElementById("stat-dynamic").textContent = d;
  }

  function populateProgramFilter() {
    const programs = new Set();
    for (const it of allItems) programs.add(it.program);
    const sel = document.getElementById("program-filter");
    const current = sel.value;
    while (sel.options.length > 1) sel.remove(1);
    for (const p of Array.from(programs).sort()) {
      const opt = document.createElement("option");
      opt.value = p;
      opt.textContent = p;
      sel.appendChild(opt);
    }
    if (Array.from(sel.options).some((o) => o.value === current)) sel.value = current;
  }

  // ---------- Filter + sort ----------

  function applyFilters() {
    const q = filters.search.toLowerCase();

    filtered = allItems.filter((it) => {
      if (filters.program !== "all" && it.program !== filters.program) return false;
      if (filters.source === "static"  && !hasStatic(it.sources))  return false;
      if (filters.source === "dynamic" && !hasDynamic(it.sources)) return false;
      if (q) {
        const hay = `${it.subdomain} ${it.program}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => {
      let va, vb;
      switch (sort.field) {
        case "subdomain":
          va = (a.subdomain || "").toLowerCase();
          vb = (b.subdomain || "").toLowerCase();
          break;
        case "program":
          va = (a.program || "").toLowerCase();
          vb = (b.program || "").toLowerCase();
          break;
        case "first_seen":
          va = a.first_seen || "";
          vb = b.first_seen || "";
          break;
        case "last_seen":
          va = a.last_seen || "";
          vb = b.last_seen || "";
          break;
        default:
          va = ""; vb = "";
      }
      if (va < vb) return sort.dir === "asc" ? -1 : 1;
      if (va > vb) return sort.dir === "asc" ? 1 : -1;
      return 0;
    });

    currentPage = 1;
    renderTable();
  }

  // ---------- Table ----------

  function renderTable() {
    const tbody = document.getElementById("bruteforce-tbody");
    const pagContainer = document.getElementById("pagination-container");

    if (!allItems.length) {
      tbody.innerHTML = `
        <tr><td colspan="5" style="padding:0">
          <div class="empty-state" style="border:none;background:transparent">
            <div class="empty-state-icon">🔨</div>
            <div class="empty-state-title">No brute-force subdomains yet</div>
            <div class="empty-state-desc">
              Brute-force modules haven't run yet, or no subdomains were discovered
              exclusively through brute-forcing. Run the static or dynamic DNS
              brute modules from <code>watch.sh</code> to populate this page.
            </div>
          </div>
        </td></tr>`;
      pagContainer.innerHTML = "";
      return;
    }

    if (!filtered.length) {
      tbody.innerHTML = `
        <tr><td colspan="5" style="text-align:center;padding:40px;color:var(--muted)">
          No items match the current filters.
        </td></tr>`;
      pagContainer.innerHTML = "";
      return;
    }

    const start = (currentPage - 1) * PER_PAGE;
    const page = filtered.slice(start, start + PER_PAGE);

    tbody.innerHTML = page
      .map((it, i) => {
        const tags = it.sources
          .map((s) => `<span class="${sourceTagClass(s)}">${escapeHTML(sourceDisplayName(s))}</span>`)
          .join(" ");
        return `
          <tr data-idx="${start + i}" style="cursor:pointer">
            <td class="cell-subdomain">${escapeHTML(it.subdomain)}</td>
            <td><span class="program-tag">${escapeHTML(it.program)}</span></td>
            <td><div class="source-list">${tags}</div></td>
            <td class="cell-muted">${relativeTime(it.first_seen)}</td>
            <td class="cell-muted">${relativeTime(it.last_seen)}</td>
          </tr>`;
      })
      .join("");

    tbody.querySelectorAll("tr[data-idx]").forEach((tr) => {
      tr.addEventListener("click", () => {
        const idx = parseInt(tr.dataset.idx, 10);
        showDetails(filtered[idx]);
      });
    });

    const totalPages = Math.ceil(filtered.length / PER_PAGE);
    pagContainer.innerHTML = "";
    pagContainer.appendChild(
      renderPagination(currentPage, totalPages, filtered.length, PER_PAGE, (p) => {
        currentPage = p;
        renderTable();
        window.scrollTo({ top: 0, behavior: "smooth" });
      })
    );
  }

  // ---------- Detail modal ----------

  function showDetails(it) {
    if (!it) return;
    const modal = document.getElementById("detail-modal");
    const body = document.getElementById("detail-modal-body");

    const sourceRows = it.sources
      .map((s) => {
        const det = it.source_details[s] || {};
        return `
          <div style="display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px solid var(--border)">
            <span class="${sourceTagClass(s)}">${escapeHTML(sourceDisplayName(s))}</span>
            <span style="font-family:var(--font-mono);font-size:0.78em;color:var(--muted);text-align:right">
              ${escapeHTML(det.first_seen || "—")}<br>
              ${det.domain ? `domain: ${escapeHTML(det.domain)}` : ""}
            </span>
          </div>`;
      })
      .join("");

    body.innerHTML = `
      <div style="margin-bottom:16px">
        <span class="program-tag">${escapeHTML(it.program)}</span>
      </div>
      <h3 style="font-family:var(--font-mono);color:var(--blue-dim);font-size:1.05em;font-weight:600;margin-bottom:16px;word-break:break-all">
        ${escapeHTML(it.subdomain)}
      </h3>
      <div style="display:grid;grid-template-columns:120px 1fr;gap:8px 16px;font-size:0.88em;margin-bottom:20px">
        <div style="color:var(--muted)">First seen</div>
        <div style="font-family:var(--font-mono)">${escapeHTML(it.first_seen || "—")}</div>
        <div style="color:var(--muted)">Last seen</div>
        <div style="font-family:var(--font-mono)">${escapeHTML(it.last_seen || "—")}</div>
      </div>
      <h4 style="color:var(--muted);font-size:0.72em;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:10px;font-weight:700">Sources</h4>
      ${sourceRows || `<p style="color:var(--muted);font-style:italic">No source details available.</p>`}
    `;

    modal.classList.add("active");
  }

  function closeModal() {
    document.getElementById("detail-modal").classList.remove("active");
  }

  // ---------- Events ----------

  function setupEvents() {
    // Source pills
    document.getElementById("source-pills").addEventListener("click", (e) => {
      const pill = e.target.closest(".filter-pill");
      if (!pill) return;
      document.querySelectorAll("#source-pills .filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      filters.source = pill.dataset.source;
      applyFilters();
    });

    // Mini stats click → set matching source filter
    document.querySelectorAll("#mini-stats .mini-stat").forEach((el) => {
      el.addEventListener("click", () => {
        const src = el.dataset.source;
        document.querySelectorAll("#source-pills .filter-pill").forEach((p) => {
          p.classList.toggle("active", p.dataset.source === src);
        });
        filters.source = src;
        applyFilters();
      });
    });

    // Program filter
    document.getElementById("program-filter").addEventListener("change", (e) => {
      filters.program = e.target.value;
      applyFilters();
    });

    // Search
    document.getElementById("search-input").addEventListener(
      "input",
      debounce((e) => {
        filters.search = e.target.value.trim();
        applyFilters();
      }, 250)
    );

    // Sort
    document.querySelectorAll(".data-table th.sortable").forEach((th) => {
      th.addEventListener("click", () => {
        const field = th.dataset.sort;
        if (sort.field === field) sort.dir = sort.dir === "asc" ? "desc" : "asc";
        else { sort.field = field; sort.dir = "asc"; }
        document.querySelectorAll(".data-table th.sortable .sort-arrow").forEach((ar) => {
          ar.classList.remove("active");
          ar.textContent = "↕";
        });
        const arrow = th.querySelector(".sort-arrow");
        if (arrow) {
          arrow.classList.add("active");
          arrow.textContent = sort.dir === "asc" ? "↑" : "↓";
        }
        applyFilters();
      });
    });

    // Modal close
    const modal = document.getElementById("detail-modal");
    document.getElementById("detail-modal-close").addEventListener("click", closeModal);
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeModal();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && modal.classList.contains("active")) closeModal();
    });
  }

  // ---------- Boot ----------

  document.addEventListener("DOMContentLoaded", () => {
    setupEvents();
    load();
  });
})();