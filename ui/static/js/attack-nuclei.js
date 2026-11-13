/* ============================================
   WatchTower — Nuclei Findings Page
   Fetches /api/nuclei, filters, sorts, paginates,
   and shows finding details in a modal.
   ============================================ */

(function () {
  "use strict";

  const PER_PAGE = 50;
  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
  const KNOWN_SEV = ["critical", "high", "medium", "low", "info"];

  let allFindings = [];
  let filtered = [];
  let currentPage = 1;

  const filters = { severity: "all", program: "all", search: "" };
  const sort = { field: "severity", dir: "asc" };

  // ---------- Helpers ----------

  function severityClass(sev) {
    const s = (sev || "").toLowerCase();
    const safe = KNOWN_SEV.includes(s) ? s : "info";
    return `badge-sev badge-sev-${safe}`;
  }

  // ---------- Data load ----------

  async function load() {
    const tbody = document.getElementById("findings-tbody");
    try {
      const data = await apiFetch("/api/nuclei");
      allFindings = data.findings || [];
      document.getElementById("finding-count").textContent = allFindings.length;
      updateMiniStats();
      populateProgramFilter();
      applyFilters();
    } catch (e) {
      console.error("Nuclei load failed:", e);
      tbody.innerHTML = `
        <tr><td colspan="7" style="text-align:center;padding:32px;color:var(--red)">
          Failed to load findings: ${escapeHTML(e.message || String(e))}
        </td></tr>
      `;
    }
  }

  // ---------- Mini stats ----------

  function updateMiniStats() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of allFindings) {
      const s = (f.severity || "").toLowerCase();
      if (counts.hasOwnProperty(s)) counts[s]++;
    }
    document.querySelectorAll("#mini-stats .mini-stat").forEach((el) => {
      const sev = el.dataset.sev;
      if (counts.hasOwnProperty(sev)) {
        el.querySelector(".mini-stat-value").textContent = counts[sev];
      }
    });
  }

  // ---------- Program filter ----------

  function populateProgramFilter() {
    const programs = new Set();
    for (const f of allFindings) {
      if (f.program) programs.add(f.program);
    }
    const sel = document.getElementById("program-filter");
    for (const p of Array.from(programs).sort()) {
      const opt = document.createElement("option");
      opt.value = p;
      opt.textContent = p;
      sel.appendChild(opt);
    }
  }

  // ---------- Filter + sort ----------

  function applyFilters() {
    const searchLower = filters.search.toLowerCase();

    filtered = allFindings.filter((f) => {
      if (filters.severity !== "all" && (f.severity || "").toLowerCase() !== filters.severity) {
        return false;
      }
      if (filters.program !== "all" && f.program !== filters.program) {
        return false;
      }
      if (searchLower) {
        const hay = `${f.host || ""} ${f.matched_at || ""} ${f.template || ""} ${f.name || ""}`.toLowerCase();
        if (!hay.includes(searchLower)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => {
      let va, vb;
      if (sort.field === "severity") {
        va = SEVERITY_ORDER[(a.severity || "").toLowerCase()] ?? 99;
        vb = SEVERITY_ORDER[(b.severity || "").toLowerCase()] ?? 99;
      } else if (sort.field === "timestamp") {
        va = a.timestamp || "";
        vb = b.timestamp || "";
      } else {
        va = String(a[sort.field] || "").toLowerCase();
        vb = String(b[sort.field] || "").toLowerCase();
      }
      if (va < vb) return sort.dir === "asc" ? -1 : 1;
      if (va > vb) return sort.dir === "asc" ? 1 : -1;
      return 0;
    });

    currentPage = 1;
    renderTable();
  }

  // ---------- Table render ----------

  function renderTable() {
    const tbody = document.getElementById("findings-tbody");
    const pagContainer = document.getElementById("pagination-container");

    if (!filtered.length) {
      tbody.innerHTML = `
        <tr><td colspan="7" style="text-align:center;padding:40px;color:var(--muted)">
          No findings match the current filters.
        </td></tr>
      `;
      pagContainer.innerHTML = "";
      return;
    }

    const start = (currentPage - 1) * PER_PAGE;
    const page = filtered.slice(start, start + PER_PAGE);

    tbody.innerHTML = page
      .map(
        (f, i) => `
      <tr data-idx="${start + i}" style="cursor:pointer">
        <td><span class="${severityClass(f.severity)}">${escapeHTML(f.severity || "unknown")}</span></td>
        <td><span style="font-family:var(--font-mono);font-size:0.82em;color:var(--blue-dim)">${escapeHTML(f.template || "—")}</span></td>
        <td class="cell-title">${escapeHTML(f.name || "—")}</td>
        <td><span class="program-tag">${escapeHTML(f.program || "—")}</span></td>
        <td class="cell-host">${escapeHTML(f.host || "—")}</td>
        <td><span style="font-family:var(--font-mono);font-size:0.78em;color:var(--muted);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle">${escapeHTML(f.matched_at || "—")}</span></td>
        <td class="cell-muted">${relativeTime(f.timestamp)}</td>
      </tr>`
      )
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

  function showDetails(f) {
    if (!f) return;
    const modal = document.getElementById("finding-modal");
    const body = document.getElementById("finding-modal-body");

    body.innerHTML = `
      <div style="margin-bottom:12px">
        <span class="${severityClass(f.severity)}">${escapeHTML(f.severity || "unknown")}</span>
        <span style="font-family:var(--font-mono);color:var(--blue);margin-left:10px;font-size:0.88em">${escapeHTML(f.template || "")}</span>
      </div>
      <h3 style="margin-bottom:10px;color:var(--text-strong);font-size:1.15em">${escapeHTML(f.name || "(unnamed)")}</h3>
      <div style="font-family:var(--font-mono);font-size:0.8em;color:var(--blue);margin-bottom:16px;word-break:break-all;padding:8px 10px;background:var(--bg-0);border:1px solid var(--border);border-radius:var(--r-sm)">${escapeHTML(f.matched_at || "")}</div>
      ${
        f.description
          ? `<p style="margin-bottom:16px;color:var(--text);line-height:1.6;font-size:0.9em">${escapeHTML(f.description)}</p>`
          : ""
      }
      <div style="display:grid;grid-template-columns:110px 1fr;gap:8px;font-size:0.88em;margin-bottom:14px">
        <div style="color:var(--muted)">Host</div>
        <div style="font-family:var(--font-mono)">${escapeHTML(f.host || "—")}</div>
        <div style="color:var(--muted)">Program</div>
        <div>${escapeHTML(f.program || "—")}</div>
        <div style="color:var(--muted)">Found</div>
        <div>${escapeHTML(f.timestamp || "—")}</div>
      </div>
      ${
        f.tags && f.tags.length
          ? `<div style="margin-top:12px"><strong style="color:var(--muted);font-size:0.78em;text-transform:uppercase;letter-spacing:0.06em">Tags:</strong> ${f.tags
              .map((t) => `<span class="tech-tag" style="margin-left:4px">${escapeHTML(t)}</span>`)
              .join("")}</div>`
          : ""
      }
    `;
    modal.classList.add("active");
  }

  function closeModal() {
    document.getElementById("finding-modal").classList.remove("active");
  }

  // ---------- Event listeners ----------

  function setupEvents() {
    // Severity pills
    document.getElementById("severity-pills").addEventListener("click", (e) => {
      const pill = e.target.closest(".filter-pill");
      if (!pill) return;
      document.querySelectorAll("#severity-pills .filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      filters.severity = pill.dataset.sev;
      applyFilters();
    });

    // Mini stats click
    document.querySelectorAll("#mini-stats .mini-stat").forEach((el) => {
      el.addEventListener("click", () => {
        const sev = el.dataset.sev;
        const pills = document.querySelectorAll("#severity-pills .filter-pill");
        let matched = null;
        pills.forEach((p) => {
          p.classList.remove("active");
          if (p.dataset.sev === sev) matched = p;
        });
        if (matched) matched.classList.add("active");
        filters.severity = sev;
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
        if (sort.field === field) {
          sort.dir = sort.dir === "asc" ? "desc" : "asc";
        } else {
          sort.field = field;
          sort.dir = "asc";
        }
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
    const modal = document.getElementById("finding-modal");
    modal.addEventListener("click", (e) => {
      if (e.target === modal || e.target.id === "finding-modal-close") closeModal();
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