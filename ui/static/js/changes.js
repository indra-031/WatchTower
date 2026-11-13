/* ============================================
   WatchTower — Changes Timeline
   ============================================ */

(function () {
  "use strict";

  const PER_PAGE = 100;

  let allChanges = [];
  let filtered = [];
  let currentPage = 1;

  const filters = { severity: "all", category: "all", program: "all", search: "" };

  function sevBadge(s) {
    return `<span class="badge-sev badge-sev-${s || "info"}">${escapeHTML(s || "?")}</span>`;
  }

  function valueStr(v) {
    if (v === null || v === undefined) return "—";
    if (Array.isArray(v)) return v.join(", ") || "(empty)";
    if (typeof v === "object") return JSON.stringify(v);
    if (v === "") return "(empty)";
    return String(v);
  }

  function formatChange(c) {
    const oldV = valueStr(c.old);
    const newV = valueStr(c.new);
    return `<span style="color:var(--muted);font-family:var(--font-mono);font-size:0.82em">${escapeHTML(oldV)}</span>
            <span style="color:var(--muted);padding:0 6px">→</span>
            <span style="color:var(--blue);font-family:var(--font-mono);font-size:0.82em">${escapeHTML(newV)}</span>`;
  }

  async function load() {
    const timeline = document.getElementById("timeline");
    try {
      const data = await apiFetch("/api/changes");
      allChanges = Array.isArray(data.changes) ? data.changes : [];
      document.getElementById("change-count").textContent = allChanges.length;
      updateMiniStats();
      populateProgramFilter();
      applyFilters();
    } catch (e) {
      console.error("Changes load failed:", e);
      timeline.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon" style="color:var(--red)">⚠️</div>
          <div class="empty-state-title">Failed to load</div>
          <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
        </div>`;
    }
  }

  function updateMiniStats() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const c of allChanges) {
      const s = (c.severity || "").toLowerCase();
      if (counts.hasOwnProperty(s)) counts[s]++;
    }
    document.getElementById("stat-critical").textContent = counts.critical;
    document.getElementById("stat-high").textContent = counts.high;
    document.getElementById("stat-medium").textContent = counts.medium;
    document.getElementById("stat-low").textContent = counts.low;
  }

  function populateProgramFilter() {
    const programs = new Set();
    for (const c of allChanges) if (c.program) programs.add(c.program);
    const sel = document.getElementById("program-filter");
    const cur = sel.value;
    while (sel.options.length > 1) sel.remove(1);
    for (const p of Array.from(programs).sort()) {
      const opt = document.createElement("option");
      opt.value = p;
      opt.textContent = p;
      sel.appendChild(opt);
    }
    if (Array.from(sel.options).some((o) => o.value === cur)) sel.value = cur;
  }

  function applyFilters() {
    const q = filters.search.toLowerCase();
    filtered = allChanges.filter((c) => {
      if (filters.severity !== "all" && (c.severity || "").toLowerCase() !== filters.severity) return false;
      if (filters.category !== "all" && (c.category || "") !== filters.category) return false;
      if (filters.program !== "all" && c.program !== filters.program) return false;
      if (q) {
        const hay = `${c.host || ""} ${c.type || ""} ${c.program || ""} ${c.category || ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    currentPage = 1;
    render();
  }

  function render() {
    const timeline = document.getElementById("timeline");
    const pagContainer = document.getElementById("pagination-container");

    if (!filtered.length) {
      timeline.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🔄</div>
          <div class="empty-state-title">No changes recorded</div>
          <div class="empty-state-desc">
            Run the pipeline twice and WatchTower will start tracking changes
            across HTTP status, titles, content hashes, tech stacks, IPs, and subdomain liveness.
          </div>
        </div>`;
      pagContainer.innerHTML = "";
      return;
    }

    const start = (currentPage - 1) * PER_PAGE;
    const page = filtered.slice(start, start + PER_PAGE);

    // Group by day
    let currentDay = null;
    const items = page.map((c) => {
      const day = (c.timestamp || "").slice(0, 10);
      let dayHeader = "";
      if (day !== currentDay) {
        currentDay = day;
        dayHeader = `
          <div style="margin:24px 0 12px;padding:8px 0;border-bottom:1px solid var(--border);color:var(--muted);font-size:0.75em;font-weight:700;text-transform:uppercase;letter-spacing:0.1em">
            ${escapeHTML(day || "(unknown)")}
          </div>`;
      }

      return `
        ${dayHeader}
        <div style="background:var(--bg-1);border:1px solid var(--border);border-radius:var(--r-md);padding:14px 16px;margin-bottom:8px;display:flex;gap:14px;align-items:flex-start;transition:all 0.15s">
          <div style="flex-shrink:0;width:100px;text-align:right;font-family:var(--font-mono);font-size:0.75em;color:var(--muted);padding-top:2px">
            ${escapeHTML((c.timestamp || "").slice(11, 19))}
          </div>
          <div style="flex-shrink:0;padding-top:2px">${sevBadge(c.severity)}</div>
          <div style="flex:1;min-width:0">
            <div style="margin-bottom:6px">
              <span style="font-family:var(--font-mono);color:var(--blue-dim);font-weight:600">${escapeHTML(c.host || "?")}</span>
              <span class="program-tag" style="margin-left:8px">${escapeHTML(c.program || "?")}</span>
            </div>
            <div style="font-size:0.85em;color:var(--muted);margin-bottom:6px">
              <strong style="color:var(--text)">${escapeHTML(c.type || "?")}</strong>
              ${c.field ? ` · <code style="font-size:0.9em;color:var(--purple)">${escapeHTML(c.field)}</code>` : ""}
            </div>
            <div>${formatChange(c)}</div>
          </div>
        </div>`;
    }).join("");

    timeline.innerHTML = `<div>${items}</div>`;

    const totalPages = Math.ceil(filtered.length / PER_PAGE);
    pagContainer.innerHTML = "";
    pagContainer.appendChild(
      renderPagination(currentPage, totalPages, filtered.length, PER_PAGE, (p) => {
        currentPage = p;
        render();
        window.scrollTo({ top: 0, behavior: "smooth" });
      })
    );
  }

  function setupEvents() {
    document.getElementById("sev-pills").addEventListener("click", (e) => {
      const pill = e.target.closest(".filter-pill");
      if (!pill) return;
      document.querySelectorAll("#sev-pills .filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      filters.severity = pill.dataset.sev;
      applyFilters();
    });

    document.querySelectorAll(".mini-stat[data-sev]").forEach((el) => {
      el.addEventListener("click", () => {
        const sev = el.dataset.sev;
        document.querySelectorAll("#sev-pills .filter-pill").forEach((p) => {
          p.classList.toggle("active", p.dataset.sev === sev);
        });
        filters.severity = sev;
        applyFilters();
      });
    });

    document.getElementById("category-filter").addEventListener("change", (e) => {
      filters.category = e.target.value;
      applyFilters();
    });

    document.getElementById("program-filter").addEventListener("change", (e) => {
      filters.program = e.target.value;
      applyFilters();
    });

    document.getElementById("search-input").addEventListener(
      "input",
      debounce((e) => { filters.search = e.target.value.trim(); applyFilters(); }, 250)
    );
  }

  document.addEventListener("DOMContentLoaded", () => {
    setupEvents();
    load();
  });
})();