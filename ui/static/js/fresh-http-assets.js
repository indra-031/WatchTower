/* ============================================
   WatchTower — Fresh HTTP Assets (with tabs)
   ============================================ */

(function () {
  "use strict";

  const PER_PAGE = 50;

  let allItems = [];
  let filtered = [];
  let currentPage = 1;

  const filters = { tab: "new", program: "all", search: "" };
  const sort = { field: "host", dir: "asc" };

  function statusBadge(code) {
    const s = String(code || "");
    const cls = s.startsWith("2") ? "badge-status-2xx"
              : s.startsWith("3") ? "badge-status-3xx"
              : s.startsWith("4") ? "badge-status-4xx"
              : s.startsWith("5") ? "badge-status-5xx"
              : "badge-status-na";
    return `<span class="badge-status ${cls}">${escapeHTML(code || "—")}</span>`;
  }

  function rowBadges(it) {
    const badges = [];
    const fresh = isFresh(it.first_seen);
    const changed = it.last_changed && it.last_changed !== it.first_seen && isFresh(it.last_changed);
    if (fresh) badges.push(`<span title="New in last 24h" style="color:var(--green);font-size:1.1em">🆕</span>`);
    if (changed) badges.push(`<span title="Changed in last 24h" style="color:var(--yellow);font-size:1.1em">🔄</span>`);
    return badges.join(" ");
  }

  function isFresh(ts) {
    if (!ts) return false;
    try {
      const t = new Date(ts.replace(" ", "T"));
      return (Date.now() - t.getTime()) <= 24 * 3600 * 1000;
    } catch { return false; }
  }

  async function load() {
    const tbody = document.getElementById("fresh-tbody");
    try {
      const data = await apiFetch("/api/http");
      allItems = (data.http_services || []).map((it) => ({
        ...it,
        _fresh: isFresh(it.first_seen),
        _changed: it.last_changed && it.last_changed !== it.first_seen && isFresh(it.last_changed),
      }));
      document.getElementById("item-count").textContent = allItems.length;
      populateProgramFilter();
      applyFilters();
    } catch (e) {
      console.error("Fresh HTTP load failed:", e);
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:32px;color:var(--red)">${escapeHTML(e.message)}</td></tr>`;
    }
  }

  function populateProgramFilter() {
    const programs = new Set();
    for (const it of allItems) if (it.program) programs.add(it.program);
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

    filtered = allItems.filter((it) => {
      if (filters.tab === "new" && !it._fresh) return false;
      if (filters.tab === "changed" && !it._changed) return false;
      if (filters.tab === "all" && !it._fresh && !it._changed) return false;
      if (filters.program !== "all" && it.program !== filters.program) return false;
      if (q) {
        const hay = `${it.host || ""} ${it.url || ""} ${it.title || ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => {
      let va, vb;
      switch (sort.field) {
        case "host": va = (a.host || "").toLowerCase(); vb = (b.host || "").toLowerCase(); break;
        case "last_seen": va = a.last_seen || ""; vb = b.last_seen || ""; break;
        case "last_changed": va = a.last_changed || ""; vb = b.last_changed || ""; break;
        default: va = ""; vb = "";
      }
      if (va < vb) return sort.dir === "asc" ? -1 : 1;
      if (va > vb) return sort.dir === "asc" ? 1 : -1;
      return 0;
    });

    currentPage = 1;
    renderTable();
  }

  function renderTable() {
    const tbody = document.getElementById("fresh-tbody");
    const pagContainer = document.getElementById("pagination-container");

    if (!filtered.length) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--muted)">No matches.</td></tr>`;
      pagContainer.innerHTML = "";
      return;
    }

    const start = (currentPage - 1) * PER_PAGE;
    const page = filtered.slice(start, start + PER_PAGE);

    tbody.innerHTML = page.map((it) => {
      const tech = Array.isArray(it.tech) ? it.tech.slice(0, 3) : [];
      const techHtml = tech.map((t) => `<span class="tech-tag-cell">${escapeHTML(t)}</span>`).join(" ");
      const moreTech = it.tech && it.tech.length > 3 ? `<span class="tech-tag-more">+${it.tech.length - 3}</span>` : "";

      return `
        <tr style="cursor:pointer" data-host="${escapeHTML(it.host)}">
          <td style="text-align:center">${rowBadges(it)}</td>
          <td class="cell-host">${escapeHTML(it.host || "—")}</td>
          <td>${statusBadge(it.status_code)}</td>
          <td class="cell-title">${escapeHTML(it.title || "—")}</td>
          <td><div class="tech-list">${techHtml} ${moreTech}</div></td>
          <td><span class="program-tag">${escapeHTML(it.program || "—")}</span></td>
          <td class="cell-muted">${relativeTime(it.last_seen)}</td>
          <td class="cell-muted">${it.last_changed && it.last_changed !== it.first_seen ? relativeTime(it.last_changed) : "—"}</td>
        </tr>`;
    }).join("");

    tbody.querySelectorAll("tr[data-host]").forEach((tr) => {
      tr.addEventListener("click", () => {
        window.open(`/http-assets?host=${encodeURIComponent(tr.dataset.host)}`, "_blank");
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

  function setupEvents() {
    document.querySelectorAll(".filter-pill[data-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".filter-pill[data-tab]").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        filters.tab = btn.dataset.tab;
        applyFilters();
      });
    });

    document.getElementById("program-filter").addEventListener("change", (e) => {
      filters.program = e.target.value;
      applyFilters();
    });

    document.getElementById("search-input").addEventListener(
      "input",
      debounce((e) => { filters.search = e.target.value.trim(); applyFilters(); }, 250)
    );

    document.querySelectorAll(".data-table th.sortable").forEach((th) => {
      th.addEventListener("click", () => {
        const field = th.dataset.sort;
        if (sort.field === field) sort.dir = sort.dir === "asc" ? "desc" : "asc";
        else { sort.field = field; sort.dir = "asc"; }
        document.querySelectorAll(".data-table th.sortable .sort-arrow").forEach((ar) => {
          ar.classList.remove("active"); ar.textContent = "↕";
        });
        const arrow = th.querySelector(".sort-arrow");
        if (arrow) { arrow.classList.add("active"); arrow.textContent = sort.dir === "asc" ? "↑" : "↓"; }
        applyFilters();
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    setupEvents();
    load();
  });
})();