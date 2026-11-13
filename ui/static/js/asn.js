/* ============================================
   WatchTower — ASN Map Page
   ============================================ */

(function () {
  "use strict";

  const PER_PAGE = 50;

  let allItems = [];
  let filtered = [];
  let currentPage = 1;

  const filters = { program: "all", search: "" };
  const sort = { field: "asn", dir: "asc" };

  async function load() {
    const tbody = document.getElementById("asn-tbody");
    try {
      const data = await apiFetch("/api/asn");
      const programs = data.programs || {};

      allItems = [];
      for (const [prog, records] of Object.entries(programs)) {
        if (!records || typeof records !== "object") continue;
        for (const [asnKey, info] of Object.entries(records)) {
          const asn = info.asn || asnKey;
          const cidrs = Array.isArray(info.cidrs) ? info.cidrs : [];
          allItems.push({
            program: prog,
            asn: asn,
            cidrs: cidrs,
            cidrs_count: info.cidrs_count != null ? info.cidrs_count : cidrs.length,
            first_seen: info.first_seen || "",
            last_seen: info.last_seen || "",
          });
        }
      }

      document.getElementById("asn-count").textContent = allItems.length;
      updateMiniStats();
      populateProgramFilter();
      applyFilters();
    } catch (e) {
      console.error("ASN load failed:", e);
      tbody.innerHTML = `
        <tr><td colspan="6" style="text-align:center;padding:32px;color:var(--red)">
          Failed to load: ${escapeHTML(e.message || String(e))}
        </td></tr>`;
    }
  }

  function updateMiniStats() {
    let totalCidrs = 0;
    const progs = new Set();
    for (const it of allItems) {
      totalCidrs += it.cidrs_count;
      progs.add(it.program);
    }
    document.getElementById("stat-asns").textContent = allItems.length;
    document.getElementById("stat-cidrs").textContent = totalCidrs.toLocaleString();
    document.getElementById("stat-programs").textContent = progs.size;
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

  function applyFilters() {
    const q = filters.search.toLowerCase();
    filtered = allItems.filter((it) => {
      if (filters.program !== "all" && it.program !== filters.program) return false;
      if (q) {
        const hay = `${it.asn} ${it.program} ${it.cidrs.join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => {
      let va, vb;
      switch (sort.field) {
        case "asn":
          va = a.asn;
          vb = b.asn;
          break;
        case "program":
          va = a.program.toLowerCase();
          vb = b.program.toLowerCase();
          break;
        case "cidrs_count":
          va = a.cidrs_count;
          vb = b.cidrs_count;
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

  function renderTable() {
    const tbody = document.getElementById("asn-tbody");
    const pagContainer = document.getElementById("pagination-container");

    if (!allItems.length) {
      tbody.innerHTML = `
        <tr><td colspan="6" style="padding:0">
          <div class="empty-state" style="border:none;background:transparent">
            <div class="empty-state-icon">🔢</div>
            <div class="empty-state-title">No ASNs yet</div>
            <div class="empty-state-desc">
              Add ASNs to a <code>program.json</code> and run <code>watch_asnmap.py</code>.
            </div>
          </div>
        </td></tr>`;
      pagContainer.innerHTML = "";
      return;
    }

    if (!filtered.length) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--muted)">No matches.</td></tr>`;
      pagContainer.innerHTML = "";
      return;
    }

    const start = (currentPage - 1) * PER_PAGE;
    const page = filtered.slice(start, start + PER_PAGE);

    tbody.innerHTML = page
      .map((it, i) => `
        <tr data-idx="${start + i}" style="cursor:pointer">
          <td class="cell-host">${escapeHTML(it.asn)}</td>
          <td><span class="program-tag">${escapeHTML(it.program)}</span></td>
          <td><span class="count-badge-inline">${it.cidrs_count.toLocaleString()}</span></td>
          <td class="cell-muted">${relativeTime(it.first_seen)}</td>
          <td class="cell-muted">${relativeTime(it.last_seen)}</td>
          <td style="text-align:center;color:var(--muted)">›</td>
        </tr>`)
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

  function showDetails(it) {
    if (!it) return;
    const modal = document.getElementById("asn-modal");
    const body = document.getElementById("asn-modal-body");

    const cidrs = it.cidrs || [];
    const visible = cidrs.slice(0, 500);
    const truncated = cidrs.length > 500;
    const cidrsText = visible.map((c) => `<div style="font-family:var(--font-mono);font-size:0.82em;padding:3px 0;color:var(--blue-dim)">${escapeHTML(c)}</div>`).join("");

    body.innerHTML = `
      <div style="margin-bottom:14px">
        <span class="program-tag">${escapeHTML(it.program)}</span>
      </div>
      <h3 style="font-family:var(--font-mono);color:var(--text-strong);font-size:1.15em;margin-bottom:12px">${escapeHTML(it.asn)}</h3>
      <div style="margin-bottom:16px;font-size:0.82em">
        <span class="count-badge-inline">${it.cidrs_count.toLocaleString()} CIDR(s)</span>
      </div>
      <div style="display:grid;grid-template-columns:120px 1fr;gap:8px 16px;font-size:0.85em;margin-bottom:20px">
        <div style="color:var(--muted)">First seen</div>
        <div style="font-family:var(--font-mono)">${escapeHTML(it.first_seen || "—")}</div>
        <div style="color:var(--muted)">Last seen</div>
        <div style="font-family:var(--font-mono)">${escapeHTML(it.last_seen || "—")}</div>
      </div>
      <h4 style="color:var(--muted);font-size:0.72em;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;font-weight:700">CIDRs</h4>
      <div style="background:var(--bg-0);border:1px solid var(--border);border-radius:var(--r-sm);padding:12px;max-height:360px;overflow-y:auto">
        ${cidrsText || `<div style="color:var(--muted);font-style:italic">No CIDRs recorded.</div>`}
        ${truncated ? `<div style="padding-top:8px;color:var(--muted);font-size:0.8em;font-style:italic">Showing first 500 of ${cidrs.length}</div>` : ""}
      </div>
    `;
    modal.classList.add("active");
  }

  function closeModal() {
    document.getElementById("asn-modal").classList.remove("active");
  }

  function setupEvents() {
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

    const modal = document.getElementById("asn-modal");
    document.getElementById("asn-modal-close").addEventListener("click", closeModal);
    modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && modal.classList.contains("active")) closeModal();
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    setupEvents();
    load();
  });
})();