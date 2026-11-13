/* ============================================
   WatchTower — CIDR Map Page
   ============================================ */

(function () {
  "use strict";

  const PER_PAGE = 50;

  let allItems = [];
  let filtered = [];
  let currentPage = 1;

  const filters = { source: "all", program: "all", search: "" };
  const sort = { field: "cidr", dir: "asc" };

  function ipTypeTag(ver) {
    return ver === "v6"
      ? `<span class="type-tag type-tag-cloud">v6</span>`
      : `<span class="type-tag type-tag-subdomain">v4</span>`;
  }

  function sourceTag(s) {
    const cls = s === "program" ? "source-tag source-findomain" : "source-tag source-pattern_recognition";
    return `<span class="${cls}">${escapeHTML(s)}</span>`;
  }

  async function load() {
    const tbody = document.getElementById("cidr-tbody");
    try {
      const data = await apiFetch("/api/cidr");
      const programs = data.programs || {};

      allItems = [];
      for (const [prog, records] of Object.entries(programs)) {
        if (!records || typeof records !== "object") continue;
        for (const [cidrKey, info] of Object.entries(records)) {
          const cidr = info.cidr || cidrKey;
          const sources = Array.isArray(info.sources) ? info.sources : [];
          const ips = Array.isArray(info.ips) ? info.ips : [];

          allItems.push({
            program: prog,
            cidr: cidr,
            sources: sources,
            ips: ips,
            ips_count: info.ips_count != null ? info.ips_count : ips.length,
            first_seen: info.first_seen || "",
            last_seen: info.last_seen || "",
          });
        }
      }

      document.getElementById("cidr-count").textContent = allItems.length;
      updateMiniStats();
      populateProgramFilter();
      applyFilters();
    } catch (e) {
      console.error("CIDR load failed:", e);
      tbody.innerHTML = `
        <tr><td colspan="6" style="text-align:center;padding:32px;color:var(--red)">
          Failed to load: ${escapeHTML(e.message || String(e))}
        </td></tr>`;
    }
  }

  function updateMiniStats() {
    let totalIps = 0;
    let fromProgram = 0;
    let fromAsn = 0;
    for (const it of allItems) {
      totalIps += it.ips_count;
      if (it.sources.includes("program")) fromProgram++;
      if (it.sources.includes("asn")) fromAsn++;
    }
    document.getElementById("stat-total").textContent = allItems.length;
    document.getElementById("stat-ips").textContent = totalIps.toLocaleString();
    document.getElementById("stat-program").textContent = fromProgram;
    document.getElementById("stat-asn").textContent = fromAsn;
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
      if (filters.source === "program" && !it.sources.includes("program")) return false;
      if (filters.source === "asn" && !it.sources.includes("asn")) return false;
      if (q) {
        const hay = `${it.cidr} ${it.program} ${it.sources.join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => {
      let va, vb;
      switch (sort.field) {
        case "cidr":
          va = a.cidr;
          vb = b.cidr;
          break;
        case "program":
          va = a.program.toLowerCase();
          vb = b.program.toLowerCase();
          break;
        case "ips_count":
          va = a.ips_count;
          vb = b.ips_count;
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
    const tbody = document.getElementById("cidr-tbody");
    const pagContainer = document.getElementById("pagination-container");

    if (!allItems.length) {
      tbody.innerHTML = `
        <tr><td colspan="6" style="padding:0">
          <div class="empty-state" style="border:none;background:transparent">
            <div class="empty-state-icon">🧮</div>
            <div class="empty-state-title">No CIDRs yet</div>
            <div class="empty-state-desc">
              Add CIDRs or ASNs to a <code>program.json</code> and run
              <code>watch_asnmap.py</code> + <code>watch_mapcidr.py</code>.
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
          <td class="cell-host">${escapeHTML(it.cidr)}</td>
          <td><span class="program-tag">${escapeHTML(it.program)}</span></td>
          <td><div class="source-list">${it.sources.map(sourceTag).join(" ")}</div></td>
          <td><span class="count-badge-inline">${it.ips_count.toLocaleString()}</span></td>
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
    const modal = document.getElementById("cidr-modal");
    const body = document.getElementById("cidr-modal-body");

    const ips = it.ips || [];
    const visible = ips.slice(0, 500);
    const truncated = ips.length > 500;
    const ipsText = visible.map((ip) => `<div style="font-family:var(--font-mono);font-size:0.82em;padding:3px 0;color:var(--blue-dim)">${escapeHTML(ip)}</div>`).join("");

    body.innerHTML = `
      <div style="margin-bottom:14px">
        <span class="program-tag">${escapeHTML(it.program)}</span>
      </div>
      <h3 style="font-family:var(--font-mono);color:var(--text-strong);font-size:1.15em;margin-bottom:12px">${escapeHTML(it.cidr)}</h3>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;font-size:0.82em">
        ${it.sources.map(sourceTag).join(" ")}
        <span class="count-badge-inline">${it.ips_count.toLocaleString()} IP(s)</span>
      </div>
      <h4 style="color:var(--muted);font-size:0.72em;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;font-weight:700">IPs</h4>
      <div style="background:var(--bg-0);border:1px solid var(--border);border-radius:var(--r-sm);padding:12px;max-height:360px;overflow-y:auto">
        ${ipsText || `<div style="color:var(--muted);font-style:italic">No IPs recorded.</div>`}
        ${truncated ? `<div style="padding-top:8px;color:var(--muted);font-size:0.8em;font-style:italic">Showing first 500 of ${ips.length}</div>` : ""}
      </div>
    `;
    modal.classList.add("active");
  }

  function closeModal() {
    document.getElementById("cidr-modal").classList.remove("active");
  }

  function setupEvents() {
    document.getElementById("source-pills").addEventListener("click", (e) => {
      const pill = e.target.closest(".filter-pill");
      if (!pill) return;
      document.querySelectorAll("#source-pills .filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      filters.source = pill.dataset.source;
      applyFilters();
    });

    document.querySelectorAll("#mini-stats .mini-stat").forEach((el) => {
      el.addEventListener("click", () => {
        const src = el.dataset.source;
        if (src === "ips") return; // not a filter
        document.querySelectorAll("#source-pills .filter-pill").forEach((p) => {
          p.classList.toggle("active", p.dataset.source === src);
        });
        filters.source = src;
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

    const modal = document.getElementById("cidr-modal");
    document.getElementById("cidr-modal-close").addEventListener("click", closeModal);
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