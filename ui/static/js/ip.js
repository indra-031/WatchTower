/* ============================================
   WatchTower — IP Enrichment Page
   ============================================ */

(function () {
  "use strict";

  const PER_PAGE = 100;

  let allItems = [];
  let filtered = [];
  let currentPage = 1;

  const filters = { version: "all", program: "all", search: "" };
  const sort = { field: "ip", dir: "asc" };

  function versionBadge(v) {
    if (v === "v6") return `<span class="type-tag type-tag-cloud">v6</span>`;
    if (v === "v4") return `<span class="type-tag type-tag-subdomain">v4</span>`;
    return `<span class="type-tag type-tag-cdn">?</span>`;
  }

  async function load() {
    const tbody = document.getElementById("ip-tbody");
    try {
      const data = await apiFetch("/api/ip");
      const programs = data.programs || {};

      allItems = [];
      for (const [prog, records] of Object.entries(programs)) {
        if (!records || typeof records !== "object") continue;
        for (const [ipKey, info] of Object.entries(records)) {
          const ip = info.ip || ipKey;
          allItems.push({
            program: prog,
            ip: ip,
            ip_version: info.ip_version || "unknown",
            reverse_dns: info.reverse_dns || "",
            asn: info.asn || "",
            as_name: info.as_name || "",
            as_country: info.as_country || "",
            as_range: Array.isArray(info.as_range) ? info.as_range : [],
            first_seen: info.first_seen || "",
            last_seen: info.last_seen || "",
          });
        }
      }

      document.getElementById("ip-count").textContent = allItems.length;
      updateMiniStats();
      populateProgramFilter();
      applyFilters();
    } catch (e) {
      console.error("IP load failed:", e);
      tbody.innerHTML = `
        <tr><td colspan="9" style="text-align:center;padding:32px;color:var(--red)">
          Failed to load: ${escapeHTML(e.message || String(e))}
        </td></tr>`;
    }
  }

  function updateMiniStats() {
    let v4 = 0, v6 = 0, withAsn = 0, withRdns = 0;
    for (const it of allItems) {
      if (it.ip_version === "v4") v4++;
      else if (it.ip_version === "v6") v6++;
      if (it.asn) withAsn++;
      if (it.reverse_dns) withRdns++;
    }
    document.getElementById("stat-total").textContent = allItems.length;
    document.getElementById("stat-v4").textContent = v4;
    document.getElementById("stat-v6").textContent = v6;
    document.getElementById("stat-with-asn").textContent = withAsn;
    document.getElementById("stat-with-rdns").textContent = withRdns;
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
      if (filters.version === "v4" && it.ip_version !== "v4") return false;
      if (filters.version === "v6" && it.ip_version !== "v6") return false;
      if (filters.version === "with-asn" && !it.asn) return false;
      if (filters.version === "with-rdns" && !it.reverse_dns) return false;
      if (q) {
        const hay = `${it.ip} ${it.program} ${it.reverse_dns} ${it.asn} ${it.as_name} ${it.as_country}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => {
      let va, vb;
      switch (sort.field) {
        case "ip":
          va = a.ip;
          vb = b.ip;
          break;
        case "program":
          va = a.program.toLowerCase();
          vb = b.program.toLowerCase();
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
    const tbody = document.getElementById("ip-tbody");
    const pagContainer = document.getElementById("pagination-container");

    if (!allItems.length) {
      tbody.innerHTML = `
        <tr><td colspan="9" style="padding:0">
          <div class="empty-state" style="border:none;background:transparent">
            <div class="empty-state-icon">🌐</div>
            <div class="empty-state-title">No single IPs yet</div>
            <div class="empty-state-desc">
              Add IPs to a <code>program.json</code> and run <code>watch_ip.py</code>.
            </div>
          </div>
        </td></tr>`;
      pagContainer.innerHTML = "";
      return;
    }

    if (!filtered.length) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:40px;color:var(--muted)">No matches.</td></tr>`;
      pagContainer.innerHTML = "";
      return;
    }

    const start = (currentPage - 1) * PER_PAGE;
    const page = filtered.slice(start, start + PER_PAGE);

    tbody.innerHTML = page
      .map((it, i) => `
        <tr data-idx="${start + i}" style="cursor:pointer">
          <td class="cell-host">${escapeHTML(it.ip)}</td>
          <td>${versionBadge(it.ip_version)}</td>
          <td><span class="program-tag">${escapeHTML(it.program)}</span></td>
          <td class="cell-muted" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHTML(it.reverse_dns || "—")}</td>
          <td style="font-family:var(--font-mono);font-size:0.82em;color:var(--purple)">${escapeHTML(it.asn || "—")}</td>
          <td class="cell-muted">${escapeHTML(it.as_name || "—")}</td>
          <td class="cell-muted">${escapeHTML(it.as_country || "—")}</td>
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
    const modal = document.getElementById("ip-modal");
    const body = document.getElementById("ip-modal-body");

    const pairs = [];
    if (it.reverse_dns) pairs.push(["Reverse DNS", it.reverse_dns]);
    if (it.asn) pairs.push(["ASN", it.asn]);
    if (it.as_name) pairs.push(["AS Name", it.as_name]);
    if (it.as_country) pairs.push(["AS Country", it.as_country]);
    if (it.as_range && it.as_range.length) pairs.push(["AS Range", it.as_range.join(", ")]);
    if (it.first_seen) pairs.push(["First Seen", it.first_seen]);
    if (it.last_seen) pairs.push(["Last Seen", it.last_seen]);

    const rows = pairs.map(([k, v]) =>
      `<div style="color:var(--muted);font-size:0.85em">${escapeHTML(k)}</div>
       <div style="font-family:var(--font-mono);font-size:0.85em;word-break:break-all">${escapeHTML(v)}</div>`
    ).join("");

    body.innerHTML = `
      <div style="margin-bottom:14px;display:flex;gap:10px;align-items:center">
        ${versionBadge(it.ip_version)}
        <span class="program-tag">${escapeHTML(it.program)}</span>
      </div>
      <h3 style="font-family:var(--font-mono);color:var(--text-strong);font-size:1.15em;margin-bottom:16px">${escapeHTML(it.ip)}</h3>
      <div style="display:grid;grid-template-columns:160px 1fr;gap:8px 16px">
        ${rows || `<div style="color:var(--muted);font-style:italic;grid-column:1 / -1">No enrichment data.</div>`}
      </div>
    `;
    modal.classList.add("active");
  }

  function closeModal() {
    document.getElementById("ip-modal").classList.remove("active");
  }

  function setupEvents() {
    document.getElementById("version-pills").addEventListener("click", (e) => {
      const pill = e.target.closest(".filter-pill");
      if (!pill) return;
      document.querySelectorAll("#version-pills .filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      filters.version = pill.dataset.version;
      applyFilters();
    });

    document.querySelectorAll("#mini-stats .mini-stat").forEach((el) => {
      el.addEventListener("click", () => {
        const ver = el.dataset.version;
        document.querySelectorAll("#version-pills .filter-pill").forEach((p) => {
          p.classList.toggle("active", p.dataset.version === ver);
        });
        filters.version = ver;
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

    const modal = document.getElementById("ip-modal");
    document.getElementById("ip-modal-close").addEventListener("click", closeModal);
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