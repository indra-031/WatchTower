/* ============================================
   WatchTower — WHOIS Records Page
   Schema: database/<program>/whois/lives-whois.json
     "<type>:<target>": {
       domain, target, target_type, last_seen, data: { ... }
     }
   ============================================ */

(function () {
  "use strict";

  const PER_PAGE = 50;

  // Field definitions per record type
  // [key, label, type?] — type ∈ {undefined, "bool"}
  const DOMAIN_KEYS = [
    ["ldh_name", "LDH Name"],
    ["registrar", "Registrar"],
    ["registrar_id", "Registrar ID"],
    ["registrar_abuse_email", "Abuse Email"],
    ["status", "Status"],
    ["nameservers", "Name Servers"],
    ["dnssec", "DNSSEC", "bool"],
    ["raw_entities_count", "Raw Entities"],
  ];

  const IP_KEYS = [
    ["handle", "Handle"],
    ["name", "Network Name"],
    ["ip_version", "IP Version"],
    ["type", "Allocation Type"],
    ["start_address", "Start Address"],
    ["end_address", "End Address"],
    ["parent_handle", "Parent Handle"],
    ["asn", "ASN"],
    ["asn_description", "ASN Description"],
    ["country", "Country"],
  ];

  let allRecords = [];
  let filtered = [];
  let currentPage = 1;

  const filters = { type: "all", program: "all", search: "" };
  const sort = { field: "target", dir: "asc" };

  // ---------- Formatting ----------

  function formatValue(raw, type) {
    if (raw === null || raw === undefined) return "";
    if (type === "bool") return raw ? "Enabled" : "Disabled";
    if (Array.isArray(raw)) return raw.join(", ");
    if (typeof raw === "object") return JSON.stringify(raw);
    return String(raw);
  }

  function formatDate(s) {
    if (!s) return "";
    try {
      const d = new Date(s);
      if (isNaN(d.getTime())) return String(s);
      return d.toISOString().slice(0, 19).replace("T", " ");
    } catch {
      return String(s);
    }
  }

  function eventLabel(key) {
    const small = new Set(["of", "the", "and", "in", "on", "at", "to", "for"]);
    return key
      .split(" ")
      .map((w, i) =>
        i > 0 && small.has(w.toLowerCase())
          ? w.toLowerCase()
          : w.charAt(0).toUpperCase() + w.slice(1)
      )
      .join(" ");
  }

  function typeBadge(type) {
    if (type === "ip") return `<span class="type-tag type-tag-cloud">IP</span>`;
    return `<span class="type-tag type-tag-subdomain">DOMAIN</span>`;
  }

  function primaryFieldFor(rec) {
    const d = rec.data || {};
    if (rec.type === "ip") {
      return d.name || d.asn_description || d.asn || d.handle || "";
    }
    return d.registrar || d.ldh_name || "";
  }

  // ---------- Load ----------

  async function load() {
    const tbody = document.getElementById("whois-tbody");
    try {
      const data = await apiFetch("/api/whois");
      const programs = data.programs || {};

      allRecords = [];
      for (const [prog, records] of Object.entries(programs)) {
        if (!records || typeof records !== "object") continue;
        for (const [key, record] of Object.entries(records)) {
          if (!record || typeof record !== "object") continue;

          const target =
            record.target ||
            (key.includes(":") ? key.split(":").slice(1).join(":") : key);
          const type =
            record.target_type ||
            (key.startsWith("ip:") ? "ip" : "domain");

          allRecords.push({
            program: prog,
            key: key,
            target: target,
            type: type,
            domain: record.domain || "",
            last_seen: record.last_seen || "",
            data: record.data && typeof record.data === "object" ? record.data : {},
          });
        }
      }

      document.getElementById("record-count").textContent = allRecords.length;
      updateMiniStats();
      populateProgramFilter();
      applyFilters();
    } catch (e) {
      console.error("WHOIS load failed:", e);
      tbody.innerHTML = `
        <tr><td colspan="7" style="text-align:center;padding:32px;color:var(--red)">
          Failed to load records: ${escapeHTML(e.message || String(e))}
        </td></tr>
      `;
    }
  }

  function updateMiniStats() {
    let domains = 0, ips = 0;
    for (const r of allRecords) {
      if (r.type === "ip") ips++;
      else domains++;
    }
    document.querySelectorAll("#mini-stats .mini-stat").forEach((el) => {
      const t = el.dataset.type;
      const v = el.querySelector(".mini-stat-value");
      if (t === "domain") v.textContent = domains;
      else if (t === "ip") v.textContent = ips;
      else if (t === "all") v.textContent = allRecords.length;
    });
  }

  function populateProgramFilter() {
    const programs = new Set();
    for (const r of allRecords) programs.add(r.program);
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
    const q = filters.search.toLowerCase();

    filtered = allRecords.filter((r) => {
      if (filters.type !== "all" && r.type !== filters.type) return false;
      if (filters.program !== "all" && r.program !== filters.program) return false;
      if (q) {
        const d = r.data || {};
        const hay = [
          r.target, r.program, r.type,
          d.registrar || "",
          d.ldh_name || "",
          d.name || "",
          d.handle || "",
          d.asn_description || "",
          d.country || "",
        ].join(" ").toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => {
      let va, vb;
      switch (sort.field) {
        case "target":
          va = a.target.toLowerCase();
          vb = b.target.toLowerCase();
          break;
        case "program":
          va = a.program.toLowerCase();
          vb = b.program.toLowerCase();
          break;
        case "type":
          va = a.type;
          vb = b.type;
          break;
        case "queried":
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
    const tbody = document.getElementById("whois-tbody");
    const pagContainer = document.getElementById("pagination-container");

    if (!filtered.length) {
      tbody.innerHTML = `
        <tr><td colspan="7" style="text-align:center;padding:40px;color:var(--muted)">
          No WHOIS records match the current filters.
        </td></tr>
      `;
      pagContainer.innerHTML = "";
      return;
    }

    const start = (currentPage - 1) * PER_PAGE;
    const page = filtered.slice(start, start + PER_PAGE);

    tbody.innerHTML = page
      .map((r, i) => {
        const primary = primaryFieldFor(r) || "—";
        const country = (r.data && r.data.country) || "—";
        return `
        <tr data-idx="${start + i}" style="cursor:pointer">
          <td>${typeBadge(r.type)}</td>
          <td class="cell-host">${escapeHTML(r.target)}</td>
          <td><span class="program-tag">${escapeHTML(r.program)}</span></td>
          <td class="cell-title">${escapeHTML(primary)}</td>
          <td class="cell-muted">${escapeHTML(country)}</td>
          <td class="cell-muted">${relativeTime(r.last_seen)}</td>
          <td style="text-align:center;color:var(--muted)">›</td>
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

  function buildKVGrid(pairs) {
    if (!pairs.length) return "";
    const rows = pairs
      .map(
        ([label, value]) => `
        <div style="color:var(--muted);font-size:0.85em">${escapeHTML(label)}</div>
        <div style="font-family:var(--font-mono);font-size:0.85em;word-break:break-all">${escapeHTML(value)}</div>
      `
      )
      .join("");
    return `
      <div style="display:grid;grid-template-columns:160px 1fr;gap:8px 16px;margin-bottom:16px">
        ${rows}
      </div>
    `;
  }

  function buildDomainRows(d) {
    const pairs = [];
    for (const [key, label, type] of DOMAIN_KEYS) {
      const v = formatValue(d[key], type);
      if (!v || !v.trim()) continue;
      pairs.push([label, v]);
    }
    // Flatten events object
    if (d.events && typeof d.events === "object") {
      for (const [k, v] of Object.entries(d.events)) {
        const vv = formatDate(v);
        if (vv) pairs.push([eventLabel(k), vv]);
      }
    }
    return pairs;
  }

  function buildIPRows(d) {
    const pairs = [];
    for (const [key, label] of IP_KEYS) {
      const v = formatValue(d[key]);
      if (!v || !v.trim()) continue;
      pairs.push([label, v]);
    }
    return pairs;
  }

  function collectExtraPairs(d, knownList) {
    const knownSet = new Set(knownList.map(([k]) => k));
    knownSet.add("events"); // handled separately
    const out = [];
    for (const [k, raw] of Object.entries(d || {})) {
      if (knownSet.has(k)) continue;
      const v = formatValue(raw);
      if (!v || !v.trim()) continue;
      out.push([k, v]);
    }
    return out;
  }

  function showDetails(rec) {
    if (!rec) return;
    const modal = document.getElementById("whois-modal");
    const body = document.getElementById("whois-modal-body");
    const d = rec.data || {};

    const knownPairs = rec.type === "ip" ? buildIPRows(d) : buildDomainRows(d);
    const knownList  = rec.type === "ip" ? IP_KEYS : DOMAIN_KEYS;
    const extraPairs = collectExtraPairs(d, knownList);

    const parentDomain =
      rec.domain && rec.domain !== rec.target && rec.type === "ip"
        ? rec.domain
        : "";

    body.innerHTML = `
      <div style="margin-bottom:16px">
        ${typeBadge(rec.type)}
        <span style="font-family:var(--font-mono);color:var(--text-strong);margin-left:10px;font-size:1.05em;font-weight:600">${escapeHTML(rec.target)}</span>
        ${parentDomain ? `<div style="color:var(--muted);font-size:0.82em;margin-top:4px">Parent domain: <span style="font-family:var(--font-mono)">${escapeHTML(parentDomain)}</span></div>` : ""}
      </div>

      <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:20px;font-size:0.85em">
        <span class="program-tag">${escapeHTML(rec.program)}</span>
        ${rec.last_seen ? `<span class="cell-muted">Queried ${escapeHTML(rec.last_seen)}</span>` : ""}
      </div>

      ${
        knownPairs.length
          ? `<h4 style="color:var(--muted);font-size:0.72em;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:10px;font-weight:700">${rec.type === "ip" ? "Network Info" : "Registration Info"}</h4>
             ${buildKVGrid(knownPairs)}`
          : ""
      }

      ${
        extraPairs.length
          ? `
            <details style="margin-top:8px">
              <summary style="cursor:pointer;color:var(--muted);font-size:0.82em;padding:8px 0;user-select:none">
                Additional fields (${extraPairs.length})
              </summary>
              <div style="margin-top:10px">${buildKVGrid(extraPairs)}</div>
            </details>
          `
          : ""
      }

      ${
        !knownPairs.length && !extraPairs.length
          ? `<p style="color:var(--muted);font-style:italic;font-size:0.9em">No parsed fields. Raw record may be empty.</p>`
          : ""
      }
    `;

    modal.classList.add("active");
  }

  function closeModal() {
    document.getElementById("whois-modal").classList.remove("active");
  }

  // ---------- Events ----------

  function setupEvents() {
    document.getElementById("type-pills").addEventListener("click", (e) => {
      const pill = e.target.closest(".filter-pill");
      if (!pill) return;
      document.querySelectorAll("#type-pills .filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      filters.type = pill.dataset.type;
      applyFilters();
    });

    document.querySelectorAll("#mini-stats .mini-stat").forEach((el) => {
      el.addEventListener("click", () => {
        const t = el.dataset.type;
        document.querySelectorAll("#type-pills .filter-pill").forEach((p) => {
          p.classList.toggle("active", p.dataset.type === t);
        });
        filters.type = t;
        applyFilters();
      });
    });

    document.getElementById("program-filter").addEventListener("change", (e) => {
      filters.program = e.target.value;
      applyFilters();
    });

    document.getElementById("search-input").addEventListener(
      "input",
      debounce((e) => {
        filters.search = e.target.value.trim();
        applyFilters();
      }, 250)
    );

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

    const modal = document.getElementById("whois-modal");
    modal.addEventListener("click", (e) => {
      if (e.target === modal || e.target.id === "whois-modal-close") closeModal();
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