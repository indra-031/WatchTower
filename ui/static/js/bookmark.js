/* ============================================
   WatchTower — Bookmarks
   1) Shared store (window.WatchTowerBookmarks)
      - LocalStorage-backed
      - Available on any page that loads this file
   2) Bookmark page logic (runs only if #bookmark-tbody exists)
   ============================================ */

/* ==========================================================
   SHARED STORE
   ========================================================== */

window.WatchTowerBookmarks = (function () {
  "use strict";

  const STORAGE_KEY = "watchtower_bookmarks_v1";

  function read() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      console.error("Bookmarks: failed to read storage", e);
      return [];
    }
  }

  function write(list) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
      window.dispatchEvent(new CustomEvent("watchtower:bookmarks-changed"));
    } catch (e) {
      console.error("Bookmarks: failed to write storage", e);
    }
  }

  function keyOf(rec) {
    return `${rec.program || ""}|${rec.type || ""}|${rec.target || ""}`;
  }

  function findIndex(list, rec) {
    const k = keyOf(rec);
    return list.findIndex((b) => keyOf(b) === k);
  }

  function newId() {
    return "b_" + Date.now() + "_" + Math.random().toString(36).slice(2, 8);
  }

  function add(rec) {
    const list = read();
    const idx = findIndex(list, rec);
    if (idx >= 0) return { id: list[idx].id, added: false };

    const entry = {
      id: newId(),
      program: rec.program || "unknown",
      type: rec.type || "unknown",
      target: rec.target || "",
      url: rec.url || "",
      notes: rec.notes || "",
      added_at: new Date().toISOString().slice(0, 19).replace("T", " "),
    };
    list.push(entry);
    write(list);
    return { id: entry.id, added: true };
  }

  function remove(id) {
    const list = read();
    const next = list.filter((b) => b.id !== id);
    if (next.length !== list.length) write(next);
  }

  function toggle(rec) {
    const list = read();
    const idx = findIndex(list, rec);
    if (idx >= 0) {
      list.splice(idx, 1);
      write(list);
      return { id: null, added: false };
    }
    return add(rec);
  }

  function has(program, type, target) {
    const list = read();
    const idx = findIndex(list, { program, type, target });
    return idx >= 0 ? list[idx].id : null;
  }

  function update(id, patch) {
    const list = read();
    const idx = list.findIndex((b) => b.id === id);
    if (idx < 0) return;
    list[idx] = Object.assign({}, list[idx], patch);
    write(list);
  }

  function get() { return read(); }
  function count() { return read().length; }

  function exportJSON() {
    return JSON.stringify(read(), null, 2);
  }

  function importJSON(jsonStr, mode) {
    mode = mode || "merge";
    let incoming;
    try {
      incoming = JSON.parse(jsonStr);
      if (!Array.isArray(incoming)) throw new Error("root is not an array");
    } catch (e) {
      throw new Error("Invalid bookmarks file: " + e.message);
    }

    if (mode === "replace") {
      write(incoming);
      return incoming.length;
    }

    const existing = read();
    const keys = new Set(existing.map(keyOf));
    let added = 0;
    for (const rec of incoming) {
      if (!rec || !rec.target) continue;
      if (!rec.id) rec.id = newId();
      const k = keyOf(rec);
      if (keys.has(k)) continue;
      existing.push(rec);
      keys.add(k);
      added++;
    }
    write(existing);
    return added;
  }

  return { add, remove, toggle, has, update, get, count, exportJSON, importJSON };
})();

/* Cross-tab sync: reflect changes from other tabs */
window.addEventListener("storage", (e) => {
  if (e.key === "watchtower_bookmarks_v1") {
    window.dispatchEvent(new CustomEvent("watchtower:bookmarks-changed"));
  }
});

/* ==========================================================
   PAGE LOGIC (only if on bookmark page)
   ========================================================== */

(function () {
  "use strict";
  if (!document.getElementById("bookmark-tbody")) return;

  const PER_PAGE = 50;
  const TYPE_ORDER = ["subdomain", "live", "http", "cdn", "vhost", "portscan", "whois", "nuclei", "other"];

  let allBookmarks = [];
  let filtered = [];
  let currentPage = 1;

  const filters = { type: "all", program: "all", search: "" };
  const sort = { field: "target", dir: "asc" };

  // ---------- Helpers ----------

  function typeBadgeClass(type) {
    const t = String(type || "").toLowerCase();
    const known = new Set(["subdomain", "http", "cdn", "portscan", "vhost", "nuclei", "live", "whois"]);
    return `type-tag type-tag-${known.has(t) ? t : "subdomain"}`;
  }

  function typeBadge(type) {
    return `<span class="${typeBadgeClass(type)}">${escapeHTML(String(type || "unknown").toUpperCase())}</span>`;
  }

  function renderTarget(bm) {
    const target = escapeHTML(bm.target || "");
    if (bm.url) {
      return `<a href="${escapeHTML(bm.url)}" target="_blank" rel="noopener" class="bm-target-link">${target}</a>`;
    }
    return `<span class="cell-host">${target}</span>`;
  }

  // ---------- Load ----------

  function load() {
    allBookmarks = window.WatchTowerBookmarks.get();
    document.getElementById("bookmark-count").textContent = allBookmarks.length;
    updateMiniStats();
    populateProgramFilter();
    applyFilters();
  }

  function updateMiniStats() {
    const counts = { all: allBookmarks.length, subdomain: 0, live: 0, http: 0, nuclei: 0 };
    for (const b of allBookmarks) {
      const t = (b.type || "").toLowerCase();
      if (counts.hasOwnProperty(t)) counts[t]++;
    }
    document.getElementById("stat-all").textContent = counts.all;
    document.getElementById("stat-subdomain").textContent = counts.subdomain;
    document.getElementById("stat-live").textContent = counts.live;
    document.getElementById("stat-http").textContent = counts.http;
    document.getElementById("stat-nuclei").textContent = counts.nuclei;
  }

  function populateProgramFilter() {
    const programs = new Set();
    for (const b of allBookmarks) programs.add(b.program);
    const sel = document.getElementById("program-filter");
    const current = sel.value;
    // keep "all" option, remove the rest
    while (sel.options.length > 1) sel.remove(1);
    for (const p of Array.from(programs).sort()) {
      const opt = document.createElement("option");
      opt.value = p;
      opt.textContent = p;
      sel.appendChild(opt);
    }
    // restore selection if still valid
    if (Array.from(sel.options).some((o) => o.value === current)) sel.value = current;
  }

  // ---------- Filter + sort ----------

  function applyFilters() {
    const q = filters.search.toLowerCase();

    filtered = allBookmarks.filter((b) => {
      if (filters.type !== "all" && (b.type || "").toLowerCase() !== filters.type) return false;
      if (filters.program !== "all" && b.program !== filters.program) return false;
      if (q) {
        const hay = `${b.target || ""} ${b.program || ""} ${b.type || ""} ${b.notes || ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => {
      let va, vb;
      switch (sort.field) {
        case "target":
          va = (a.target || "").toLowerCase();
          vb = (b.target || "").toLowerCase();
          break;
        case "program":
          va = (a.program || "").toLowerCase();
          vb = (b.program || "").toLowerCase();
          break;
        case "type":
          va = TYPE_ORDER.indexOf((a.type || "").toLowerCase());
          vb = TYPE_ORDER.indexOf((b.type || "").toLowerCase());
          if (va === -1) va = 99;
          if (vb === -1) vb = 99;
          break;
        case "added":
          va = a.added_at || "";
          vb = b.added_at || "";
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
    const tbody = document.getElementById("bookmark-tbody");
    const pagContainer = document.getElementById("pagination-container");

    if (!filtered.length) {
      const isFiltered = filters.type !== "all" || filters.program !== "all" || filters.search;
      if (!isFiltered && !allBookmarks.length) {
        tbody.innerHTML = `
          <tr><td colspan="6" style="padding:0">
            <div class="empty-state" style="border:none;background:transparent">
              <div class="empty-state-icon">🔖</div>
              <div class="empty-state-title">No bookmarks yet</div>
              <div class="empty-state-desc">
                Click the <strong>☆ star</strong> on any row in <a href="/subdomains">Subdomains</a>,
                <a href="/live-subdomains">Live Hosts</a>, <a href="/http-assets">HTTP Assets</a>,
                or any other list page to add it here.
              </div>
            </div>
          </td></tr>`;
      } else {
        tbody.innerHTML = `
          <tr><td colspan="6" style="text-align:center;padding:40px;color:var(--muted)">
            No bookmarks match the current filters.
          </td></tr>`;
      }
      pagContainer.innerHTML = "";
      return;
    }

    const start = (currentPage - 1) * PER_PAGE;
    const page = filtered.slice(start, start + PER_PAGE);

    tbody.innerHTML = page
      .map((bm) => `
        <tr data-bm-id="${escapeHTML(bm.id)}">
          <td>${typeBadge(bm.type)}</td>
          <td>${renderTarget(bm)}</td>
          <td><span class="program-tag">${escapeHTML(bm.program || "—")}</span></td>
          <td>
            <input type="text"
                   class="bm-notes"
                   data-bm-id="${escapeHTML(bm.id)}"
                   value="${escapeHTML(bm.notes || "")}"
                   placeholder="Add note…">
          </td>
          <td class="cell-muted">${relativeTime(bm.added_at)}</td>
          <td>
            <button type="button" class="bm-del" data-bm-id="${escapeHTML(bm.id)}" title="Remove bookmark">×</button>
          </td>
        </tr>
      `)
      .join("");

    // Note editing: save on blur / Enter
    tbody.querySelectorAll(".bm-notes").forEach((input) => {
      input.addEventListener("blur", () => {
        const id = input.dataset.bmId;
        const val = input.value.trim();
        const bm = allBookmarks.find((b) => b.id === id);
        if (!bm) return;
        if ((bm.notes || "") === val) return;
        window.WatchTowerBookmarks.update(id, { notes: val });
        bm.notes = val;
      });
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") { e.preventDefault(); input.blur(); }
      });
    });

    // Delete buttons
    tbody.querySelectorAll(".bm-del").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const id = btn.dataset.bmId;
        window.WatchTowerBookmarks.remove(id);
        // The bookmarks-changed handler reloads the list
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

  // ---------- Export / import ----------

  function doExport() {
    if (!allBookmarks.length) {
      alert("No bookmarks to export.");
      return;
    }
    const json = window.WatchTowerBookmarks.exportJSON();
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const ts = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `watchtower-bookmarks-${ts}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function doImport(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const added = window.WatchTowerBookmarks.importJSON(e.target.result, "merge");
        alert(`Import complete. ${added} new bookmark(s) added.`);
      } catch (err) {
        alert("Import failed: " + err.message);
      }
    };
    reader.readAsText(file);
  }

  // ---------- Events ----------

  function setupEvents() {
    // Type pills
    document.getElementById("type-pills").addEventListener("click", (e) => {
      const pill = e.target.closest(".filter-pill");
      if (!pill) return;
      document.querySelectorAll("#type-pills .filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      filters.type = pill.dataset.type;
      applyFilters();
    });

    // Mini stats → set matching filter
    document.querySelectorAll("#mini-stats .mini-stat").forEach((el) => {
      el.addEventListener("click", () => {
        const t = el.dataset.type;
        const pills = document.querySelectorAll("#type-pills .filter-pill");
        let matched = null;
        pills.forEach((p) => {
          p.classList.toggle("active", p.dataset.type === t);
          if (p.dataset.type === t) matched = p;
        });
        if (!matched) {
          // "live" and "http" have their own pills, so this is fine.
          // If type has no pill (e.g. "all"), it's still handled.
        }
        filters.type = t;
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

    // Export / Import
    document.getElementById("export-btn").addEventListener("click", doExport);
    document.getElementById("import-btn").addEventListener("click", () => {
      document.getElementById("import-input").click();
    });
    document.getElementById("import-input").addEventListener("change", (e) => {
      const file = e.target.files && e.target.files[0];
      if (file) doImport(file);
      e.target.value = "";
    });

    // React to store changes (from this page or other tabs)
    window.addEventListener("watchtower:bookmarks-changed", () => {
      load();
    });
  }

  // ---------- Boot ----------

  document.addEventListener("DOMContentLoaded", () => {
    setupEvents();
    load();
  });
})();