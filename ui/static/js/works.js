/* ============================================
   WatchTower — Works (per-target journal)
   Shared store (window.WatchTowerWorks) + page logic.
   ============================================ */

/* ==========================================================
   SHARED STORE
   ========================================================== */

window.WatchTowerWorks = (function () {
  "use strict";

  const STORAGE_KEY = "watchtower_works_v1";

  function read() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      console.error("Works: failed to read storage", e);
      return [];
    }
  }

  function write(list) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
      window.dispatchEvent(new CustomEvent("watchtower:works-changed"));
    } catch (e) {
      console.error("Works: failed to write storage", e);
    }
  }

  function newId() {
    return "w_" + Date.now() + "_" + Math.random().toString(36).slice(2, 8);
  }

  function nowStr() {
    return new Date().toISOString().slice(0, 19).replace("T", " ");
  }

  function normalizeTags(raw) {
    if (Array.isArray(raw)) {
      return raw.map((t) => String(t).trim()).filter(Boolean);
    }
    if (typeof raw === "string") {
      return raw.split(",").map((t) => t.trim()).filter(Boolean);
    }
    return [];
  }

  function getAll() { return read(); }

  function getById(id) {
    return read().find((w) => w.id === id) || null;
  }

  function add(data) {
    const list = read();
    const entry = {
      id: newId(),
      program: String(data.program || "").trim() || "unknown",
      target: String(data.target || "").trim(),
      title: String(data.title || "").trim() || "(untitled)",
      content: String(data.content || ""),
      tags: normalizeTags(data.tags),
      created_at: nowStr(),
      updated_at: nowStr(),
    };
    list.unshift(entry);
    write(list);
    return entry.id;
  }

  function update(id, patch) {
    const list = read();
    const idx = list.findIndex((w) => w.id === id);
    if (idx < 0) return false;

    const cur = list[idx];
    const next = Object.assign({}, cur);

    if (patch.program !== undefined) {
      next.program = String(patch.program || "").trim() || "unknown";
    }
    if (patch.target !== undefined) next.target = String(patch.target || "").trim();
    if (patch.title !== undefined) next.title = String(patch.title || "").trim() || "(untitled)";
    if (patch.content !== undefined) next.content = String(patch.content || "");
    if (patch.tags !== undefined) next.tags = normalizeTags(patch.tags);

    next.updated_at = nowStr();
    list[idx] = next;
    write(list);
    return true;
  }

  function remove(id) {
    const list = read();
    const next = list.filter((w) => w.id !== id);
    if (next.length !== list.length) write(next);
  }

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
      throw new Error("Invalid works file: " + e.message);
    }

    // Normalize incoming records
    const normalized = [];
    for (const rec of incoming) {
      if (!rec || typeof rec !== "object") continue;
      if (!rec.title && !rec.content) continue;
      normalized.push({
        id: rec.id || newId(),
        program: rec.program || "unknown",
        target: rec.target || "",
        title: rec.title || "(untitled)",
        content: rec.content || "",
        tags: normalizeTags(rec.tags),
        created_at: rec.created_at || nowStr(),
        updated_at: rec.updated_at || rec.created_at || nowStr(),
      });
    }

    if (mode === "replace") {
      write(normalized);
      return normalized.length;
    }

    // Merge
    const existing = read();
    const seen = new Set(existing.map((w) => w.id));
    let added = 0;
    for (const rec of normalized) {
      if (seen.has(rec.id)) continue;
      existing.push(rec);
      seen.add(rec.id);
      added++;
    }
    write(existing);
    return added;
  }

  return {
    getAll, getById, add, update, remove, count,
    exportJSON, importJSON,
  };
})();

/* Cross-tab sync */
window.addEventListener("storage", (e) => {
  if (e.key === "watchtower_works_v1") {
    window.dispatchEvent(new CustomEvent("watchtower:works-changed"));
  }
});

/* ==========================================================
   PAGE LOGIC (only if on works page)
   ========================================================== */

(function () {
  "use strict";
  if (!document.getElementById("works-container")) return;

  // State
  let allWorks = [];
  let filtered = [];
  const filters = { program: "all", search: "" };
  let sortMode = "newest";
  let modalMode = null;     // "view" | "edit" | "new"
  let editingId = null;
  let deletingId = null;

  // ---------- Helpers ----------

  function programTag(p) {
    return `<span class="program-tag">${escapeHTML(p || "—")}</span>`;
  }

  function targetTag(t) {
    if (!t) return "";
    return `<span class="work-target">${escapeHTML(t)}</span>`;
  }

  function tagList(tags) {
    if (!tags || !tags.length) return "";
    return tags.map((t) => `<span class="work-tag">${escapeHTML(t)}</span>`).join("");
  }

  // ---------- Load ----------

  function load() {
    allWorks = window.WatchTowerWorks.getAll();
    document.getElementById("work-count").textContent = allWorks.length;
    populateProgramFilter();
    populateProgramDatalist();
    applyFilters();
  }

  function populateProgramFilter() {
    const programs = new Set();
    for (const w of allWorks) if (w.program) programs.add(w.program);
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

  function populateProgramDatalist() {
    const programs = new Set();
    for (const w of allWorks) if (w.program) programs.add(w.program);
    const dl = document.getElementById("program-datalist");
    dl.innerHTML = "";
    for (const p of Array.from(programs).sort()) {
      const opt = document.createElement("option");
      opt.value = p;
      dl.appendChild(opt);
    }
  }

  // ---------- Filter + sort ----------

  function applyFilters() {
    const q = filters.search.toLowerCase();

    filtered = allWorks.filter((w) => {
      if (filters.program !== "all" && w.program !== filters.program) return false;
      if (q) {
        const hay = `${w.title || ""} ${w.content || ""} ${w.target || ""} ${w.program || ""} ${(w.tags || []).join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => {
      switch (sortMode) {
        case "newest":
          return (b.created_at || "").localeCompare(a.created_at || "");
        case "oldest":
          return (a.created_at || "").localeCompare(b.created_at || "");
        case "updated":
          return (b.updated_at || "").localeCompare(a.updated_at || "");
        case "title":
          return (a.title || "").toLowerCase().localeCompare((b.title || "").toLowerCase());
        default:
          return 0;
      }
    });

    renderGrid();
  }

  // ---------- Render grid ----------

  function renderGrid() {
    const container = document.getElementById("works-container");

    if (!allWorks.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">📝</div>
          <div class="empty-state-title">No entries yet</div>
          <div class="empty-state-desc">
            Click <strong>+ New Entry</strong> to start a journal of what you've tested on each target.
            <br><br>
            <button type="button" class="btn-primary" id="empty-new-btn" style="margin-top:8px">Create your first entry</button>
          </div>
        </div>`;
      const b = document.getElementById("empty-new-btn");
      if (b) b.addEventListener("click", openNewModal);
      return;
    }

    if (!filtered.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🔍</div>
          <div class="empty-state-title">No matches</div>
          <div class="empty-state-desc">No entries match the current filters.</div>
        </div>`;
      return;
    }

    container.innerHTML = `<div class="works-grid">${
      filtered
        .map((w) => {
          const preview = (w.content || "").slice(0, 400);
          const tagsHTML = tagList(w.tags);
          return `
          <div class="work-card" data-id="${escapeHTML(w.id)}">
            <div class="work-card-header">
              <div class="work-title">${escapeHTML(w.title)}</div>
            </div>
            <div class="work-meta">
              ${programTag(w.program)}
              ${targetTag(w.target)}
              <span style="color:var(--faint);margin-left:auto">${relativeTime(w.updated_at)}</span>
            </div>
            ${preview ? `<div class="work-content-preview">${escapeHTML(preview)}</div>` : ""}
            ${tagsHTML ? `<div class="work-tags">${tagsHTML}</div>` : ""}
            <div class="work-footer">
              <span>Created ${relativeTime(w.created_at)}</span>
              <div class="work-actions">
                <button type="button" class="work-action-btn" data-action="edit" data-id="${escapeHTML(w.id)}" title="Edit">✎</button>
                <button type="button" class="work-action-btn danger" data-action="delete" data-id="${escapeHTML(w.id)}" title="Delete">×</button>
              </div>
            </div>
          </div>`;
        })
        .join("")
    }</div>`;

    // Card click → open view modal
    container.querySelectorAll(".work-card").forEach((card) => {
      card.addEventListener("click", (e) => {
        // Ignore clicks on action buttons
        if (e.target.closest("[data-action]")) return;
        const id = card.dataset.id;
        openViewModal(id);
      });
    });

    // Edit button
    container.querySelectorAll('[data-action="edit"]').forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        openEditModal(btn.dataset.id);
      });
    });

    // Delete button
    container.querySelectorAll('[data-action="delete"]').forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        if (confirm("Delete this entry? This cannot be undone.")) {
          window.WatchTowerWorks.remove(btn.dataset.id);
        }
      });
    });
  }

  // ---------- View modal ----------

  function openViewModal(id) {
    const w = window.WatchTowerWorks.getById(id);
    if (!w) return;
    editingId = id;
    modalMode = "view";

    document.getElementById("view-title").textContent = w.title;
    document.getElementById("view-program").textContent = w.program || "—";

    const targetEl = document.getElementById("view-target");
    if (w.target) {
      targetEl.textContent = w.target;
      targetEl.style.display = "";
    } else {
      targetEl.style.display = "none";
    }

    document.getElementById("view-dates").textContent =
      `Created ${w.created_at} · Updated ${w.updated_at}`;

    document.getElementById("view-tags").innerHTML = tagList(w.tags);
    document.getElementById("view-content").textContent = w.content || "(empty)";

    document.getElementById("work-view-screen").style.display = "";
    document.getElementById("work-edit-screen").style.display = "none";

    document.getElementById("work-modal").classList.add("active");
  }

  // ---------- Edit / New modal ----------

  function openNewModal() {
    editingId = null;
    modalMode = "new";

    document.getElementById("edit-header").textContent = "New Entry";
    document.getElementById("edit-program").value = "";
    document.getElementById("edit-target").value = "";
    document.getElementById("edit-title").value = "";
    document.getElementById("edit-content").value = "";
    document.getElementById("edit-tags").value = "";

    document.getElementById("work-view-screen").style.display = "none";
    document.getElementById("work-edit-screen").style.display = "";

    document.getElementById("work-modal").classList.add("active");
    setTimeout(() => document.getElementById("edit-title").focus(), 50);
  }

  function openEditModal(id) {
    const w = window.WatchTowerWorks.getById(id);
    if (!w) return;
    editingId = id;
    modalMode = "edit";

    document.getElementById("edit-header").textContent = "Edit Entry";
    document.getElementById("edit-program").value = w.program || "";
    document.getElementById("edit-target").value = w.target || "";
    document.getElementById("edit-title").value = w.title || "";
    document.getElementById("edit-content").value = w.content || "";
    document.getElementById("edit-tags").value = (w.tags || []).join(", ");

    document.getElementById("work-view-screen").style.display = "none";
    document.getElementById("work-edit-screen").style.display = "";

    document.getElementById("work-modal").classList.add("active");
    setTimeout(() => document.getElementById("edit-title").focus(), 50);
  }

  // ---------- Save ----------

  function saveEntry() {
    const program = document.getElementById("edit-program").value.trim();
    const target = document.getElementById("edit-target").value.trim();
    const title = document.getElementById("edit-title").value.trim();
    const content = document.getElementById("edit-content").value;
    const tagsRaw = document.getElementById("edit-tags").value;

    if (!title) {
      alert("Title is required.");
      document.getElementById("edit-title").focus();
      return;
    }
    if (!content.trim()) {
      alert("Content is required.");
      document.getElementById("edit-content").focus();
      return;
    }

    const payload = { program, target, title, content, tags: tagsRaw };

    if (modalMode === "new") {
      window.WatchTowerWorks.add(payload);
    } else if (modalMode === "edit" && editingId) {
      window.WatchTowerWorks.update(editingId, payload);
    }

    closeModal();
  }

  function closeModal() {
    document.getElementById("work-modal").classList.remove("active");
    modalMode = null;
    editingId = null;
  }

  // ---------- Export / Import ----------

  function doExport() {
    if (!allWorks.length) {
      alert("No entries to export.");
      return;
    }
    const json = window.WatchTowerWorks.exportJSON();
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const ts = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `watchtower-works-${ts}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function doImport(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const added = window.WatchTowerWorks.importJSON(e.target.result, "merge");
        alert(`Import complete. ${added} new entries added.`);
      } catch (err) {
        alert("Import failed: " + err.message);
      }
    };
    reader.readAsText(file);
  }

  // ---------- Events ----------

  function setupEvents() {
    document.getElementById("new-entry-btn").addEventListener("click", openNewModal);

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

    document.getElementById("sort-select").addEventListener("change", (e) => {
      sortMode = e.target.value;
      applyFilters();
    });

    document.getElementById("export-btn").addEventListener("click", doExport);
    document.getElementById("import-btn").addEventListener("click", () => {
      document.getElementById("import-input").click();
    });
    document.getElementById("import-input").addEventListener("change", (e) => {
      const file = e.target.files && e.target.files[0];
      if (file) doImport(file);
      e.target.value = "";
    });

    // Modal — view screen actions
    document.getElementById("view-edit-btn").addEventListener("click", () => {
      if (editingId) openEditModal(editingId);
    });
    document.getElementById("view-delete-btn").addEventListener("click", () => {
      if (!editingId) return;
      if (confirm("Delete this entry? This cannot be undone.")) {
        window.WatchTowerWorks.remove(editingId);
        closeModal();
      }
    });
    document.getElementById("view-close-btn").addEventListener("click", closeModal);

    // Modal — edit screen actions
    document.getElementById("edit-save-btn").addEventListener("click", saveEntry);
    document.getElementById("edit-cancel-btn").addEventListener("click", () => {
      if (modalMode === "edit" && editingId) openViewModal(editingId);
      else closeModal();
    });

    // Modal close button + backdrop
    const modal = document.getElementById("work-modal");
    document.getElementById("work-modal-close").addEventListener("click", closeModal);
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeModal();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && modal.classList.contains("active")) closeModal();
    });

    // Ctrl/Cmd+Enter in textarea = save
    document.getElementById("edit-content").addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        saveEntry();
      }
    });

    // React to store changes
    window.addEventListener("watchtower:works-changed", load);
  }

  // ---------- Boot ----------

  document.addEventListener("DOMContentLoaded", () => {
    setupEvents();
    load();
  });
})();