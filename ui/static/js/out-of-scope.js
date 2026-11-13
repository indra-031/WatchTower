/* ============================================
   WatchTower — Out-of-Scope Page
   Reads /api/programs, shows every program's out_of_scope
   list with scope for context. Warning-style cards.
   ============================================ */

(function () {
  "use strict";
  if (!document.getElementById("oos-container")) return;

  let allPrograms = [];   // [{ name, scopes, out_of_scope, ... }]
  let filtered = [];

  const filters = { search: "" };

  // ---------- Load ----------

  async function load() {
    const container = document.getElementById("oos-container");
    try {
      const data = await apiFetch("/api/programs");

      allPrograms = [];
      let totalPrograms = 0;

      for (const [name, prog] of Object.entries(data || {})) {
        totalPrograms++;
        const oos = prog.out_of_scope || prog.ooscope || [];
        if (!Array.isArray(oos) || !oos.length) continue;

        allPrograms.push({
          name,
          scopes: Array.isArray(prog.scopes) ? prog.scopes : [],
          out_of_scope: oos,
          cidr: Array.isArray(prog.cidr) ? prog.cidr : [],
          asn: Array.isArray(prog.asn) ? prog.asn : [],
          ip: Array.isArray(prog.ip) ? prog.ip : [],
        });
      }

      let totalOOS = 0;
      for (const p of allPrograms) totalOOS += p.out_of_scope.length;

      document.getElementById("oos-count").textContent = totalOOS;
      document.getElementById("stat-programs-with-oos").textContent = allPrograms.length;
      document.getElementById("stat-total-programs").textContent = totalPrograms;
      document.getElementById("stat-total-oos").textContent = totalOOS;

      applyFilters();
    } catch (e) {
      console.error("Out-of-scope load failed:", e);
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon" style="color:var(--red)">⚠️</div>
          <div class="empty-state-title">Failed to load</div>
          <div class="empty-state-desc">${escapeHTML(e.message || String(e))}</div>
        </div>`;
    }
  }

  // ---------- Filter ----------

  function applyFilters() {
    const q = filters.search.toLowerCase();

    if (!q) {
      filtered = allPrograms.slice();
    } else {
      filtered = allPrograms.filter((p) => {
        const hay = [
          p.name,
          ...p.scopes,
          ...p.out_of_scope,
          ...p.cidr,
          ...p.asn,
          ...p.ip,
        ].join(" ").toLowerCase();
        return hay.includes(q);
      });
    }

    // Sort alphabetically
    filtered.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));

    render();
  }

  // ---------- Render ----------

  function render() {
    const container = document.getElementById("oos-container");

    if (!allPrograms.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon" style="color:var(--green)">✓</div>
          <div class="empty-state-title">All clean</div>
          <div class="empty-state-desc">
            No programs currently define any out-of-scope targets.
            Every asset within a program's <code>scope</code> list is fair game.
          </div>
        </div>`;
      return;
    }

    if (!filtered.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🔍</div>
          <div class="empty-state-title">No matches</div>
          <div class="empty-state-desc">No programs match the current search.</div>
        </div>`;
      return;
    }

    container.innerHTML = `<div class="oos-grid">${
      filtered.map((p) => renderCard(p)).join("")
    }</div>`;

    // Wire up interactions inside each card
    container.querySelectorAll(".oos-card").forEach((card) => {
      const prog = card.dataset.program;

      const copyBtn = card.querySelector('[data-action="copy-oos"]');
      if (copyBtn) {
        copyBtn.addEventListener("click", () => {
          const items = JSON.parse(copyBtn.dataset.items || "[]");
          const text = items.join("\n");
          navigator.clipboard.writeText(text).then(() => {
            const original = copyBtn.textContent;
            copyBtn.textContent = "✓ Copied";
            copyBtn.classList.add("copied");
            setTimeout(() => {
              copyBtn.textContent = original;
              copyBtn.classList.remove("copied");
            }, 1500);
          }).catch((err) => {
            console.error("Copy failed:", err);
            alert("Copy failed. Your browser may block clipboard access.");
          });
        });
      }

      const toggleBtn = card.querySelector(".oos-details-toggle");
      if (toggleBtn) {
        toggleBtn.addEventListener("click", () => {
          const details = card.querySelector(".oos-details");
          const isOpen = details.classList.contains("open");
          details.classList.toggle("open", !isOpen);
          toggleBtn.classList.toggle("open", !isOpen);
        });
      }
    });
  }

  function renderCard(p) {
    const oosTags = p.out_of_scope
      .map((t) => `<span class="oos-tag out-of-scope">${escapeHTML(t)}</span>`)
      .join(" ");

    const scopeTags = p.scopes.length
      ? p.scopes.map((s) => `<span class="oos-tag in-scope">${escapeHTML(s)}</span>`).join(" ")
      : `<span style="color:var(--faint);font-style:italic;font-size:0.85em">No scope defined</span>`;

    const extraSections = [];
    if (p.cidr.length) {
      extraSections.push(`
        <div class="oos-section-label in-scope" style="margin-top:10px">CIDR</div>
        <div class="oos-tag-list">
          ${p.cidr.map((c) => `<span class="oos-tag in-scope">${escapeHTML(c)}</span>`).join(" ")}
        </div>`);
    }
    if (p.asn.length) {
      extraSections.push(`
        <div class="oos-section-label in-scope" style="margin-top:10px">ASN</div>
        <div class="oos-tag-list">
          ${p.asn.map((a) => `<span class="oos-tag in-scope">${escapeHTML(a)}</span>`).join(" ")}
        </div>`);
    }
    if (p.ip.length) {
      extraSections.push(`
        <div class="oos-section-label in-scope" style="margin-top:10px">IP</div>
        <div class="oos-tag-list">
          ${p.ip.map((ip) => `<span class="oos-tag in-scope">${escapeHTML(ip)}</span>`).join(" ")}
        </div>`);
    }

    const hasExtra = extraSections.length > 0;

    return `
      <div class="oos-card" data-program="${escapeHTML(p.name)}">
        <div class="oos-card-header">
          <div class="oos-program">
            <div class="oos-program-name">${escapeHTML(p.name)}</div>
            <div class="oos-program-meta">${p.scopes.length} in-scope${hasExtra ? " · " + (p.cidr.length + p.asn.length + p.ip.length) + " extra" : ""}</div>
          </div>
          <span class="oos-count-badge">${p.out_of_scope.length} excluded</span>
        </div>

        <div class="oos-section">
          <div class="oos-section-label out-of-scope">
            <span>⚠️</span> Out of scope — do not test
          </div>
          <div class="oos-tag-list">${oosTags}</div>
        </div>

        <div class="oos-section" style="margin-top:8px">
          <div class="oos-section-label in-scope">In-scope targets</div>
          <div class="oos-tag-list">${scopeTags}</div>
        </div>

        ${
          hasExtra
            ? `<button type="button" class="oos-details-toggle">
                 <span class="chev">▶</span> Show CIDR / ASN / IP
               </button>
               <div class="oos-details">
                 ${extraSections.join("")}
               </div>`
            : ""
        }

        <div class="oos-card-actions">
          <button type="button"
                  class="oos-action-btn"
                  data-action="copy-oos"
                  data-items='${escapeHTML(JSON.stringify(p.out_of_scope))}'>
            📋 Copy out-of-scope list
          </button>
        </div>
      </div>
    `;
  }

  // ---------- Events ----------

  function setupEvents() {
    document.getElementById("search-input").addEventListener(
      "input",
      debounce((e) => {
        filters.search = e.target.value.trim();
        applyFilters();
      }, 250)
    );
  }

  // ---------- Boot ----------

  document.addEventListener("DOMContentLoaded", () => {
    setupEvents();
    load();
  });
})();