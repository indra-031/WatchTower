/* ============================================
   WatchTower — Attack Surface (parent page)
   Loads finding counts for each attack module.
   ============================================ */

(function () {
  "use strict";

  async function loadNucleiStats() {
    try {
      const data = await apiFetch("/api/nuclei");
      const findings = data.findings || [];

      const el = document.querySelector('[data-attack-count="nuclei"]');
      if (el) el.textContent = findings.length;

      const counts = { critical: 0, high: 0 };
      for (const f of findings) {
        const s = (f.severity || "").toLowerCase();
        if (counts.hasOwnProperty(s)) counts[s]++;
      }

      const crit = document.querySelector('[data-attack-count="critical"]');
      const high = document.querySelector('[data-attack-count="high"]');
      if (crit) crit.textContent = counts.critical;
      if (high) high.textContent = counts.high;
    } catch (e) {
      console.error("Attack stats load failed:", e);
    }
  }

  document.addEventListener("DOMContentLoaded", loadNucleiStats);
})();