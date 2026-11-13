/* ============================================
   WatchTower — Shared JS + Dashboard
   ============================================ */

// ---------- Utilities ----------
function escapeHTML(str) {
  if (str === null || str === undefined) return "";
  return String(str).replace(/[&<>"']/g, (t) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[t]);
}

async function apiFetch(url) {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} for ${url}`);
  }
  return res.json();
}

// ---------- Dashboard Stats ----------
async function loadStats() {
  const map = {
    "stat-programs": "programs",
    "stat-subdomains": "total_subdomains",
    "stat-lives": "total_lives",
    "stat-http": "total_http",
    "stat-nuclei": "total_nuclei",
  };

  try {
    const data = await apiFetch("/api/stats");
    for (const [elId, key] of Object.entries(map)) {
      const el = document.getElementById(elId);
      if (!el) continue;
      const val = data[key] ?? 0;
      el.textContent = Number(val).toLocaleString();
      el.classList.remove("loading");
    }
  } catch (e) {
    console.error("Stats load failed:", e);
    for (const elId of Object.keys(map)) {
      const el = document.getElementById(elId);
      if (el) {
        el.textContent = "—";
        el.classList.remove("loading");
      }
    }
  }
}

// ---------- Time-of-day greeting ----------
function paintGreeting() {
  const el = document.getElementById("greeting");
  if (!el) return;
  const h = new Date().getHours();
  let g = "Hello";
  if (h < 6) g = "Good night";
  else if (h < 12) g = "Good morning";
  else if (h < 18) g = "Good afternoon";
  else g = "Good evening";
  el.textContent = g;
}

// ---------- Boot ----------
document.addEventListener("DOMContentLoaded", () => {
  paintGreeting();
  loadStats();

  // Optional: refresh stats every 60s
  setInterval(loadStats, 60_000);
});

// ---------- Helpers for list pages ----------

function debounce(fn, ms = 200) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function relativeTime(dateStr) {
  if (!dateStr) return "—";
  const t = new Date(dateStr.replace(" ", "T"));
  if (isNaN(t.getTime())) return dateStr;
  const diff = (Date.now() - t.getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 2592000) return `${Math.floor(diff / 86400)}d ago`;
  return t.toISOString().slice(0, 10);
}

function statusBadgeClass(code) {
  const s = String(code || "");
  if (s.startsWith("2")) return "badge-status-2xx";
  if (s.startsWith("3")) return "badge-status-3xx";
  if (s.startsWith("4")) return "badge-status-4xx";
  if (s.startsWith("5")) return "badge-status-5xx";
  return "badge-status-na";
}

function renderPagination(currentPage, totalPages, totalItems, perPage, onPageChange) {
  const wrap = document.createElement("div");
  wrap.className = "pagination-bar";

  const start = totalItems === 0 ? 0 : (currentPage - 1) * perPage + 1;
  const end = Math.min(currentPage * perPage, totalItems);

  const info = document.createElement("div");
  info.className = "pagination-info";
  info.innerHTML = `Showing <strong>${start}</strong>–<strong>${end}</strong> of <strong>${totalItems}</strong>`;
  wrap.appendChild(info);

  if (totalPages > 1) {
    const pager = document.createElement("div");
    pager.className = "pagination";

    const mkBtn = (label, page, disabled, active) => {
      const b = document.createElement("button");
      b.className = "page-btn" + (active ? " active" : "");
      b.textContent = label;
      b.disabled = disabled;
      if (!disabled && !active) {
        b.addEventListener("click", () => onPageChange(page));
      }
      return b;
    };

    pager.appendChild(mkBtn("←", currentPage - 1, currentPage === 1, false));

    let pages = [];
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      const s = Math.max(2, currentPage - 1);
      const e = Math.min(totalPages - 1, currentPage + 1);
      if (s > 2) pages.push("...");
      for (let i = s; i <= e; i++) pages.push(i);
      if (e < totalPages - 1) pages.push("...");
      pages.push(totalPages);
    }

    for (const p of pages) {
      if (p === "...") {
        const sp = document.createElement("span");
        sp.className = "page-ellipsis";
        sp.textContent = "…";
        pager.appendChild(sp);
      } else {
        pager.appendChild(mkBtn(String(p), p, false, p === currentPage));
      }
    }

    pager.appendChild(mkBtn("→", currentPage + 1, currentPage === totalPages, false));
    wrap.appendChild(pager);
  }

  return wrap;
}

// ---------- Modal helper ----------

function initModal(modalId) {
  const modal = document.getElementById(modalId);
  if (!modal) return { open: () => {}, close: () => {} };

  const close = () => modal.classList.remove("active");

  modal.addEventListener("click", (e) => {
    if (e.target === modal || e.target.classList.contains("modal-close")) close();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal.classList.contains("active")) close();
  });

  return {
    open(src, caption) {
      const img = modal.querySelector(".modal-image");
      const cap = modal.querySelector(".modal-caption");
      if (img) img.src = src;
      if (cap) cap.textContent = caption || "";
      modal.classList.add("active");
    },
    close,
  };
}