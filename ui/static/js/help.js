/* ============================================
   Help — docs page: TOC scroll spy, search, copy
   ============================================ */

function initScrollSpy() {
  const links = document.querySelectorAll(".docs-nav a");
  const sections = [];
  links.forEach((link) => {
    const href = link.getAttribute("href");
    if (href && href.startsWith("#")) {
      const el = document.querySelector(href);
      if (el) sections.push({ link, el });
    }
  });

  if (!sections.length) return;

  const onScroll = () => {
    const scrollY = window.scrollY + 110;
    let current = sections[0];

    for (const s of sections) {
      if (s.el.offsetTop <= scrollY) {
        current = s;
      } else {
        break;
      }
    }

    links.forEach((l) => l.classList.remove("active"));
    if (current) current.link.classList.add("active");
  };

  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
}

// ---------- Section search ----------

function initSearch() {
  const input = document.getElementById("doc-search");
  const noResults = document.getElementById("doc-no-results");
  if (!input) return;

  const sections = Array.from(document.querySelectorAll(".doc-section"));

  const apply = () => {
    const q = input.value.trim().toLowerCase();
    let visible = 0;

    for (const sec of sections) {
      if (!q) {
        sec.classList.remove("hidden");
        visible++;
        continue;
      }
      const hay = (sec.textContent || "").toLowerCase();
      if (hay.includes(q)) {
        sec.classList.remove("hidden");
        visible++;
      } else {
        sec.classList.add("hidden");
      }
    }

    if (noResults) {
      noResults.classList.toggle("active", visible === 0);
    }
  };

  input.addEventListener("input", debounce(apply, 150));
}

// ---------- Copy code blocks ----------

function initCopyButtons() {
  document.querySelectorAll(".doc-code-copy").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const target = btn.dataset.target;
      const codeEl = target ? document.querySelector(target) : null;
      if (!codeEl) return;
      const text = codeEl.textContent || "";
      try {
        await navigator.clipboard.writeText(text.trim());
        const old = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => (btn.textContent = old), 1200);
      } catch (_) {
        btn.textContent = "Failed";
        setTimeout(() => (btn.textContent = "Copy"), 1200);
      }
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initScrollSpy();
  initSearch();
  initCopyButtons();
});