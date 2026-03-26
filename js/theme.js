(function () {
  const STORAGE_KEY = "aes-theme";
  const root = document.documentElement;

  function getSavedTheme() {
    try {
      const value = localStorage.getItem(STORAGE_KEY);
      return value === "light" || value === "dark" ? value : null;
    } catch (_) {
      return null;
    }
  }

  function setTheme(theme, persist) {
    const next = theme === "light" ? "light" : "dark";
    root.setAttribute("data-theme", next);

    if (persist) {
      try {
        localStorage.setItem(STORAGE_KEY, next);
      } catch (_) {
        // Ignore storage failures in private mode.
      }
    }

    const btn = document.querySelector(".theme-toggle");
    if (btn) {
      const isLight = next === "light";
      btn.setAttribute("aria-pressed", String(isLight));
      btn.setAttribute("aria-label", isLight ? "Chuyển sang chế độ tối" : "Chuyển sang chế độ sáng");
      btn.innerHTML = isLight ? "☀️ Chế độ sáng" : "🌙 Chế độ tối";
    }
  }

  function toggleTheme() {
    const current = root.getAttribute("data-theme") === "light" ? "light" : "dark";
    setTheme(current === "light" ? "dark" : "light", true);
  }

  // Apply saved theme as early as possible.
  setTheme(getSavedTheme() || "dark", false);

  document.addEventListener("DOMContentLoaded", function () {
    if (!document.querySelector(".theme-toggle")) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "theme-toggle";
      button.addEventListener("click", toggleTheme);
      document.body.appendChild(button);
    }

    setTheme(getSavedTheme() || "dark", false);
  });
})();