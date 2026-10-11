// Small enhancements on top of the server-rendered pages. Everything still
// works without this file: times show in UTC, snippets are selectable text.
(() => {
  "use strict";

  // ── Times in the viewer's timezone ──
  // The server renders <time datetime="…Z" title="… UTC">3m ago</time>; those
  // marked data-absolute show the date itself rather than a relative time.
  const fullTime = new Intl.DateTimeFormat(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    timeZoneName: "short",
  });

  function localTimes(root) {
    for (const el of root.querySelectorAll("time[datetime]")) {
      const at = new Date(el.dateTime);
      if (Number.isNaN(at.getTime())) continue;
      const text = fullTime.format(at);
      el.title = text;
      if (el.hasAttribute("data-absolute")) el.textContent = text;
    }
  }

  // ── Copy buttons on code snippets ──
  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    // Plain-HTTP deployments have no Clipboard API.
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.cssText = "position:fixed;opacity:0";
    document.body.append(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    if (!ok) throw new Error("copy failed");
  }

  function copyButtons(root) {
    for (const code of root.querySelectorAll("pre.snippet > code")) {
      const pre = code.parentElement;
      if (pre.parentElement.classList.contains("copyable")) continue;
      const wrap = document.createElement("div");
      wrap.className = "copyable";
      pre.replaceWith(wrap);
      wrap.append(pre);

      const button = document.createElement("button");
      button.type = "button";
      button.className = "copy";
      button.textContent = "Copy";
      button.setAttribute("aria-label", "Copy to clipboard");
      button.addEventListener("click", async () => {
        try {
          await copyText(code.textContent);
          button.textContent = "Copied";
        } catch {
          // Leave it selected so Ctrl+C works.
          getSelection().selectAllChildren(code);
          button.textContent = "Press Ctrl+C";
        }
        clearTimeout(button.reset);
        button.reset = setTimeout(() => { button.textContent = "Copy"; }, 2000);
      });
      wrap.append(button);
    }
  }

  // ── Current page in the nav ──
  function markNav() {
    const path = location.pathname;
    for (const link of document.querySelectorAll("[data-nav]")) {
      const base = link.dataset.nav;
      if (path === base || path.startsWith(base + "/")) {
        link.setAttribute("aria-current", "page");
      }
    }
  }

  // ── Tab title and favicon follow the nav's down count ──
  const baseTitle = document.title;
  function syncHealth() {
    const badge = document.getElementById("health");
    const down = Number(badge?.dataset.down ?? 0);
    document.title = down > 0 ? `(${down} down) ${baseTitle}` : baseTitle;
    const icon = document.querySelector('link[rel="icon"]');
    if (icon) icon.href = down > 0 ? "/static/favicon-down.svg" : "/static/favicon.svg";
  }

  function enhance(root) {
    localTimes(root);
    copyButtons(root);
    syncHealth();
  }

  markNav();
  // htmx.onLoad runs for the initial page and for every swapped-in fragment.
  if (window.htmx) {
    htmx.onLoad(enhance);
  } else {
    enhance(document.body);
  }
})();
