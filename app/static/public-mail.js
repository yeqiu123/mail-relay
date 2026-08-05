(() => {
  const button = document.getElementById("public-refresh");
  let mailRegion = document.getElementById("public-mail-region");
  const refreshUrl = button?.dataset.refreshUrl;
  if (!button || !mailRegion || !refreshUrl) return;

  const buttonLabel = button.innerHTML;
  button.addEventListener("click", async () => {
    if (button.disabled) return;

    const previousError = mailRegion.querySelector(".public-refresh-error");
    if (previousError) previousError.remove();
    button.disabled = true;
    button.innerHTML = '<span class="public-refresh-spinner" aria-hidden="true"></span><span>刷新中</span>';
    mailRegion.setAttribute("aria-busy", "true");

    try {
      const response = await fetch(refreshUrl, {
        method: "POST",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      let payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.status_url) {
        throw new Error(payload.detail || "刷新失败，请稍后再试。");
      }
      while (!payload.done) {
        await new Promise((resolve) => window.setTimeout(resolve, 650));
        const statusResponse = await fetch(payload.status_url, {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        payload = await statusResponse.json().catch(() => ({}));
        if (!statusResponse.ok) {
          throw new Error(payload.detail || "刷新失败，请稍后再试。");
        }
      }
      if (payload.failed || !payload.html) {
        throw new Error(payload.error || "刷新失败，请稍后再试。");
      }
      mailRegion.outerHTML = payload.html;
      mailRegion = document.getElementById("public-mail-region");
    } catch (error) {
      const alert = document.createElement("p");
      alert.className = "public-refresh-error";
      alert.setAttribute("role", "alert");
      alert.textContent = error instanceof Error ? error.message : "刷新失败，请稍后再试。";
      mailRegion.prepend(alert);
    } finally {
      mailRegion.removeAttribute("aria-busy");
      button.disabled = false;
      button.innerHTML = buttonLabel;
    }
  });
})();
