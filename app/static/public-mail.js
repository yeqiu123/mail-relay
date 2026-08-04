(() => {
  const button = document.getElementById("public-refresh");
  const mailList = document.getElementById("public-mail-list");
  const refreshUrl = button?.dataset.refreshUrl;
  if (!button || !mailList || !refreshUrl) return;

  const buttonLabel = button.innerHTML;
  button.addEventListener("click", async () => {
    if (button.disabled) return;

    const previousError = mailList.querySelector(".public-refresh-error");
    if (previousError) previousError.remove();
    button.disabled = true;
    button.innerHTML = '<span class="public-refresh-spinner" aria-hidden="true"></span><span>刷新中</span>';
    mailList.setAttribute("aria-busy", "true");

    try {
      const response = await fetch(refreshUrl, {
        method: "POST",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.html) {
        throw new Error(payload.detail || "刷新失败，请稍后再试。");
      }
      mailList.innerHTML = payload.html;
    } catch (error) {
      const alert = document.createElement("p");
      alert.className = "public-refresh-error";
      alert.setAttribute("role", "alert");
      alert.textContent = error instanceof Error ? error.message : "刷新失败，请稍后再试。";
      mailList.prepend(alert);
    } finally {
      mailList.removeAttribute("aria-busy");
      button.disabled = false;
      button.innerHTML = buttonLabel;
    }
  });
})();
