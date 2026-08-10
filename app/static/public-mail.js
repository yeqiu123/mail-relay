(() => {
  const button = document.getElementById("public-refresh");
  let mailRegion = document.getElementById("public-mail-region");
  const refreshUrl = button?.dataset.refreshUrl;
  if (!button || !mailRegion || !refreshUrl) return;

  const buttonLabel = button.innerHTML;
  const cooldownSeconds = Number.parseInt(button.dataset.cooldownSeconds || "10", 10);
  let cooldownTimer = null;

  const startCooldown = (seconds) => {
    let remaining = Math.max(1, Number.parseInt(String(seconds), 10) || cooldownSeconds);
    button.disabled = true;

    // 冷却期间直接在按钮内显示剩余秒数，归零后恢复可点击状态。
    const renderCountdown = () => {
      button.textContent = `${remaining}s 后可刷新`;
    };
    renderCountdown();
    cooldownTimer = window.setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        window.clearInterval(cooldownTimer);
        cooldownTimer = null;
        button.disabled = false;
        button.innerHTML = buttonLabel;
        return;
      }
      renderCountdown();
    }, 1000);
  };

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
        if (response.status === 429) {
          startCooldown(response.headers.get("Retry-After"));
        }
        throw new Error(payload.detail || "刷新失败，请稍后再试。");
      }
      // 状态响应不包含 status_url，轮询期间固定使用创建任务时返回的地址。
      const statusUrl = payload.status_url;
      const deadline = Date.now() + 10 * 60 * 1000;
      while (!payload.done) {
        if (Date.now() >= deadline) throw new Error("刷新任务等待超时，请稍后重试。");
        await new Promise((resolve) => window.setTimeout(resolve, 650));
        const statusResponse = await fetch(statusUrl, {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        payload = await statusResponse.json().catch(() => ({}));
        if (!statusResponse.ok) {
          throw new Error(payload.detail || "刷新失败，请稍后再试。");
        }
      }
      startCooldown(cooldownSeconds);
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
      if (!cooldownTimer) {
        button.disabled = false;
        button.innerHTML = buttonLabel;
      }
    }
  });
})();
