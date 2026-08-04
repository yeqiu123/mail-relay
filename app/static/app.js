const state = {
  view: "accounts",
  accountsPage: 1,
  accountsPageSize: 20,
  accountsTotal: 0,
  accounts: [],
  accountsSignature: "",
  selected: new Set(),
  search: "",
  status: "",
  logsPage: 1,
  logsPageSize: 30,
  mailAccount: null,
  accountRequest: 0,
  currentUser: { username: "", role: "" },
  users: [],
  targets: [],
  targetAccounts: [],
  targetSearch: "",
  targetTagsEditingId: null,
  userModalMode: "create",
  userEditingId: null,
  shareUrl: "",
  shareToken: "",
  shareExpiresAt: null,
  shareLastAccessAt: null,
  oauthClientId: "",
  oauthFlowId: "",
  confirmResolve: null,
};

const viewMeta = {
  accounts: {
    title: "邮箱管理",
    subtitle: "Outlook 账号与收件箱管理",
  },
  targets: {
    title: "别名管理",
    subtitle: "按隐藏邮箱地址筛选归档邮件",
  },
  logs: {
    title: "刷新记录",
    subtitle: "Microsoft OAuth 令牌轮换结果",
  },
  settings: {
    title: "系统设置",
    subtitle: "OAuth 刷新周期与收件箱参数",
  },
  users: {
    title: "用户管理",
    subtitle: "账号状态与邮箱数据归属",
  },
};

const statusMeta = {
  active: { label: "可读取", className: "active" },
  pending: { label: "待刷新", className: "pending" },
  error: { label: "账户异常", className: "error" },
  invalid: { label: "已失效", className: "invalid" },
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function refreshIcons(root = document) {
  if (window.lucide) {
    window.lucide.createIcons({
      attrs: { "stroke-width": 1.8 },
      root,
    });
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatTime(timestamp) {
  if (!timestamp) return "—";
  const date = new Date(Number(timestamp) * 1000);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}

function detailFrom(data, fallback) {
  if (typeof data === "string" && data.trim()) return data;
  if (data && typeof data.detail === "string") return data.detail;
  if (data && Array.isArray(data.detail)) {
    return data.detail.map((item) => item.msg).filter(Boolean).join("；") || fallback;
  }
  return fallback;
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    ...options,
    headers,
    credentials: "same-origin",
  });
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (response.status === 401 && path !== "/api/login") {
    showLogin();
    const error = new Error("登录已过期，请重新登录");
    error.authExpired = true;
    throw error;
  }
  if (!response.ok) {
    throw new Error(detailFrom(data, `请求失败（${response.status}）`));
  }
  return data;
}

function setButtonBusy(button, busy, label = "处理中") {
  if (busy) {
    button.dataset.originalHtml = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<span class="spinner"></span><span>${escapeHtml(label)}</span>`;
  } else {
    button.innerHTML = button.dataset.originalHtml || button.innerHTML;
    button.disabled = false;
    delete button.dataset.originalHtml;
    refreshIcons(button);
  }
}

function toast(message, type = "success") {
  const item = document.createElement("div");
  item.className = `toast ${type}`;
  item.innerHTML = `
    <i data-lucide="${type === "error" ? "circle-alert" : "circle-check"}"></i>
    <span>${escapeHtml(message)}</span>
  `;
  $("#toast-region").append(item);
  refreshIcons(item);
  window.setTimeout(() => item.remove(), 4200);
}

async function copyEmailAddress(email) {
  try {
    await navigator.clipboard.writeText(email);
    toast("邮箱地址已复制");
  } catch (error) {
    toast("复制失败，请检查浏览器权限", "error");
  }
}

function showLogin(message = "") {
  state.currentUser = { username: "", role: "" };
  $("#boot-screen").classList.add("hidden");
  $("#app-shell").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
  $("#users-nav").classList.add("hidden");
  $("#settings-nav").classList.add("hidden");
  $("#login-password").value = "";
  $("#login-error").textContent = message;
  $("#login-error").classList.toggle("hidden", !message);
  refreshIcons($("#login-view"));
}

function applySession(session) {
  state.currentUser = {
    username: String(session.username || ""),
    role: String(session.role || "user"),
  };
  const isAdmin = state.currentUser.role === "admin";
  // 管理入口按当前会话角色展示，接口权限仍由后端再次校验。
  $("#current-username").textContent = state.currentUser.username;
  $("#current-role").textContent = isAdmin ? "管理员" : "普通用户";
  $("#users-nav").classList.toggle("hidden", !isAdmin);
  $("#settings-nav").classList.toggle("hidden", !isAdmin);
}

function showApp() {
  $("#boot-screen").classList.add("hidden");
  $("#login-view").classList.add("hidden");
  $("#app-shell").classList.remove("hidden");
  state.view = "accounts";
  $$(".view").forEach((element) => element.classList.toggle("hidden", element.id !== "accounts-view"));
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === "accounts"));
  $("#page-title").textContent = viewMeta.accounts.title;
  $("#page-subtitle").textContent = viewMeta.accounts.subtitle;
  $("#account-top-actions").classList.remove("hidden");
  refreshIcons($("#app-shell"));
}

async function initialize() {
  refreshIcons();
  bindEvents();
  try {
    const session = await api("/api/session");
    if (!session.authenticated) {
      showLogin();
      return;
    }
    applySession(session);
    showApp();
    await loadAccounts();
  } catch (error) {
    showLogin(error.message || "无法连接服务");
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const errorBox = $("#login-error");
  errorBox.classList.add("hidden");
  setButtonBusy(button, true, "登录中");
  try {
    const session = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("#login-username").value.trim(),
        password: $("#login-password").value,
      }),
    });
    applySession(session);
    showApp();
    await loadAccounts();
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.classList.remove("hidden");
  } finally {
    setButtonBusy(button, false);
  }
}

async function logout() {
  try {
    await api("/api/logout", { method: "POST" });
  } finally {
    state.selected.clear();
    showLogin();
  }
}

function setView(view) {
  if (!viewMeta[view]) return;
  if ((view === "users" || view === "settings") && state.currentUser.role !== "admin") {
    return;
  }
  state.view = view;
  $$(".view").forEach((element) => element.classList.add("hidden"));
  $(`#${view}-view`).classList.remove("hidden");
  $$(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  $("#page-title").textContent = viewMeta[view].title;
  $("#page-subtitle").textContent = viewMeta[view].subtitle;
  $("#account-top-actions").classList.toggle("hidden", view !== "accounts");
  closeSidebar();

  if (view === "accounts") loadAccounts();
  if (view === "targets") loadTargets();
  if (view === "logs") loadLogs();
  if (view === "settings") loadSettings();
  if (view === "users") loadUsers();
}

function renderTableLoading(tbody, columnCount) {
  tbody.innerHTML = `
    <tr>
      <td class="loading-cell" colspan="${columnCount}">
        <span class="table-loader"><span class="spinner"></span>正在加载</span>
      </td>
    </tr>
  `;
}

function renderTableError(tbody, columnCount, message) {
  tbody.innerHTML = `
    <tr>
      <td class="empty-cell" colspan="${columnCount}">
        <div class="empty-state">
          <i data-lucide="circle-alert"></i>
          <strong>加载失败</strong>
          <span>${escapeHtml(message)}</span>
        </div>
      </td>
    </tr>
  `;
  refreshIcons(tbody);
}

async function loadAccounts({ silent = false } = {}) {
  const requestId = ++state.accountRequest;
  const tbody = $("#account-tbody");
  if (!silent) {
    renderTableLoading(tbody, 7);
  }

  const params = new URLSearchParams({
    page: String(state.accountsPage),
    page_size: String(state.accountsPageSize),
  });
  if (state.search) params.set("search", state.search);
  if (state.status) params.set("status", state.status);

  try {
    const [result, dashboard] = await Promise.all([
      api(`/api/accounts?${params}`),
      api("/api/dashboard"),
    ]);
    if (requestId !== state.accountRequest) return;

    if (!result.items.length && result.total > 0 && state.accountsPage > 1) {
      state.accountsPage -= 1;
      await loadAccounts({ silent });
      return;
    }

    const signature = JSON.stringify(result);
    const dataChanged = signature !== state.accountsSignature;
    state.accounts = result.items;
    state.accountsTotal = result.total;
    if (silent) {
      const visibleIds = new Set(result.items.map((account) => account.id));
      state.selected = new Set(
        Array.from(state.selected).filter((id) => visibleIds.has(id)),
      );
    } else {
      state.selected.clear();
    }
    if (!silent || dataChanged) {
      renderAccounts(result);
    }
    state.accountsSignature = signature;
    renderDashboard(dashboard);
  } catch (error) {
    if (requestId !== state.accountRequest || error.authExpired) return;
    if (!silent) {
      renderTableError(tbody, 7, error.message);
    }
  }
}

function renderDashboard(dashboard) {
  const stats = dashboard.accounts || {};
  $("#metric-total").textContent = stats.total ?? 0;
  $("#metric-active").textContent = stats.active ?? 0;
  $("#metric-pending").textContent = stats.pending ?? 0;
  $("#metric-invalid").textContent = stats.invalid ?? 0;
  const service = dashboard.service || {};
  $("#service-detail").textContent = `${service.workers ?? 0} 个工作线程 · ${service.queued ?? 0} 个排队`;
}

function renderAccounts(result) {
  const tbody = $("#account-tbody");
  if (!result.items.length) {
    const filtered = Boolean(state.search || state.status);
    tbody.innerHTML = `
      <tr>
        <td class="empty-cell" colspan="7">
          <div class="empty-state">
            <i data-lucide="${filtered ? "search-x" : "inbox"}"></i>
            <strong>${filtered ? "没有匹配的邮箱" : "尚未导入邮箱"}</strong>
            <span>${filtered ? "调整搜索或状态筛选" : "使用右上角批量导入"}</span>
          </div>
        </td>
      </tr>
    `;
  } else {
    tbody.innerHTML = result.items.map((account) => {
      const meta = statusMeta[account.status] || statusMeta.error;
      const title = account.last_error ? ` title="${escapeHtml(account.last_error)}"` : "";
      const checked = state.selected.has(account.id) ? " checked" : "";
      const provider = account.client_id;
      const refreshAction = `
              <button class="row-action" type="button" data-action="refresh" data-id="${account.id}" aria-label="刷新令牌" title="刷新令牌">
                <i data-lucide="rotate-cw"></i>
              </button>`;
      return `
        <tr data-account-id="${account.id}">
          <td><input class="checkbox account-checkbox" type="checkbox" data-id="${account.id}" aria-label="选择 ${escapeHtml(account.email)}"${checked}></td>
          <td class="email-cell">
            <button class="email-copy" type="button" data-action="copy-email" data-id="${account.id}" aria-label="复制 ${escapeHtml(account.email)}" title="点击复制邮箱地址">
              <strong>${escapeHtml(account.email)}</strong>
              <i data-lucide="copy"></i>
            </button>
            <small title="${escapeHtml(provider)}">${escapeHtml(provider)}</small>
          </td>
          <td><span class="status ${meta.className}"${title}>${meta.label}</span></td>
          <td class="time-cell">${formatTime(account.last_refresh_at)}</td>
          <td class="time-cell">${formatTime(account.next_refresh_at)}</td>
          <td class="time-cell">${formatTime(account.last_mail_at)}</td>
          <td>
            <div class="row-actions">
              <button class="row-action" type="button" data-action="mail" data-id="${account.id}" aria-label="查看收件箱" title="查看收件箱">
                <i data-lucide="mail-open"></i>
              </button>
              <button class="row-action" type="button" data-action="share" data-id="${account.id}" aria-label="生成共享链接" title="生成共享链接">
                <i data-lucide="link"></i>
              </button>
              ${refreshAction}
              <button class="row-action delete" type="button" data-action="delete" data-id="${account.id}" aria-label="删除邮箱" title="删除邮箱">
                <i data-lucide="trash-2"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  $("#account-total").textContent = `共 ${result.total} 个邮箱`;
  renderPagination(
    $("#account-pagination"),
    result.page,
    Math.ceil(result.total / result.page_size),
    (page) => {
      state.accountsPage = page;
      loadAccounts();
    },
  );
  $("#select-all").checked = false;
  $("#select-all").indeterminate = false;
  updateSelectionUi();
  refreshIcons(tbody);
}

function paginationItems(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1);
  const values = new Set([1, total, current - 1, current, current + 1]);
  const pages = Array.from(values)
    .filter((page) => page >= 1 && page <= total)
    .sort((a, b) => a - b);
  const result = [];
  pages.forEach((page, index) => {
    if (index && page - pages[index - 1] > 1) result.push("ellipsis");
    result.push(page);
  });
  return result;
}

function renderPagination(container, current, total, onPage) {
  container.replaceChildren();
  if (total <= 1) return;

  const createButton = (content, page, label, active = false) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `page-button${active ? " active" : ""}`;
    button.setAttribute("aria-label", label);
    button.disabled = page < 1 || page > total || active;
    button.innerHTML = content;
    button.addEventListener("click", () => onPage(page));
    return button;
  };

  container.append(createButton('<i data-lucide="chevron-left"></i>', current - 1, "上一页"));
  paginationItems(current, total).forEach((item) => {
    if (item === "ellipsis") {
      const ellipsis = document.createElement("span");
      ellipsis.className = "page-button";
      ellipsis.textContent = "…";
      container.append(ellipsis);
      return;
    }
    container.append(createButton(String(item), item, `第 ${item} 页`, item === current));
  });
  container.append(createButton('<i data-lucide="chevron-right"></i>', current + 1, "下一页"));
  refreshIcons(container);
}

function updateSelectionUi() {
  const count = state.selected.size;
  const countElement = $("#selection-count");
  countElement.textContent = `已选 ${count} 个`;
  countElement.classList.toggle("hidden", count === 0);
  $("#share-button").disabled = count !== 1;
  $("#delete-button").disabled = count === 0;
  const refreshLabel = $("#refresh-button span");
  refreshLabel.textContent = count ? `刷新所选 (${count})` : "刷新全部";

  const pageIds = state.accounts.map((account) => account.id);
  const checkedCount = pageIds.filter((id) => state.selected.has(id)).length;
  $("#select-all").checked = pageIds.length > 0 && checkedCount === pageIds.length;
  $("#select-all").indeterminate = checkedCount > 0 && checkedCount < pageIds.length;
}

function toggleSelectAll(checked) {
  state.accounts.forEach((account) => {
    if (checked) state.selected.add(account.id);
    else state.selected.delete(account.id);
  });
  $$(".account-checkbox").forEach((checkbox) => {
    checkbox.checked = checked;
  });
  updateSelectionUi();
}

async function queueRefresh(ids) {
  const button = $("#refresh-button");
  setButtonBusy(button, true, "加入队列");
  try {
    const result = await api("/api/accounts/refresh", {
      method: "POST",
      body: JSON.stringify({ ids }),
    });
    toast(`已加入刷新队列：${result.queued} 个`);
    window.setTimeout(() => {
      if (state.view === "accounts") loadAccounts();
    }, 1600);
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  } finally {
    setButtonBusy(button, false);
    updateSelectionUi();
  }
}

async function deleteAccounts(ids) {
  if (!ids.length) return;
  const accepted = await askDelete(ids.length);
  if (!accepted) return;

  try {
    const result = await api("/api/accounts", {
      method: "DELETE",
      body: JSON.stringify({ ids }),
    });
    toast(`已删除 ${result.deleted} 个邮箱`);
    await loadAccounts();
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  }
}

function askConfirm({ title, message, submitLabel = "确认", danger = true }) {
  $("#confirm-title").textContent = title;
  $("#confirm-message").textContent = message;
  const submit = $("#confirm-submit");
  submit.textContent = submitLabel;
  submit.classList.toggle("danger", danger);
  showOverlay($("#confirm-overlay"), true);
  return new Promise((resolve) => {
    state.confirmResolve = resolve;
  });
}

function askDelete(count) {
  return askConfirm({
    title: "删除邮箱",
    message: `将永久删除 ${count} 个邮箱及其加密凭据。`,
    submitLabel: "确认删除",
  });
}

function resolveConfirm(value) {
  showOverlay($("#confirm-overlay"), false);
  if (state.confirmResolve) {
    state.confirmResolve(value);
    state.confirmResolve = null;
  }
}

async function exportAccounts() {
  if (!state.accountsTotal) {
    toast("没有可导出的邮箱", "error");
    return;
  }
  const ids = Array.from(state.selected);
  const params = ids.length ? `?ids=${encodeURIComponent(ids.join(","))}` : "";
  const button = $("#export-button");
  setButtonBusy(button, true, "导出中");
  try {
    const response = await fetch(`/api/accounts/export${params}`, {
      credentials: "same-origin",
    });
    if (response.status === 401) {
      showLogin();
      throw new Error("登录已过期，请重新登录");
    }
    if (!response.ok) {
      const data = await response.json();
      throw new Error(detailFrom(data, "导出失败"));
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "outlook-accounts.txt";
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    toast(`已导出 ${ids.length || state.accountsTotal} 个邮箱`);
  } catch (error) {
    toast(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function loadTargets() {
  const tbody = $("#targets-tbody");
  renderTableLoading(tbody, 7);
  try {
    const result = await api("/api/targets");
    state.targets = Array.isArray(result.items) ? result.items : [];
    renderTargets(state.targets);
  } catch (error) {
    if (!error.authExpired) renderTableError(tbody, 7, error.message);
  }
}

function renderTargets(targets) {
  const tbody = $("#targets-tbody");
  const keyword = state.targetSearch.toLocaleLowerCase();
  const visibleTargets = keyword
    ? targets.filter((target) => [
      target.email,
      target.account_email,
      ...(Array.isArray(target.tags) ? target.tags : []),
    ].some((value) => String(value || "").toLocaleLowerCase().includes(keyword)))
    : targets;
  if (!visibleTargets.length) {
    const filtered = Boolean(keyword);
    tbody.innerHTML = `
      <tr>
        <td class="empty-cell" colspan="7">
          <div class="empty-state">
            <i data-lucide="${filtered ? "search-x" : "at-sign"}"></i>
            <strong>${filtered ? "没有匹配的别名" : "尚未添加别名"}</strong>
            <span>${filtered ? "调整搜索条件" : "为 Outlook 邮箱添加隐藏邮箱地址后，可生成独立共享链接"}</span>
          </div>
        </td>
      </tr>
    `;
  } else {
    tbody.innerHTML = visibleTargets.map((target) => {
      const enabled = Boolean(target.enabled);
      const tags = Array.isArray(target.tags) ? target.tags : [];
      const tagsHtml = tags.length
        ? tags.map((tag) => `<span class="target-tag">${escapeHtml(tag)}</span>`).join("")
        : '<span class="target-tag-empty">—</span>';
      return `
        <tr data-target-id="${target.id}">
          <td class="email-cell">
            <button class="email-copy" type="button" data-target-action="copy-email" data-id="${target.id}" aria-label="复制 ${escapeHtml(target.email)}" title="点击复制邮箱地址">
              <strong>${escapeHtml(target.email)}</strong>
              <i data-lucide="copy"></i>
            </button>
          </td>
          <td class="email-cell"><strong title="${escapeHtml(target.account_email)}">${escapeHtml(target.account_email)}</strong></td>
          <td><div class="target-tag-list">${tagsHtml}</div></td>
          <td><span class="user-count">${Number(target.message_count || 0)}</span></td>
          <td><span class="status ${enabled ? "active" : "user-disabled"}">${enabled ? "启用" : "已停用"}</span></td>
          <td class="time-cell">${formatTime(target.created_at)}</td>
          <td>
            <div class="row-actions">
              <button class="row-action" type="button" data-target-action="share" data-id="${target.id}" aria-label="生成共享链接" title="生成共享链接">
                <i data-lucide="link"></i>
              </button>
              <button class="row-action" type="button" data-target-action="tags" data-id="${target.id}" aria-label="编辑标签" title="编辑标签">
                <i data-lucide="tags"></i>
              </button>
              <button class="row-action" type="button" data-target-action="toggle" data-id="${target.id}" aria-label="${enabled ? "停用别名" : "启用别名"}" title="${enabled ? "停用别名" : "启用别名"}">
                <i data-lucide="power"></i>
              </button>
              <button class="row-action delete" type="button" data-target-action="delete" data-id="${target.id}" aria-label="删除别名" title="删除别名">
                <i data-lucide="trash-2"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }
  $("#targets-total").textContent = keyword
    ? `显示 ${visibleTargets.length} / ${targets.length} 个别名`
    : `共 ${targets.length} 个别名`;
  refreshIcons(tbody);
}

function parseTargetTags(value) {
  return value.split(/[，,]/).map((tag) => tag.trim()).filter(Boolean);
}

async function openTargetModal() {
  try {
    const result = await api("/api/accounts/options");
    state.targetAccounts = Array.isArray(result.items) ? result.items : [];
    if (!state.targetAccounts.length) {
      toast("请先导入 Outlook 邮箱", "error");
      return;
    }
    $("#target-account-select").innerHTML = state.targetAccounts.map((account) => `
      <option value="${account.id}">${escapeHtml(account.email)}</option>
    `).join("");
    $("#target-email-input").value = "";
    $("#target-new-tags-input").value = "";
    showOverlay($("#target-overlay"), true);
    window.setTimeout(() => $("#target-email-input").focus(), 80);
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  }
}

function closeTargetModal() {
  showOverlay($("#target-overlay"), false);
}

function openTargetTagsModal(target) {
  state.targetTagsEditingId = Number(target.id);
  $("#target-tags-subtitle").textContent = target.email;
  $("#target-tags-input").value = (target.tags || []).join("，");
  showOverlay($("#target-tags-overlay"), true);
  window.setTimeout(() => $("#target-tags-input").focus(), 80);
}

function closeTargetTagsModal() {
  showOverlay($("#target-tags-overlay"), false);
  state.targetTagsEditingId = null;
}

async function submitTargetForm(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setButtonBusy(button, true, "添加中");
  try {
    await api("/api/targets", {
      method: "POST",
      body: JSON.stringify({
        account_id: Number($("#target-account-select").value),
        email: $("#target-email-input").value.trim(),
        tags: parseTargetTags($("#target-new-tags-input").value),
      }),
    });
    closeTargetModal();
    toast("别名已添加");
    await loadTargets();
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function submitTargetTags(event) {
  event.preventDefault();
  if (!state.targetTagsEditingId) return;
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setButtonBusy(button, true, "保存中");
  try {
    await api(`/api/targets/${state.targetTagsEditingId}/tags`, {
      method: "PUT",
      body: JSON.stringify({ tags: parseTargetTags($("#target-tags-input").value) }),
    });
    closeTargetTagsModal();
    toast("标签已保存");
    await loadTargets();
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function generateTargetShareLink(target) {
  try {
    const result = await api(`/api/targets/${target.id}/share`, { method: "POST" });
    const url = result.url || new URL(result.path, window.location.origin).href;
    openShareLink(result.email, url, result);
    toast("别名共享链接已生成");
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  }
}

async function toggleTarget(target) {
  try {
    await api(`/api/targets/${target.id}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled: !target.enabled }),
    });
    toast(target.enabled ? "别名已停用" : "别名已启用");
    await loadTargets();
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  }
}

async function deleteTarget(target) {
  const accepted = await askConfirm({
    title: "删除别名",
    message: `将删除别名 ${target.email} 及其共享链接。`,
    submitLabel: "确认删除",
  });
  if (!accepted) return;
  try {
    await api(`/api/targets/${target.id}`, { method: "DELETE" });
    toast("别名及其共享链接已删除");
    await loadTargets();
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  }
}

async function generateShareLink(accountId) {
  try {
    const result = await api("/api/accounts/share", {
      method: "POST",
      body: JSON.stringify({ account_id: accountId }),
    });
    const url = result.url || new URL(result.path, window.location.origin).href;
    openShareLink(result.email, url, result);
    toast("共享链接已生成");
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  }
}

function shareExpiryValue(expiresAt) {
  if (!expiresAt) return "0";
  const remaining = Math.max(
    1,
    Math.ceil((Number(expiresAt) * 1000 - Date.now()) / (24 * 60 * 60 * 1000)),
  );
  const values = [1, 7, 30, 90, 365];
  return String(values.includes(remaining) ? remaining : "custom");
}

function renderShareDetails() {
  const expires = state.shareExpiresAt
    ? `有效至 ${formatTime(state.shareExpiresAt)}`
    : "永久有效";
  const accessed = state.shareLastAccessAt
    ? `上次访问 ${formatTime(state.shareLastAccessAt)}`
    : "尚未访问";
  $("#share-expiry-select").value = shareExpiryValue(state.shareExpiresAt);
  $("#share-link-meta").textContent = `${expires} · ${accessed}`;
  $("#save-share-expiry").disabled = !state.shareToken;
  $("#revoke-share-link").disabled = !state.shareToken;
}

function openShareLink(email, url, link = {}) {
  state.shareUrl = url;
  state.shareToken = String(link.token || "");
  state.shareExpiresAt = link.expires_at || null;
  state.shareLastAccessAt = link.last_access_at || null;
  $("#share-email").textContent = email;
  $("#share-link-input").value = url;
  renderShareDetails();
  showOverlay($("#share-overlay"), true);
  window.setTimeout(() => {
    $("#share-link-input").focus();
    $("#share-link-input").select();
  }, 80);
}

function closeShareLink() {
  showOverlay($("#share-overlay"), false);
}

async function copyShareLink() {
  try {
    await navigator.clipboard.writeText(state.shareUrl);
    toast("链接已复制");
  } catch (error) {
    toast("复制失败，请检查浏览器权限", "error");
  }
}

async function saveShareExpiry() {
  if (!state.shareToken) return;
  const expiresInDays = Number($("#share-expiry-select").value);
  if (!Number.isInteger(expiresInDays)) {
    toast("请选择新的有效期", "error");
    return;
  }
  const button = $("#save-share-expiry");
  setButtonBusy(button, true, "保存中");
  try {
    const result = await api(`/api/shares/${state.shareToken}`, {
      method: "PUT",
      body: JSON.stringify({
        expires_in_days: expiresInDays,
      }),
    });
    state.shareExpiresAt = result.expires_at || null;
    renderShareDetails();
    toast("链接有效期已保存");
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function revokeShareLink() {
  if (!state.shareToken) return;
  const accepted = await askConfirm({
    title: "撤销共享链接",
    message: "撤销后该链接将立即失效，重新生成会得到新的链接。",
    submitLabel: "确认撤销",
  });
  if (!accepted) return;
  try {
    await api(`/api/shares/${state.shareToken}/revoke`, { method: "POST" });
    closeShareLink();
    toast("共享链接已撤销");
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  }
}

function showOverlay(overlay, open) {
  if (open) {
    overlay.classList.remove("hidden");
    overlay.setAttribute("aria-hidden", "false");
    requestAnimationFrame(() => overlay.classList.add("open"));
    return;
  }
  overlay.classList.remove("open");
  overlay.setAttribute("aria-hidden", "true");
  window.setTimeout(() => overlay.classList.add("hidden"), 160);
}

function openImport() {
  $("#account-lines").value = "";
  updateImportLineCount();
  showOverlay($("#import-overlay"), true);
  window.setTimeout(() => $("#account-lines").focus(), 80);
}

function closeImport() {
  showOverlay($("#import-overlay"), false);
}

function openOAuthModal() {
  state.oauthFlowId = "";
  $("#oauth-email-input").value = "";
  $("#oauth-client-id-input").value = state.oauthClientId;
  $("#oauth-start-form").classList.remove("hidden");
  $("#oauth-device-panel").classList.add("hidden");
  $("#oauth-verification-uri").value = "";
  $("#oauth-user-code").value = "";
  $("#oauth-open-link").removeAttribute("href");
  $("#oauth-device-status").textContent = "";
  showOverlay($("#oauth-overlay"), true);
  window.setTimeout(() => $("#oauth-email-input").focus(), 80);
}

function closeOAuthModal() {
  showOverlay($("#oauth-overlay"), false);
}

async function startOAuthDeviceAuthorization(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setButtonBusy(button, true, "获取中");
  try {
    const clientId = $("#oauth-client-id-input").value.trim();
    const result = await api("/api/oauth/device", {
      method: "POST",
      body: JSON.stringify({
        email: $("#oauth-email-input").value.trim(),
        client_id: clientId,
      }),
    });
    state.oauthClientId = clientId;
    state.oauthFlowId = String(result.id || "");
    $("#oauth-start-form").classList.add("hidden");
    $("#oauth-device-panel").classList.remove("hidden");
    $("#oauth-verification-uri").value = result.verification_uri || "";
    $("#oauth-user-code").value = result.user_code || "";
    $("#oauth-open-link").href = result.verification_uri_complete || result.verification_uri || "#";
    $("#oauth-device-status").textContent = `授权码有效至 ${formatTime(result.expires_at)}`;
    refreshIcons($("#oauth-device-panel"));
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function completeOAuthDeviceAuthorization() {
  if (!state.oauthFlowId) return;
  const button = $("#oauth-complete");
  setButtonBusy(button, true, "检查中");
  try {
    const result = await api(`/api/oauth/device/${state.oauthFlowId}/complete`, {
      method: "POST",
    });
    if (result.status === "pending") {
      $("#oauth-device-status").textContent = result.message || "请先在 Microsoft 页面完成授权";
      return;
    }
    closeOAuthModal();
    toast(`${result.email} 已授权并加入邮箱列表`);
    state.accountsPage = 1;
    await loadAccounts();
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

function updateImportLineCount() {
  const lines = $("#account-lines").value
    .split(/\r?\n/)
    .filter((line) => line.trim()).length;
  $("#import-line-count").textContent = `${lines} 行`;
}

async function importAccounts(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setButtonBusy(button, true, "导入中");
  try {
    const result = await api("/api/accounts/import", {
      method: "POST",
      body: JSON.stringify({ content: $("#account-lines").value }),
    });
    closeImport();
    toast(`新增 ${result.imported} 个，更新 ${result.updated} 个，排队 ${result.queued} 个`);
    state.accountsPage = 1;
    await loadAccounts();
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function loadLogs() {
  const tbody = $("#logs-tbody");
  renderTableLoading(tbody, 4);
  try {
    const result = await api(`/api/refresh-logs?page=${state.logsPage}&page_size=${state.logsPageSize}`);
    if (!result.items.length && result.total > 0 && state.logsPage > 1) {
      state.logsPage -= 1;
      await loadLogs();
      return;
    }
    renderLogs(result);
  } catch (error) {
    if (!error.authExpired) renderTableError(tbody, 4, error.message);
  }
}

function renderLogs(result) {
  const tbody = $("#logs-tbody");
  if (!result.items.length) {
    tbody.innerHTML = `
      <tr>
        <td class="empty-cell" colspan="4">
          <div class="empty-state">
            <i data-lucide="history"></i>
            <strong>暂无刷新记录</strong>
          </div>
        </td>
      </tr>
    `;
  } else {
    tbody.innerHTML = result.items.map((log) => {
      const resultMeta = log.outcome === "success"
        ? { label: "成功", className: "success" }
        : log.outcome === "invalid"
          ? { label: "已失效", className: "invalid" }
          : { label: "失败", className: "error" };
      return `
        <tr>
          <td class="email-cell"><strong title="${escapeHtml(log.email)}">${escapeHtml(log.email)}</strong></td>
          <td><span class="status ${resultMeta.className}">${resultMeta.label}</span></td>
          <td class="message-cell" title="${escapeHtml(log.message || "")}">${escapeHtml(log.message || "—")}</td>
          <td class="time-cell">${formatTime(log.created_at)}</td>
        </tr>
      `;
    }).join("");
  }
  $("#logs-total").textContent = `共 ${result.total} 条记录`;
  renderPagination(
    $("#logs-pagination"),
    result.page,
    Math.ceil(result.total / result.page_size),
    (page) => {
      state.logsPage = page;
      loadLogs();
    },
  );
  refreshIcons(tbody);
}

async function loadSettings() {
  const form = $("#settings-form");
  form.classList.add("is-loading");
  try {
    const settings = await api("/api/settings");
    $("#setting-tenant").value = settings.tenant;
    $("#setting-refresh-days").value = settings.refresh_interval_days;
    $("#setting-mail-size").value = settings.mail_page_size;
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  } finally {
    form.classList.remove("is-loading");
  }
}

async function loadUsers() {
  const tbody = $("#users-tbody");
  renderTableLoading(tbody, 6);
  try {
    const result = await api("/api/users");
    state.users = result.items || [];
    renderUsers(state.users);
  } catch (error) {
    if (!error.authExpired) renderTableError(tbody, 6, error.message);
  }
}

function renderUsers(users) {
  const tbody = $("#users-tbody");
  if (!users.length) {
    tbody.innerHTML = `
      <tr>
        <td class="empty-cell" colspan="6">
          <div class="empty-state">
            <i data-lucide="users"></i>
            <strong>暂无用户</strong>
          </div>
        </td>
      </tr>
    `;
  } else {
    tbody.innerHTML = users.map((user) => {
      const isAdmin = user.role === "admin";
      const enabled = Boolean(user.enabled);
      const actions = isAdmin
        ? '<span class="user-protected">当前管理员</span>'
        : `
          <button class="row-action" type="button" data-user-action="toggle" data-id="${user.id}" aria-label="${enabled ? "停用" : "启用"}用户" title="${enabled ? "停用用户" : "启用用户"}">
            <i data-lucide="${enabled ? "user-round-x" : "user-round-check"}"></i>
          </button>
          <button class="row-action" type="button" data-user-action="password" data-id="${user.id}" aria-label="重置密码" title="重置密码">
            <i data-lucide="key-round"></i>
          </button>
          <button class="row-action delete" type="button" data-user-action="delete" data-id="${user.id}" aria-label="删除用户" title="删除用户">
            <i data-lucide="trash-2"></i>
          </button>
        `;
      return `
        <tr data-user-id="${user.id}">
          <td class="email-cell"><strong title="${escapeHtml(user.username)}">${escapeHtml(user.username)}</strong></td>
          <td><span class="user-role">${isAdmin ? "管理员" : "普通用户"}</span></td>
          <td><span class="status ${enabled ? "active" : "user-disabled"}">${enabled ? "启用" : "已停用"}</span></td>
          <td><span class="user-count">${user.account_count}</span></td>
          <td class="time-cell">${formatTime(user.created_at)}</td>
          <td><div class="row-actions">${actions}</div></td>
        </tr>
      `;
    }).join("");
  }
  $("#users-total").textContent = `共 ${users.length} 个用户`;
  refreshIcons(tbody);
}

function openUserModal(mode = "create", user = null) {
  const creating = mode === "create";
  state.userModalMode = mode;
  state.userEditingId = user ? Number(user.id) : null;
  $("#user-modal-title").textContent = creating ? "添加用户" : "重置密码";
  $("#user-modal-subtitle").textContent = creating
    ? "新用户登录后只能查看自己的邮箱数据"
    : `为 ${user ? user.username : "用户"} 设置新密码`;
  $("#user-name-field").classList.toggle("hidden", !creating);
  $("#user-name-input").disabled = !creating;
  $("#user-name-input").required = creating;
  $("#user-name-input").value = creating ? "" : user?.username || "";
  $("#user-password-label").textContent = creating ? "初始密码" : "新密码";
  $("#user-password-input").value = "";
  const submit = $("#user-form button[type=submit]");
  submit.innerHTML = `
    <i data-lucide="${creating ? "user-plus" : "key-round"}"></i>
    <span id="user-submit-label">${creating ? "添加用户" : "保存密码"}</span>
  `;
  showOverlay($("#user-overlay"), true);
  refreshIcons(submit);
  window.setTimeout(() => {
    $(creating ? "#user-name-input" : "#user-password-input").focus();
  }, 80);
}

function closeUserModal() {
  showOverlay($("#user-overlay"), false);
}

async function submitUserForm(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const creating = state.userModalMode === "create";
  setButtonBusy(button, true, creating ? "添加中" : "保存中");
  try {
    if (creating) {
      await api("/api/users", {
        method: "POST",
        body: JSON.stringify({
          username: $("#user-name-input").value.trim(),
          password: $("#user-password-input").value,
        }),
      });
      toast("用户已添加");
    } else {
      await api(`/api/users/${state.userEditingId}/password`, {
        method: "PUT",
        body: JSON.stringify({ password: $("#user-password-input").value }),
      });
      toast("密码已重置");
    }
    closeUserModal();
    await loadUsers();
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function toggleUser(user) {
  try {
    await api(`/api/users/${user.id}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled: !user.enabled }),
    });
    toast(user.enabled ? "用户已停用" : "用户已启用");
    await loadUsers();
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  }
}

async function deleteUser(user) {
  const accepted = await askConfirm({
    title: "删除用户",
    message: `将删除用户 ${user.username} 及其全部邮箱、邮件刷新记录。`,
    submitLabel: "确认删除",
  });
  if (!accepted) return;
  try {
    await api(`/api/users/${user.id}`, { method: "DELETE" });
    toast("用户及其数据已删除");
    await loadUsers();
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  }
}

async function saveSettings(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setButtonBusy(button, true, "保存中");
  try {
    await api("/api/settings", {
      method: "PUT",
      body: JSON.stringify({
        tenant: $("#setting-tenant").value.trim(),
        refresh_interval_days: Number($("#setting-refresh-days").value),
        mail_page_size: Number($("#setting-mail-size").value),
      }),
    });
    toast("设置已保存");
  } catch (error) {
    if (!error.authExpired) toast(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

function openDrawer(account) {
  state.mailAccount = account;
  $("#drawer-email strong").textContent = account.email;
  $("#drawer-email").dataset.email = account.email;
  $("#mail-list").innerHTML = `
    <div class="mail-list-state">
      <span class="spinner"></span>
      <span>正在加载已归档邮件</span>
    </div>
  `;
  $("#mail-content").innerHTML = `
    <div class="empty-state compact">
      <i data-lucide="mail-open"></i>
      <strong>正在读取本地归档</strong>
    </div>
  `;
  $("#drawer-scrim").classList.remove("hidden");
  requestAnimationFrame(() => {
    $("#drawer-scrim").classList.add("open");
    $("#mail-drawer").classList.add("open");
    $("#mail-drawer").setAttribute("aria-hidden", "false");
  });
  refreshIcons($("#mail-content"));
  loadMailbox();
}

function closeDrawer() {
  $("#mail-drawer").classList.remove("open");
  $("#mail-drawer").setAttribute("aria-hidden", "true");
  $("#drawer-scrim").classList.remove("open");
  window.setTimeout(() => $("#drawer-scrim").classList.add("hidden"), 180);
}

async function loadMailbox(refresh = false) {
  const account = state.mailAccount;
  if (!account) return;
  const mailList = $("#mail-list");
  mailList.innerHTML = `
    <div class="mail-list-state">
      <span class="spinner"></span>
      <span>${refresh ? "正在刷新收件箱" : "正在加载已归档邮件"}</span>
    </div>
  `;
  try {
    const result = refresh
      ? await api(`/api/accounts/${account.id}/messages/sync`, { method: "POST" })
      : await api(`/api/accounts/${account.id}/messages`);
    if (!state.mailAccount || state.mailAccount.id !== account.id) return;
    if (result.last_mail_at) {
      state.mailAccount.last_mail_at = result.last_mail_at;
      const stored = state.accounts.find((item) => item.id === account.id);
      if (stored) stored.last_mail_at = result.last_mail_at;
      const row = $(`tr[data-account-id="${account.id}"]`);
      if (row) {
        const cells = row.querySelectorAll(".time-cell");
        if (cells.length >= 3) cells[2].textContent = formatTime(result.last_mail_at);
      }
    }
    renderMailList(result.items);
    if (result.items.length) {
      await loadMessage(result.items[0].uid);
    } else {
      $("#mail-content").innerHTML = `
        <div class="empty-state compact">
          <i data-lucide="mail"></i>
          <strong>暂无归档邮件</strong>
        </div>
      `;
      refreshIcons($("#mail-content"));
    }
  } catch (error) {
    if (error.authExpired) return;
    mailList.innerHTML = `
      <div class="mail-list-state">
        <i data-lucide="circle-alert"></i>
        <span>${escapeHtml(error.message)}</span>
      </div>
    `;
    $("#mail-content").innerHTML = `
      <div class="empty-state compact">
        <i data-lucide="circle-alert"></i>
        <strong>无法读取收件箱</strong>
      </div>
    `;
    refreshIcons($("#mail-drawer"));
  }
}

function renderMailList(messages) {
  const list = $("#mail-list");
  if (!messages.length) {
    list.innerHTML = '<div class="mail-list-state"><span>收件箱为空</span></div>';
    return;
  }
  list.innerHTML = messages.map((message, index) => `
    <button class="mail-item${index === 0 ? " active" : ""}" type="button" data-uid="${escapeHtml(message.uid)}">
      <strong title="${escapeHtml(message.sender_address)}">${escapeHtml(message.sender_name || message.sender_address || "未知发件人")}</strong>
      <span class="mail-subject" title="${escapeHtml(message.subject)}">${escapeHtml(message.subject || "无主题")}</span>
      <span class="mail-date">${formatTime(message.received_at)}</span>
    </button>
  `).join("");
}

async function loadMessage(uid) {
  const account = state.mailAccount;
  if (!account) return;
  $$(".mail-item", $("#mail-list")).forEach((item) => {
    item.classList.toggle("active", item.dataset.uid === String(uid));
  });
  const content = $("#mail-content");
  content.innerHTML = `
    <div class="empty-state compact">
      <span class="spinner"></span>
      <strong>正在读取正文</strong>
    </div>
  `;
  try {
    const message = await api(`/api/accounts/${account.id}/messages/${encodeURIComponent(uid)}`);
    if (!state.mailAccount || state.mailAccount.id !== account.id) return;
    content.innerHTML = `
      <h2></h2>
      <div class="mail-meta">
        <div class="mail-from"></div>
        <div class="mail-received"></div>
      </div>
      <pre class="mail-body"></pre>
    `;
    $("h2", content).textContent = message.subject || "无主题";
    $(".mail-from", content).textContent = `发件人：${message.sender_name || "未知发件人"}${message.sender_address ? ` <${message.sender_address}>` : ""}`;
    $(".mail-received", content).textContent = `接收时间：${formatTime(message.received_at)}`;
    $(".mail-body", content).textContent = message.body || "（无可显示的文本正文）";
    content.scrollTop = 0;
  } catch (error) {
    if (error.authExpired) return;
    content.innerHTML = `
      <div class="empty-state compact">
        <i data-lucide="circle-alert"></i>
        <strong>正文读取失败</strong>
        <span>${escapeHtml(error.message)}</span>
      </div>
    `;
    refreshIcons(content);
  }
}

function openSidebar() {
  $("#sidebar").classList.add("open");
  $("#sidebar-scrim").classList.add("open");
}

function closeSidebar() {
  $("#sidebar").classList.remove("open");
  $("#sidebar-scrim").classList.remove("open");
}

function bindEvents() {
  $("#login-form").addEventListener("submit", handleLogin);
  $("#logout-button").addEventListener("click", logout);
  $$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });
  $("#mobile-menu").addEventListener("click", openSidebar);
  $("#sidebar-close").addEventListener("click", closeSidebar);
  $("#sidebar-scrim").addEventListener("click", closeSidebar);

  let searchTimer;
  $("#account-search").addEventListener("input", (event) => {
    const value = event.currentTarget.value.trim();
    $("#search-clear").classList.toggle("hidden", !event.currentTarget.value);
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => {
      state.search = value;
      state.accountsPage = 1;
      loadAccounts();
    }, 320);
  });
  $("#search-clear").addEventListener("click", () => {
    $("#account-search").value = "";
    $("#search-clear").classList.add("hidden");
    state.search = "";
    state.accountsPage = 1;
    loadAccounts();
  });
  $("#status-filter").addEventListener("change", (event) => {
    state.status = event.currentTarget.value;
    state.accountsPage = 1;
    loadAccounts();
  });
  $("#select-all").addEventListener("change", (event) => toggleSelectAll(event.currentTarget.checked));
  $("#account-tbody").addEventListener("change", (event) => {
    const checkbox = event.target.closest(".account-checkbox");
    if (!checkbox) return;
    const id = Number(checkbox.dataset.id);
    if (checkbox.checked) state.selected.add(id);
    else state.selected.delete(id);
    updateSelectionUi();
  });
  $("#account-tbody").addEventListener("click", (event) => {
    const button = event.target.closest("[data-action]");
    if (!button) return;
    const id = Number(button.dataset.id);
    const account = state.accounts.find((item) => item.id === id);
    if (!account) return;
    if (button.dataset.action === "copy-email") copyEmailAddress(account.email);
    if (button.dataset.action === "mail") openDrawer(account);
    if (button.dataset.action === "share") generateShareLink(id);
    if (button.dataset.action === "refresh") queueRefresh([id]);
    if (button.dataset.action === "delete") deleteAccounts([id]);
  });
  $("#share-button").addEventListener("click", () => {
    const ids = Array.from(state.selected);
    if (ids.length !== 1) {
      toast("请选择一个邮箱生成链接", "error");
      return;
    }
    generateShareLink(ids[0]);
  });
  $("#refresh-button").addEventListener("click", () => queueRefresh(Array.from(state.selected)));
  $("#delete-button").addEventListener("click", () => deleteAccounts(Array.from(state.selected)));
  $("#export-button").addEventListener("click", exportAccounts);

  $("#open-import").addEventListener("click", openImport);
  $$(".close-import").forEach((button) => button.addEventListener("click", closeImport));
  $("#import-overlay").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeImport();
  });
  $("#account-lines").addEventListener("input", updateImportLineCount);
  $("#import-form").addEventListener("submit", importAccounts);
  $("#open-oauth-modal").addEventListener("click", openOAuthModal);
  $$(".close-oauth-modal").forEach((button) => button.addEventListener("click", closeOAuthModal));
  $("#oauth-overlay").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeOAuthModal();
  });
  $("#oauth-start-form").addEventListener("submit", startOAuthDeviceAuthorization);
  $("#oauth-complete").addEventListener("click", completeOAuthDeviceAuthorization);

  $("#confirm-cancel").addEventListener("click", () => resolveConfirm(false));
  $("#confirm-submit").addEventListener("click", () => resolveConfirm(true));
  $("#confirm-overlay").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) resolveConfirm(false);
  });
  $$(".close-share").forEach((button) => button.addEventListener("click", closeShareLink));
  $("#share-overlay").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeShareLink();
  });
  $("#copy-share-link").addEventListener("click", copyShareLink);
  $("#save-share-expiry").addEventListener("click", saveShareExpiry);
  $("#revoke-share-link").addEventListener("click", revokeShareLink);
  $("#target-search").addEventListener("input", (event) => {
    state.targetSearch = event.currentTarget.value.trim();
    renderTargets(state.targets);
  });
  $("#open-target-modal").addEventListener("click", openTargetModal);
  $$(".close-target-modal").forEach((button) => button.addEventListener("click", closeTargetModal));
  $("#target-overlay").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeTargetModal();
  });
  $("#target-form").addEventListener("submit", submitTargetForm);
  $$(".close-target-tags-modal").forEach((button) => button.addEventListener("click", closeTargetTagsModal));
  $("#target-tags-overlay").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeTargetTagsModal();
  });
  $("#target-tags-form").addEventListener("submit", submitTargetTags);
  $("#targets-tbody").addEventListener("click", (event) => {
    const button = event.target.closest("[data-target-action]");
    if (!button) return;
    const target = state.targets.find((item) => item.id === Number(button.dataset.id));
    if (!target) return;
    if (button.dataset.targetAction === "copy-email") copyEmailAddress(target.email);
    if (button.dataset.targetAction === "share") generateTargetShareLink(target);
    if (button.dataset.targetAction === "tags") openTargetTagsModal(target);
    if (button.dataset.targetAction === "toggle") toggleTarget(target);
    if (button.dataset.targetAction === "delete") deleteTarget(target);
  });
  $("#open-user-modal").addEventListener("click", () => openUserModal());
  $$(".close-user-modal").forEach((button) => button.addEventListener("click", closeUserModal));
  $("#user-overlay").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeUserModal();
  });
  $("#user-form").addEventListener("submit", submitUserForm);
  $("#users-tbody").addEventListener("click", (event) => {
    const button = event.target.closest("[data-user-action]");
    if (!button) return;
    const user = state.users.find((item) => item.id === Number(button.dataset.id));
    if (!user || user.role === "admin") return;
    if (button.dataset.userAction === "toggle") toggleUser(user);
    if (button.dataset.userAction === "password") openUserModal("password", user);
    if (button.dataset.userAction === "delete") deleteUser(user);
  });

  $("#reload-logs").addEventListener("click", loadLogs);
  $("#settings-form").addEventListener("submit", saveSettings);

  $("#close-drawer").addEventListener("click", closeDrawer);
  $("#drawer-scrim").addEventListener("click", closeDrawer);
  $("#reload-mail").addEventListener("click", () => loadMailbox(true));
  $("#drawer-email").addEventListener("click", (event) => {
    copyEmailAddress(event.currentTarget.dataset.email || "");
  });
  $("#mail-list").addEventListener("click", (event) => {
    const item = event.target.closest(".mail-item");
    if (item) loadMessage(item.dataset.uid);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    closeImport();
    closeOAuthModal();
    closeShareLink();
    closeTargetModal();
    closeTargetTagsModal();
    closeDrawer();
    closeSidebar();
    if (state.confirmResolve) resolveConfirm(false);
  });

}

document.addEventListener("DOMContentLoaded", initialize);
