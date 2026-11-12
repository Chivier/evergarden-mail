"use strict";

const state = {
  csrf: "",
  approvalUrl: "",
  accountAdminEnabled: false,
  accounts: [],
  account: null,
  view: "today",
  messages: [],
  current: null,
  currentAttachments: [],
  preferences: null,
  draft: null,
  composeArchiveAttachments: [],
  mcp: { resource: "", discoveryUrl: "", issuer: "", oauthEnabled: false, scopes: [] },
  mcpClient: "claude-code",
  apiKeysEnabled: false,
  apiKeys: null,
  // Plaintext of the key just issued. Memory only, never persisted, cleared
  // when the dialog closes.
  mcpToken: "",
  subject: "",
  listRendered: false,
};

// Keep redacted list metadata briefly in this page only; never persist private mail in the browser.
const MESSAGE_PRELOAD_TTL_MS = 30_000;
const MESSAGE_PRELOAD_MAX_ENTRIES = 12;
const messagePreloads = new Map();
let messageLoadSequence = 0;
let countLoadSequence = 0;

const byId = (id) => document.getElementById(id);

function node(tag, options = {}, children = []) {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(options)) {
    if (key === "className") element.className = value;
    else if (key === "text") element.textContent = value;
    else if (key === "dataset") Object.assign(element.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") {
      element.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value !== null && value !== undefined) element.setAttribute(key, value);
  }
  element.append(...children);
  return element;
}

function showNotice(message, error = false) {
  const notice = byId("notice");
  notice.textContent = message;
  notice.classList.toggle("error", error);
  notice.hidden = false;
  window.clearTimeout(showNotice.timer);
  showNotice.timer = window.setTimeout(() => { notice.hidden = true; }, 7000);
}

const SYNC_FAILURE_REASONS = {
  dns: "mail.syncFailure.dns",
  refused: "mail.syncFailure.refused",
  auth: "mail.syncFailure.auth",
  timeout: "mail.syncFailure.timeout",
  other: "mail.syncFailure.other",
};

// One readable line per failed mailbox; the provider's own wording is kept
// behind a disclosure for diagnosis.
function syncFailureItem(failure) {
  const reason = t(SYNC_FAILURE_REASONS[failure.reason] || SYNC_FAILURE_REASONS.other);
  const folders = Array.isArray(failure.folders) && failure.folders.length
    ? ` ${t("mail.syncFailure.folders", { folders: failure.folders.join(", ") })}`
    : "";
  const raw = [failure.error_class, failure.detail].filter(Boolean).join(": ");
  return node("li", { className: "sync-failure" }, [
    node("strong", { text: String(failure.account || "?") }),
    node("span", { text: ` ${reason}${folders}` }),
    ...(raw ? [node("details", {}, [
      node("summary", { text: t("mail.syncFailure.detail") }),
      node("code", { text: raw }),
    ])] : []),
  ]);
}

// A failed sync stays on screen until dismissed: the person has to act on it.
function showSyncFailures(failures) {
  const notice = byId("notice");
  window.clearTimeout(showNotice.timer);
  notice.classList.toggle("error", true);
  notice.replaceChildren(
    node("div", { className: "notice-heading" }, [
      node("span", { text: t("mail.syncFailure.title") }),
      node("button", {
        type: "button", className: "icon-button", text: "×", "aria-label": t("common.close"),
        onClick: () => { notice.hidden = true; },
      }),
    ]),
    node("ul", { className: "sync-failures" }, failures.map(syncFailureItem)),
  );
  notice.hidden = false;
}

function request(url, { method = "GET", body = null, timeoutMs = 25000 } = {}) {
  return jsonRequest(url, {
    method,
    body: body ?? undefined,
    csrf: method === "GET" ? "" : state.csrf,
    timeoutMs,
  });
}

// Execution and sync wait for the provider (MCP execute timeout 150 s); prepare
// reads the provider once; every other tool is a local read.
function mcpTimeout(tool) {
  if (tool.endsWith("_approved") || tool === "sync_mail") return 170000;
  if (tool.startsWith("prepare_") || tool.startsWith("preview_")) return 70000;
  return 25000;
}

const mcp = (tool, argumentsValue = {}) =>
  request(`/api/mcp/${encodeURIComponent(tool)}`, {
    method: "POST",
    body: { arguments: argumentsValue },
    timeoutMs: mcpTimeout(tool),
  });

function localDayStart() {
  const date = new Date();
  date.setHours(0, 0, 0, 0);
  return date.toISOString();
}

function sameCalendarDay(left, right) {
  return left.getFullYear() === right.getFullYear()
    && left.getMonth() === right.getMonth()
    && left.getDate() === right.getDate();
}

// List rows always carry a date; only today's mail may shorten it to a time.
function formatDate(value, detailed = false, now = new Date()) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return t("mail.date.unknown");
  const locale = EG.locale();
  if (detailed) {
    return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
  }
  const time = new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit" }).format(parsed);
  if (sameCalendarDay(parsed, now)) return t("mail.date.today", { time });
  const options = parsed.getFullYear() === now.getFullYear()
    ? { month: "2-digit", day: "2-digit" }
    : { year: "numeric", month: "2-digit", day: "2-digit" };
  return `${new Intl.DateTimeFormat(locale, options).format(parsed)} ${time}`;
}

function splitAddresses(value) {
  return String(value || "").split(/[;,\n]/).map((item) => item.trim()).filter(Boolean);
}

function accountByAlias(alias) {
  return state.accounts.find((item) => item.alias === alias);
}

async function loadSession() {
  const session = await request("/api/session");
  state.csrf = session.csrf;
  state.approvalUrl = session.approval_url.replace(/\/$/, "");
  state.accountAdminEnabled = Boolean(session.account_admin_enabled);
  state.apiKeysEnabled = Boolean(session.api_keys_enabled);
  state.mcp = {
    resource: session.mcp_resource || "",
    discoveryUrl: session.mcp_discovery_url || "",
    issuer: session.oauth_issuer || "",
    // OAuth is offered only when the server can verify OAuth tokens.
    oauthEnabled: session.mcp_oauth_enabled === true,
    scopes: Array.isArray(session.mcp_scopes) ? session.mcp_scopes : [],
  };
  state.subject = session.subject;
  renderIdentity();
}

async function logout() {
  await request("/api/logout", { method: "POST" });
  window.location.replace("/login");
}

function fillAccountSelect(select, includeAll = false) {
  const current = select.value;
  select.replaceChildren();
  if (includeAll) select.append(node("option", { value: "", text: t("common.allMailboxes") }));
  for (const account of state.accounts) {
    if (["composeAccount", "preferenceAccount"].includes(select.id) && account.receive_only) continue;
    select.append(node("option", { value: account.alias, text: `${account.alias} · ${account.email}` }));
  }
  if ([...select.options].some((option) => option.value === current)) select.value = current;
}

function renderAccounts() {
  const list = byId("accountList");
  list.replaceChildren();
  for (const account of state.accounts) {
    const preload = () => preloadSilently("all", account.alias);
    const button = node("button", {
      className: `account-item${state.account === account.alias ? " active" : ""}`,
      type: "button",
      onPointerenter: preload,
      onFocus: preload,
      "aria-current": state.account === account.alias ? "true" : null,
      onClick: async () => {
        state.account = account.alias;
        state.view = "all";
        markActiveView(null);
        renderAccounts();
        closeNav();
        await loadMessages();
      },
    }, [node("strong", { text: account.alias }), node("span", { text: account.email })]);
    list.append(button);
  }
  fillAccountSelect(byId("composeAccount"));
  fillAccountSelect(byId("verificationAccount"), true);
  fillAccountSelect(byId("preferenceAccount"));
}

async function loadAccounts() {
  state.accounts = await mcp("list_accounts");
  renderAccounts();
}

function viewTarget(view = state.view, account = state.account) {
  const argumentsValue = { account, limit: 100 };
  if (view === "today") argumentsValue.since = localDayStart();
  if (view === "unread") {
    argumentsValue.unread_only = true;
    argumentsValue.inbox_only = true;
    argumentsValue.actionable_only = true;
  }
  return {
    view,
    account,
    argumentsValue,
    key: JSON.stringify(argumentsValue),
  };
}

function trimMessagePreloads() {
  while (messagePreloads.size > MESSAGE_PRELOAD_MAX_ENTRIES) {
    messagePreloads.delete(messagePreloads.keys().next().value);
  }
}

function cachedMessages(target) {
  const entry = messagePreloads.get(target.key);
  if (!entry || entry.messages === null) return null;
  if (entry.expiresAt <= Date.now()) {
    messagePreloads.delete(target.key);
    return null;
  }
  messagePreloads.delete(target.key);
  messagePreloads.set(target.key, entry);
  return entry.messages;
}

function updateApproximateCount(target, messages) {
  if (target.account !== null || !["today", "unread"].includes(target.view)) return;
  const count = byId(target.view === "today" ? "todayCount" : "unreadCount");
  count.textContent = messages.length < 100 ? String(messages.length) : "100+";
}

function preloadMessages(target, { refresh = false } = {}) {
  if (!refresh) {
    const cached = cachedMessages(target);
    if (cached !== null) return Promise.resolve(cached);
    const pending = messagePreloads.get(target.key)?.promise;
    if (pending) return pending;
  }

  const entry = { promise: null, messages: null, expiresAt: 0 };
  const pending = mcp("list_recent", target.argumentsValue)
    .then((messages) => {
      if (!Array.isArray(messages)) throw new Error(t("mail.list.invalidResponse"));
      if (messagePreloads.get(target.key) === entry) {
        entry.promise = null;
        entry.messages = messages;
        entry.expiresAt = Date.now() + MESSAGE_PRELOAD_TTL_MS;
        messagePreloads.delete(target.key);
        messagePreloads.set(target.key, entry);
        updateApproximateCount(target, messages);
      }
      return messages;
    })
    .catch((error) => {
      if (messagePreloads.get(target.key) === entry) messagePreloads.delete(target.key);
      throw error;
    });
  entry.promise = pending;
  messagePreloads.set(target.key, entry);
  trimMessagePreloads();
  return pending;
}

function preloadView(view, account = null, options = {}) {
  return preloadMessages(viewTarget(view, account), options);
}

function preloadSilently(view, account = null) {
  if (!state.csrf) return;
  void preloadView(view, account).catch(() => {});
}

function clearMessagePreloads() {
  messagePreloads.clear();
}

async function loadCounts() {
  const sequence = ++countLoadSequence;
  const loadCount = async (elementId, argumentsValue) => {
    const value = await mcp("count_mail", argumentsValue);
    if (sequence !== countLoadSequence) return;
    byId(elementId).textContent = String(elementId === "unreadCount" ? (value.actionable_count ?? value.count) : value.count);
    byId(elementId).title = t("mail.count.title", {
      indexed: value.indexed_count ?? value.count,
      present: value.provider_present_count ?? value.actionable_count ?? value.count,
      actionable: value.actionable_count ?? value.count,
      historical: value.historical_copy_only_count ?? 0,
      unknown: value.unknown_outcome_count ?? 0,
    });
  };
  await Promise.all([
    loadCount("todayCount", { since: localDayStart() }),
    loadCount("unreadCount", { unread_only: true, inbox_only: true }),
  ]);
}

function setHeading(searching = false) {
  const labels = {
    today: [t("mail.heading.today.eyebrow"), t("mail.heading.today.title")],
    unread: [t("mail.heading.unread.eyebrow"), t("mail.heading.unread.title")],
    all: state.account
      ? [state.account, t("mail.heading.account.title", { account: state.account })]
      : [t("mail.heading.all.eyebrow"), t("mail.heading.all.title")],
  };
  const label = searching
    ? [t("mail.heading.search.eyebrow"), t("mail.heading.search.title", { query: byId("searchInput").value.trim() })]
    : labels[state.view];
  byId("eyebrow").textContent = label[0];
  byId("viewTitle").textContent = label[1];
}

function renderMessages() {
  const list = byId("messageList");
  list.setAttribute("aria-busy", "false");
  list.replaceChildren();
  state.listRendered = true;
  const count = state.messages.length;
  byId("resultCount").textContent = count === 100 ? t("mail.list.countCapped", { n: count }) : t("mail.list.count", { n: count });
  if (!count) {
    list.append(node("div", { className: "empty-state" }, [
      node("div", { className: "empty-flower", "aria-hidden": "true", text: "✦" }),
      node("h2", { text: t("mail.list.emptyTitle") }),
      node("p", { text: t("mail.list.emptyBody") }),
    ]));
    return;
  }
  for (const message of state.messages) {
    const unread = !message.flags.includes("\\Seen");
    const sender = message.sender_name || message.sender_email || t("mail.unknownSender");
    const active = Boolean(state.current && state.current.id === message.id);
    const button = node("button", {
      type: "button",
      className: `message-card${unread ? " unread" : ""}${active ? " active" : ""}`,
      "aria-current": active ? "true" : null,
      onClick: () => openMessage(message.id),
    }, [
      node("span", { className: "unread-dot", "aria-hidden": "true" }),
      node("div", { className: "message-card-main" }, [
        node("div", { className: "message-card-top" }, [node("strong", { text: sender }), node("time", { text: formatDate(message.date_received) })]),
        node("div", { className: "subject", text: message.subject || t("mail.noSubject") }),
        node("p", { className: "snippet", text: `${message.account} · ${message.folder}` }),
      ]),
      message.has_attachments ? node("span", { className: "badge", text: t("mail.list.attachment") }) : node("span"),
    ]);
    list.append(button);
    if (message.actionable === false) {
      const code = message.reason_code || message.location_status;
      list.append(node("a", {
        href: message.feedback_url,
        className: "row-warning",
        title: EG.reasonText(code),
        text: t("mail.list.needsCheck", { reason: reasonShort(code) }),
      }));
    }
  }
}

async function loadMessages({ refresh = false } = {}) {
  const sequence = ++messageLoadSequence;
  const query = byId("searchInput").value.trim();
  const target = query ? null : viewTarget();
  setHeading(Boolean(query));
  const cached = target && !refresh ? cachedMessages(target) : null;
  if (cached === null) {
    byId("resultCount").textContent = t("common.loading");
    byId("messageList").setAttribute("aria-busy", "true");
  }
  try {
    const messages = query
      ? await mcp("search_mail", { query, account: state.account, limit: 100 })
      : cached || await preloadMessages(target, { refresh });
    if (sequence !== messageLoadSequence) return;
    state.messages = messages;
    renderMessages();
  } catch (error) {
    if (sequence !== messageLoadSequence) return;
    byId("resultCount").textContent = t("mail.list.failed");
    byId("messageList").setAttribute("aria-busy", "false");
    showNotice(error.message, true);
  }
}

function renderAttachments() {
  const section = byId("attachmentSection");
  const list = byId("attachmentList");
  list.replaceChildren();
  section.hidden = state.currentAttachments.length === 0;
  for (const attachment of state.currentAttachments) {
    const details = node("div", {}, [
      node("strong", { text: attachment.filename }),
      node("div", { className: "muted", text: `${attachment.mimetype} · ${EG.formatBytes(attachment.size)}` }),
    ]);
    const download = node("button", {
      type: "button",
      className: "secondary",
      text: attachment.available ? t("mail.attachment.download") : t("mail.attachment.unavailable"),
      disabled: attachment.available ? null : "disabled",
      onClick: () => downloadAttachment(attachment),
    });
    list.append(node("div", { className: "attachment" }, [details, download]));
  }
}

async function openMessage(messageId) {
  try {
    const [message, attachments] = await Promise.all([
      mcp("get_message", { message_id: messageId }),
      mcp("list_attachments", { message_id: messageId }),
    ]);
    state.current = message;
    state.currentAttachments = attachments;
    byId("reader").classList.remove("empty");
    byId("readerEmpty").hidden = true;
    byId("readerContent").hidden = false;
    renderReader();
    renderAttachments();
    renderMessages();
    showReader();
  } catch (error) { showNotice(error.message, true); }
}

async function downloadAttachment(attachment) {
  if (!state.current) return;
  try {
    const value = await mcp("download_attachment", {
      message_id: state.current.id,
      attachment_id: attachment.attachment_id,
    });
    const binary = atob(value.content_base64);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    const url = URL.createObjectURL(new Blob([bytes], { type: value.mimetype }));
    const link = node("a", { href: url, download: value.filename });
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { showNotice(error.message, true); }
}

function showDialog(dialog) {
  if (!dialog.open) dialog.showModal();
}

function renderComposeAttachments() {
  const list = byId("composeAttachmentList");
  list.replaceChildren();
  for (const attachment of state.composeArchiveAttachments) {
    const checkbox = node("input", {
      type: "checkbox",
      value: attachment.attachment_id,
      checked: attachment.available ? "checked" : null,
      disabled: attachment.available ? null : "disabled",
    });
    list.append(node("label", { className: "compose-attachment" }, [
      checkbox,
      node("span", { text: t("compose.reuseAttachment", { name: attachment.filename, size: EG.formatBytes(attachment.size) }) }),
    ]));
  }
}

async function openCompose(mode = "send") {
  const current = state.current;
  if (mode !== "send" && !current) return;
  byId("composeForm").reset();
  byId("composeMode").value = mode;
  byId("composeMessageId").value = current ? current.id : "";
  byId("composeAccount").disabled = mode !== "send";
  byId("composeAccount").value = current ? current.account : (state.account || state.accounts[0]?.alias || "");
  EG.setText(byId("composeTitle"), `compose.title.${mode}`);
  byId("composeTo").value = current && mode.startsWith("reply") ? current.sender_email : "";
  byId("composeSubject").value = current
    ? `${mode === "forward" ? "Fwd:" : "Re:"} ${String(current.subject || "").replace(/^(re|fwd?):\s*/i, "")}`
    : "";
  byId("composeTo").disabled = mode.startsWith("reply");
  byId("composeSubject").disabled = mode !== "send";
  byId("bccLabel").hidden = mode !== "send";
  state.composeArchiveAttachments = mode === "send" ? [] : state.currentAttachments;
  renderComposeAttachments();
  showDialog(byId("composeDialog"));
}

const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;

async function fileBase64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 32768) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
  }
  return btoa(binary);
}

async function stagedFileReferences() {
  const files = [...byId("composeFiles").files];
  // Reject before encoding or staging anything; the base64 body would exceed the request limit.
  const oversized = files.find((file) => file.size > MAX_ATTACHMENT_BYTES);
  if (oversized) throw new Error(t("compose.tooLarge", { name: oversized.name }));
  const references = [];
  for (const file of files) {
    const staged = await mcp("stage_attachment", {
      filename: file.name,
      mimetype: file.type || "application/octet-stream",
      content_base64: await fileBase64(file),
    });
    references.push({ staged_attachment_id: staged.staged_attachment_id });
  }
  return references;
}

function archivedAttachmentReferences() {
  return [...byId("composeAttachmentList").querySelectorAll("input:checked")].map((input) => ({
    message_id: byId("composeMessageId").value,
    attachment_id: input.value,
  }));
}

async function submitCompose(event) {
  event.preventDefault();
  const mode = byId("composeMode").value;
  try {
    const attachments = [...archivedAttachmentReferences(), ...await stagedFileReferences()];
    let tool = "prepare_send";
    let argumentsValue;
    if (mode === "send") {
      argumentsValue = {
        account: byId("composeAccount").value,
        to: splitAddresses(byId("composeTo").value),
        cc: splitAddresses(byId("composeCc").value),
        bcc: splitAddresses(byId("composeBcc").value),
        subject: byId("composeSubject").value,
        body: byId("composeBody").value,
        attachments,
      };
    } else if (mode === "forward") {
      tool = "prepare_forward";
      argumentsValue = {
        message_id: byId("composeMessageId").value,
        to: splitAddresses(byId("composeTo").value),
        cc: splitAddresses(byId("composeCc").value),
        body: byId("composeBody").value,
        attachments,
      };
    } else {
      tool = "prepare_reply";
      argumentsValue = {
        message_id: byId("composeMessageId").value,
        body: byId("composeBody").value,
        cc: splitAddresses(byId("composeCc").value),
        reply_all: mode === "replyAll",
        attachments,
      };
    }
    const draft = await mcp(tool, argumentsValue);
    byId("composeDialog").close();
    openReview(draft, "send_approved", t("review.warning.send"));
  } catch (error) { showNotice(error.message, true); }
}

// When this page executes, nothing retries or runs on the server by itself,
// so those statuses get client-side wording (mail.status.client.*).
const CLIENT_STATUS_LABELS = new Set(["approved", "retryable"]);
const CLIENT_EXECUTABLE_STATUSES = new Set(["approved", "awaiting_client", "retryable"]);

function approvalStatusLabel(status, serverExecutes) {
  const value = String(status || "").toLowerCase();
  if (!serverExecutes && CLIENT_STATUS_LABELS.has(value)) return t(`mail.status.client.${value}`);
  if (value === "pending_approval") return t("mail.status.pendingApproval");
  if (value && EG.has(`status.${value}`)) return t(`status.${value}`);
  return value || t("common.unknown");
}

function openReview(draft, executeTool, warning) {
  const serverExecutes = draft.execution_owner === "server";
  state.draft = { ...draft, executeTool, serverExecutes, approvalId: draft.approval_id || null };
  const packet = draft.review_packet || {};
  byId("reviewWarning").textContent = [
    warning,
    packet.copy_preserve_source_fallback ? t("review.warning.copyFallback") : "",
    packet.uidplus_move_fallback ? t("review.warning.uidplus") : "",
  ].filter(Boolean).join(" ");
  byId("reviewPacket").textContent = JSON.stringify(draft.review_packet, null, 2);
  const execute = byId("executeApprovedButton");
  const link = byId("approvalLink");
  if (serverExecutes) {
    execute.hidden = true;
    execute.disabled = true;
    link.hidden = false;
    byId("reviewStatus").textContent = t("review.status.serverWaiting");
  } else {
    execute.hidden = false;
    execute.disabled = !state.draft.approvalId;
    link.hidden = !draft.requires_human_approval;
    byId("reviewStatus").textContent = state.draft.approvalId
      ? t("review.status.autoApproved")
      : t("review.waiting");
  }
  const approvalPath = draft.kind === "send" ? "/review/send?" : draft.kind === "trash" ? "/review?batch=trash&" : "/review?mode=single&";
  link.href = `${state.approvalUrl}${approvalPath}draft_id=${encodeURIComponent(draft.draft_id)}`;
  showDialog(byId("reviewDialog"));
}

async function prepareCurrent(tool, executeTool, extra, warning) {
  if (!state.current) return;
  try {
    const draft = await mcp(tool, {
      account: state.current.account,
      stable_message_id: state.current.id,
      source_folder: state.current.folder,
      ...extra,
    });
    openReview(draft, executeTool, warning);
  } catch (error) { showNotice(error.message, true); }
}

async function checkApproval() {
  const draft = state.draft;
  if (!draft) return;
  try {
    const review = await mcp("get_draft_status", { draft_id: draft.draft_id });
    if (state.draft !== draft) return;
    byId("reviewStatus").textContent = t("review.status.current", { status: approvalStatusLabel(review.status, draft.serverExecutes) });
    const execute = byId("executeApprovedButton");
    if (!draft.serverExecutes) {
      const executable = CLIENT_EXECUTABLE_STATUSES.has(review.status) && Boolean(review.approval);
      if (executable) {
        draft.approvalId = review.approval.approval_id;
        if (review.review_packet) draft.review_packet = review.review_packet;
      }
      execute.disabled = !executable;
    }
    if (review.status === "confirmed") {
      execute.disabled = true;
      clearMessagePreloads();
      await loadMessages({ refresh: true });
    }
  } catch (error) { showNotice(error.message, true); }
}

async function executeApproved() {
  const draft = state.draft;
  if (!draft || draft.serverExecutes || !draft.approvalId) return;
  const execute = byId("executeApprovedButton");
  // Only a fresh status check may enable it again: a lost response can still have executed.
  execute.disabled = true;
  let result;
  try {
    result = await mcp(draft.executeTool, {
      approval_id: draft.approvalId,
      draft_id: draft.draft_id,
      payload: draft.review_packet,
    });
  } catch (error) {
    showNotice(error.message, true);
    byId("reviewStatus").textContent = t("review.status.verifying");
    await checkApproval();
    return;
  }
  byId("reviewStatus").textContent = t("review.status.execution", { status: approvalStatusLabel(result.state || result.status, false) });
  const preserved = result.source_preserved || result.degraded_copy;
  if (preserved) byId("reviewStatus").textContent += t("review.status.copiedSuffix");
  showNotice(preserved
    ? t("review.done.copied")
    : result.strategy === "uidplus_expunge"
      ? t("review.done.uidplus")
      : t("review.done.executed"));
  clearMessagePreloads();
  await loadMessages({ refresh: true });
  void warmSecondaryData();
}

function preferenceProfile(alias) {
  return state.preferences?.mailboxes?.[alias] || { description: "", preferences: "" };
}

function showPreferenceProfile() {
  const profile = preferenceProfile(byId("preferenceAccount").value);
  byId("mailboxDescription").value = profile.description || "";
  byId("mailboxPreferences").value = profile.preferences || "";
}

async function openPreferences() {
  try {
    state.preferences = await mcp("get_mail_preferences");
    byId("globalNotes").value = state.preferences.global_notes;
    fillAccountSelect(byId("preferenceAccount"));
    showPreferenceProfile();
    showDialog(byId("preferencesDialog"));
  } catch (error) { showNotice(error.message, true); }
}

async function savePreferences(event) {
  event.preventDefault();
  try {
    let current = state.preferences;
    if (byId("globalNotes").value !== current.global_notes) {
      current = await mcp("edit_global_notes", {
        expected_revision: current.revision,
        notes: byId("globalNotes").value,
      });
    }
    const alias = byId("preferenceAccount").value;
    const original = current.mailboxes[alias] || { description: "", preferences: "" };
    if (byId("mailboxDescription").value !== original.description || byId("mailboxPreferences").value !== original.preferences) {
      current = await mcp("edit_mailbox_preferences", {
        account: alias,
        expected_revision: current.revision,
        description: byId("mailboxDescription").value,
        preferences: byId("mailboxPreferences").value,
      });
    }
    state.preferences = current;
    byId("preferencesDialog").close();
    showNotice(t("prefs.saved"));
  } catch (error) { showNotice(error.message, true); }
}

function renderVerificationResults(value) {
  const list = byId("verificationResults");
  list.replaceChildren();
  if (!value.matches.length) {
    list.append(node("p", { className: "muted", text: t("codes.none") }));
    return;
  }
  for (const match of value.matches) {
    for (const code of match.codes) {
      const copy = node("button", {
        type: "button", className: "secondary", text: t("common.copy"),
        onClick: () => copyText(code, t("codes.copied")),
      });
      list.append(node("div", { className: "code-card" }, [
        node("div", {}, [node("code", { text: code }), node("div", { className: "muted", text: `${match.sender_domain} · ${formatDate(match.date_received, true)} · ${match.subject}` })]),
        copy,
      ]));
    }
  }
}

async function findCodes(event) {
  event.preventDefault();
  try {
    const value = await mcp("find_verification_codes", {
      account: byId("verificationAccount").value || null,
      sender_domain: byId("verificationDomain").value.trim() || null,
      minutes: Number(byId("verificationMinutes").value),
      limit: 10,
    });
    renderVerificationResults(value);
  } catch (error) { showNotice(error.message, true); }
}

async function copyText(value, message) {
  try {
    await navigator.clipboard.writeText(value);
    showNotice(message);
  } catch (_error) {
    showNotice(t("common.clipboardDenied"), true);
  }
}

// Read per call so a language switch also changes the snippet placeholder.
const tokenPlaceholder = () => t("mcp.tokenPlaceholder");

function mcpClientGuides() {
  const resource = state.mcp.resource || "https://mail.example.test/mcp";
  const oauthScopes = ["openid", "offline_access", ...state.mcp.scopes].join(" ");
  // A key issued in this session makes every snippet paste-ready as-is.
  const TOKEN = state.mcpToken || tokenPlaceholder();
  const guides = [
    {
      id: "claude-code",
      label: "Claude Code",
      steps: [
        {
          title: t("mcp.claude.step1.title"),
          note: t("mcp.claude.step1.note"),
          language: "bash",
          code: `umask 077\nprintf '%s' '${TOKEN}' > ~/.evergarden-mcp.token`,
        },
        {
          title: t("mcp.claude.step2.title"),
          note: t("mcp.claude.step2.note"),
          language: "bash",
          code: `TOKEN="$(tr -d '\\n' < ~/.evergarden-mcp.token)"\nclaude mcp remove evergarden-mail -s user 2>/dev/null || true\nclaude mcp add --transport http evergarden-mail ${resource} \\\n  --scope user \\\n  --header "Authorization: Bearer \${TOKEN}"\nunset TOKEN`,
        },
        {
          title: t("mcp.claude.step3.title"),
          note: t("mcp.claude.step3.note"),
          language: "bash",
          code: "claude mcp list",
        },
      ],
    },
    {
      id: "codex",
      label: "Codex",
      steps: [
        {
          title: t("mcp.codex.step1.title"),
          note: t("mcp.codex.step1.note"),
          language: "bash",
          code: `umask 077\nprintf 'EVERGARDEN_MCP_TOKEN=%s\\n' '${TOKEN}' >> ~/.codex/.env\nchmod 600 ~/.codex/.env`,
        },
        {
          title: t("mcp.codex.step2.title"),
          note: t("mcp.codex.step2.note"),
          language: "bash",
          code: `codex mcp remove evergarden-mail 2>/dev/null || true\ncodex mcp add evergarden-mail \\\n  --url ${resource} \\\n  --bearer-token-env-var EVERGARDEN_MCP_TOKEN`,
        },
        {
          title: t("mcp.codex.step3.title"),
          note: t("mcp.codex.step3.note"),
          language: "toml",
          code: `[mcp_servers.evergarden-mail]\nurl = "${resource}"\nbearer_token_env_var = "EVERGARDEN_MCP_TOKEN"\nstartup_timeout_sec = 30\ntool_timeout_sec = 120\ndefault_tools_approval_mode = "writes"`,
        },
        {
          title: t("mcp.codex.step4.title"),
          note: t("mcp.codex.step4.note"),
          language: "bash",
          code: "codex mcp list",
        },
      ],
    },
    {
      id: "json",
      label: t("mcp.json.label"),
      steps: [
        {
          title: t("mcp.json.step.title"),
          note: t("mcp.json.step.note"),
          language: "json",
          code: `{\n  "mcpServers": {\n    "evergarden-mail": {\n      "type": "http",\n      "url": "${resource}",\n      "headers": {\n        "Authorization": "Bearer ${TOKEN}"\n      }\n    }\n  }\n}`,
        },
      ],
    },
    {
      id: "oauth",
      label: t("mcp.oauth.label"),
      steps: [
        {
          title: "Claude Code",
          note: t("mcp.oauth.claude.note"),
          language: "bash",
          code: `claude mcp add-json evergarden-mail \\\n  '{"type":"http","url":"${resource}","oauth":{"clientId":"claude-code-evergarden","callbackPort":32125,"scopes":"${oauthScopes}"}}' \\\n  --scope user\nclaude mcp login evergarden-mail`,
        },
        {
          title: "Codex",
          note: t("mcp.oauth.codex.note", { issuer: state.mcp.issuer || t("common.notConfigured") }),
          language: "toml",
          code: `mcp_oauth_callback_port = 32124\nmcp_oauth_credentials_store = "keyring"\n\n[mcp_servers.evergarden-mail]\nurl = "${resource}"\nauth = "oauth"\noauth_resource = "${resource}"\nscopes = [\n${["openid", "offline_access", ...state.mcp.scopes].map((scope) => `  "${scope}",`).join("\n")}\n]\n\n[mcp_servers.evergarden-mail.oauth]\nclient_id = "codex-evergarden"`,
        },
      ],
    },
  ];
  return state.mcp.oauthEnabled ? guides : guides.filter((guide) => guide.id !== "oauth");
}

const SCOPE_PRESETS = {
  readonly: ["mail:metadata", "mail:read", "mail:attachments", "mail:verification"],
  drafting: ["mail:metadata", "mail:read", "mail:attachments", "mail:verification", "mail:draft", "mail:sync", "mail:settings"],
};

function presetScopes(preset) {
  if (preset === "full") return [...state.mcp.scopes];
  return (SCOPE_PRESETS[preset] || []).filter((scope) => state.mcp.scopes.includes(scope));
}

function scopeCheckboxes() {
  return [...byId("apiKeyScopes").querySelectorAll("input[type=checkbox]")];
}

function selectedScopes() {
  return scopeCheckboxes().filter((box) => box.checked).map((box) => box.value);
}

function renderScopeChoices() {
  const container = byId("apiKeyScopes");
  if (container.childElementCount) return;
  container.replaceChildren(...state.mcp.scopes.map((scope) => node("label", { className: "mcp-scope" }, [
    node("input", { type: "checkbox", value: scope, onChange: () => { byId("apiKeyPreset").value = "custom"; } }),
    node("span", { text: scope }),
  ])));
  applyScopePreset(byId("apiKeyPreset").value);
}

function applyScopePreset(preset) {
  if (preset === "custom") return;
  const wanted = new Set(presetScopes(preset));
  for (const box of scopeCheckboxes()) box.checked = wanted.has(box.value);
}

function clearIssuedToken() {
  state.mcpToken = "";
  byId("apiKeyToken").textContent = "";
  byId("apiKeyIssued").hidden = true;
}

function renderApiKeys() {
  const list = byId("apiKeyList");
  const snapshot = state.apiKeys;
  list.replaceChildren();
  byId("apiKeyCount").textContent = snapshot ? `${snapshot.keys.length} / ${snapshot.max_keys}` : "";
  if (!snapshot) return;
  if (!snapshot.keys.length) {
    list.append(node("p", { className: "muted", text: t("mcp.noKeys") }));
    return;
  }
  for (const key of snapshot.keys) {
    const summary = key.scopes.length === state.mcp.scopes.length
      ? t("mcp.preset.full")
      : key.scopes.map((scope) => scope.replace("mail:", "")).join(" ");
    list.append(node("div", { className: `mcp-key${key.expired ? " expired" : ""}` }, [
      node("div", { className: "mcp-key-main" }, [
        node("strong", { text: key.client_id }),
        node("p", { className: "muted", text: t(key.expired ? "mcp.keyExpired" : "mcp.keyExpires", { summary, date: key.expires_at.slice(0, 10) }) }),
      ]),
      node("button", {
        type: "button", className: "danger-ghost", text: t("mcp.revoke"),
        onClick: () => revokeApiKey(key.client_id),
      }),
    ]));
  }
}

async function loadApiKeys() {
  if (!state.apiKeysEnabled) return;
  try {
    state.apiKeys = await request("/api/admin/api-keys");
  } catch (error) {
    state.apiKeys = null;
    showNotice(error.message, true);
  }
  renderApiKeys();
}

async function createApiKey(event) {
  event.preventDefault();
  const scopes = selectedScopes();
  if (!scopes.length) {
    showNotice(t("mcp.needScope"), true);
    return;
  }
  if (!state.apiKeys) {
    showNotice(t("mcp.keysLoading"), true);
    return;
  }
  try {
    const issued = await request("/api/admin/api-keys", {
      method: "POST",
      body: {
        expected_revision: state.apiKeys.revision,
        label: byId("apiKeyLabel").value,
        scopes,
        ttl_days: Number(byId("apiKeyTtl").value),
      },
    });
    state.apiKeys = { revision: issued.revision, keys: issued.keys, max_keys: issued.max_keys };
    state.mcpToken = issued.token;
    byId("apiKeyToken").textContent = issued.token;
    byId("apiKeyIssued").hidden = false;
    byId("apiKeyLabel").value = "";
    renderApiKeys();
    // Re-render so every snippet below now carries the real bearer.
    renderMcpSteps();
    showNotice(t("mcp.issued", { client: issued.client_id }));
  } catch (error) { showNotice(error.message, true); }
}

async function revokeApiKey(clientId) {
  if (!state.apiKeys) return;
  const confirmed = await EG.confirm({
    title: t("mcp.revokeConfirm.title", { client: clientId }),
    message: t("mcp.revokeConfirm.body"),
    confirmLabel: t("mcp.revoke"),
    danger: true,
  });
  if (!confirmed) return;
  try {
    state.apiKeys = await request(`/api/admin/api-keys/${encodeURIComponent(clientId)}/revoke`, {
      method: "POST",
      body: { expected_revision: state.apiKeys.revision },
    });
    renderApiKeys();
    showNotice(t("mcp.revoked", { client: clientId }));
  } catch (error) { showNotice(error.message, true); }
}

function renderMcpSteps() {
  const guides = mcpClientGuides();
  const guide = guides.find((item) => item.id === state.mcpClient) || guides[0];
  document.querySelectorAll(".mcp-tab").forEach((tab) => {
    const active = tab.dataset.client === guide.id;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-pressed", String(active));
    tab.textContent = guides.find((item) => item.id === tab.dataset.client)?.label || tab.textContent;
  });
  const container = byId("mcpSteps");
  container.replaceChildren(...guide.steps.map((step) => node("section", { className: "mcp-step" }, [
    node("div", { className: "mcp-step-top" }, [
      node("h3", { text: step.title }),
      node("button", {
        type: "button", className: "text-button", text: t("common.copy"),
        "aria-label": t("mcp.copyStep", { step: step.title }),
        onClick: () => copyText(step.code, t("mcp.copiedCommand")),
      }),
    ]),
    node("p", { className: "muted", text: step.note }),
    node("pre", { className: "mcp-code", dataset: { language: step.language } }, [node("code", { text: step.code })]),
  ])));
}

function openMcpGuide() {
  renderMcpFacts();
  const tabs = byId("mcpDialog").querySelector(".mcp-tabs");
  if (!tabs.childElementCount) {
    tabs.replaceChildren(...mcpClientGuides().map((guide) => node("button", {
      type: "button", className: "mcp-tab", text: guide.label, "aria-pressed": "false",
      dataset: { client: guide.id },
      onClick: () => { state.mcpClient = guide.id; renderMcpSteps(); },
    })));
  }
  byId("apiKeysDisabled").hidden = state.apiKeysEnabled;
  byId("apiKeyForm").hidden = !state.apiKeysEnabled;
  renderScopeChoices();
  renderApiKeys();
  renderMcpSteps();
  showDialog(byId("mcpDialog"));
  void loadApiKeys();
}

function renderManagedAccounts(snapshot) {
  const list = byId("managedAccounts");
  list.replaceChildren();
  for (const account of snapshot.accounts) {
    const action = node("button", {
      type: "button",
      className: account.enabled ? "danger-ghost" : "secondary",
      text: account.enabled ? t("accounts.disable") : t("accounts.enable"),
      onClick: async () => {
        try {
          const updated = await request(`/api/admin/accounts/${encodeURIComponent(account.alias)}/state`, {
            method: "POST",
            body: { expected_revision: snapshot.revision, enabled: !account.enabled },
          });
          renderManagedAccounts(updated);
          showNotice(t("accounts.updated"));
        } catch (error) { showNotice(error.message, true); }
      },
    });
    const oauth = node("a", {
      className: "secondary button-link",
      href: `${state.approvalUrl}/oauth?account=${encodeURIComponent(account.alias)}`,
      target: "_blank", rel: "noopener", text: account.oauth_provider === "google" ? t("accounts.connectGoogle") : t("accounts.connectOauth"),
    });
    list.append(node("div", { className: "managed-account" }, [
      node("div", {}, [node("strong", { text: `${account.alias} · ${account.address}` }), node("p", { text: t("accounts.summary", {
        auth: account.auth_kind,
        from: account.default_from,
        state: account.enabled ? t("accounts.enabled") : t("accounts.disabledState"),
        trash: account.trash_folder,
      }) })]),
      node("div", {}, [...(account.auth_kind === "oauth2" ? [oauth] : []), action]),
    ]));
  }
  byId("accountDialog").dataset.revision = snapshot.revision;
}

async function openAccountAdmin() {
  byId("adminDisabled").hidden = state.accountAdminEnabled;
  byId("managedAccounts").replaceChildren();
  showDialog(byId("accountDialog"));
  if (!state.accountAdminEnabled) return;
  try { renderManagedAccounts(await request("/api/admin/accounts")); }
  catch (error) { byId("adminDisabled").hidden = false; byId("adminDisabled").textContent = error.message; }
}

function commaValues(form, name) {
  return String(new FormData(form).get(name) || "").split(",").map((item) => item.trim()).filter(Boolean);
}

// Credential records follow "<kind>:<alias>": password:personal for an app
// password, google:<alias> for Gmail OAuth (the backend picks Google by the
// imap.gmail.com host) and microsoft:<alias> for every other OAuth mailbox.
function credentialRecordKind(authKind, imapHost) {
  if (authKind !== "oauth2") return "password";
  return String(imapHost || "").trim().toLowerCase() === "imap.gmail.com" ? "google" : "microsoft";
}

function suggestedCredentialRecord(alias, authKind, imapHost) {
  const token = String(alias || "").trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^[-_]+/, "");
  return token ? `${credentialRecordKind(authKind, imapHost)}:${token}` : "";
}

// Fill the credential record from alias, authentication and IMAP host until
// the person types their own value; clearing the field or typing the
// suggestion hands it back to the suggestion.
function refreshCredentialSuggestion(form, edited = false) {
  const { alias, auth_kind: authKind, imap_host: imapHost, credential_record: field } = form.elements;
  const suggestion = suggestedCredentialRecord(alias.value, authKind.value, imapHost.value);
  field.placeholder = `${credentialRecordKind(authKind.value, imapHost.value)}:<alias>`;
  if (edited) {
    field.dataset.custom = field.value && field.value !== suggestion ? "1" : "";
    return;
  }
  if (field.dataset.custom !== "1") field.value = suggestion;
}

function bindCredentialSuggestion(form) {
  for (const name of ["alias", "auth_kind", "imap_host"]) {
    form.elements[name].addEventListener("input", () => refreshCredentialSuggestion(form));
    form.elements[name].addEventListener("change", () => refreshCredentialSuggestion(form));
  }
  form.elements.credential_record.addEventListener("input", () => refreshCredentialSuggestion(form, true));
  form.addEventListener("reset", () => window.setTimeout(() => {
    form.elements.credential_record.dataset.custom = "";
    refreshCredentialSuggestion(form);
  }, 0));
  refreshCredentialSuggestion(form);
}

async function addAccount(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const authKind = String(data.get("auth_kind"));
  const address = String(data.get("address"));
  const configuredSenders = commaValues(form, "send_from_addresses");
  const account = {
    alias: String(data.get("alias")), address,
    send_from_addresses: configuredSenders.length ? configuredSenders : [address],
    imap_host: String(data.get("imap_host")), imap_port: Number(data.get("imap_port")),
    smtp_host: String(data.get("smtp_host")), smtp_port: Number(data.get("smtp_port")),
    smtp_mode: String(data.get("smtp_mode")),
    auth_kind: authKind, credential_record: String(data.get("credential_record")),
    folders: commaValues(form, "folders"), archive_folder: String(data.get("archive_folder")),
    sent_folder: String(data.get("sent_folder")), trash_folder: String(data.get("trash_folder")),
    safe_move_folders: commaValues(form, "safe_move_folders"),
    copy_preserve_source_fallback: data.get("copy_preserve_source_fallback") === "on", enabled: true,
  };
  try {
    const snapshot = await request("/api/admin/accounts", {
      method: "POST",
      body: { expected_revision: byId("accountDialog").dataset.revision, account },
    });
    form.reset();
    renderManagedAccounts(snapshot);
    showNotice(t("accounts.added"));
  } catch (error) { showNotice(error.message, true); }
}

async function synchronize() {
  byId("syncButton").disabled = true;
  EG.setText(byId("syncState"), "mail.sync.running");
  try {
    const result = await mcp("sync_mail", { account: state.account, per_folder_limit: 500 });
    EG.setText(byId("syncState"), "mail.sync.done", { n: result.length });
    clearMessagePreloads();
    await loadMessages({ refresh: true });
    void warmSecondaryData();
  } catch (error) {
    EG.setText(byId("syncState"), "mail.sync.failed");
    const failures = error?.reasonCode === "MAIL_SYNC_INCOMPLETE" ? error.payload?.sync_failures : null;
    if (Array.isArray(failures) && failures.length) showSyncFailures(failures);
    else showNotice(error.message, true);
  } finally { byId("syncButton").disabled = false; }
}

// ---- Navigation (sidebar drawer below the mobile breakpoint) ----

const MOBILE_QUERY = "(max-width: 860px)";

function isMobile() {
  return typeof window.matchMedia === "function" && window.matchMedia(MOBILE_QUERY).matches;
}

function markActiveView(view) {
  document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
    const active = item.dataset.view === view;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
}

function openNav() {
  byId("shell").classList.add("nav-open");
  byId("navBackdrop").hidden = false;
  byId("menuButton").setAttribute("aria-expanded", "true");
  byId("navClose").focus();
}

function closeNav() {
  const shell = byId("shell");
  if (!shell?.classList?.contains?.("nav-open")) return;
  shell.classList.remove("nav-open");
  byId("navBackdrop").hidden = true;
  byId("menuButton").setAttribute("aria-expanded", "false");
  byId("menuButton").focus();
}

// Phones show either the list or the open message; the back button returns.
function showReader() {
  byId("shell")?.classList?.add?.("reading");
  if (isMobile()) {
    window.scrollTo?.(0, 0);
    byId("readerBack").focus();
  }
}

function showList() {
  byId("shell").classList.remove("reading");
  byId("messageList").querySelector(".message-card.active")?.focus();
}

// ---- Rendering that depends on the active language ----

function renderIdentity() {
  if (state.subject) byId("identity").textContent = t("mail.identity.admin", { subject: state.subject });
}

function reasonShort(code) {
  return EG.has(`reasonShort.${code}`) ? t(`reasonShort.${code}`) : (code || t("common.unknown"));
}

function renderReader() {
  const message = state.current;
  if (!message) return;
  byId("messageAccount").textContent = `${message.account} · ${message.folder}`;
  byId("messageDate").textContent = formatDate(message.date_received, true);
  byId("messageSubject").textContent = message.subject || t("mail.noSubject");
  byId("messageSender").textContent = message.sender_name
    ? `${message.sender_name} <${message.sender_email}>`
    : message.sender_email;
  byId("messageRecipients").textContent = t("mail.reader.recipients", { to: message.recipients_to || "—" })
    + (message.recipients_cc ? t("mail.reader.cc", { cc: message.recipients_cc }) : "");
  byId("messageBody").textContent = message.body_text || t("mail.reader.noPlainText");
  const receiveOnly = state.accounts.some(account => account.alias === message.account && account.receive_only);
  for (const id of ["replyButton", "replyAllButton", "forwardButton", "archiveButton", "moveButton", "markButton", "trashButton"]) {
    byId(id).disabled = receiveOnly;
    byId(id).title = receiveOnly ? t("mail.reader.receiveOnly") : "";
  }
}

function renderMcpFacts() {
  const missing = t("common.notConfigured");
  byId("mcpResource").textContent = state.mcp.resource || missing;
  byId("mcpIssuerFact").hidden = !state.mcp.oauthEnabled;
  byId("mcpIssuer").textContent = state.mcp.issuer || missing;
  byId("mcpScopes").textContent = state.mcp.scopes.join(" ") || missing;
  byId("mcpDiscovery").textContent = state.mcp.discoveryUrl
    ? `curl -fsS ${state.mcp.discoveryUrl}`
    : missing;
}

function rerender() {
  renderIdentity();
  setHeading(Boolean(byId("searchInput").value.trim()));
  renderAccounts();
  if (state.listRendered) renderMessages();
  renderReader();
  renderAttachments();
  renderComposeAttachments();
  if (byId("mcpDialog").open) {
    renderMcpFacts();
    renderApiKeys();
    renderMcpSteps();
  }
}

// ---- Move and mark pick from fixed choices instead of free text ----

function openMove() {
  const account = accountByAlias(state.current?.account);
  const folders = account?.safe_move_folders || [];
  const select = byId("moveDestination");
  select.replaceChildren(...folders.map((folder) => node("option", { value: folder, text: folder })));
  if (folders.includes(account?.archive_folder)) select.value = account.archive_folder;
  select.disabled = !folders.length;
  byId("moveSubmit").disabled = !folders.length;
  byId("moveEmpty").hidden = Boolean(folders.length);
  showDialog(byId("moveDialog"));
}

function submitMove(event) {
  event.preventDefault();
  const destination = byId("moveDestination").value;
  byId("moveDialog").close();
  if (destination) prepareCurrent("preview_move", "move_approved", { destination }, t("review.warning.move"));
}

function openMark() {
  // The likely choice is highlighted and focused; all four stay available.
  const preferred = state.current?.flags?.includes("\\Seen") ? "unseen" : "seen";
  for (const button of byId("markDialog").querySelectorAll("[data-mark]")) {
    button.className = button.dataset.mark === preferred ? "primary" : "secondary";
  }
  showDialog(byId("markDialog"));
  byId("markDialog").querySelector(`[data-mark="${preferred}"]`)?.focus();
}

async function confirmTrash() {
  const confirmed = await EG.confirm({
    title: t("trash.confirm.title"),
    message: t("trash.confirm.body"),
    confirmLabel: t("trash.confirm.accept"),
    danger: true,
  });
  if (confirmed) prepareCurrent("preview_trash", "trash_approved", {}, t("review.warning.trash"));
}

function bindEvents() {
  document.querySelectorAll(".close-dialog").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
  document.querySelectorAll(".nav-item[data-view]").forEach((button) => {
    const preload = () => preloadSilently(button.dataset.view);
    button.addEventListener("pointerenter", preload);
    button.addEventListener("focus", preload);
    button.addEventListener("click", async () => {
      state.view = button.dataset.view;
      state.account = null;
      markActiveView(state.view);
      renderAccounts();
      closeNav();
      await loadMessages();
    });
  });
  byId("menuButton").addEventListener("click", openNav);
  byId("navClose").addEventListener("click", closeNav);
  byId("navBackdrop").addEventListener("click", closeNav);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && byId("shell").classList.contains("nav-open")) closeNav();
  });
  byId("readerBack").addEventListener("click", showList);
  byId("bodyFontButton").addEventListener("click", () => {
    const mono = byId("messageBody").classList.toggle("monospace");
    byId("bodyFontButton").setAttribute("aria-pressed", String(mono));
  });
  byId("searchForm").addEventListener("submit", (event) => { event.preventDefault(); loadMessages(); });
  byId("searchInput").addEventListener("search", loadMessages);
  byId("syncButton").addEventListener("click", synchronize);
  byId("composeButton").addEventListener("click", () => { closeNav(); openCompose("send"); });
  byId("composeFab").addEventListener("click", () => openCompose("send"));
  byId("composeForm").addEventListener("submit", submitCompose);
  byId("replyButton").addEventListener("click", () => openCompose("reply"));
  byId("replyAllButton").addEventListener("click", () => openCompose("replyAll"));
  byId("forwardButton").addEventListener("click", () => openCompose("forward"));
  byId("archiveButton").addEventListener("click", () => prepareCurrent("preview_archive", "archive_approved", {}, t("review.warning.archive")));
  byId("moveButton").addEventListener("click", openMove);
  byId("moveForm").addEventListener("submit", submitMove);
  byId("markButton").addEventListener("click", openMark);
  for (const button of byId("markDialog").querySelectorAll("[data-mark]")) {
    button.addEventListener("click", () => {
      byId("markDialog").close();
      prepareCurrent("preview_mark", "mark_approved", { action: button.dataset.mark }, t("review.warning.mark"));
    });
  }
  byId("trashButton").addEventListener("click", confirmTrash);
  byId("checkApprovalButton").addEventListener("click", checkApproval);
  byId("executeApprovedButton").addEventListener("click", executeApproved);
  byId("preferencesButton").addEventListener("click", () => { closeNav(); openPreferences(); });
  byId("preferenceAccount").addEventListener("change", showPreferenceProfile);
  byId("preferencesForm").addEventListener("submit", savePreferences);
  byId("verificationButton").addEventListener("click", () => { closeNav(); showDialog(byId("verificationDialog")); });
  byId("mcpGuideButton").addEventListener("click", () => { closeNav(); openMcpGuide(); });
  byId("apiKeyForm").addEventListener("submit", createApiKey);
  byId("apiKeyPreset").addEventListener("change", (event) => applyScopePreset(event.target.value));
  byId("copyApiKeyButton").addEventListener("click", () => copyText(state.mcpToken, t("mcp.copiedKey")));
  // Losing the plaintext on close is the point: it must not survive the dialog.
  byId("mcpDialog").addEventListener("close", () => { clearIssuedToken(); renderMcpSteps(); });
  document.querySelectorAll("[data-copy-target]").forEach((button) => button.addEventListener(
    "click",
    () => copyText(byId(button.dataset.copyTarget).textContent, t("common.copied")),
  ));
  byId("verificationForm").addEventListener("submit", findCodes);
  byId("accountAdminButton").addEventListener("click", () => { closeNav(); openAccountAdmin(); });
  byId("accountForm").addEventListener("submit", addAccount);
  bindCredentialSuggestion(byId("accountForm"));
  byId("logoutButton").addEventListener("click", () => logout().catch((error) => showNotice(error.message, true)));
  EG.onLocaleChange(rerender);
}

async function warmSecondaryData() {
  try {
    await preloadView("unread");
  } catch (_error) {
    // Navigation retries on demand.
  }
  try { await loadCounts(); } catch (error) { showNotice(error.message, true); }
}

function scheduleSecondaryData() {
  const run = () => { void warmSecondaryData(); };
  if (typeof window.requestIdleCallback === "function") {
    window.requestIdleCallback(run, { timeout: 1500 });
  } else {
    window.setTimeout(run, 100);
  }
}

async function start() {
  bindEvents();
  try {
    await loadSession();
    const initialMessages = loadMessages();
    const accounts = loadAccounts();
    await Promise.all([initialMessages, accounts]);
    scheduleSecondaryData();
  } catch (error) {
    showNotice(error.message, true);
    if (!state.csrf) byId("identity").textContent = t("mail.identity.unavailable");
  }
}

document.addEventListener("DOMContentLoaded", start);
