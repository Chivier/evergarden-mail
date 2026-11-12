"use strict";

const byId = (id) => document.getElementById(id);
let csrf = "";
let reviewer = "";
let listMode = false;
let activeTab = "pending";

let draft = null;
let singleBusy = false;
let draftTimer = null;
let draftLoading = false;
let draftPolling = false;

let batchDrafts = [];
let batchOffset = 0;
let batchBusy = false;
let batchLoading = false;
let batchHasMore = false;
let pendingTotal = null;
let pageSize = 50;
const batchSelection = new Set();
const batchItemsById = new Map();
let selectingAll = false;

let executionStatus = "all";
let executionOffset = 0;
let executionLoading = false;
let executionQueued = false;
let executionTimer = null;
let executionRows = [];
let executionHasMore = false;
let executionCounts = null;
let executionButtons = [];
let revoking = false;

let dispatchInfo = null;
let dispatchTimer = null;
let drawerDraftId = null;
let drawerToken = 0;
let drawerDraft = null;
let drawerBusy = false;
let drawerReturnFocus = null;

const POST_TIMEOUT_MS = 45000;
const POLL_MS = 5000;
const TOAST_MS = 6000;
const MAX_TOASTS = 5;
const EXECUTION_PAGE_SIZE = 50;
const DRAFT_ID = /^[0-9a-f-]{36}$/;

// Every label is looked up when rendered, so a language switch takes effect on
// the next render. Keys: status.*, phase.*, statusNote.*, error.*, kind.*, source.*.
const PHASE_TONES = { pending: "warn", running: "info", confirmed: "ok", failed: "bad" };
const EXECUTION_FILTERS = ["all", "pending", "running", "confirmed", "failed"];
// The server may still change these; every other status is final for this page.
const ACTIVE_STATUSES = new Set(["approved", "blocked", "retryable", "attempting", "unknown"]);
const APPROVED_RESULTS = new Set(["approved", "already_approved"]);

const labelOr = (prefix, value, fallback = value) => (value && EG.has(`${prefix}.${value}`) ? t(`${prefix}.${value}`) : fallback);
const statusLabel = (status) => labelOr("status", status, status || "—");
const errorLabel = (name) => labelOr("error", name);
const kindLabel = (kind, fallback = kind) => labelOr("kind", kind, fallback);
const sourceLabel = (source) => labelOr("source", source, "—");
const phasePill = (phase) => (PHASE_TONES[phase] ? [t(`phase.${phase}`), PHASE_TONES[phase]] : null);
const clip = (text, size = 40) => (text.length > size ? `${text.slice(0, size)}…` : text);
// Already ends in a full stop, "!" or "?" (ASCII or full-width).
const sentence = (text) => (/[\u3002\uff01\uff1f.!?]$/.test(text) ? text : `${text}${t("common.sentenceEnd")}`);
const post = (url, body) => jsonRequest(url, { method: "POST", body, csrf, timeoutMs: POST_TIMEOUT_MS });
const pad = (value) => String(value).padStart(2, "0");

// Plain explanation of the fine-grained status, shown under the phase.
function statusNote(item) {
  if (item.status === "failed") return item.error_class ? errorLabel(item.error_class) : t("status.failed");
  if (item.status === "confirmed") return "";
  return labelOr("statusNote", item.status, statusLabel(item.status));
}

function parseTime(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function localTime(value) {
  const date = parseTime(value);
  return date ? date.toLocaleString(EG.locale()) : "—";
}

// "14:05" today, "10/12 14:05" this year, "2025/10/12" otherwise.
function shortTime(value) {
  const date = parseTime(value);
  if (!date) return "";
  const now = new Date();
  const clock = `${pad(date.getHours())}:${pad(date.getMinutes())}`;
  if (date.toDateString() === now.toDateString()) return clock;
  if (date.getFullYear() === now.getFullYear()) return `${date.getMonth() + 1}/${date.getDate()} ${clock}`;
  return `${date.getFullYear()}/${date.getMonth() + 1}/${date.getDate()}`;
}

function relativeTime(value) {
  const date = parseTime(value);
  if (!date) return { text: "—", ms: Number.NaN };
  const ms = date.getTime() - Date.now();
  const span = EG.formatSpan(ms);
  return { text: t(ms >= 0 ? "time.left" : "time.past", { span }), ms };
}

// "Expires in 5 h" / "Expired 4 h ago": English needs a different sentence
// for each side of the limit, so each gets its own catalogue key.
function timeLimitText(value, leftKey, pastKey) {
  const date = parseTime(value);
  if (!date) return t(leftKey, { span: "—" });
  const ms = date.getTime() - Date.now();
  return t(ms >= 0 ? leftKey : pastKey, { span: EG.formatSpan(ms) });
}

function singleHref(draftId, kind) {
  const base = kind === "send" ? "/review/send?" : "/review?mode=single&";
  return `${base}draft_id=${encodeURIComponent(draftId)}`;
}

// ---- Feedback ----

// `action` adds one button ({ label, run }) that runs and then closes the toast.
function toast(text, tone = "info", { sticky = tone === "error" || tone === "warn", action = null } = {}) {
  const stack = byId("toasts");
  const item = document.createElement("div");
  item.className = `toast toast-${tone}`;
  const message = document.createElement("p");
  message.className = "toast-text";
  message.textContent = text;
  const close = document.createElement("button");
  close.type = "button";
  close.className = "toast-close";
  close.setAttribute("aria-label", t("approvals.toast.close"));
  close.textContent = "×";
  close.addEventListener("click", () => item.remove());
  item.append(message, close);
  if (action) {
    item.append(textButton(action.label, "toast-action link-button", () => {
      item.remove();
      action.run();
    }));
  }
  stack.append(item);
  // Errors and warnings stay until the reviewer closes them; everything else fades out.
  if (!sticky) setTimeout(() => item.remove(), TOAST_MS);
  while (stack.children.length > MAX_TOASTS) stack.children[0].remove();
  return item;
}

function showInline(id, text) {
  byId(id).textContent = text;
  byId(id).hidden = !text;
}

// Failed items are named by subject when this page has seen it.
function itemLabel(draftId) {
  const row = executionRows.find((item) => item.draft_id === draftId)
    || batchDrafts.find((item) => item.draft_id === draftId)
    || (draft?.draft_id === draftId ? draft : null);
  const subject = (row?.summary || row?.review_packet)?.subject;
  if (!subject) return draftId;
  return t("approvals.quotedSubject", { subject: clip(subject) });
}

function failureDetails(failed) {
  const details = failed.slice(0, 3).map((item) => `\n${itemLabel(item.draft_id)}: ${item.detail ? EG.serverMessage(item.detail) : t("approvals.notCompleted")}`).join("");
  return failed.length > 3 ? `${details}\n${t("approvals.moreFailed", { n: failed.length - 3 })}` : details;
}

// `verb` is "approved" or "revoked" (approvals.outcome.<verb>[Failed]).
function outcomeText(verb, done, failed) {
  if (!failed.length) return t(`approvals.outcome.${verb}`, { n: done });
  return t(`approvals.outcome.${verb}Failed`, { n: done, failed: failed.length, details: failureDetails(failed) });
}

// ---- Dispatcher gating ----

// Mirrors the server: while the dispatcher is enabled, approvals need a fresh
// heartbeat and a dispatcher that runs this kind.
function blockedReason(kind) {
  if (!dispatchInfo?.enabled) return "";
  if (!dispatchInfo.ready) return t("approvals.blocked.notRunning");
  if (kind && Array.isArray(dispatchInfo.kinds) && !dispatchInfo.kinds.includes(kind)) {
    return t("approvals.blocked.kind");
  }
  return "";
}

// Human approvals waiting for the server dispatcher. They never expire.
function queueText(queue) {
  if (!queue || !Number.isInteger(queue.ready)) return "";
  return t("approvals.queue", { n: queue.ready });
}

// Minutes until the ready queue drains at the recent completion rate; null
// while the queue is empty or nothing finished recently.
function etaMinutes(info) {
  const queued = info?.queue?.ready;
  const finished = info?.activity?.finished_recent;
  const minutes = info?.activity?.window_minutes || 10;
  if (!Number.isInteger(queued) || queued <= 0 || !(finished > 0)) return null;
  return Math.ceil(queued / (finished / minutes));
}

function durationText(minutes) {
  return minutes >= 120
    ? t("time.span.hours", { n: Number((minutes / 60).toFixed(1)) })
    : t("time.span.minutes", { n: minutes });
}

// One line describing what the dispatcher is doing right now.
function activityText(info) {
  if (!info?.enabled) return "";
  if (!info.ready) return t("approvals.activity.down");
  const activity = info.activity || {};
  const queued = Number.isInteger(info.queue?.ready) ? info.queue.ready : null;
  const minutes = activity.window_minutes || 10;
  const current = activity.current;
  const parts = [];
  if (current) {
    const where = current.account ? t("approvals.activity.where", { account: current.account }) : "";
    parts.push(t("approvals.activity.current", {
      kind: kindLabel(current.kind, current.kind || t("approvals.activity.operation")),
      subject: clip(current.subject || current.draft_id || ""),
      where,
    }));
  } else if (queued === 0) {
    parts.push(t("approvals.activity.idle"));
  } else {
    parts.push(t("approvals.activity.running"));
  }
  if (queued) parts.push(t("approvals.activity.queued", { n: queued }));
  if (activity.finished_recent > 0) parts.push(t("approvals.activity.finished", { minutes, n: activity.finished_recent }));
  const eta = etaMinutes(info);
  if (eta !== null) parts.push(t("approvals.activity.eta", { duration: durationText(eta) }));
  if (activity.blocked > 0) parts.push(t("approvals.activity.blocked", { n: activity.blocked }));
  return parts.join(" · ");
}

function renderActivity(info) {
  const bar = byId("activityBar");
  const text = listMode ? activityText(info) : "";
  bar.textContent = text;
  bar.hidden = !text;
  const tone = !info?.ready ? " activity-bad" : info.activity?.current ? " activity-busy" : "";
  bar.className = `activity-bar${tone}`;
}

function applyDispatch(info) {
  if (!info) return;
  dispatchInfo = info;
  const pill = byId("dispatchPill");
  const scanned = info.last_scan_at ? t("approvals.dispatch.lastScan", { time: localTime(info.last_scan_at) }) : t("approvals.dispatch.noScan");
  const queue = queueText(info.queue);
  const join = (...parts) => parts.filter(Boolean).join(t("common.clauseSeparator"));
  if (!info.enabled) {
    pill.textContent = t("approvals.dispatch.client");
    pill.className = "pill pill-muted dispatch-pill";
    pill.title = t("approvals.dispatch.clientTitle");
  } else if (info.ready) {
    pill.textContent = t("approvals.dispatch.running");
    pill.className = "pill pill-ok dispatch-pill";
    pill.title = join(scanned, queue);
  } else {
    pill.textContent = t("approvals.dispatch.down");
    pill.className = "pill pill-bad dispatch-pill";
    pill.title = join(scanned, t("approvals.dispatch.notAccepting"), queue);
  }
  byId("queueInfo").textContent = queue;
  byId("queueInfo").title = queue ? t("approvals.queueTitle") : "";
  byId("queueInfo").className = "queue-info";
  byId("queueInfo").hidden = !info.enabled || !queue;
  renderActivity(info);
  updateSingle();
  updateBatch();
  updateDrawerApprove();
  updateRevokeControls();
}

async function readQueue() {
  applyDispatch((await jsonRequest("/drafts?view=execution&status=all&offset=0&limit=1")).approval_dispatch);
}

// While the pending tab is open the activity line follows the dispatcher.
function scheduleDispatch() {
  clearTimeout(dispatchTimer);
  dispatchTimer = listMode && activeTab === "pending" && !document.hidden
    ? setTimeout(pollDispatch, POLL_MS) : null;
}

async function pollDispatch() {
  clearTimeout(dispatchTimer);
  dispatchTimer = null;
  try {
    await readQueue();
  } catch (_error) {
    // The line keeps the last known state; the next poll retries.
  } finally {
    scheduleDispatch();
  }
}

// Revoking is the only way to stop a durable approval; the dispatcher may
// still claim an item in the seconds before the request lands.
async function revoke(items) {
  if (!items.length || revoking) return null;
  const confirmed = await EG.confirm({
    title: t("approvals.revokeConfirm.title", { n: items.length }),
    message: t("approvals.revokeConfirm.body"),
    confirmLabel: t("approvals.revoke"),
    danger: true,
  });
  if (!confirmed) return null;
  revoking = true;
  updateRevokeControls();
  try {
    const value = await post("/approvals/revoke", {
      items: items.map(({ draft_id, payload_hash }) => ({ draft_id, payload_hash })),
    });
    const results = Array.isArray(value.results) ? value.results : [];
    const failed = results.filter((item) => item.status !== "revoked");
    toast(outcomeText("revoked", results.length - failed.length, failed), failed.length ? "error" : "success");
    return results;
  } catch (error) {
    toast(t("approvals.revokeFailed", { message: sentence(error.message) }), "error");
    return null;
  } finally {
    revoking = false;
    updateRevokeControls();
  }
}

// ---- Shared table helpers ----

function cell(row, text, className = "", label = "") {
  const td = document.createElement("td");
  td.className = className;
  if (label) td.setAttribute("data-label", label);
  if (text !== undefined) td.textContent = text;
  row.append(td);
  return td;
}

function mailDate(summary) {
  return shortTime(summary.date_received || summary.date);
}

function mailCell(row, summary, fallback) {
  const td = cell(row, undefined, "mail-cell", t("approvals.col.mail"));
  const subject = document.createElement("strong");
  subject.className = "subject";
  subject.textContent = summary.subject || summary.provider_message_id || summary.stable_message_id || fallback;
  subject.title = subject.textContent;
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = [summary.sender || summary.from || "—", mailDate(summary)].filter(Boolean).join(" · ");
  meta.title = meta.textContent;
  td.append(subject, meta);
  return td;
}

function textButton(label, className, onClick) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", onClick);
  return button;
}

function markOpenRows() {
  for (const id of ["batchItems", "executionItems"]) {
    for (const row of byId(id).children) row.classList.toggle("is-open", row.draftId === drawerDraftId);
  }
}

// ---- Tabs ----

function tabFromHash() {
  return window.location.hash === "#execution" ? "execution" : "pending";
}

function showTab(name, { remember = true, refresh = true } = {}) {
  activeTab = name === "execution" ? "execution" : "pending";
  const execution = activeTab === "execution";
  byId("tabPending").setAttribute("aria-selected", String(!execution));
  byId("tabExecution").setAttribute("aria-selected", String(execution));
  byId("tabPending").classList.toggle("active", !execution);
  byId("tabExecution").classList.toggle("active", execution);
  // Roving tabindex: Tab reaches the active tab, arrow keys move between tabs.
  byId("tabPending").tabIndex = execution ? -1 : 0;
  byId("tabExecution").tabIndex = execution ? 0 : -1;
  byId("pendingPanel").hidden = execution;
  byId("executionPanel").hidden = !execution;
  if (remember && window.location.hash !== `#${activeTab}`) {
    window.history?.replaceState?.(null, "", `#${activeTab}`);
  }
  if (!execution) {
    clearTimeout(executionTimer);
    executionTimer = null;
    scheduleDispatch();
  } else {
    clearTimeout(dispatchTimer);
    dispatchTimer = null;
    if (refresh) void refreshExecution();
  }
}

function updateTabCounts() {
  byId("pendingCount").textContent = t("approvals.tabs.count", { n: pendingTotal ?? "—" });
  byId("executionCount").textContent = t("approvals.tabs.count", { n: executionCounts?.all ?? "—" });
}

byId("tabPending").addEventListener("click", () => showTab("pending"));
byId("tabExecution").addEventListener("click", () => showTab("execution"));
for (const id of ["tabPending", "tabExecution"]) {
  byId(id).addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next = activeTab === "pending" ? "execution" : "pending";
    const target = event.key === "Home" ? "pending" : event.key === "End" ? "execution" : next;
    showTab(target);
    byId(target === "pending" ? "tabPending" : "tabExecution").focus();
  });
}

// ---- Archived mail (full text) ----


// The last preview shown in each slot, so a language switch can rebuild it.
const filledMail = new Map();

function fillMail(ids, packet, result) {
  filledMail.set(ids, { packet, result });
  const envelope = byId(ids.envelope);
  const notice = byId(ids.notice);
  envelope.replaceChildren();
  notice.hidden = true;
  notice.className = "mail-notice";
  if (!result?.available && typeof packet.body === "string") {
    // Send drafts carry their own full text in the packet.
    if (ids.subject) byId(ids.subject).textContent = packet.subject || t("mail.noSubject");
    metaEntry(envelope, t("envelope.from"), packet.from);
    for (const key of ["to", "cc", "bcc"]) {
      metaEntry(envelope, t(`envelope.${key}`), Array.isArray(packet[key]) ? packet[key].join(", ") : packet[key]);
    }
    byId(ids.body).textContent = packet.body || t("approvals.mail.emptyBody");
    return;
  }
  if (!result?.available) {
    if (ids.subject) byId(ids.subject).textContent = packet.subject || t("approvals.mail.fullText");
    byId(ids.body).textContent = "";
    notice.textContent = labelOr("approvals.mail.unavailable", result?.reason, t("approvals.mail.unreadable"));
    notice.hidden = false;
    return;
  }
  const mail = result.message;
  if (ids.subject) byId(ids.subject).textContent = mail.subject || t("mail.noSubject");
  const sender = mail.sender_name && mail.sender_email
    ? `${mail.sender_name} <${mail.sender_email}>` : mail.sender_name || mail.sender_email;
  metaEntry(envelope, t("envelope.from"), sender);
  metaEntry(envelope, t("envelope.to"), mail.recipients_to);
  metaEntry(envelope, t("envelope.cc"), mail.recipients_cc);
  metaEntry(envelope, t("envelope.time"), mail.date_received ? localTime(mail.date_received) : "");
  metaEntry(envelope, t("envelope.location"), [mail.account, mail.folder].filter(Boolean).join(" · "));
  metaEntry(envelope, t("envelope.attachments"), mail.has_attachments ? t("envelope.hasAttachments") : "");
  const notes = [];
  if (mail.hash_matches === false) notes.push(t("approvals.mail.hashMismatch"));
  if (!mail.body_fetched && !mail.body_text) notes.push(t("approvals.mail.notFetched"));
  if (mail.body_truncated) notes.push(t("approvals.mail.truncated"));
  if (notes.length) {
    notice.textContent = notes.join(" ");
    notice.hidden = false;
  }
  byId(ids.body).textContent = mail.body_text || (mail.body_fetched ? t("approvals.mail.emptyBody") : "");
}

async function loadMail(draftId, ids, packet, isCurrent) {
  filledMail.delete(ids);
  let result;
  try {
    result = await jsonRequest(`/drafts/${encodeURIComponent(draftId)}/message`);
  } catch (_error) {
    result = { available: false, reason: "archive_unavailable" };
  }
  if (isCurrent()) fillMail(ids, packet, result);
}

const DRAWER_MAIL = { envelope: "drawerMailEnvelope", notice: "drawerMailNotice", body: "drawerMailBody" };
const SINGLE_MAIL = { subject: "mailSubject", envelope: "mailEnvelope", notice: "mailNotice", body: "mailBody" };

// ---- Drawer ----

function metaEntry(list, term, value) {
  if (value === undefined || value === null || value === "") return;
  const dt = document.createElement("dt");
  dt.textContent = term;
  const dd = document.createElement("dd");
  dd.textContent = String(value);
  list.append(dt, dd);
}

function renderDrawer(value) {
  const packet = value.review_packet || {};
  byId("drawerTitle").textContent = packet.subject || kindLabel(value.kind, "") || t("approvals.drawer.title");
  byId("drawerSingleLink").href = singleHref(value.draft_id, value.kind);
  const meta = byId("drawerMeta");
  meta.replaceChildren();
  metaEntry(meta, t("approvals.col.kind"), kindLabel(value.kind));
  metaEntry(meta, t("approvals.col.status"), [phasePill(value.phase)?.[0], statusNote(value)].filter(Boolean).join(" · ")
    || statusLabel(value.status));
  if (Number.isInteger(value.queue_position)) {
    metaEntry(meta, t("approvals.meta.queuePosition"), t("approvals.meta.position", { n: value.queue_position }));
  }
  metaEntry(meta, t("approvals.col.mailbox"), packet.account);
  metaEntry(meta, t("envelope.from"), packet.sender || packet.from);
  if (packet.source_folder) metaEntry(meta, t("approvals.meta.source"), `${packet.source_folder} · UID ${packet.source_uid ?? "—"}`);
  metaEntry(meta, t("approvals.meta.destination"), packet.destination);
  metaEntry(meta, t("approvals.meta.draftExpiry"), localTime(value.expires_at));
  if (value.approval) {
    const approval = value.approval;
    metaEntry(meta, t("approvals.meta.approval"),
      `${sourceLabel(approval.source)} · ${approval.approved_by || "—"} · ${localTime(approval.approved_at)}`);
    if (approval.revoked_at) metaEntry(meta, t("approvals.meta.revoked"), localTime(approval.revoked_at));
    else metaEntry(meta, t("approvals.meta.deadline"), approval.expires_at ? localTime(approval.expires_at) : t("approvals.meta.noExpiry"));
  }
  if (value.execution) metaEntry(meta, t("approvals.meta.execution"), value.execution.state);
  byId("drawerPacket").textContent = JSON.stringify(value.review_packet, null, 2);
  drawerDraft = value;
  updateDrawerApprove();
}

// Approve straight from the drawer; sends keep their dedicated review page.
function updateDrawerApprove() {
  const button = byId("drawerApprove");
  const value = drawerDraft;
  const approvable = Boolean(value) && value.status === "pending_approval" && value.kind !== "send";
  button.hidden = !approvable;
  if (!approvable) return;
  const reason = blockedReason(value.kind);
  button.disabled = drawerBusy || Boolean(reason);
  button.title = reason;
  button.textContent = value.kind === "trash"
    ? t("approvals.approveTrash")
    : t("approvals.approveKind", { kind: kindLabel(value.kind, "") });
}

byId("drawerApprove").addEventListener("click", async () => {
  const value = drawerDraft;
  if (drawerBusy || !value || value.status !== "pending_approval" || blockedReason(value.kind)) return;
  drawerBusy = true;
  updateDrawerApprove();
  try {
    const result = await post("/approvals", { draft_id: value.draft_id, payload_hash: value.payload_hash });
    let fresh = null;
    try {
      fresh = await jsonRequest(`/drafts/${encodeURIComponent(value.draft_id)}`);
      if (drawerDraftId === value.draft_id) renderDrawer(fresh);
    } catch (_error) {
      // The list refresh below still shows the approval.
    }
    toast(approvedText(result, fresh), "success");
    batchSelection.delete(value.draft_id);
    batchItemsById.delete(value.draft_id);
    await refreshBatch(batchOffset);
    await refreshExecution();
  } catch (error) {
    toast(error.message, "error");
  } finally {
    drawerBusy = false;
    updateDrawerApprove();
  }
});

async function openDrawer(draftId, trigger = null) {
  const token = ++drawerToken;
  drawerDraftId = draftId;
  drawerReturnFocus = trigger;
  showDrawerDialog();
  byId("drawerTitle").textContent = t("common.reading");
  byId("drawerMeta").replaceChildren();
  byId("drawerSingleLink").href = singleHref(draftId);
  drawerDraft = null;
  updateDrawerApprove();
  byId("drawerPacket").textContent = t("approvals.drawer.readingPacket");
  filledMail.delete(DRAWER_MAIL);
  byId("drawerMailEnvelope").replaceChildren();
  byId("drawerMailNotice").hidden = true;
  byId("drawerMailBody").textContent = t("approvals.mail.loading");
  markOpenRows();
  byId("drawerClose").focus?.();
  try {
    const value = await jsonRequest(`/drafts/${encodeURIComponent(draftId)}`);
    if (token !== drawerToken) return;
    renderDrawer(value);
    await loadMail(draftId, DRAWER_MAIL, value.review_packet || {}, () => token === drawerToken);
  } catch (error) {
    if (token !== drawerToken) return;
    byId("drawerTitle").textContent = t("common.readFailed");
    byId("drawerPacket").textContent = t("common.readFailedDetail", { message: error.message });
  }
}

// The drawer is a native modal <dialog>: showModal() traps focus, makes the
// page behind it inert and adds the ::backdrop scrim. Toasts move into the
// dialog while it is open so they stay visible above the scrim.
function showDrawerDialog() {
  const drawer = byId("drawer");
  drawer.hidden = false;
  if (typeof drawer.showModal === "function" && !drawer.open) {
    drawer.showModal();
    drawer.append(byId("toasts"));
  }
}

function closeDrawer() {
  const drawer = byId("drawer");
  if (drawer.hidden) return;
  drawerToken += 1;
  drawerDraftId = null;
  drawer.hidden = true;
  if (drawer.open) {
    drawer.close();
    document.body.append(byId("toasts"));
  }
  markOpenRows();
  drawerReturnFocus?.focus?.();
  drawerReturnFocus = null;
}

byId("drawerClose").addEventListener("click", closeDrawer);
// Escape on a modal dialog fires "cancel"; route it through the same cleanup.
byId("drawer").addEventListener("cancel", (event) => {
  event.preventDefault();
  closeDrawer();
});
// A click on the backdrop lands on the dialog element itself.
byId("drawer").addEventListener("click", (event) => {
  if (event.target === byId("drawer")) closeDrawer();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDrawer();
});

// ---- Single draft ----

function updateSingle() {
  const pending = draft?.status === "pending_approval";
  const reason = draft ? blockedReason(draft.kind) : "";
  showInline("singleBlocked", pending ? reason : "");
  byId("approve").disabled = singleBusy || Boolean(reason) || !pending;
}

// What is happening to this approval right now, in plain words.
function executionText(value) {
  const error = value.error_class;
  switch (value.status) {
    case "approved":
      if (!dispatchInfo?.enabled) return t("approvals.exec.awaitingClient");
      if (!Number.isInteger(value.queue_position)) return t("approvals.exec.queued");
      return value.queue_position > 1
        ? t("approvals.exec.queuedBehind", { n: value.queue_position - 1 }) : t("approvals.exec.next");
    case "attempting": return t("approvals.exec.attempting");
    case "unknown": return t("approvals.exec.verifying");
    case "confirmed": return t("status.confirmed");
    case "failed": return error ? t("approvals.exec.failedBecause", { error: errorLabel(error) }) : t("status.failed");
    default: return value.approval ? statusLabel(value.status) : "";
  }
}

function showDraftState(value) {
  draft = value;
  applyDispatch(value.approval_dispatch);
  byId("status").textContent = statusLabel(value.status);
  byId("executionState").textContent = executionText(value);
  byId("executionState").className = `execution-state tone-${PHASE_TONES[value.phase] || "muted"}`;
  const pending = value.status === "pending_approval";
  showInline("singleNote", pending ? "" : value.revocable
    ? t("approvals.single.revocableNote")
    : t("approvals.single.final", { status: statusLabel(value.status) }));
  draftPolling = ACTIVE_STATUSES.has(value.status);
  updateSingle();
  updateRevokeControls();
}

function scheduleDraftPoll() {
  clearTimeout(draftTimer);
  draftTimer = draftPolling && !document.hidden ? setTimeout(pollDraft, POLL_MS) : null;
}

async function pollDraft() {
  if (!draft || draftLoading) return;
  clearTimeout(draftTimer);
  draftTimer = null;
  draftLoading = true;
  try {
    showDraftState(await jsonRequest(`/drafts/${encodeURIComponent(draft.draft_id)}`));
  } catch (error) {
    byId("executionState").textContent = t("approvals.exec.readFailed", { message: sentence(error.message) });
  } finally {
    draftLoading = false;
    scheduleDraftPoll();
  }
}

// Single-page text that only depends on the draft and the active language.
function renderSingleStatic() {
  if (!draft) return;
  byId("kind").textContent = kindLabel(draft.kind);
  byId("expiry").textContent = localTime(draft.expires_at);
  byId("warning").textContent = [
    t("approvals.single.warning"),
    draft.review_packet?.copy_preserve_source_fallback ? t("review.warning.copyFallback") : "",
    draft.review_packet?.uidplus_move_fallback ? t("review.warning.uidplus") : "",
  ].filter(Boolean).join(" ");
}

async function startSingle(draftId) {
  byId("single").hidden = false;
  if (!DRAFT_ID.test(draftId)) throw new Error(t("approvals.invalidId"));
  const value = await jsonRequest(`/drafts/${encodeURIComponent(draftId)}`);
  if (value.kind === "send") {
    window.location.assign(singleHref(draftId, "send"));
    return;
  }
  byId("packet").textContent = JSON.stringify(value.review_packet, null, 2);
  draft = value;
  renderSingleStatic();
  showDraftState(value);
  scheduleDraftPoll();
  await loadMail(draftId, SINGLE_MAIL, value.review_packet || {}, () => draft?.draft_id === draftId);
}


function approvedText(result, fresh) {
  if (!dispatchInfo?.enabled) return t("approvals.approved.client", { id: result.approval_id });
  if (fresh?.status === "approved" && Number.isInteger(fresh.queue_position)) {
    return t("approvals.approved.position", { n: fresh.queue_position });
  }
  if (fresh && fresh.status !== "approved") return t("approvals.approved.status", { status: statusLabel(fresh.status) });
  return t("approvals.approved.queued");
}

byId("approve").addEventListener("click", async () => {
  if (singleBusy || blockedReason(draft?.kind) || draft?.status !== "pending_approval") return;
  singleBusy = true;
  updateSingle();
  try {
    const result = await post("/approvals", { draft_id: draft.draft_id, payload_hash: draft.payload_hash });
    showDraftState({ ...draft, status: "approved", phase: "running", revocable: true, queue_position: null,
      approval: { approval_id: result.approval_id, source: result.approval_source } });
    // A fresh read tells the reviewer where the approval sits in the queue.
    let fresh = null;
    try {
      fresh = await jsonRequest(`/drafts/${encodeURIComponent(draft.draft_id)}`);
      showDraftState(fresh);
    } catch (_error) {
      draftPolling = true;
    }
    toast(approvedText(result, fresh), "success");
    scheduleDraftPoll();
  } catch (error) {
    toast(error.message, "error");
  } finally {
    singleBusy = false;
    updateSingle();
  }
});

byId("revokeSingle").addEventListener("click", async () => {
  if (!draft) return;
  const results = await revoke([draft]);
  if (results?.some((item) => item.status === "revoked")) await pollDraft();
});

// ---- Pending Trash approvals ----

function selectedBatch() {
  return [...batchSelection].map((id) => batchItemsById.get(id)).filter(Boolean);
}

function updateBatch() {
  const count = batchSelection.size;
  const locked = batchBusy || batchLoading || selectingAll;
  const reason = blockedReason("trash");
  if (!batchBusy) byId("approveBatch").textContent = t("approvals.approveBatch", { n: count });
  byId("approveBatch").disabled = locked || Boolean(reason) || !count;
  showInline("batchBlocked", reason);
  const pageCount = batchDrafts.filter((item) => batchSelection.has(item.draft_id)).length;
  byId("selectionCount").textContent = t("approvals.selected", { n: count });
  byId("selectAll").checked = pageCount > 0 && pageCount === batchDrafts.length;
  byId("selectAll").indeterminate = pageCount > 0 && pageCount < batchDrafts.length;
  byId("selectAll").disabled = locked || !batchDrafts.length;
  byId("previousPage").disabled = locked || batchOffset === 0;
  byId("nextPage").disabled = locked || !batchHasMore;
  byId("refreshBatch").disabled = locked;
  byId("pageSize").disabled = locked;
  byId("selectAllPages").disabled = locked || (!batchHasMore && !batchDrafts.length);
  for (const input of byId("batchItems").querySelectorAll("input")) {
    input.checked = batchSelection.has(input.value);
    input.disabled = locked;
  }
}

function setBatchSelected(item, selected) {
  if (selected) {
    batchItemsById.set(item.draft_id, { draft_id: item.draft_id, payload_hash: item.payload_hash });
    batchSelection.add(item.draft_id);
  } else {
    batchSelection.delete(item.draft_id);
    batchItemsById.delete(item.draft_id);
  }
}

function pendingRow(item) {
  // Keep compatibility with older servers while the list endpoint rolls out.
  const summary = item.summary || item.review_packet || {};
  const row = document.createElement("tr");
  row.draftId = item.draft_id;
  if (item.draft_id === drawerDraftId) row.classList.add("is-open");
  const input = document.createElement("input");
  input.type = "checkbox";
  input.value = item.draft_id;
  input.setAttribute("aria-label", t("approvals.selectRow", { subject: summary.subject || item.draft_id }));
  input.addEventListener("change", () => {
    if (batchBusy || batchLoading || selectingAll) return;
    setBatchSelected(item, input.checked);
    updateBatch();
  });
  cell(row, undefined, "check-col").append(input);
  mailCell(row, summary, item.draft_id);
  cell(row, summary.account || "—", "account-col", t("approvals.col.mailbox"));
  const folder = cell(row, summary.source_folder || "—", "folder-col", t("approvals.col.folder"));
  folder.title = `${summary.source_folder || "—"} · UID ${summary.source_uid ?? "—"}`;
  const remaining = relativeTime(item.expires_at);
  const expiry = cell(row, remaining.text, remaining.ms < 3600000 ? "expiry-col soon" : "expiry-col", t("approvals.col.expiry"));
  expiry.title = t("approvals.expiresAt", { time: localTime(item.expires_at) });
  const details = textButton(t("approvals.col.details"), "link-button", () => openDrawer(item.draft_id, details));
  cell(row, undefined, "action-col").append(details);
  return row;
}

async function loadBatch() {
  byId("pageInfo").textContent = t("common.reading");
  updateBatch();
  let value = await jsonRequest(`/drafts?offset=${batchOffset}&limit=${pageSize}`);
  // Concurrent approvals can shrink the queue while a later page is open.
  if (!value.drafts.length && batchOffset > 0) {
    batchOffset = 0;
    value = await jsonRequest(`/drafts?offset=0&limit=${pageSize}`);
  }
  showInline("pendingError", "");
  batchHasMore = value.has_more;
  const trashTotal = Number.isInteger(value.total) ? value.total : null;
  const otherTotal = Number.isInteger(value.other_total) ? value.other_total : 0;
  pendingTotal = trashTotal === null ? null : trashTotal + otherTotal;
  applyDispatch(value.approval_dispatch);
  batchDrafts = value.drafts.filter((item) => item.status === "pending_approval");
  for (const id of batchItemsById.keys()) {
    if (!batchSelection.has(id)) batchItemsById.delete(id);
  }
  byId("batchItems").replaceChildren();
  byId("batchItems").append(...batchDrafts.map(pendingRow));
  const other = Array.isArray(value.other_drafts) ? value.other_drafts : [];
  byId("otherPending").hidden = !other.length;
  byId("otherPendingMore").hidden = otherTotal <= other.length;
  byId("otherPendingItems").replaceChildren();
  for (const item of other) {
    const row = document.createElement("tr");
    const summary = item.summary || {};
    mailCell(row, summary, item.draft_id);
    const operation = kindLabel(item.kind);
    cell(row, summary.recovery_of ? t("approvals.reapproval", { operation }) : operation, "kind-col", t("approvals.col.operation"));
    cell(row, summary.account || "—", "account-col", t("approvals.col.mailbox"));
    const link = document.createElement("a");
    link.href = singleHref(item.draft_id, item.kind);
    link.textContent = t("approvals.goReview");
    link.className = "link-button";
    cell(row, undefined, "ops-col").append(link);
    byId("otherPendingItems").append(row);
  }
  showInline("pendingEmpty", batchDrafts.length ? "" : t("approvals.emptyPending"));
  const range = batchDrafts.length ? `${batchOffset + 1}–${batchOffset + batchDrafts.length}` : "0";
  byId("pageInfo").textContent = trashTotal === null ? range : `${range} / ${trashTotal}`;
  updateTabCounts();
  updateBatch();
}

byId("selectAll").addEventListener("change", (event) => {
  if (batchBusy || batchLoading || selectingAll) return;
  const checked = event.currentTarget.checked;
  for (const item of batchDrafts) setBatchSelected(item, checked);
  updateBatch();
});
byId("selectAllPages").addEventListener("click", async () => {
  if (batchBusy || batchLoading || selectingAll) return;
  selectingAll = true;
  byId("selectAllPages").textContent = t("approvals.selectingAll");
  updateBatch();
  try {
    // One query returns only IDs and hashes; packets load in the drawer on demand.
    const value = await jsonRequest("/drafts?select_all=true");
    if (!Array.isArray(value.drafts) || value.drafts.some((item) =>
      typeof item.draft_id !== "string" || typeof item.payload_hash !== "string")) {
      throw new Error(t("approvals.selectAllIncomplete"));
    }
    // Replace the selection only after a complete snapshot arrives. Previously
    // selected drafts that expired or were approved elsewhere are dropped.
    batchItemsById.clear();
    batchSelection.clear();
    for (const item of value.drafts) setBatchSelected(item, true);
  } catch (error) {
    toast(t("approvals.selectAllFailed", { message: error.message }), "error");
  } finally {
    selectingAll = false;
    byId("selectAllPages").textContent = t("approvals.selectAllPages");
    updateBatch();
  }
});

async function refreshBatch(offset, clearSelection = false) {
  if (batchBusy || batchLoading || selectingAll) return;
  if (clearSelection) {
    batchSelection.clear();
    batchItemsById.clear();
  }
  const moved = offset !== batchOffset;
  batchOffset = offset;
  batchLoading = true;
  updateBatch();
  try {
    await loadBatch();
    if (moved) byId("pendingRegion").scrollTop = 0;
  } catch (error) {
    byId("pageInfo").textContent = t("common.readFailed");
    showInline("pendingError", t("approvals.pendingReadFailed", { message: sentence(error.message) }));
  } finally {
    batchLoading = false;
    updateBatch();
  }
}

// After an interrupted submission keep only drafts that are confirmed still
// pending, so a retry never resubmits work the server already accepted.
async function keepUnapprovedSelection(approved) {
  for (const item of approved) {
    batchSelection.delete(item.draft_id);
    batchItemsById.delete(item.draft_id);
  }
  try {
    const value = await jsonRequest("/drafts?select_all=true");
    if (Array.isArray(value.drafts)) {
      const pending = new Set(value.drafts.map((item) => item.draft_id));
      for (const id of [...batchSelection]) {
        if (!pending.has(id)) {
          batchSelection.delete(id);
          batchItemsById.delete(id);
        }
      }
    }
  } catch (_error) {
    // Without a fresh snapshot keep the rest selected; the server revalidates every item.
  }
}

byId("previousPage").addEventListener("click", () => refreshBatch(Math.max(0, batchOffset - pageSize)));
byId("nextPage").addEventListener("click", () => refreshBatch(batchOffset + pageSize));
byId("refreshBatch").addEventListener("click", () => refreshBatch(batchOffset));
byId("pageSize").addEventListener("change", (event) => {
  if (batchBusy || batchLoading || selectingAll) return;
  pageSize = Number(event.currentTarget.value);
  refreshBatch(0);
});

// Where the freshly approved batch sits, from the queue numbers read after it.
function queuedText(count) {
  const progress = t("approvals.batch.progress");
  if (!dispatchInfo?.enabled) return t("approvals.batch.client", { n: count, progress });
  const queued = dispatchInfo.queue?.ready;
  const eta = etaMinutes(dispatchInfo);
  const minutes = dispatchInfo.activity?.window_minutes || 10;
  let queue = "";
  if (queued === 0) {
    queue = t("approvals.batch.queueEmpty");
  } else if (Number.isInteger(queued)) {
    queue = eta === null ? t("approvals.batch.queue", { n: queued })
      : t("approvals.batch.queueEta", { n: queued, minutes, duration: durationText(eta) });
  }
  return t("approvals.batch.queued", { n: count, queue, progress });
}

function showRunning() {
  showTab("execution", { refresh: false });
  void selectFilter("running");
}

byId("approveBatch").addEventListener("click", async () => {
  if (batchBusy || batchLoading || selectingAll || blockedReason("trash")) return;
  const items = selectedBatch().map(({ draft_id, payload_hash }) => ({ draft_id, payload_hash }));
  if (!items.length) return;
  batchBusy = true;
  updateBatch();
  const results = [];
  let failure = null;
  try {
    for (let index = 0; index < items.length; index += 200) {
      const end = Math.min(index + 200, items.length);
      byId("approveBatch").textContent = t("approvals.batch.submitting", { from: index + 1, to: end, total: items.length });
      const value = await post("/approvals/batch", { items: items.slice(index, end) });
      results.push(...value.results);
    }
  } catch (error) {
    failure = error;
  }
  const approved = results.filter((item) => APPROVED_RESULTS.has(item.status));
  const failed = results.filter((item) => item.status === "failed");
  if (failure) {
    await keepUnapprovedSelection(approved);
    batchBusy = false;
    await refreshBatch(batchOffset);
    toast(t("approvals.batch.interrupted", {
      approved: approved.length, failed: failed.length, message: sentence(failure.message),
    }), "error");
  } else {
    if (failed.length) {
      toast(outcomeText("approved", approved.length, failed), "error");
    } else {
      byId("approveBatch").textContent = t("approvals.batch.readingQueue");
      try {
        await readQueue();
      } catch (_error) {
        // Without fresh numbers the message leaves out the queue.
      }
      toast(queuedText(approved.length), "success", { action: { label: t("approvals.batch.viewProgress"), run: showRunning } });
    }
    batchBusy = false;
    await refreshBatch(0, true);
  }
  updateBatch();
  await refreshExecution();
});

// ---- Execution records ----

function scheduleExecution() {
  clearTimeout(executionTimer);
  executionTimer = listMode && activeTab === "execution" && !document.hidden
    ? setTimeout(refreshExecution, POLL_MS) : null;
}

function updateChips() {
  for (const status of EXECUTION_FILTERS) {
    const chip = byId(`chip-${status}`);
    chip.setAttribute("aria-pressed", String(status === executionStatus));
    chip.classList.toggle("active", status === executionStatus);
    const count = executionCounts?.[status];
    byId(`count-${status}`).textContent = Number.isInteger(count) ? String(count) : "";
  }
}

function updateRevokeControls() {
  for (const button of executionButtons) button.disabled = revoking;
  byId("revokeSingle").hidden = !draft?.revocable;
  byId("revokeSingle").disabled = revoking;
}

function statusCell(row, item) {
  const td = cell(row, undefined, "status-col", t("approvals.col.status"));
  const [text, tone] = phasePill(item.phase) || [statusLabel(item.status), "muted"];
  const pill = document.createElement("span");
  pill.className = `pill pill-${tone}`;
  pill.textContent = text;
  pill.title = statusLabel(item.status);
  td.append(pill);
  const notes = [statusNote(item)];
  if (item.attempt > 1) notes.push(t("approvals.attempt", { n: item.attempt }));
  const noteText = notes.filter(Boolean).join(" · ");
  if (noteText) {
    const note = document.createElement("span");
    note.className = "note";
    note.textContent = noteText;
    note.title = item.error_class ? t("approvals.noteWithClass", { note: noteText, error: item.error_class }) : noteText;
    td.append(note);
  }
  return td;
}

function timeCell(row, item) {
  const td = cell(row, undefined, "time-col", t("approvals.col.time"));
  const approval = item.approval;
  const first = document.createElement("span");
  const second = document.createElement("span");
  second.className = "note";
  if (approval) {
    const approvedAt = localTime(approval.approved_at);
    first.textContent = t("approvals.time.approved", { time: shortTime(approval.approved_at) || "—" });
    if (approval.revoked_at) {
      second.textContent = t("approvals.time.revoked", { time: shortTime(approval.revoked_at) });
      td.title = t("approvals.time.revokedTitle", { approved: approvedAt, revoked: localTime(approval.revoked_at) });
    } else if (approval.expires_at) {
      second.textContent = timeLimitText(approval.expires_at, "approvals.time.deadlineLeft", "approvals.time.deadlinePast");
      td.title = t("approvals.time.deadlineTitle", { approved: approvedAt, deadline: localTime(approval.expires_at) });
    } else {
      second.textContent = t("approvals.time.durable");
      td.title = t("approvals.time.durableTitle", { approved: approvedAt });
    }
  } else {
    first.textContent = t("approvals.time.submitted", { time: shortTime(item.created_at) || "—" });
    second.textContent = timeLimitText(item.expires_at, "approvals.time.validLeft", "approvals.time.validPast");
    td.title = t("approvals.time.submittedTitle", { created: localTime(item.created_at), expires: localTime(item.expires_at) });
  }
  td.append(first, second);
  return td;
}

function executionRow(item) {
  const summary = item.summary || {};
  const row = document.createElement("tr");
  row.draftId = item.draft_id;
  if (item.draft_id === drawerDraftId) row.classList.add("is-open");
  mailCell(row, summary, item.draft_id);
  cell(row, kindLabel(item.kind, item.kind || "—"), "kind-col", t("approvals.col.kind"));
  cell(row, summary.account || "—", "account-col", t("approvals.col.mailbox"));
  cell(row, sourceLabel(item.approval?.source), "source-col", t("approvals.col.source"));
  statusCell(row, item);
  timeCell(row, item);
  const ops = cell(row, undefined, "ops-col");
  if (!item.approval && item.status === "pending_approval") {
    const link = document.createElement("a");
    link.className = "link-button";
    link.href = singleHref(item.draft_id, item.kind);
    link.textContent = t("approvals.goReview");
    ops.append(link);
  }
  if (item.revocable) {
    const button = textButton(t("approvals.revoke"), "secondary small", () => revokeExecution([item]));
    executionButtons.push(button);
    ops.append(button);
  }
  const details = textButton(t("approvals.col.details"), "link-button", () => openDrawer(item.draft_id, details));
  ops.append(details);
  return row;
}

function renderExecution(value) {
  const region = byId("executionRegion");
  const scrollTop = region.scrollTop;
  executionRows = Array.isArray(value.drafts) ? value.drafts : [];
  executionHasMore = Boolean(value.has_more);
  if (value.counts && typeof value.counts === "object") executionCounts = value.counts;
  executionButtons = [];
  byId("executionItems").replaceChildren();
  byId("executionItems").append(...executionRows.map(executionRow));
  showInline("executionEmpty", executionRows.length ? "" : executionStatus === "all"
    ? t("approvals.emptyExecution") : t("approvals.emptyFilter"));
  const total = executionCounts?.[executionStatus];
  const range = executionRows.length
    ? `${executionOffset + 1}–${executionOffset + executionRows.length}` : "0";
  byId("executionPageInfo").textContent = Number.isInteger(total) ? `${range} / ${total}` : range;
  const updated = new Date();
  byId("executionUpdated").textContent =
    t("approvals.updated", { time: `${pad(updated.getHours())}:${pad(updated.getMinutes())}:${pad(updated.getSeconds())}` });
  byId("previousExecution").disabled = executionOffset === 0;
  byId("nextExecution").disabled = !executionHasMore;
  region.scrollTop = scrollTop;
  updateChips();
  updateTabCounts();
  updateRevokeControls();
}

const executionQuery = () =>
  `/drafts?view=execution&status=${encodeURIComponent(executionStatus)}&offset=${executionOffset}&limit=${EXECUTION_PAGE_SIZE}`;

async function refreshExecution() {
  if (executionLoading) {
    executionQueued = true;
    return;
  }
  clearTimeout(executionTimer);
  executionTimer = null;
  executionLoading = true;
  byId("previousExecution").disabled = true;
  byId("nextExecution").disabled = true;
  const query = executionQuery();
  try {
    const value = await jsonRequest(query);
    // A filter or page change while loading supersedes this response.
    if (query === executionQuery()) {
      applyDispatch(value.approval_dispatch);
      renderExecution(value);
      showInline("executionError", "");
    } else {
      executionQueued = true;
    }
  } catch (error) {
    showInline("executionError", t("approvals.executionReadFailed", { message: sentence(error.message) }));
    byId("previousExecution").disabled = executionOffset === 0;
    byId("nextExecution").disabled = !executionHasMore;
  } finally {
    executionLoading = false;
    if (executionQueued) {
      executionQueued = false;
      void refreshExecution();
    } else {
      scheduleExecution();
    }
  }
}

async function revokeExecution(items) {
  const results = await revoke(items);
  if (!results) return;
  await refreshExecution();
}

function selectFilter(status) {
  executionStatus = status;
  executionOffset = 0;
  byId("executionRegion").scrollTop = 0;
  updateChips();
  updateRevokeControls();
  return refreshExecution();
}

function changeExecutionPage(offset) {
  if (executionLoading) return undefined;
  executionOffset = Math.max(0, offset);
  byId("executionRegion").scrollTop = 0;
  return refreshExecution();
}

for (const status of EXECUTION_FILTERS) {
  byId(`chip-${status}`).addEventListener("click", () => selectFilter(status));
}
byId("refreshExecution").addEventListener("click", () => refreshExecution());
byId("previousExecution").addEventListener("click", () => changeExecutionPage(executionOffset - EXECUTION_PAGE_SIZE));
byId("nextExecution").addEventListener("click", () => changeExecutionPage(executionOffset + EXECUTION_PAGE_SIZE));

// Polling pauses in background tabs and catches up as soon as the tab is visible.
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    clearTimeout(executionTimer);
    executionTimer = null;
    clearTimeout(dispatchTimer);
    dispatchTimer = null;
    clearTimeout(draftTimer);
    draftTimer = null;
    return;
  }
  if (listMode && activeTab === "execution") void refreshExecution();
  if (listMode && activeTab === "pending") void pollDispatch();
  if (draftPolling) void pollDraft();
});

window.addEventListener?.("hashchange", () => {
  if (listMode && tabFromHash() !== activeTab) showTab(tabFromHash(), { remember: false });
});

function renderIdentity() {
  if (reviewer) byId("identity").textContent = t("approvals.identity.reviewer", { subject: reviewer });
}

// A language switch re-renders everything this page wrote with t().
function rerender() {
  renderIdentity();
  if (dispatchInfo) applyDispatch(dispatchInfo);
  updateTabCounts();
  updateBatch();
  if (listMode) {
    void refreshBatch(batchOffset);
    renderExecution({ drafts: executionRows, has_more: executionHasMore, counts: executionCounts });
  }
  if (drawerDraft && drawerDraftId === drawerDraft.draft_id) {
    renderDrawer(drawerDraft);
    const shown = filledMail.get(DRAWER_MAIL);
    if (shown) fillMail(DRAWER_MAIL, shown.packet, shown.result);
  }
  if (draft && !listMode) {
    renderSingleStatic();
    showDraftState(draft);
    const shown = filledMail.get(SINGLE_MAIL);
    if (shown) fillMail(SINGLE_MAIL, shown.packet, shown.result);
  }
}
EG.onLocaleChange(rerender);

async function start() {
  const params = new URLSearchParams(window.location.search);
  const draftParam = params.get("draft_id") || "";
  try {
    const session = await jsonRequest("/session?surface=approval");
    csrf = session.csrf;
    reviewer = session.subject;
    renderIdentity();
    if (draftParam && !params.has("batch")) {
      await startSingle(draftParam);
      return;
    }
    listMode = true;
    byId("tabs").hidden = false;
    showTab(tabFromHash(), { remember: false, refresh: false });
    updateChips();
    await Promise.all([refreshBatch(0, true), refreshExecution()]);
    if (DRAFT_ID.test(draftParam)) void openDrawer(draftParam);
  } catch (error) {
    if (!reviewer) byId("identity").textContent = t("approvals.identity.failed");
    toast(error.message, "error");
  }
}

document.addEventListener("DOMContentLoaded", start);
