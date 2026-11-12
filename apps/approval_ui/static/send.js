"use strict";

const byId = (id) => document.getElementById(id);
let csrf = "";
let reviewer = "";
let draft = null;
let busy = false;
let pollTimer = null;

// The server may still change these; every other status is final for this page.
const ACTIVE_STATUSES = new Set(["approved", "blocked", "retryable", "attempting", "unknown"]);
// Without the server dispatcher the original sender still has to execute the approval.
const statusLabel = (status, dispatch = draft?.approval_dispatch) => {
  if (status === "approved" && !dispatch?.enabled) return t("send.awaitingSender");
  return status && EG.has(`status.${status}`) ? t(`status.${status}`) : status || "—";
};
let lastExecution = null;

function updateControls() {
  const pending = draft?.status === "pending_approval";
  byId("confirm").disabled = busy || !pending;
  byId("approve").disabled = busy || !pending || !byId("confirm").checked;
}

function showExecution(status) {
  lastExecution = status;
  byId("status").textContent = statusLabel(status);
  byId("executionState").textContent = t("review.status.execution", { status: statusLabel(status) });
}

function schedulePoll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(pollDraft, 5000);
}

async function pollDraft() {
  pollTimer = null;
  if (!draft) return;
  try {
    const value = await jsonRequest(`/drafts/${encodeURIComponent(draft.draft_id)}`);
    draft.status = value.status;
    if (value.approval_dispatch) draft.approval_dispatch = value.approval_dispatch;
    showExecution(value.status);
    if (ACTIVE_STATUSES.has(value.status)) schedulePoll();
  } catch (error) {
    byId("executionState").textContent = t("send.readFailed", { message: error.message });
    schedulePoll();
  }
}

async function start() {
  try {
    const session = await jsonRequest("/session?surface=approval");
    csrf = session.csrf;
    reviewer = session.subject;
    renderIdentity();
    const id = new URLSearchParams(window.location.search).get("draft_id") || "";
    if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error(t("approvals.invalidId"));
    const value = await jsonRequest(`/drafts/${encodeURIComponent(id)}`);
    if (value.kind !== "send") throw new Error(t("send.wrongKind"));
    const packet = value.review_packet;
    if (!packet || typeof packet.body !== "string" || !Array.isArray(packet.to)) {
      throw new Error(t("send.incomplete"));
    }
    byId("subject").textContent = packet.subject;
    // Outbound mail is plain text: preserve every newline and never interpret markup.
    byId("mailBody").textContent = packet.body;
    byId("packet").textContent = JSON.stringify(packet, null, 2);
    byId("mailPreview").hidden = false;
    draft = value;
    renderDraft();
    updateControls();
    if (draft.status !== "pending_approval") {
      byId("result").textContent = t("approvals.single.final", { status: statusLabel(draft.status) });
    }
    if (ACTIVE_STATUSES.has(draft.status) && draft.approval_dispatch?.enabled) {
      showExecution(draft.status);
      schedulePoll();
    }
  } catch (error) {
    byId("result").textContent = error.message;
    byId("result").className = "result error";
  }
}

byId("confirm").addEventListener("change", updateControls);
byId("approve").addEventListener("click", async () => {
  if (busy || !draft || draft.status !== "pending_approval" || !byId("confirm").checked) return;
  busy = true;
  updateControls();
  try {
    const result = await jsonRequest("/approvals", {
      method: "POST",
      body: {draft_id: draft.draft_id, payload_hash: draft.payload_hash},
      csrf,
    });
    draft.status = "approved";
    byId("status").textContent = statusLabel("approved");
    byId("result").className = "result success";
    if (draft.approval_dispatch?.enabled) {
      byId("result").textContent = t("send.approvedServer");
      showExecution("approved");
      schedulePoll();
    } else {
      byId("result").textContent = t("send.approvedClient", { id: result.approval_id });
    }
  } catch (error) {
    byId("result").textContent = error.message;
    byId("result").className = "result error";
    byId("confirm").checked = false;
  } finally {
    busy = false;
    updateControls();
  }
});
function renderIdentity() {
  if (reviewer) byId("identity").textContent = t("approvals.identity.reviewer", { subject: reviewer });
}

// Everything derived from the draft that depends on the active language.
function renderDraft() {
  const packet = draft.review_packet;
  byId("operation").textContent = EG.has(`send.op.${packet.operation}`) ? t(`send.op.${packet.operation}`) : t("send.op.default");
  const remaining = Date.parse(draft.expires_at) - Date.now();
  const expiry = new Date(draft.expires_at).toLocaleString(EG.locale());
  byId("expiry").textContent = Number.isFinite(remaining)
    ? `${expiry} · ${t(remaining >= 0 ? "time.left" : "time.past", { span: EG.formatSpan(remaining) })}`
    : expiry;
  byId("status").textContent = statusLabel(draft.status, draft.approval_dispatch);
  for (const field of ["account", "from", "to", "cc", "bcc"]) {
    const content = packet[field];
    byId(field).textContent = Array.isArray(content) ? content.join("\n") || t("common.none") : content || t("common.none");
  }
  byId("attachments").replaceChildren();
  for (const attachment of packet.attachments || []) {
    const item = document.createElement("li");
    item.textContent = `${attachment.filename} · ${attachment.mimetype || t("send.unknownType")} · ${EG.formatBytes(attachment.size)}`;
    byId("attachments").append(item);
  }
  if (!packet.attachments?.length) {
    const item = document.createElement("li");
    item.textContent = t("send.noAttachments");
    byId("attachments").append(item);
  }
}

EG.onLocaleChange(() => {
  renderIdentity();
  if (draft) renderDraft();
  if (lastExecution) showExecution(lastExecution);
});
document.addEventListener("DOMContentLoaded", start);
