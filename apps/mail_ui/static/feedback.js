"use strict";
const el = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const state = { csrf: "", diagnostic: null, cursor: null, next: null, previous: [], issuesCursor: null };
const api = (tool, args = {}) => jsonRequest(`/api/mcp/${encodeURIComponent(tool)}`, {
  method: "POST", body: { arguments: args }, csrf: state.csrf });
const processingLabel = (status) => (EG.has(`feedback.processing.${status}`) ? t(`feedback.processing.${status}`) : status);
function report(error) { el("notice").textContent = error.message; }
function anchor(text, path) { const a = document.createElement("a"); a.textContent = text; a.href = path; return a; }

async function diagnose(mid) {
  const value = await api("diagnose_message", { stable_message_id: mid });
  state.diagnostic = value;
  el("detail").hidden = false;
  el("diagnostic").textContent = JSON.stringify(value, null, 2);
  el("explanation").textContent = value.reason_code
    ? EG.reasonText(value.reason_code)
    : (value.actionable ? t("feedback.actionable") : "");
  el("submit").disabled = !value.reason_code;
  el("detail").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function load() {
  const status = el("status").value;
  const [page, counts] = await Promise.all([
    api("list_recent", { location_status: status, paginated: true, cursor: state.cursor, limit: 25 }),
    api("count_mail", { inbox_only: true, unread_only: true }),
  ]);
  el("counts").textContent = t("feedback.counts", {
    indexed: counts.indexed_count,
    present: counts.provider_present_count ?? counts.actionable_count,
    actionable: counts.actionable_count,
    historical: counts.historical_copy_only_count ?? 0,
    unknown: counts.unknown_outcome_count ?? 0,
    anomalies: counts.location_anomaly_count,
    unverified: counts.unverified_count,
  });
  el("messages").replaceChildren();
  for (const message of page.items) {
    const tr = document.createElement("tr");
    const reason = message.reason_code ? EG.reasonText(message.reason_code) : message.location_status;
    for (const text of [message.subject || t("mail.noSubject"), `${message.account} / ${message.indexed_folder}`, reason]) {
      const td = document.createElement("td");
      td.textContent = text;
      tr.append(td);
    }
    const td = document.createElement("td");
    td.append(anchor(t("feedback.open"), message.feedback_url));
    tr.append(td);
    el("messages").append(tr);
  }
  state.next = page.next_cursor;
  el("next").disabled = !state.next;
  el("previous").disabled = !state.previous.length;
}

async function showIssue(id) {
  const value = await api("get_mail_feedback", { issue_id: id });
  el("action").value = value.intended_action;
  el("decision").value = value.user_decision;
  el("detail").hidden = false;
  el("issue").textContent = JSON.stringify(value, null, 2);
  el("issueLink").replaceChildren(anchor(t("feedback.ticket", { id: value.issue_id }), value.feedback_url));
  await diagnose(value.stable_message_id);
}

function issueText(issue) {
  return t("feedback.issueLine", {
    message: issue.stable_message_id,
    action: issue.intended_action,
    decision: issue.user_decision,
    processing: processingLabel(issue.processing_status),
    result: issue.execution_result,
    restored: issue.restored_actionable ? t("feedback.restored") : t("feedback.toVerify"),
  });
}

async function loadIssues(append = false) {
  const value = await api("list_mail_feedback", {
    restored_only: el("restored").checked, cursor: append ? state.issuesCursor : null, limit: 25 });
  if (!append) el("issues").replaceChildren();
  for (const issue of value.items) {
    const li = document.createElement("li");
    li.append(anchor(issueText(issue), issue.feedback_url));
    el("issues").append(li);
  }
  state.issuesCursor = value.next_cursor;
  el("moreIssues").disabled = !state.issuesCursor;
}

el("feedbackForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  el("submit").disabled = true;
  try {
    const value = await api("submit_mail_feedback", {
      stable_message_id: state.diagnostic.stable_message_id,
      intended_action: el("action").value,
      user_decision: el("decision").value,
      processing_status: state.diagnostic.reason_code === "PROVIDER_OUTCOME_UNKNOWN" ? "unknown" : "blocked",
      reason_code: state.diagnostic.reason_code,
    });
    history.replaceState(null, "", value.feedback_url);
    await showIssue(value.issue_id);
    await loadIssues();
  } catch (error) { report(error); } finally { el("submit").disabled = !state.diagnostic?.reason_code; }
});
el("refresh").onclick = () => start().catch(report);
el("status").onchange = () => { state.cursor = null; state.previous = []; load().catch(report); };
el("next").onclick = () => { state.previous.push(state.cursor); state.cursor = state.next; load().catch(report); };
el("previous").onclick = () => { state.cursor = state.previous.pop(); load().catch(report); };
el("refreshIssues").onclick = () => loadIssues().catch(report);
el("restored").onchange = () => loadIssues().catch(report);
el("moreIssues").onclick = () => loadIssues(true).catch(report);
// Lists re-render in the new language; the diagnostic JSON stays as received.
EG.onLocaleChange(() => { load().catch(report); loadIssues().catch(report); });

async function start() {
  el("notice").textContent = "";
  state.csrf = (await jsonRequest("/api/session")).csrf;
  const sections = [load(), loadIssues()];
  if (params.get("issue_id")) sections.push(showIssue(params.get("issue_id")));
  else if (params.get("message_id")) sections.push(diagnose(params.get("message_id")));
  const results = await Promise.allSettled(sections);
  const errors = results.filter((result) => result.status === "rejected").map((result) => result.reason.message);
  if (errors.length) report(new Error([...new Set(errors)].join(t("common.listSeparator"))));
}
start().catch(report);
