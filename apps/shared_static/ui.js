"use strict";

// Shared UI helpers. Classic script loaded after i18n.js and its catalogues.
// EG.confirm replaces window.confirm with a styled, translated modal
// <dialog>: focus is trapped by showModal(), Escape cancels, and the promise
// resolves to true only when the confirm button is pressed.
(function install(root) {
  const EG = root.EG;
  let dialog = null;
  let settle = null;

  function build() {
    const doc = root.document;
    dialog = doc.createElement("dialog");
    dialog.className = "eg-confirm";
    dialog.setAttribute("aria-labelledby", "egConfirmTitle");
    dialog.setAttribute("aria-describedby", "egConfirmMessage");
    const form = doc.createElement("form");
    form.method = "dialog";
    const title = doc.createElement("h2");
    title.id = "egConfirmTitle";
    const message = doc.createElement("p");
    message.id = "egConfirmMessage";
    const actions = doc.createElement("div");
    actions.className = "eg-confirm-actions";
    const cancel = doc.createElement("button");
    cancel.type = "submit";
    cancel.value = "cancel";
    cancel.className = "secondary eg-confirm-cancel";
    const accept = doc.createElement("button");
    accept.type = "submit";
    accept.value = "confirm";
    accept.className = "primary eg-confirm-accept";
    actions.append(cancel, accept);
    form.append(title, message, actions);
    dialog.append(form);
    dialog.addEventListener("close", () => {
      // A stale close event from a replaced request arrives after the dialog
      // was reopened; it belongs to nobody still waiting.
      if (dialog.open) return;
      const done = settle;
      settle = null;
      done?.(dialog.returnValue === "confirm");
    });
    doc.body.append(dialog);
  }

  function confirmAction({ title = "", message = "", confirmLabel = "", cancelLabel = "", danger = false } = {}) {
    if (!dialog) build();
    // A second request while one is open cancels the first. The dialog's
    // asynchronous "close" event must not settle the new request, so the old
    // resolver is detached and settled here before the dialog is reused.
    if (settle) {
      const previous = settle;
      settle = null;
      dialog.close("cancel");
      previous(false);
    }
    dialog.querySelector("#egConfirmTitle").textContent = title || EG.t("common.confirmTitle");
    dialog.querySelector("#egConfirmMessage").textContent = message;
    dialog.querySelector(".eg-confirm-cancel").textContent = cancelLabel || EG.t("common.cancel");
    const accept = dialog.querySelector(".eg-confirm-accept");
    accept.textContent = confirmLabel || EG.t("common.confirm");
    accept.className = `${danger ? "danger" : "primary"} eg-confirm-accept`;
    dialog.returnValue = "cancel";
    return new Promise((resolve) => {
      settle = resolve;
      dialog.showModal();
      // Destructive prompts start on Cancel so Enter never confirms by accident.
      dialog.querySelector(danger ? ".eg-confirm-cancel" : ".eg-confirm-accept").focus();
    });
  }

  EG.confirm = confirmAction;
})(globalThis);
