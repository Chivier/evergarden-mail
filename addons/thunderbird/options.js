"use strict";
// English and Simplified Chinese, chosen from Thunderbird's UI language.
const STRINGS = {
  en: {
    title: "Evergarden bridge",
    heading: "Evergarden mail bridge",
    intro: "First sign in to the company Google mailbox in Thunderbird. Download the pairing file from the Evergarden workbench, then import it here. No Google Cloud app is needed.",
    scope: "The bridge only receives Inbox mail. The first run backfills the last 7 days, and mail from before pairing does not trigger new-mail alerts. Keep Thunderbird running; mail and the upload queue stay on this machine and in Evergarden.",
    import: "Import pairing file",
    sync: "Retry now / backfill",
    limits: "Each message is limited to 16 MiB; read larger ones in Thunderbird. After more than 7 days offline, check for missing mail by hand.",
    unpaired: "Not paired yet",
    invalidFile: "Choose a valid pairing file",
  },
  "zh-CN": {
    title: "Evergarden 桥接",
    heading: "Evergarden 邮件桥接",
    intro: "先在 Thunderbird 登录 公司 Google 邮箱。在 Evergarden 工作台下载配对文件，然后在这里导入。无需创建 Google Cloud 应用。",
    scope: "桥接只接收收件箱邮件；首次补收最近 7 天，配对前邮件不触发新邮件提醒。请保持 Thunderbird 运行，邮件和待上传队列仅保存在本机与 Evergarden。",
    import: "导入配对文件",
    sync: "立即重试 / 补收",
    limits: "单封邮件上限 16 MiB；超过上限时请在 Thunderbird 查看。断线超过 7 天需人工核对缺失邮件。",
    unpaired: "尚未配对",
    invalidFile: "请选择有效的配对文件",
  },
};
const locale = String(navigator.language || "").toLowerCase().startsWith("zh") ? "zh-CN" : "en";
const text = (key) => STRINGS[locale][key] || STRINGS.en[key];
document.documentElement.lang = locale;
for (const element of document.querySelectorAll("[data-i18n]")) element.textContent = text(element.dataset.i18n);

const status = document.getElementById("status");
async function showStatus() {
  const value = await browser.storage.local.get(["status", "config"]);
  status.textContent = `${value.config ? value.config.address : text("unpaired")}\n${JSON.stringify(value.status || {}, null, 2)}`;
}
document.getElementById("config").addEventListener("change", async event => {
  try {
    const file = event.target.files[0];
    if (!file || file.size > 4096) throw new Error(text("invalidFile"));
    await browser.runtime.sendMessage({ type: "bridge-config", config: JSON.parse(await file.text()) });
    await showStatus();
  } catch (error) { status.textContent = error.message; }
  event.target.value = "";
});
document.getElementById("sync").addEventListener("click", async () => {
  try { await browser.runtime.sendMessage({ type: "bridge-sync" }); await showStatus(); }
  catch (error) { status.textContent = error.message; }
});
void showStatus();
setInterval(showStatus, 5000);
