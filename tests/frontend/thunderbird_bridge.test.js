const { test } = require("node:test");
const assert = require("node:assert/strict");
const { Bridge, validateConfig } = require("../../addons/thunderbird/background.js");
const config = { version: 1, endpoint: "https://evergarden.example.invalid/bridge/ingest", account: "work", address: "user@work.test", token: "t".repeat(64), paired_at: new Date().toISOString() };
function fake() {
  let value = { config };
  const api = {
    storage: { local: { get: async () => structuredClone(value), set: async patch => { value = { ...value, ...structuredClone(patch) }; } } },
    accounts: { list: async () => [{ id: "a", type: "imap", identities: [{ email: config.address }], folders: [{ id: "inbox", type: "inbox" }] }] },
    messages: { getRaw: async () => new Blob([Uint8Array.from([0, 128, 255, 13, 10])]), query: async () => ({ messages: [] }) },
  };
  return { api, value: () => value };
}
const header = { id: 123, headerMessageId: "test@work.test", subject: "hello", author: "sender", date: new Date(), size: 5, read: false };
test("durable offline queue survives restart; remove only after acceptance", async () => {
  const f = fake();
  const bridge = new Bridge(f.api, async () => { throw new Error("offline"); });
  await bridge.newMail({ accountId: "a", type: "inbox" }, { messages: [header] });
  assert.equal(f.value().queue.length, 1);
  assert.deepEqual(Buffer.from(f.value().queue[0].payload.raw_base64, "base64"), Buffer.from([0, 128, 255, 13, 10]));
  const badAck = new Bridge(f.api, async () => ({ ok: true, json: async () => ({ accepted: false }) }));
  await badAck.tick();
  assert.equal(f.value().queue.length, 1);
  let uploads = 0;
  const recovered = new Bridge(f.api, async (url) => ({ ok: true, json: async () => {
    if (url.endsWith("ingest")) uploads++;
    return { accepted: true };
  } }));
  await recovered.tick();
  assert.equal(f.value().queue.length, 0);
  assert.equal(uploads, 1);
  await recovered.newMail({ accountId: "a", type: "inbox" }, { messages: [{ ...header, id: 999 }] });
  assert.equal(uploads, 1, "transient Thunderbird IDs do not defeat deduplication");
});
test("ignore unrelated mailbox; restrict pairing destination", async () => {
  const f = fake();
  const bridge = new Bridge(f.api, () => { throw new Error("must not upload"); });
  await bridge.newMail({ accountId: "other", type: "inbox" }, { messages: [header] });
  assert.equal(f.value().queue, undefined);
  assert.throws(() => validateConfig({ ...config, endpoint: "https://evil.test/bridge/ingest" }));
});
test("catchup paginates and suppresses old mail alerts; 401 retains queued data", async () => {
  const f = fake();
  f.api.messages.query = async () => ({ messages: [{ ...header, date: new Date("2026-01-01") }], id: "page2" });
  f.api.messages.continueList = async () => ({ messages: [{ ...header, headerMessageId: "second@work.test" }] });
  const sent = [];
  const bridge = new Bridge(f.api, async (url, options) => ({ ok: true, json: async () => { if (url.endsWith("ingest")) sent.push(JSON.parse(options.body)); return { accepted: true }; } }));
  await bridge.tick();
  assert.equal(sent.length, 2);
  assert.equal(sent[0].notify, false);
  const expired = new Bridge(f.api, async () => ({ ok: false, status: 401 }));
  await expired.newMail({ accountId: "a", type: "inbox" }, { messages: [{ ...header, headerMessageId: "third@work.test" }] });
  assert.equal(f.value().queue.length, 1);
  assert.match(f.value().status.error, /pairing is no longer valid/);
});
