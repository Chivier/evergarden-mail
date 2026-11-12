# UI preview

A fictional-data preview of both web UIs for design work and README screenshots.
`mock.py` serves the real static files from `apps/` under the production
Content-Security-Policy and answers the API with made-up mailboxes and
approvals. It imports no project code and reads no configuration or secrets.

```bash
# Browse by hand
python3 tools/ui-preview/mock.py mail 48711 --approval-url http://127.0.0.1:48712 &
python3 tools/ui-preview/mock.py approval 48712 &
# then open http://127.0.0.1:48711/ and http://127.0.0.1:48712/review

# Screenshots (needs playwright-core and a Chromium build)
PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core \
CHROMIUM_EXECUTABLE=/path/to/chrome \
node tools/ui-preview/shots.js matrix /tmp/evergarden-shots   # en + zh-CN, light + dark, 1440 + 390 px
node tools/ui-preview/shots.js readme docs/assets/screenshots  # the README set
```

`shots.js` starts both mock servers on `127.0.0.1` (ports `PREVIEW_PORT` and
the next one, default 48711) and reports console errors, horizontal overflow
and a wrong `<html lang>`. Without a CJK font the README set hides the
language switcher so the "中文" label never renders as empty boxes.
