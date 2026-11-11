import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { isAbsolute } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

// Serve only source HTML: no RainScanner executable, live API, or remote feed.
// PLAYWRIGHT_MODULE may point to an existing playwright-core index.mjs file.
// CHROMIUM_PATH may point to an existing Chromium; otherwise use Playwright's cache.
const TIMEOUT = 10000;
const CASE_TIMEOUT = 15000;
const htmlPath = new URL('../internal/web/static/index.html', import.meta.url);
const modulePath = process.env.PLAYWRIGHT_MODULE || 'playwright-core';
const playwrightModule = isAbsolute(modulePath) ? pathToFileURL(modulePath).href : modulePath;
const executablePath = process.env.CHROMIUM_PATH;
const results = [];
let scheduledCases = 0;
const serverApiLeaks = [];
let server;
let browser;
let origin;

const clone = value => structuredClone(value);
const fixtureTargets = () => [
  { name: 'A', cidrs: ['192.0.2.0/30'], api_url: 'https://a.invalid/fixture.txt', builtin: false },
  { name: 'B', cidrs: ['198.51.100.0/30'], api_url: 'https://b.invalid/fixture.txt', builtin: false },
];
const resultFixture = {
  ranges: 1, ranges_v4: 1, ranges_v6: 0,
  hosts: 4, hosts_v4: 4, hosts_v6: 0,
  tcp_open: 1, tcp_ips: ['192.0.2.1'], confirmed_ips: [], configs: [],
};

async function bounded(promise, description, timeout = TIMEOUT) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Timed out: ${description}`)), timeout);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function until(predicate, description) {
  const deadline = Date.now() + TIMEOUT;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await delay(20);
  }
  throw new Error(`Timed out: ${description}`);
}

function gate() {
  let release;
  const promise = new Promise(resolve => { release = resolve; });
  return { release, wait: () => bounded(promise, 'fixture gate') };
}

const requests = (state, path) => state.requests.filter(request => request.path === path);
const posts = state => state.requests.filter(request => request.method === 'POST');
const openEdit = (page, name) => page.locator(`#cdns .pick[data-name="${name}"] .edit`).click();

async function isolated(name, test, options = {}) {
  scheduledCases++;
  const context = await browser.newContext({
    viewport: options.mobile ? { width: 390, height: 844 } : { width: 1365, height: 1000 },
    isMobile: !!options.mobile, hasTouch: !!options.mobile,
    reducedMotion: 'reduce', serviceWorkers: 'block',
  });
  context.setDefaultTimeout(TIMEOUT);
  context.setDefaultNavigationTimeout(TIMEOUT);
  const state = {
    records: fixtureTargets(), requests: [], routeErrors: [], pageErrors: [],
    dialogs: [], active: false, scanCount: 0, gates: [], pendingRoutes: new Set(),
    save400: false, reloadGate: null, scanGate: null,
  };
  state.hold = () => { const value = gate(); state.gates.push(value); return value; };
  const entries = new Map();
  let closing = false;
  let failure;
  try {
    await bounded((async () => {
      // Keep fetch, scripts, DOM events and rendering real. Control only the
      // stream transport and clipboard so error paths need no external service.
      await context.addInitScript(({ rejectClipboard }) => {
        const streams = [];
        const audit = { clipboardCalls: [], rejectedWrites: [], rejections: [] };
        class ControlledEventSource extends EventTarget {
          static CONNECTING = 0;
          static OPEN = 1;
          static CLOSED = 2;
          CONNECTING = 0;
          OPEN = 1;
          CLOSED = 2;
          constructor(url) {
            super();
            this.url = new URL(url, location.href).href;
            this.readyState = this.OPEN;
            this.withCredentials = false;
            streams.push(this);
          }
          close() { this.readyState = this.CLOSED; }
          emit(value, id) {
            if (this.readyState === this.CLOSED) throw new Error('Emitting on a closed fixture stream');
            this.readyState = this.OPEN;
            const event = new MessageEvent('message', { data: JSON.stringify(value), lastEventId: String(id) });
            this.dispatchEvent(event);
            this.onmessage?.(event);
          }
          fail() {
            if (this.readyState === this.CLOSED) throw new Error('Failing a closed fixture stream');
            this.readyState = this.CONNECTING;
            const event = new Event('error');
            this.dispatchEvent(event);
            this.onerror?.(event);
          }
        }
        Object.defineProperty(window, 'EventSource', { configurable: true, value: ControlledEventSource });
        Object.defineProperty(navigator, 'clipboard', {
          configurable: true,
          value: { writeText(text) {
            audit.clipboardCalls.push(String(text));
            if (rejectClipboard) {
              audit.rejectedWrites.push(String(text));
              return Promise.reject(new DOMException('Fixture clipboard denied', 'NotAllowedError'));
            }
            return Promise.resolve();
          } },
        });
        window.addEventListener('unhandledrejection', event => audit.rejections.push(String(event.reason)));
        window.__regression = {
          audit,
          streams: () => streams.map(stream => ({ url: stream.url, readyState: stream.readyState })),
          emit: (index, value, id) => streams[index].emit(value, id),
          fail: index => streams[index].fail(),
        };
      }, { rejectClipboard: !!options.rejectClipboard });

      context.on('requestfailed', request => {
        const entry = entries.get(request);
        if (entry) entry.failure = request.failure()?.errorText || 'Request failed';
      });
      context.on('requestfinished', request => {
        const entry = entries.get(request);
        if (entry) entry.received = true;
      });
      await context.route('**/*', route => {
        const operation = (async () => {
          const request = route.request();
          const url = new URL(request.url());
          if (url.origin !== origin) {
            await route.abort('blockedbyclient');
            return;
          }
          if (!url.pathname.startsWith('/api/')) {
            if (url.pathname === '/' || url.pathname === '/index.html') await route.continue();
            else await route.abort('blockedbyclient');
            return;
          }
          const entry = {
            method: request.method(), path: url.pathname,
            body: request.postDataJSON(), status: null, finished: false,
          };
          entries.set(request, entry);
          state.requests.push(entry);
          const reply = async (status, body) => {
            entry.status = status;
            await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
          };
          try {
            if (entry.path === '/api/targets' && entry.method === 'GET') {
              await reply(200, state.records);
            } else if (entry.path === '/api/targets' && entry.method === 'POST') {
              if (state.save400) {
                await reply(400, { error: 'Fixture prerequisite save rejected' });
                return;
              }
              const record = clone(entry.body);
              record.name = record.name.trim();
              const index = state.records.findIndex(value => value.name.toLowerCase() === record.name.toLowerCase());
              // The real API upserts by name; do not mask a UI collision bug.
              record.api_url ||= index >= 0 ? state.records[index].api_url : '';
              record.builtin = index >= 0 ? state.records[index].builtin : false;
              if (index >= 0) state.records[index] = record;
              else state.records.push(record);
              await reply(200, record);
            } else if (entry.path === '/api/targets/reload' && entry.method === 'POST') {
              if (state.reloadGate) await state.reloadGate.wait();
              const record = state.records.find(value => value.name === entry.body.name);
              assert.ok(record, 'Reload requested an unknown target');
              record.cidrs = ['203.0.113.0/30'];
              await reply(200, record);
            } else if (entry.path === '/api/scan' && entry.method === 'POST') {
              state.scanCount++;
              if (state.active) { await reply(409, { error: 'scan already running' }); return; }
              state.active = true;
              const id = `fixture-scan-${state.scanCount}`;
              if (state.scanGate) await state.scanGate.wait();
              await reply(200, { id });
            } else if (entry.path === '/api/stop' && entry.method === 'POST') {
              state.active = false;
              await reply(200, { ok: true });
            } else {
              throw new Error(`Unconfigured API fixture: ${entry.method} ${entry.path}`);
            }
          } catch (error) {
            // Closing the editor aborts fetch while its gated route is pending.
            // Only that exact cancellation is expected, never arbitrary errors.
            const canceledReload = entry.path === '/api/targets/reload' && /ERR_ABORTED/i.test(entry.failure || '');
            if (!closing && !canceledReload) state.routeErrors.push(String(error));
            await route.abort('failed').catch(() => {});
          } finally {
            entry.finished = true;
          }
        })();
        state.pendingRoutes.add(operation);
        return operation.catch(error => {
          if (!closing) state.routeErrors.push(String(error));
        }).finally(() => state.pendingRoutes.delete(operation));
      });
      const page = await context.newPage();
      page.on('pageerror', error => state.pageErrors.push(String(error)));
      page.on('dialog', async dialog => {
        state.dialogs.push({ type: dialog.type(), message: dialog.message() });
        await dialog.dismiss();
      });
      await page.goto(origin, { waitUntil: 'domcontentloaded' });
      await page.locator('#cdns .pick[data-name="A"].on').waitFor({ state: 'attached' });
      await page.locator('#cdns .pick[data-name="B"]').waitFor({ state: 'attached' });
      await test(page, state);
      await until(() => state.pendingRoutes.size === 0, 'all fixture operations to finish');
      assert.deepEqual(state.routeErrors, [], 'Unexpected fixture errors');
      assert.deepEqual(state.pageErrors, [], 'Unexpected application errors');
      assert.deepEqual(await page.evaluate(() => window.__regression.audit.rejections), [], 'Unhandled promise rejection');
      assert.deepEqual(serverApiLeaks, [], 'API requests escaped the browser mocks');
    })(), name, CASE_TIMEOUT);
  } catch (error) {
    failure = error;
  } finally {
    closing = true;
    state.gates.forEach(value => value.release());
    try { await bounded(context.close(), `${name} context cleanup`); }
    catch (error) { failure ||= error; }
  }
  results.push({ name, passed: !failure });
  if (failure) {
    console.error(`FAIL ${name}: ${failure.stack || failure}`);
    console.error(`Requests: ${JSON.stringify(state.requests)}`);
  } else {
    console.log(`PASS ${name}`);
  }
}

async function waitStream(page, count = 1) {
  await page.waitForFunction(count => window.__regression.streams().length === count, count);
}

async function finishScan(page, state, index = 0) {
  await page.evaluate(({ result, index }) => {
    window.__regression.emit(index, { type: 'progress', data: { cdn: 'A', stage: 'tcp', done: 4, total: 4 } }, 1);
    window.__regression.emit(index, { type: 'result', data: result }, 2);
    window.__regression.emit(index, { type: 'done', data: { status: 'done' } }, 3);
  }, { result: resultFixture, index });
  state.active = false;
  await page.waitForFunction(() => document.getElementById('status').textContent === 'done');
}

async function completeScan(page, state) {
  await page.locator('#go').click();
  await waitStream(page);
  await finishScan(page, state);
}

async function runTests() {
  for (const mobile of [false, true]) {
    await isolated(`start_result_done_${mobile ? 'mobile' : 'desktop'}`, async (page, state) => {
      if (mobile) {
        assert.equal(await page.locator('#hamburger').isVisible(), true);
        await page.locator('#hamburger').click();
        await page.locator('#cdns .pick[data-name="B"] .nm').click();
        await page.locator('#cdns .pick[data-name="A"] .nm').click();
      }
      await completeScan(page, state);
      if (mobile) {
        assert.equal(await page.locator('body').evaluate(element => element.classList.contains('drawer-open')), false);
      }
      const actual = await page.evaluate(() => ({
        label: document.getElementById('goLabel').textContent,
        disabled: document.getElementById('go').disabled,
        status: document.getElementById('status').textContent,
        tcp: document.getElementById('tcpips').textContent,
        progress: document.getElementById('pfill').style.width,
        stream: window.__regression.streams()[0],
      }));
      const streamURL = new URL(actual.stream.url);
      assert.equal(streamURL.origin, origin);
      assert.equal(streamURL.pathname, '/api/stream');
      assert.equal(streamURL.searchParams.get('id'), 'fixture-scan-1');
      assert.equal(streamURL.searchParams.get('after'), '0');
      assert.deepEqual({ ...actual, stream: actual.stream.readyState }, {
        label: 'Start scan', disabled: false, status: 'done', tcp: '192.0.2.1', progress: '100%', stream: 2,
      });
      assert.equal(requests(state, '/api/scan').length, 1);
      assert.equal(requests(state, '/api/scan')[0].body.cdn, 'A');
      assert.equal(requests(state, '/api/stop').length, 0);
    }, { mobile });
  }

  await isolated('pending_start_is_disabled', async (page, state) => {
    state.scanGate = state.hold();
    await page.locator('#go').click();
    await until(() => requests(state, '/api/scan').length === 1, 'pending scan request');
    assert.equal(requests(state, '/api/scan')[0].status, null);
    assert.equal(await page.locator('#go').isDisabled(), true, 'Pending Start must be disabled');
    assert.equal(requests(state, '/api/scan').length, 1, 'Do not issue a second click while Start is pending');
    assert.equal(requests(state, '/api/stop').length, 0);
    state.scanGate.release();
    await waitStream(page);
    assert.equal(await page.locator('#go').isEnabled(), true);
    await finishScan(page, state);
    assert.equal(requests(state, '/api/scan').length, 1);
  });

  await isolated('transient_stream_error_preserves_stop', async (page, state) => {
    await page.locator('#go').click();
    await waitStream(page);
    await page.evaluate(() => window.__regression.fail(0));
    const afterError = await page.evaluate(() => ({
      label: document.getElementById('goLabel').textContent,
      disabled: document.getElementById('go').disabled,
      readyState: window.__regression.streams()[0].readyState,
    }));
    assert.deepEqual(afterError, { label: 'Stop', disabled: false, readyState: 0 }, 'CONNECTING must not close or abandon the scan');
    assert.equal(state.active, true);
    await page.locator('#go').click();
    await until(() => requests(state, '/api/stop').some(request => request.status === 200), 'Stop API response');
    assert.equal(requests(state, '/api/scan').length, 1);
    assert.equal(requests(state, '/api/stop').length, 1);
    assert.equal(await page.evaluate(() => window.__regression.streams()[0].readyState), 0, 'Wait for terminal status before closing');
    await page.evaluate(() => window.__regression.emit(0, { type: 'done', data: { status: 'stopped' } }, 1));
    await page.waitForFunction(() => document.getElementById('status').textContent === 'stopped');
    assert.equal(await page.locator('#goLabel').textContent(), 'Start scan');
    assert.equal(await page.locator('#go').isEnabled(), true);
    assert.equal(await page.evaluate(() => window.__regression.streams()[0].readyState), 2);
  });

  await isolated('canceled_reload_cannot_write_next_editor', async (page, state) => {
    state.reloadGate = state.hold();
    await openEdit(page, 'A');
    await page.locator('#cReload').click();
    await until(() => requests(state, '/api/targets/reload').length === 1, 'pending A reload');
    const operation = requests(state, '/api/targets/reload')[0];
    assert.equal(operation.body.name, 'A');
    await page.locator('#cCancel').click();
    await openEdit(page, 'B');
    const expectedRanges = fixtureTargets()[1].cidrs.join('\n');
    assert.equal(await page.locator('#cRanges').inputValue(), expectedRanges);
    // Release even an aborted route, then wait for both its fixture operation
    // and browser request to close before inspecting the new editor.
    state.reloadGate.release();
    await until(() => operation.finished && (operation.received || operation.failure), 'closed A reload operation');
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await page.locator('#cName').inputValue(), 'B');
    assert.equal(await page.locator('#cRanges').inputValue(), expectedRanges, 'A response must never overwrite B');
    assert.equal(await page.locator('#cReloadMsg').textContent(), '', 'Closed A operation must not write B status');
    assert.equal(await page.locator('#cReload').isEnabled(), true);
    assert.equal(await page.locator('#cSave').isEnabled(), true);
    assert.deepEqual(state.records.find(record => record.name === 'B'), fixtureTargets()[1]);
  });

  await isolated('existing_target_names_are_read_only', async (page, state) => {
    for (const name of ['A', 'B']) {
      await openEdit(page, name);
      assert.equal(await page.locator('#cName').inputValue(), name);
      assert.equal(await page.locator('#cName').isDisabled(), true, 'Existing target identity must not be editable');
      await page.locator('#cCancel').click();
    }
    assert.deepEqual(posts(state), []);
    assert.deepEqual(state.records, fixtureTargets());
  });

  await isolated('new_target_name_collision_is_rejected', async (page, state) => {
    await page.locator('#addcustom').click();
    assert.equal(await page.locator('#cName').isEnabled(), true);
    await page.locator('#cName').fill(' b ');
    await page.locator('#cRanges').fill('203.0.113.0/30');
    await page.locator('#cSave').click();
    await until(() => state.dialogs.length > 0 || posts(state).length > 0, 'collision rejection');
    assert.deepEqual(posts(state), [], 'Collision must be rejected before any upsert');
    assert.deepEqual(state.records, fixtureTargets(), 'Collision must preserve both existing targets');
    assert.match(state.dialogs[0]?.message || '', /exists|duplicate|collision/i);
    assert.equal(await page.locator('#overlay').evaluate(element => element.classList.contains('show')), true);
    await page.locator('#cUrl').fill('https://collision.invalid/fixture.txt');
    await page.locator('#cReload').click();
    await page.waitForFunction(() => !document.getElementById('cReload').disabled);
    assert.deepEqual(posts(state), [], 'Reload must not upsert a colliding new name either');
    assert.deepEqual(state.records, fixtureTargets());
    assert.match(await page.locator('#cReloadMsg').textContent(), /exists|duplicate|collision/i);
  });

  await isolated('save_400_prevents_reload', async (page, state) => {
    state.save400 = true;
    await openEdit(page, 'A');
    await page.locator('#cUrl').fill('file:///fixture-must-not-be-read');
    await page.locator('#cReload').click();
    await until(() => posts(state).some(request => request.path === '/api/targets' && request.status === 400), 'save 400');
    await page.waitForFunction(() => !document.getElementById('cReload').disabled);
    assert.equal(requests(state, '/api/targets/reload').length, 0, 'Failed prerequisite save must stop reload');
    assert.deepEqual(state.records, fixtureTargets());
    assert.equal(await page.locator('#cRanges').inputValue(), fixtureTargets()[0].cidrs.join('\n'));
    assert.match(await page.locator('#cReloadMsg').textContent(), /fail|reject|400/i, 'Save error must be visible');
  });

  await isolated('new_target_reload_can_be_saved_and_reloaded', async (page, state) => {
    await page.locator('#addcustom').click();
    await page.locator('#cName').fill('new-feed');
    await page.locator('#cUrl').fill('https://new.invalid/fixture');
    await page.locator('#cReload').click();
    await page.waitForFunction(() => document.getElementById('cReloadMsg').textContent.includes('loaded'));
    assert.equal(await page.locator('#cName').isDisabled(), true);
    await page.locator('#cReload').click();
    await until(() => requests(state, '/api/targets/reload').length === 2, 'second reload');
    await page.waitForFunction(() => !document.getElementById('cReload').disabled);
    await page.locator('#cRanges').fill('198.51.100.0/30');
    await page.locator('#cSave').click();
    await page.waitForFunction(() => !document.getElementById('overlay').classList.contains('show'));
    assert.deepEqual(state.records.find(record => record.name === 'new-feed').cidrs, ['198.51.100.0/30']);
    assert.deepEqual(state.dialogs, []);
  });

  for (const status of ['stopped', 'error']) {
    await isolated(`partial_${status}_clears_incomplete_results`, async (page, state) => {
      await page.locator('#go').click();
      await waitStream(page);
      await page.evaluate(({ status, result }) => {
        window.__regression.emit(0, { type: 'result', data: { ...result, confirmed_ips: ['192.0.2.1'], configs: ['vless://fixture'] } }, 1);
        window.__regression.emit(0, { type: 'done', data: { status } }, 2);
      }, { status, result: resultFixture });
      state.active = false;
      assert.equal(await page.locator('#status').textContent(), status);
      assert.equal(await page.locator('#copyConfigs').isVisible(), false);
      assert.equal(await page.locator('#xraySub').isVisible(), false);
      assert.equal(await page.locator('#tcpCount').textContent(), '');
      assert.equal(await page.locator('#xrayips').textContent(), '');
      assert.equal(await page.locator('#goLabel').textContent(), 'Start scan');
    });
  }

  await isolated('clipboard_denial_does_not_claim_success', async (page, state) => {
    await completeScan(page, state);
    await page.locator('#copyTcp').click();
    await page.waitForFunction(() => window.__regression.audit.clipboardCalls.length === 1 && !document.getElementById('copyTcp').disabled);
    const actual = await page.evaluate(() => ({
      label: document.getElementById('copyTcp').textContent,
      clipboardCalls: window.__regression.audit.clipboardCalls,
      rejectedWrites: window.__regression.audit.rejectedWrites,
    }));
    assert.deepEqual(actual.clipboardCalls, ['192.0.2.1']);
    assert.deepEqual(actual.rejectedWrites, ['192.0.2.1']);
    assert.doesNotMatch(actual.label, /copied/i, 'Denied clipboard write must not display success');
    assert.match(actual.label, /fail|denied|unable/i, 'Clipboard denial must be visible');
  }, { rejectClipboard: true });
}

// A last-resort deadline also bounds launch/teardown and unexpected hung APIs.
const watchdog = setTimeout(() => {
  console.error('FAIL harness: exceeded 180s suite deadline');
  process.exit(1);
}, 180000);

try {
  const html = await readFile(htmlPath);
  const { chromium } = await import(playwrightModule);
  server = createServer((request, response) => {
    if (request.url === '/' || request.url === '/index.html') {
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      response.end(html);
    } else {
      if (request.url?.startsWith('/api/')) serverApiLeaks.push(request.url);
      response.writeHead(404);
      response.end('No live backend exists in this harness');
    }
  });
  server.requestTimeout = TIMEOUT;
  server.headersTimeout = TIMEOUT;
  await bounded(new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  }), 'local fixture server startup');
  origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({
    ...(executablePath ? { executablePath } : {}),
    headless: true, timeout: TIMEOUT,
    // Routing blocks remote requests; DNS denial also blocks decorative
    // preconnects, which do not pass through Playwright's request routing.
    args: [
      '--disable-background-networking', '--disable-component-update',
      '--disable-domain-reliability', '--no-pings',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost',
    ],
  });
  await runTests();
  assert.deepEqual(serverApiLeaks, [], 'API requests escaped the browser mocks');
} catch (error) {
  results.push({ name: 'harness', passed: false });
  console.error(`FAIL harness: ${error.stack || error}`);
} finally {
  const cleanup = [
    async () => { if (browser) await bounded(browser.close(), 'browser cleanup'); },
    async () => { if (server?.listening) {
      server.closeAllConnections();
      await bounded(new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())), 'server cleanup');
    } },
  ];
  for (const close of cleanup) {
    try { await close(); }
    catch (error) {
      results.push({ name: 'cleanup', passed: false });
      console.error(`FAIL cleanup: ${error.message}`);
    }
  }
  clearTimeout(watchdog);
  const failed = results.filter(result => !result.passed).length;
  console.log(`${results.length - failed} passed, ${failed} failed`);
  process.exitCode = failed || scheduledCases === 0 || results.length !== scheduledCases ? 1 : 0;
}
