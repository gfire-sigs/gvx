// gvx WebGL CTS guest driver. It serves the CTS tree over loopback HTTP,
// launches Chromium headless-shell through playwright-core, and runs each page
// of the run list in a new page of one browser. Results go to
// GVX_CTS_OUT/results.jsonl, one JSON line for each page attempt.
const { chromium } = require('/opt/playwright-core');
const { execFileSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const path = require('path');
const stream = require('stream');

const rootDir = path.resolve(process.env.GVX_CTS_ROOT || '/opt/webgl-cts');
const outDir = process.env.GVX_CTS_OUT || '/out';
const listFile = process.env.GVX_CTS_LIST;
const mode = process.env.GVX_CTS_MODE;
const probeBin = process.env.GVX_CTS_PROBE || '';
const args = (process.env.GVX_CTS_ARGS || '').split(/\s+/).filter(Boolean);
const pageTimeoutMs = Number(process.env.GVX_CTS_PAGE_TIMEOUT_MS || 300000);
const idleTimeoutMs = Number(process.env.GVX_CTS_IDLE_TIMEOUT_MS || 60000);
const slowFactor = Number(process.env.GVX_CTS_SLOW_FACTOR || 4);
const retryEnabled = (process.env.GVX_CTS_RETRY ?? '1') !== '0';
const maxCrashRun = Number(process.env.GVX_CTS_MAX_CRASH_RUN || 3);

if (!listFile) {
  console.log('GVX-CTS error="GVX_CTS_LIST is not set"');
  process.exit(1);
}
if (!mode) {
  console.log('GVX-CTS error="GVX_CTS_MODE is not set"');
  process.exit(1);
}

const isGpuMode = mode === 'venus' || mode === 'virgl';
const softwareRendererRe = /swiftshader|llvmpipe|lavapipe|softpipe/i;
const probeExitLost = 2;
const probeTimeoutMs = 20000;
const now = () => Number(process.hrtime.bigint() / 1000000n);

// probeDevice runs the virtio-gpu CONTEXT_INIT probe in GPU modes.
// It returns { alive: true } in swiftshader mode or when the device answers.
// It returns { alive: false, lost: true } on EIO (exit 2), and
// { alive: false, error } on any other failure.
function probeDevice() {
  if (!isGpuMode) {
    return { alive: true };
  }
  if (!probeBin) {
    return { alive: false, error: 'GVX_CTS_PROBE is not set' };
  }
  try {
    execFileSync(probeBin, [mode], { timeout: probeTimeoutMs, stdio: ['ignore', 'pipe', 'pipe'] });
    return { alive: true };
  } catch (e) {
    const stderr = e && e.stderr ? String(e.stderr).trim() : '';
    if (e && e.status === probeExitLost) {
      return { alive: false, lost: true, detail: stderr || 'EIO' };
    }
    const detail = stderr || String((e && e.message) || e);
    return { alive: false, error: detail };
  }
}

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css',
  '.json': 'application/json',
  '.txt': 'text/plain; charset=utf-8',
  '.vert': 'text/plain',
  '.frag': 'text/plain',
  '.vs': 'text/plain',
  '.test': 'text/plain',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.bmp': 'image/bmp',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.hdr': 'application/octet-stream',
  '.mp4': 'video/mp4',
  '.m4v': 'video/mp4',
  '.webm': 'video/webm',
  '.ogv': 'video/ogg',
  '.ogg': 'audio/ogg',
  '.wasm': 'application/wasm',
  '.bin': 'application/octet-stream',
};

function serve(req, res) {
  let pathname;
  try {
    const u = new URL(req.url, 'http://127.0.0.1');
    pathname = decodeURIComponent(u.pathname);
  } catch (_) {
    res.writeHead(400);
    res.end();
    return;
  }
  const rel = path.normalize(pathname).replace(/^([/\\])+/, '');
  const file = path.resolve(rootDir, rel);
  if (file !== rootDir && !file.startsWith(rootDir + path.sep)) {
    res.writeHead(403);
    res.end();
    return;
  }
  fs.lstat(file, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, {
      'Content-Type': mimeTypes[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Content-Length': st.size,
      'Cache-Control': 'no-store',
    });
    if (req.method === 'HEAD') {
      res.end();
      return;
    }
    stream.pipeline(fs.createReadStream(file), res, () => {});
  });
}

// harnessScript runs in every frame before the page scripts. It mirrors
// Chromium's webgl_conformance_harness_script.js: subframes share the top
// frame's harness object, quietMode() returns true, and uncaught errors fail
// the page.
function harnessScript() {
  const inIframe = window.parent !== window;
  let h;
  if (!inIframe) {
    h = {
      passed: 0,
      failed: 0,
      skipped: 0,
      finished: false,
      finishedUrl: null,
      messages: [],
      contextLost: 0,
      renderers: [],
      foreignReports: 0,
      lastReportMs: Date.now(),
    };
    h.reportResults = function (url, success, msg, skipped) {
      h.lastReportMs = Date.now();
      if (url && url !== location.pathname) h.foreignReports++;
      if (skipped) {
        h.skipped++;
        return;
      }
      if (success) {
        h.passed++;
        return;
      }
      h.failed++;
      if (h.messages.length < 20) h.messages.push(String(msg).slice(0, 400));
    };
    h.notifyFinished = function (url) {
      h.lastReportMs = Date.now();
      h.finished = true;
      h.finishedUrl = url;
    };
    window.__gvxCts = h;
  } else {
    try {
      h = window.parent.webglTestHarness;
    } catch (_) {
      h = undefined;
    }
  }
  if (!h) return;
  window.webglTestHarness = h;
  window.quietMode = function () {
    return true;
  };
  window.addEventListener('error', (e) => {
    h.reportResults(null, false, 'uncaught: ' + (e.message || String(e)));
    h.notifyFinished(null);
  });

  function wrapGetContext(proto) {
    if (!proto || typeof proto.getContext !== 'function') return;
    const origGetContext = proto.getContext;
    proto.getContext = function (type, ...rest) {
      const ctx = origGetContext.call(this, type, ...rest);
      if (ctx && /webgl/i.test(String(type)) && !this.__gvxLost) {
        this.__gvxLost = true;
        if (typeof this.addEventListener === 'function') {
          this.addEventListener('webglcontextlost', () => {
            h.contextLost++;
          });
        }
        // Do not call getExtension on the page context. An enabled
        // WEBGL_debug_renderer_info changes the result of
        // webgl-debug-renderer-info.html. The driver reads the renderer
        // string from the browser through CDP after the page.
      }
      return ctx;
    };
  }

  wrapGetContext(HTMLCanvasElement.prototype);
  if (typeof OffscreenCanvas !== 'undefined') {
    wrapGetContext(OffscreenCanvas.prototype);
  }
}

function raceTimeout(promise, ms, fallback) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(fallback), Math.max(1, ms));
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function gpuCrashCount(browser) {
  if (!browser || !browser.isConnected()) {
    return { crashes: undefined };
  }
  return raceTimeout(
    (async () => {
      let cdp;
      try {
        cdp = await browser.newBrowserCDPSession();
        const info = await cdp.send('SystemInfo.getInfo');
        await cdp.detach().catch(() => {});
        const aux = (info && info.gpu && info.gpu.auxAttributes) || {};
        return { crashes: aux.processCrashCount, gpu: info && info.gpu };
      } catch (e) {
        if (cdp) await cdp.detach().catch(() => {});
        return { crashes: undefined, error: String(e) };
      }
    })(),
    5000,
    { crashes: undefined, error: 'cdp timeout' },
  );
}

(async () => {
  const pages = fs
    .readFileSync(listFile, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l, idx) => {
      const [v, p, ...flags] = l.split(/\s+/);
      return {
        index: idx,
        webgl: Number(v),
        page: p,
        slow: flags.includes('slow'),
        retry: flags.includes('retry'),
      };
    });

  const server4 = http.createServer(serve);
  await new Promise((resolve, reject) => {
    server4.once('error', reject);
    server4.listen(0, '127.0.0.1', resolve);
  });
  const port = server4.address().port;

  let server6 = null;
  try {
    const s6 = http.createServer(serve);
    s6.on('error', () => {});
    await new Promise((resolve) => {
      s6.once('listening', () => {
        server6 = s6;
        resolve();
      });
      s6.once('error', () => resolve());
      s6.listen(port, '::1');
    });
  } catch (_) {}

  const base = `http://127.0.0.1:${port}/`;
  console.log(`GVX-CTS base=${base} pages=${pages.length} args=${JSON.stringify(args)}`);

  const resultsFd = fs.openSync(path.join(outDir, 'results.jsonl'), 'a');
  let browser = null;
  let ctx = null;
  let crashBase;
  let launches = 0;
  let aborted = false;
  let lastAttempt = null;
  let prevCompleted = null;

  const mainPages = pages.filter((p) => !p.retry);
  const retryPages = pages.filter((p) => p.retry);
  const retryQueued = new Set(retryPages.map((p) => `${p.webgl}/${p.page}`));

  function enqueueRetry(p) {
    const id = `${p.webgl}/${p.page}`;
    if (!retryQueued.has(id)) {
      retryQueued.add(id);
      retryPages.push(p);
    }
  }

  async function launch() {
    if (browser) {
      await raceTimeout(browser.close().catch(() => {}), 5000, undefined);
      browser = null;
      ctx = null;
    }
    lastAttempt = null;
    const t0 = now();
    browser = await chromium.launch({ args, timeout: 60000 });
    launches++;
    ctx = await browser.newContext({ viewport: { width: 800, height: 600 }, deviceScaleFactor: 1 });
    await ctx.addInitScript(harnessScript);
    const info = await gpuCrashCount(browser);
    crashBase = info.crashes;
    if (launches === 1) {
      fs.writeFileSync(path.join(outDir, 'gpu-info.json'), JSON.stringify(info.gpu || info, null, 2) + '\n');
    }
    console.log(
      `GVX-CTS launch=${launches} ms=${now() - t0} version=${browser.version()} gpu_crashes=${crashBase}`,
    );
  }

  async function safeLaunch() {
    try {
      await launch();
      return true;
    } catch (e) {
      console.log('GVX-CTS error=' + JSON.stringify('launch failed: ' + String((e && e.message) || e)));
      console.log('GVX-CTS abort=launch-failed');
      aborted = true;
      return false;
    }
  }

  async function runOnePage(p, attempt) {
    const beforeInfo = await gpuCrashCount(browser);
    if (crashBase === undefined && beforeInfo.crashes !== undefined) {
      crashBase = beforeInfo.crashes;
    }
    const delayedCrash =
      !browser ||
      !browser.isConnected() ||
      (beforeInfo.crashes !== undefined && crashBase !== undefined && beforeInfo.crashes > crashBase);
    if (delayedCrash) {
      const delta =
        beforeInfo.crashes !== undefined && crashBase !== undefined
          ? beforeInfo.crashes - crashBase
          : 1;
      const target = lastAttempt || prevCompleted;
      const prevName = target ? target.pageObj.page : 'none';
      console.log(`GVX-CTS delayed_gpu_crash=1 prev_page=${prevName} delta=${delta}`);
      const delayProbe = probeDevice();
      if (target) {
        const corr = {
          i: target.pageObj.index,
          attempt: target.attempt,
          webgl: target.pageObj.webgl,
          page: target.pageObj.page,
          status: 'crash',
          reason: 'delayed-gpu-process-crash',
          passed: target.rec.passed,
          failed: target.rec.failed,
          skipped: target.rec.skipped,
          ms: target.rec.ms,
          start_unix_ms: target.rec.start_unix_ms,
          context_lost: target.rec.context_lost,
          foreign_reports: target.rec.foreign_reports,
          launch: target.rec.launch,
          renderers: target.rec.renderers,
          software_renderer: target.rec.software_renderer,
          messages: target.rec.messages,
          gpu_crashes: delta,
          device_alive: delayProbe.alive,
          renderer_lost: !delayProbe.alive && Boolean(delayProbe.lost),
        };
        fs.writeSync(resultsFd, JSON.stringify(corr) + '\n');
        if (delayProbe.alive && target.attempt === 1 && retryEnabled) {
          enqueueRetry(target.pageObj);
        }
      }
      if (!delayProbe.alive) {
        if (delayProbe.lost) {
          console.log('GVX-CTS abort=renderer-lost');
        } else {
          console.log('GVX-CTS error=' + JSON.stringify('device probe failed: ' + (delayProbe.error || 'unknown')));
          console.log('GVX-CTS abort=probe-error');
        }
        aborted = true;
        return null;
      }
      if (!(await safeLaunch())) {
        return null;
      }
    }

    // Probe before writing the next page start marker so an asynchronous
    // renderer death after the previous page blames that page, not this one.
    if (isGpuMode) {
      const preProbe = probeDevice();
      if (!preProbe.alive) {
        if (prevCompleted) {
          const corr = {
            i: prevCompleted.pageObj.index,
            attempt: prevCompleted.attempt,
            webgl: prevCompleted.pageObj.webgl,
            page: prevCompleted.pageObj.page,
            status: 'crash',
            reason: 'delayed-gpu-process-crash',
            passed: prevCompleted.rec.passed,
            failed: prevCompleted.rec.failed,
            skipped: prevCompleted.rec.skipped,
            ms: prevCompleted.rec.ms,
            start_unix_ms: prevCompleted.rec.start_unix_ms,
            context_lost: prevCompleted.rec.context_lost,
            foreign_reports: prevCompleted.rec.foreign_reports,
            launch: prevCompleted.rec.launch,
            renderers: prevCompleted.rec.renderers,
            software_renderer: prevCompleted.rec.software_renderer,
            messages: prevCompleted.rec.messages,
            device_alive: false,
            renderer_lost: Boolean(preProbe.lost),
          };
          fs.writeSync(resultsFd, JSON.stringify(corr) + '\n');
        }
        if (preProbe.lost) {
          console.log('GVX-CTS abort=renderer-lost');
        } else {
          console.log('GVX-CTS error=' + JSON.stringify('device probe failed: ' + (preProbe.error || 'unknown')));
          console.log('GVX-CTS abort=probe-error');
        }
        aborted = true;
        return null;
      }
    }

    const hardLimit = p.slow ? pageTimeoutMs * slowFactor : pageTimeoutMs;
    const idleLimit = p.slow ? idleTimeoutMs * slowFactor : idleTimeoutMs;
    const url = base + p.page + (p.webgl > 1 ? '?webglVersion=' + p.webgl : '');
    const t0 = now();
    const rec = {
      i: p.index,
      attempt,
      webgl: p.webgl,
      page: p.page,
      status: 'error',
      reason: '',
      passed: 0,
      failed: 0,
      skipped: 0,
      ms: 0,
      start_unix_ms: Date.now(),
      context_lost: 0,
      foreign_reports: 0,
      launch: launches,
      renderers: [],
      software_renderer: false,
      messages: [],
    };

    const startRec = {
      kind: 'start',
      i: p.index,
      attempt,
      webgl: p.webgl,
      page: p.page,
      start_unix_ms: rec.start_unix_ms,
    };
    fs.writeSync(resultsFd, JSON.stringify(startRec) + '\n');

    let page = null;
    let crashed = false;
    let timeoutReason = '';
    let driverError = '';

    try {
      page = await raceTimeout(ctx.newPage(), 30000, null);
      if (!page) {
        throw new Error('newPage timed out after 30000ms');
      }
      page.on('crash', () => {
        crashed = true;
      });
      const deadline = t0 + hardLimit;
      let navTimedOut = false;
      try {
        await page.goto(url, { timeout: Math.min(hardLimit, idleLimit), waitUntil: 'commit' });
      } catch (e) {
        const msg = String(e).slice(0, 300);
        if (crashed || !browser.isConnected()) {
          // Classified as crash below.
        } else if (/Timeout/i.test(msg)) {
          navTimedOut = true;
          timeoutReason = 'unresponsive';
        } else {
          driverError = msg;
        }
      }

      if (!crashed && !navTimedOut && !driverError) {
        let lastActivity = now();
        let lastCount = -1;
        let lastReportMs = 0;

        while (true) {
          if (crashed || !browser.isConnected()) break;
          const remHard = deadline - now();
          const remIdle = lastActivity + idleLimit - now();
          if (remHard <= 0) {
            timeoutReason = 'limit';
            break;
          }
          if (remIdle <= 0) {
            timeoutReason = 'idle';
            break;
          }
          const waitMs = Math.min(remHard, remIdle);
          const state = await raceTimeout(
            page
              .evaluate(() => {
                const h = window.__gvxCts;
                if (!h) return null;
                return {
                  finished: h.finished,
                  passed: h.passed,
                  failed: h.failed,
                  skipped: h.skipped,
                  lastReportMs: h.lastReportMs,
                };
              })
              .catch((e) => ({ evalError: String(e) })),
            Math.max(100, waitMs),
            'stuck',
          );
          if (crashed || !browser.isConnected()) break;
          if (state === 'stuck') {
            timeoutReason = now() >= deadline ? 'limit' : 'unresponsive';
            break;
          }
          if (state && !state.evalError) {
            const count = state.passed + state.failed + state.skipped;
            if (count !== lastCount || state.lastReportMs !== lastReportMs) {
              lastCount = count;
              lastReportMs = state.lastReportMs;
              lastActivity = now();
            }
            if (state.finished) break;
          }
          await new Promise((r) => setTimeout(r, 100));
        }
      }

      const full =
        crashed || !browser.isConnected() || driverError
          ? null
          : await raceTimeout(
              page.evaluate(() => window.__gvxCts).catch(() => null),
              5000,
              null,
            );
      if (full) {
        rec.passed = full.passed || 0;
        rec.failed = full.failed || 0;
        rec.skipped = full.skipped || 0;
        rec.messages = Array.isArray(full.messages) ? full.messages : [];
        rec.context_lost = full.contextLost || 0;
        rec.renderers = Array.isArray(full.renderers) ? full.renderers : [];
        rec.foreign_reports = full.foreignReports || 0;
      }

      if (crashed) {
        rec.status = 'crash';
        rec.reason = 'renderer-crash';
      } else if (driverError) {
        rec.status = 'error';
        rec.reason = driverError;
      } else if (timeoutReason) {
        rec.status = 'timeout';
        rec.reason = timeoutReason;
      } else if (!full || !full.finished) {
        rec.status = 'timeout';
        rec.reason = 'unresponsive';
      } else if (full.failed > 0) {
        rec.status = 'fail';
      } else if (full.passed === 0) {
        rec.status = 'fail';
        rec.reason = 'no-results';
      } else {
        rec.status = 'pass';
      }
    } catch (e) {
      rec.status = 'error';
      rec.reason = String(e).slice(0, 300);
    }

    rec.ms = now() - t0;
    if (page) {
      await raceTimeout(page.close().catch(() => {}), 5000, undefined);
    }

    const afterInfo = await gpuCrashCount(browser);
    if (!browser.isConnected()) {
      rec.status = 'crash';
      rec.reason = 'browser-disconnected';
    } else if (
      afterInfo.crashes !== undefined &&
      crashBase !== undefined &&
      afterInfo.crashes > crashBase
    ) {
      rec.status = 'crash';
      rec.reason = 'gpu-process-crash';
      rec.gpu_crashes = afterInfo.crashes - crashBase;
      crashBase = afterInfo.crashes;
    }

    // The GPU process reports the renderer of its current GL context. After
    // a fallback to software it reports the software renderer.
    const aux = (afterInfo.gpu && afterInfo.gpu.auxAttributes) || {};
    if (aux.glRenderer) {
      rec.renderers = [String(aux.glRenderer)];
    }

    if (isGpuMode && rec.renderers.some((r) => softwareRendererRe.test(r))) {
      rec.software_renderer = true;
    }

    const probe = probeDevice();
    rec.device_alive = probe.alive;
    if (!probe.alive && probe.lost) {
      rec.renderer_lost = true;
    }

    fs.writeSync(resultsFd, JSON.stringify(rec) + '\n');
    console.log(
      `GVX-CTS attempt=${attempt} page=${p.index + 1}/${pages.length} status=${rec.status} ms=${rec.ms} pass=${rec.passed} fail=${rec.failed} device_alive=${rec.device_alive} ${p.page}${rec.reason ? ' reason=' + rec.reason : ''}`,
    );
    if (!probe.alive) {
      if (probe.lost) {
        console.log('GVX-CTS abort=renderer-lost');
      } else {
        console.log('GVX-CTS error=' + JSON.stringify('device probe failed: ' + (probe.error || 'unknown')));
        console.log('GVX-CTS abort=probe-error');
      }
      aborted = true;
      return null;
    }
    lastAttempt = { pageObj: p, attempt, rec };
    prevCompleted = lastAttempt;
    return rec;
  }

  const tStart = now();
  let crashRun = 0;

  if (isGpuMode) {
    const initProbe = probeDevice();
    if (!initProbe.alive) {
      if (initProbe.error) {
        console.log('GVX-CTS error=' + JSON.stringify('startup probe failed: ' + initProbe.error));
      }
      console.log('GVX-CTS abort=device-dead-at-start');
      aborted = true;
    }
  }

  if (!aborted && mainPages.length > 0 && (await safeLaunch())) {
    for (const p of mainPages) {
      const rec = await runOnePage(p, 1);
      if (!rec) break;
      if (rec.status !== 'pass' && retryEnabled) enqueueRetry(p);
      if (rec.status === 'crash' || rec.status === 'timeout' || rec.status === 'error') {
        crashRun = rec.status === 'crash' ? crashRun + 1 : 0;
        if (crashRun >= maxCrashRun) {
          console.log('GVX-CTS abort=crash-run');
          aborted = true;
          break;
        }
        if (!(await safeLaunch())) break;
      } else {
        crashRun = 0;
      }
    }
  }

  if (!aborted && retryEnabled && retryPages.length > 0) {
    console.log(`GVX-CTS retry_pages=${retryPages.length}`);
    crashRun = 0;
    if (await safeLaunch()) {
      for (const p of retryPages) {
        const rec = await runOnePage(p, 2);
        if (!rec) break;
        if (rec.status === 'crash' || rec.status === 'timeout' || rec.status === 'error') {
          crashRun = rec.status === 'crash' ? crashRun + 1 : 0;
          if (crashRun >= maxCrashRun) {
            console.log('GVX-CTS abort=crash-run');
            aborted = true;
            break;
          }
          if (!(await safeLaunch())) break;
        } else {
          crashRun = 0;
        }
      }
    }
  }

  console.log(`GVX-CTS total_ms=${now() - tStart} launches=${launches}`);
  if (browser) {
    await raceTimeout(browser.close().catch(() => {}), 5000, undefined);
  }
  server4.close();
  if (server6) server6.close();
  fs.closeSync(resultsFd);
  if (!aborted) {
    console.log('GVX-CTS done');
    process.exit(0);
  }
  process.exit(1);
})().catch((e) => {
  console.log('GVX-CTS error=' + JSON.stringify(String((e && e.stack) || e)));
  process.exit(1);
});
