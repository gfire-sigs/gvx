// gvx gate G2 driver. For each browser in GVX_G2_CHANNELS it launches
// Chromium through playwright-core with the flags in GVX_G2_ARGS and:
//   1. loads the Phase 0 WebGL probe (/workspace/webgl-probe.html) and saves
//      its text and a canvas screenshot;
//   2. loads the scene (/workspace/gpu/webgl-scene.html) and saves its JSON
//      result and a canvas screenshot;
//   3. saves the GPU information of the browser (CDP SystemInfo.getInfo);
//   4. loads the probe again in a new tab of the same browser (the second
//      page: pipelines that the first page compiled are warm);
//   5. runs one WebGL load page and saves its frame time.
// GVX_G2_NAV_TIMEOUTS sets the timeout of the launch and of every navigation
// and wait for each browser, as "headless-shell=30000 chromium=30000" (ms).
// The Go test sets it (gate rule: both browsers at the Playwright default of
// 30 s, so a regression of known defect KD-2 fails the gate). A browser that
// the variable does not name gets 30000.
// GVX_G2_NAV_TIMEOUT_MS, when set, replaces the value of every browser: a
// manual override for diagnosis, recorded in timings.json.
// timings.json holds the wall time of each step and the timeout used.
// The browsers are "headless-shell" (the Playwright default) and "chromium"
// (the full browser in its headless mode). Files go to GVX_G2_OUT/<browser>/.
// Each result line starts with "GVX-G2 ". The last line is "GVX-G2 done".
// A failure in one browser does not stop the next one; the Go test decides.
const { chromium } = require('/opt/playwright-core');
const fs = require('fs');
const path = require('path');

const outRoot = process.env.GVX_G2_OUT || '/workspace/out';
const args = (process.env.GVX_G2_ARGS || '').split(' ').filter(Boolean);
const channels = (process.env.GVX_G2_CHANNELS || 'headless-shell chromium').split(' ').filter(Boolean);
const loadQuery = process.env.GVX_G2_LOAD || 'frames=60&sync=1&n=200&size=1.0&iters=64';
const navTimeouts = Object.fromEntries((process.env.GVX_G2_NAV_TIMEOUTS || '')
  .split(' ').filter(Boolean).map((kv) => kv.split('=')).map(([k, v]) => [k, Number(v)]));
const now = () => Number(process.hrtime.bigint() / 1000000n);

async function runChannel(name) {
  const out = path.join(outRoot, name);
  fs.mkdirSync(out, { recursive: true });
  const save = (file, data) => fs.writeFileSync(path.join(out, file), data);
  const log = (line) => console.log(`GVX-G2 browser=${name} ${line}`);
  const override = Number(process.env.GVX_G2_NAV_TIMEOUT_MS || 0);
  const navTimeout = override > 0 ? override : (navTimeouts[name] || 30000);
  const opts = { args, timeout: navTimeout };
  if (name === 'chromium') opts.channel = 'chromium';
  const timings = { nav_timeout_ms: navTimeout, nav_timeout_override: override > 0 ? 1 : 0 };
  const saveTimings = () => save('timings.json', JSON.stringify(timings, null, 2));
  let t0 = now();
  const browser = await chromium.launch(opts);
  timings.launch_ms = now() - t0;
  try {
    log('version=' + browser.version());
    const ctx = await browser.newContext({ viewport: { width: 800, height: 700 }, deviceScaleFactor: 1 });
    ctx.setDefaultTimeout(navTimeout);
    ctx.setDefaultNavigationTimeout(navTimeout);
    const probeDone = () => document.getElementById('out').textContent.includes('GVX-WEBGL done');

    t0 = now();
    const probePage = await ctx.newPage();
    await probePage.goto('file:///workspace/webgl-probe.html');
    await probePage.waitForFunction(probeDone);
    timings.first_page_ms = now() - t0;
    saveTimings();
    const probe = await probePage.textContent('#out');
    save('probe.txt', probe);
    save('probe.png', await probePage.locator('#c').screenshot());
    for (const line of probe.split('\n')) log('probe ' + line);

    t0 = now();
    const scenePage = await ctx.newPage();
    await scenePage.goto('file:///workspace/gpu/webgl-scene.html');
    await scenePage.waitForFunction(() => window.__gvxScene !== undefined);
    timings.scene_page_ms = now() - t0;
    const scene = await scenePage.evaluate(() => window.__gvxScene);
    save('scene.json', JSON.stringify(scene, null, 2));
    save('scene.png', await scenePage.locator('#c').screenshot());
    log(`scene_pass=${scene.pass} webgl=${scene.webglVersion}`);

    // The headless shell has no chrome://gpu page; CDP returns the same data.
    try {
      const cdp = await browser.newBrowserCDPSession();
      const info = await cdp.send('SystemInfo.getInfo');
      save('gpu-info.json', JSON.stringify(info.gpu, null, 2));
    } catch (err) {
      save('gpu-info.json', JSON.stringify({ error: String(err) }));
    }

    t0 = now();
    const againPage = await ctx.newPage();
    await againPage.goto('file:///workspace/webgl-probe.html');
    await againPage.waitForFunction(probeDone);
    timings.second_page_ms = now() - t0;

    t0 = now();
    const loadPage = await ctx.newPage();
    await loadPage.goto('file:///workspace/webgl-load.html?' + loadQuery);
    await loadPage.waitForFunction(() => document.getElementById('out').textContent.includes('done'));
    timings.load_page_ms = now() - t0;
    const load = await loadPage.textContent('#out');
    save('load.txt', load);
    saveTimings();
    log('load=' + load);
    log('timings=' + JSON.stringify(timings));
    log('finished');
  } finally {
    await browser.close();
  }
}

(async () => {
  console.log('GVX-G2 args=' + JSON.stringify(args));
  let failed = 0;
  for (const name of channels) {
    try {
      await runChannel(name);
    } catch (err) {
      failed++;
      console.log(`GVX-G2 browser=${name} error=` + JSON.stringify(String(err && err.stack || err)));
    }
  }
  console.log('GVX-G2 done');
  process.exit(failed === 0 ? 0 : 1);
})();
