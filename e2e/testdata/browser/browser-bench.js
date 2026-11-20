// gvx browser baseline benchmark (Phase 0, steps 6 to 9 of docs/moonshots.md
// section 9.1). It measures the launch time of the browser, the time of each
// new tab, the time of WebGL pages, and the time of an automation script
// (full-page screenshot and PDF). It reads the CPU time of each Chromium
// thread from /proc, so it reports the share of SwiftShader worker threads.
//
// Environment:
//   GVX_BENCH_ARGS     Extra Chromium flags, separated by spaces.
//   GVX_BENCH_WEBGL    Query strings of webgl-load.html, separated by ";".
//   GVX_BENCH_FRAMES   Frames for each WebGL page (default 60).
//   GVX_BENCH_ROUNDS   Rounds of the automation script (default 10).
//
// Each result line starts with "GVX-BENCH ". The last line is "GVX-BENCH done".
const { chromium } = require(process.env.GVX_BENCH_PWCORE || '/opt/playwright-core');
const fs = require('fs');

const base = process.env.GVX_BENCH_BASE || 'file:///workspace/';
const now = () => Number(process.hrtime.bigint()) / 1e6;
const median = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const CLK_TCK = 100;

// threadTimes returns a map from "pid/tid" to {type, comm, cpu} for every
// thread of every Chromium process. cpu is utime + stime in milliseconds.
function threadTimes() {
  const out = new Map();
  if (!fs.existsSync('/proc/self/stat')) return out;
  for (const pid of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(pid)) continue;
    let cmd;
    try { cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').join(' '); } catch { continue; }
    if (!/chrom|headless_shell/.test(cmd)) continue;
    const m = cmd.match(/--type=([a-z-]+)/);
    const type = m ? m[1] : 'browser';
    let tids = [];
    try { tids = fs.readdirSync(`/proc/${pid}/task`); } catch { continue; }
    for (const tid of tids) {
      try {
        const st = fs.readFileSync(`/proc/${pid}/task/${tid}/stat`, 'utf8');
        const comm = st.slice(st.indexOf('(') + 1, st.lastIndexOf(')'));
        const f = st.slice(st.lastIndexOf(')') + 2).split(' ');
        out.set(`${pid}/${tid}`, { type, comm, cpu: (Number(f[11]) + Number(f[12])) * 1000 / CLK_TCK });
      } catch { /* The thread exited. */ }
    }
  }
  return out;
}

// cpuDelta sums the CPU time that each thread used between two snapshots.
// SwiftShader runs its rasterizer on worker threads named "Thread<NN>" in the
// GPU process.
function cpuDelta(before, after) {
  let total = 0, swiftshader = 0;
  const byType = {};
  for (const [key, t] of after) {
    const d = t.cpu - ((before.get(key) || {}).cpu || 0);
    if (d <= 0) continue;
    total += d;
    byType[t.type] = (byType[t.type] || 0) + d;
    if (t.type === 'gpu-process' && /^Thread<\d+>$/.test(t.comm)) swiftshader += d;
  }
  return { total, swiftshader, byType };
}

function report(name, wall, d) {
  const share = d.total > 0 ? (100 * d.swiftshader / d.total).toFixed(1) : 'n/a';
  const types = Object.entries(d.byType).map(([k, v]) => `${k}:${Math.round(v)}`).join(',');
  console.log(`GVX-BENCH ${name} wall_ms=${Math.round(wall)} chrome_cpu_ms=${Math.round(d.total)} ` +
    `swiftshader_cpu_ms=${Math.round(d.swiftshader)} swiftshader_share_pct=${share} by_type=${types}`);
}

(async () => {
  const args = (process.env.GVX_BENCH_ARGS || '--enable-unsafe-swiftshader').split(' ').filter(Boolean);
  const launches = [];
  for (let i = 0; i < 5; i++) {
    const t0 = now();
    const b = await chromium.launch({ args });
    launches.push(now() - t0);
    await b.close();
  }
  console.log(`GVX-BENCH launch_ms median=${Math.round(median(launches))} runs=${launches.map(Math.round).join(',')}`);

  const browser = await chromium.launch({ args });
  console.log('GVX-BENCH version=' + browser.version());
  const ctx = await browser.newContext({ viewport: { width: 1024, height: 768 }, deviceScaleFactor: 1 });
  const tabs = [], gotos = [];
  for (let i = 0; i < 10; i++) {
    const t0 = now();
    const p = await ctx.newPage();
    const t1 = now();
    await p.goto(base + 'hello.html');
    tabs.push(t1 - t0);
    gotos.push(now() - t1);
    await p.close();
  }
  console.log(`GVX-BENCH newtab_ms median=${Math.round(median(tabs))} runs=${tabs.map(Math.round).join(',')}`);
  console.log(`GVX-BENCH goto_ms median=${Math.round(median(gotos))} runs=${gotos.map(Math.round).join(',')}`);

  const frames = process.env.GVX_BENCH_FRAMES || '60';
  const pages = (process.env.GVX_BENCH_WEBGL || 'n=20000&size=0.05&iters=16;sync=1&n=200&size=1.0&iters=64').split(';');
  for (const q of pages.filter(Boolean)) {
    const p = await ctx.newPage();
    const before = threadTimes();
    const t0 = now();
    await p.goto(`${base}webgl-load.html?frames=${frames}&${q}`);
    await p.waitForFunction(() => document.getElementById('out').textContent.includes('done'), null, { timeout: 600000 });
    const wall = now() - t0;
    console.log(`GVX-BENCH webgl_result [${q}] ` + await p.textContent('#out'));
    report(`webgl[${q}]`, wall, cpuDelta(before, threadTimes()));
    await p.close();
  }

  const rounds = Number(process.env.GVX_BENCH_ROUNDS || '10');
  const p = await ctx.newPage();
  const before = threadTimes();
  const t0 = now();
  for (let i = 0; i < rounds; i++) {
    await p.goto(base + 'automation-doc.html');
    await p.screenshot({ fullPage: true });
    await p.pdf();
  }
  report(`automation[rounds=${rounds}]`, now() - t0, cpuDelta(before, threadTimes()));
  await browser.close();
  console.log('GVX-BENCH done');
})().catch((err) => { console.error('GVX-BENCH error ' + (err && err.stack || err)); process.exit(1); });
