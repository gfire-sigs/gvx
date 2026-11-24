// gvx Playwright gate. It launches the Chromium headless shell of the image
// through playwright-core, loads two pages, and writes a screenshot and a PDF
// to the workspace. The Go test decodes both files on the host.
// Each result line starts with "GVX-PW ". The last line is "GVX-PW done".
const { chromium } = require('/opt/playwright-core');
const fs = require('fs');

(async () => {
  const browser = await chromium.launch({ args: ['--enable-unsafe-swiftshader'] });
  console.log('GVX-PW version=' + browser.version());
  const ctx = await browser.newContext({ viewport: { width: 256, height: 256 }, deviceScaleFactor: 1 });
  ctx.setDefaultTimeout(180_000);
  const page = await ctx.newPage();
  await page.goto('file:///workspace/hello.html');
  console.log('GVX-PW text=' + await page.textContent('#v'));
  await page.goto('file:///workspace/webgl-probe.html');
  await page.waitForFunction(() => document.getElementById('out').textContent.includes('GVX-WEBGL done'));
  console.log(await page.textContent('#out'));
  fs.writeFileSync('/workspace/out/probe.png', await page.locator('#c').screenshot());
  await page.goto('file:///workspace/hello.html');
  fs.writeFileSync('/workspace/out/hello.pdf', await page.pdf({ format: 'A4' }));
  await browser.close();
  console.log('GVX-PW done');
})().catch((err) => { console.error('GVX-PW error ' + (err && err.stack || err)); process.exit(1); });
