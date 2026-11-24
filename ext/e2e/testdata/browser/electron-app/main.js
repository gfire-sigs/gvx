// gvx Electron gate. The application opens a hidden window, reads a value
// from a page, runs the WebGL probe, and exits with code 0. Any error exits
// with code 1, so the process never waits for a window that does not paint.
// Each result line starts with "GVX-EL ". The last line is "GVX-EL done".
const { app, BrowserWindow } = require('electron');

function fail(err) {
  console.error('GVX-EL error ' + (err && err.stack || err));
  app.exit(1);
}
process.on('uncaughtException', fail);
process.on('unhandledRejection', fail);

app.whenReady().then(async () => {
  console.log('GVX-EL electron=' + process.versions.electron + ' chrome=' + process.versions.chrome);
  const win = new BrowserWindow({ show: false, width: 256, height: 256 });
  win.webContents.on('render-process-gone', (_event, details) => {
    fail(new Error('renderer process gone: ' + JSON.stringify(details)));
  });
  await win.loadFile('/workspace/hello.html');
  console.log('GVX-EL text=' + await win.webContents.executeJavaScript("document.getElementById('v').textContent"));
  await win.loadFile('/workspace/webgl-probe.html');
  const probe = await win.webContents.executeJavaScript(
    "new Promise((resolve, reject) => { const deadline = Date.now() + 120000;" +
    " const poll = () => { const el = document.getElementById('out'); const t = el ? el.textContent : '';" +
    " if (t.includes('GVX-WEBGL done')) { resolve(t); }" +
    " else if (Date.now() >= deadline) { reject(new Error('WebGL probe timed out: ' + t)); }" +
    " else { setTimeout(poll, 20); } }; poll(); })");
  console.log(probe);
  console.log('GVX-EL done');
  app.exit(0);
}).catch(fail);
