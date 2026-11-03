// Linux/Chrome diagnostic: fresh profile, no cache, scroll to load page resources.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import assert from 'node:assert/strict';

const port = Number(process.argv[2] ?? 8080);
const url = process.argv[3] ?? 'https://doodles.google/';
assert(Number.isInteger(port) && port > 0 && port < 65536);
assert(['https:', 'http:'].includes(new URL(url).protocol));
const profile = await mkdtemp('/tmp/helios-browser-smoke-');
const chrome = spawn('/usr/bin/google-chrome', ['--headless=new', '--no-sandbox', '--disable-dev-shm-usage', '--disable-extensions', `--user-data-dir=${profile}`, `--proxy-server=http://127.0.0.1:${port}`, '--proxy-bypass-list=<-loopback>', '--remote-debugging-port=0', 'about:blank']);
const exited = new Promise(resolve => chrome.once('exit', resolve));
let ws;
const deadline = setTimeout(() => chrome.kill(), 45000);
try {
  const endpoint = await new Promise((resolve, reject) => {
    let log = '';
    chrome.on('error', reject);
    chrome.once('exit', () => reject(Error('Chrome exited before debugging was ready')));
    chrome.stderr.on('data', data => {
      log += data;
      const match = log.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) resolve(match[1]);
    });
  });
  const base = endpoint.replace('ws:', 'http:').split('/devtools')[0];
  const tabs = await (await fetch(`${base}/json/list`)).json();
  ws = new WebSocket(tabs.find(tab => tab.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.addEventListener('open', resolve, { once: true }); ws.addEventListener('error', reject, { once: true }); });
  let id = 0, completed = 0, bytes = 0;
  const pending = new Map(), failures = [];
  ws.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) { pending.get(message.id)?.resolve(message); pending.delete(message.id); }
    if (message.method === 'Network.loadingFinished') { completed++; bytes += message.params.encodedDataLength; }
    if (message.method === 'Network.loadingFailed' && message.params.errorText !== 'net::ERR_ABORTED') failures.push(message.params.errorText);
  });
  ws.addEventListener('close', () => { for (const request of pending.values()) request.reject(Error('Chrome disconnected')); });
  const send = (method, params = {}) => new Promise((resolve, reject) => { if (ws.readyState !== WebSocket.OPEN) { reject(Error('Chrome disconnected')); return; } const current = ++id; pending.set(current, { resolve, reject }); ws.send(JSON.stringify({ id: current, method, params })); });
  await send('Network.enable');
  await send('Network.setCacheDisabled', { cacheDisabled: true });
  await send('Page.navigate', { url });
  for (let i = 0; i < 6; i++) { await new Promise(resolve => setTimeout(resolve, 5000)); await send('Runtime.evaluate', { expression: 'window.scrollBy(0,700)' }); }
  const result = await send('Runtime.evaluate', { expression: 'JSON.stringify({images:document.images.length,loaded:[...document.images].filter(i=>i.complete&&i.naturalWidth>0).length})', returnByValue: true });
  const images = JSON.parse(result.result.result.value);
  console.log(JSON.stringify({ url, completed, bytes, failures, ...images }));
  assert.equal(failures.length, 0, 'page resource requests failed');
  assert(images.images > 0 && images.loaded === images.images, 'page images did not finish within 30 seconds');
} finally {
  clearTimeout(deadline);
  ws?.close();
  chrome.kill();
  await exited;
  await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
