import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const deadline = Date.now() + 20000;
let page;
while (Date.now() < deadline) {
  try {
    const port = (await readFile(join(process.argv[2], 'DevToolsActivePort'), 'utf8')).split('\n')[0];
    page = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find(p => p.type === 'page');
    if (page) break;
  } catch {}
  await delay(100);
}
if (!page) throw new Error('Chrome did not start');
const socket = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener('open', resolve, { once: true });
  socket.addEventListener('error', reject, { once: true });
});
let id = 0;
let status;
const pending = new Map();
socket.addEventListener('message', event => {
  const message = JSON.parse(event.data);
  if (message.id) {
    const request = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) request?.reject(new Error(message.error.message));
    else request?.resolve(message.result);
  }
  if (message.method === 'Network.responseReceived' && message.params.type === 'Document') {
    status = message.params.response.status;
  }
});
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const requestId = ++id;
    pending.set(requestId, { resolve, reject });
    socket.send(JSON.stringify({ id: requestId, method, params }));
  });
}
try {
  await send('Network.enable');
  await send('Page.enable');
  await send('Page.navigate', { url: 'https://www.google.com/' });
  while (Date.now() < deadline) {
    const result = await send('Runtime.evaluate', { expression: 'document.title', returnByValue: true });
    if (status === 200 && result.result.value === 'Google') {
      console.log('Chrome system proxy: Google HTTP 200, title=Google');
      process.exitCode = 0;
      break;
    }
    await delay(200);
  }
  if (process.exitCode !== 0) throw new Error(`Google page did not load (document status=${status})`);
} finally {
  socket.close();
}
