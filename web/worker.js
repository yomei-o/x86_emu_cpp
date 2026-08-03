// The emulator lives here, off the main thread, so a multi-second guest (CPython
// startup is ~60M instructions) never freezes the page. The page posts commands;
// this streams the guest's output back line by line and reports the exit.
//
// Protocol (page -> worker):
//   {type:'writeFiles', dir, files:[{name, bytes}]}   populate MEMFS (e.g. a Python install)
//   {type:'runBytes',  bytes, traceCalls, maxInsns}   run an image held in memory
//   {type:'runPath',   path, argv, traceCalls, maxInsns}  run a program already in MEMFS, with argv
// (worker -> page):
//   {type:'ready'} | {type:'output', fd, bytes} | {type:'log', text}
//   {type:'done', code, insns, format, secs, error}
importScripts('x86emu.js');

let mod = null;
const queue = [];

// The emscripten glue calls these on the worker global.
self.x86emuOutput = (fd, bytes) => self.postMessage({ type: 'output', fd, bytes: bytes.slice() });
self.x86emuLog = (text) => self.postMessage({ type: 'log', text });

createX86Emu().then((m) => {
  mod = m;
  self.postMessage({ type: 'ready' });
  for (const msg of queue) handle(msg);
  queue.length = 0;
});

self.onmessage = (e) => {
  if (!mod) { queue.push(e.data); return; }
  handle(e.data);
};

function handle(msg) {
  switch (msg.type) {
    case 'writeFiles': return writeFiles(msg);
    case 'runBytes':   return runBytes(msg);
    case 'runPath':    return runPath(msg);
  }
}

function mkdirp(dir) {
  const parts = dir.split('/').filter(Boolean);
  let cur = '';
  for (const p of parts) {
    cur += '/' + p;
    try { mod.FS.mkdir(cur); } catch (_) { /* already exists */ }
  }
}

function writeFiles(msg) {
  mkdirp(msg.dir);
  for (const f of msg.files) {
    const full = msg.dir + '/' + f.name;      // f.name may contain subdirectories
    const slash = full.lastIndexOf('/');
    if (slash > 0) mkdirp(full.slice(0, slash));
    mod.FS.writeFile(full, new Uint8Array(f.bytes));
  }
  self.postMessage({ type: 'log', text: `loaded ${msg.files.length} files into ${msg.dir}` });
}

function finish(code, started) {
  const secs = (performance.now() - started) / 1000;
  const insns = mod.ccall('emu_instructions', 'number', [], []);
  const format = mod.ccall('emu_format', 'string', [], []);
  const error = code < 0 ? mod.ccall('emu_error', 'string', [], []) : '';
  self.postMessage({ type: 'done', code, insns, format, secs, error });
}

function runBytes(msg) {
  const bytes = new Uint8Array(msg.bytes);
  const ptr = mod._malloc(bytes.length);
  mod.HEAPU8.set(bytes, ptr);
  const started = performance.now();
  let code;
  try {
    code = mod.ccall('emu_run', 'number', ['number', 'number', 'number', 'number'],
                     [ptr, bytes.length, msg.traceCalls ? 1 : 0, msg.maxInsns || 200000000]);
  } finally { mod._free(ptr); }
  finish(code, started);
}

function runPath(msg) {
  // argv as a NUL-separated blob, argv[0] included.
  const blob = new TextEncoder().encode(msg.argv.join('\0') + '\0');
  const ap = mod._malloc(blob.length);
  mod.HEAPU8.set(blob, ap);
  const started = performance.now();
  let code;
  try {
    code = mod.ccall('emu_run_path', 'number',
                     ['string', 'number', 'number', 'number', 'number'],
                     [msg.path, ap, blob.length, msg.traceCalls ? 1 : 0, msg.maxInsns || 5e9]);
  } finally { mod._free(ap); }
  finish(code, started);
}
