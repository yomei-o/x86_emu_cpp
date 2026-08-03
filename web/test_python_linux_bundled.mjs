// Verifies the *committed* Linux bundle (web/pylinux/python3.13.gz + stdlib.tar.gz)
// unpacks and runs, using the same gunzip + tar-parse the page does client-side.
//   node web/test_python_linux_bundled.mjs
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const createX86Emu = require(path.join(here, 'x86emu.js'));

// Minimal tar reader (ustar): 512-byte header blocks, octal size at 124, type at
// 156; file data follows, padded to 512. This is the same logic the browser uses.
function untar(buf) {
  const out = [];
  for (let o = 0; o + 512 <= buf.length; ) {
    let name = '';
    for (let i = 0; i < 100 && buf[o + i]; i++) name += String.fromCharCode(buf[o + i]);
    if (!name) break;                                   // zero block => end
    let prefix = '';
    for (let i = 0; i < 155 && buf[o + 345 + i]; i++) prefix += String.fromCharCode(buf[o + 345 + i]);
    if (prefix) name = prefix + '/' + name;
    let sz = 0;
    for (let i = 0; i < 11 && buf[o + 124 + i]; i++) sz = sz * 8 + (buf[o + 124 + i] - 48);
    const type = buf[o + 156];
    o += 512;
    if (type === 0x30 || type === 0) out.push({ name: name.replace(/^\.\//, ''), bytes: buf.subarray(o, o + sz) });
    o += Math.ceil(sz / 512) * 512;
  }
  return out;
}

let out = '';
const decoder = new TextDecoder();
globalThis.x86emuOutput = (fd, bytes) => { out += decoder.decode(bytes, { stream: true }); };
globalThis.x86emuLog = () => {};

const mod = await createX86Emu();
const FS = mod.FS;
const mkdirp = (p) => { let c = ''; for (const s of p.split('/').filter(Boolean)) { c += '/' + s; try { FS.mkdir(c); } catch {} } };

// python3.13.gz -> /pyl/bin/python3.13
mkdirp('/pyl/bin');
const exe = zlib.gunzipSync(fs.readFileSync(path.join(here, 'pylinux/python3.13.gz')));
FS.writeFile('/pyl/bin/python3.13', new Uint8Array(exe));

// stdlib.tar.gz -> /pyl/lib/python3.13/**
mkdirp('/pyl/lib/python3.13');
const entries = untar(zlib.gunzipSync(fs.readFileSync(path.join(here, 'pylinux/stdlib.tar.gz'))));
for (const e of entries) {
  const full = '/pyl/lib/python3.13/' + e.name;
  mkdirp(full.slice(0, full.lastIndexOf('/')));
  FS.writeFile(full, new Uint8Array(e.bytes));
}
console.log(`unpacked python3.13 (${(exe.length/1e6).toFixed(1)} MB) + ${entries.length} stdlib files`);

const code = "import sys, hashlib; print('py', sys.version.split()[0]); print('sha', hashlib.sha256(b'abc').hexdigest())";
const argv = ['/pyl/bin/python3.13', '-c', code];
const enc = new TextEncoder().encode(argv.join('\0') + '\0');
const ap = mod._malloc(enc.length); mod.HEAPU8.set(enc, ap);
const t = Date.now();
const rc = mod.ccall('emu_run_path', 'number', ['string','number','number','number','number'],
                     ['/pyl/bin/python3.13', ap, enc.length, 0, 5e9]);
mod._free(ap);
const text = out.replace(/\r/g, '');
process.stdout.write(text);
console.log(`--- exit ${rc} in ${((Date.now()-t)/1000).toFixed(1)}s ---`);
const ok = rc === 0 && text.includes('py 3.13') &&
           text.includes('sha ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
console.log(ok ? 'BUNDLED LINUX CPYTHON OK' : 'FAIL');
process.exit(ok ? 0 : 1);
