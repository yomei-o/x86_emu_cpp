// Linux CPython in the WASM build. Unlike the Windows guest (PE + hooked imports),
// a static Linux ELF talks straight to the kernel, so this exercises syscalls.cpp.
// The emscripten MEMFS is Unix-shaped, which is exactly what the Linux guest's path
// handling expects. Put a static musl CPython + a trimmed stdlib under /py and run it.
//
//   node web/test_python_linux.mjs
//   (expects pylinux/python/install/bin/python3.13 and pylinux/stdlib/ — see the
//    download+trim steps; both are gitignored.)
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const createX86Emu = require(path.join(here, 'x86emu.js'));

const exe = path.join(root, 'pylinux/python/install/bin/python3.13');
const stdlib = path.join(root, 'pylinux/stdlib');
if (!fs.existsSync(exe) || !fs.existsSync(stdlib)) {
  console.error('missing pylinux/python/install/bin/python3.13 or pylinux/stdlib/');
  process.exit(2);
}

let out = '';
const decoder = new TextDecoder();
globalThis.x86emuOutput = (fd, bytes) => { out += decoder.decode(bytes, { stream: true }); };
globalThis.x86emuLog = () => {};

const mod = await createX86Emu();
const FS = mod.FS;
function mkdirp(p) {
  const parts = p.split('/').filter(Boolean); let cur = '';
  for (const s of parts) { cur += '/' + s; try { FS.mkdir(cur); } catch (_) {} }
}
function putTree(srcDir, dstDir) {
  let n = 0;
  for (const ent of fs.readdirSync(srcDir, { withFileTypes: true })) {
    const s = path.join(srcDir, ent.name), d = dstDir + '/' + ent.name;
    if (ent.isDirectory()) { mkdirp(d); n += putTree(s, d); }
    else { FS.writeFile(d, new Uint8Array(fs.readFileSync(s))); n++; }
  }
  return n;
}

mkdirp('/py/bin');
FS.writeFile('/py/bin/python3.13', new Uint8Array(fs.readFileSync(exe)));
mkdirp('/py/lib/python3.13');
const t0 = Date.now();
const files = putTree(stdlib, '/py/lib/python3.13');
console.log(`staged python3.13 + ${files} stdlib files into MEMFS in ${((Date.now()-t0)/1000).toFixed(1)}s`);

const code = "import sys, hashlib; print('py', sys.version.split()[0]); print('sha', hashlib.sha256(b'abc').hexdigest())";
const argv = ['/py/bin/python3.13', '-c', code];
const enc = new TextEncoder().encode(argv.join('\0') + '\0');
const ap = mod._malloc(enc.length); mod.HEAPU8.set(enc, ap);

const t = Date.now();
out = '';
const rc = mod.ccall('emu_run_path', 'number',
                     ['string', 'number', 'number', 'number', 'number'],
                     ['/py/bin/python3.13', ap, enc.length, 0, 5e9]);
mod._free(ap);
const secs = ((Date.now() - t) / 1000).toFixed(1);
const text = out.replace(/\r/g, '');
console.log('--- guest output ---');
process.stdout.write(text || '(no output)\n');
console.log(`--- exit ${rc} in ${secs}s (${mod.ccall('emu_instructions','number',[],[]).toExponential(2)} insns) ---`);
if (rc < 0) console.log('emu_error: ' + mod.ccall('emu_error', 'string', [], []));
const ok = rc === 0 && text.includes('py 3.13') &&
           text.includes('sha ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
console.log(ok ? 'LINUX CPYTHON IN WASM OK' : 'not yet');
process.exit(ok ? 0 : 1);
