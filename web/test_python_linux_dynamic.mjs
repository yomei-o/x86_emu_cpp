// A *dynamically* linked Linux CPython (musl, ET_DYN + PT_INTERP=/lib/ld-musl).
// Exercises the dynamic-loader path: ld-musl maps + relocates, and any extension
// .so goes through file-backed mmap. Contrast with the static build (no .so).
//   node web/test_python_linux_dynamic.mjs
//   (expects pylinux/python/bin/python3.13 [dynamic], pylinux/stdlib_dyn/,
//    pylinux/alpine/lib/ld-musl-x86_64.so.1)
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const createX86Emu = require(path.join(here, 'x86emu.js'));

const exe = path.join(root, 'pylinux/python/bin/python3.13');
const stdlib = path.join(root, 'pylinux/stdlib_dyn');
const ld = path.join(root, 'pylinux/alpine/lib/ld-musl-x86_64.so.1');
for (const p of [exe, stdlib, ld]) if (!fs.existsSync(p)) { console.error('missing ' + p); process.exit(2); }

let out = '';
const decoder = new TextDecoder();
globalThis.x86emuOutput = (fd, bytes) => { out += decoder.decode(bytes, { stream: true }); };
globalThis.x86emuLog = () => {};

const mod = await createX86Emu();
const FS = mod.FS;
const mkdirp = (p) => { let c=''; for (const s of p.split('/').filter(Boolean)) { c+='/'+s; try { FS.mkdir(c); } catch {} } };
function putTree(src, dst) { let n=0; for (const e of fs.readdirSync(src,{withFileTypes:true})) {
  const s=path.join(src,e.name), d=dst+'/'+e.name;
  if (e.isDirectory()) { mkdirp(d); n+=putTree(s,d); } else { FS.writeFile(d, new Uint8Array(fs.readFileSync(s))); n++; } } return n; }

mkdirp('/lib'); FS.writeFile('/lib/ld-musl-x86_64.so.1', new Uint8Array(fs.readFileSync(ld)));
mkdirp('/py2/bin'); FS.writeFile('/py2/bin/python3.13', new Uint8Array(fs.readFileSync(exe)));
mkdirp('/py2/lib/python3.13');
const n = putTree(stdlib, '/py2/lib/python3.13');
console.log(`staged ld-musl + python3.13 (dynamic) + ${n} stdlib files`);

const code = "import sys, hashlib; print('py', sys.version.split()[0]); print('sha', hashlib.sha256(b'abc').hexdigest())";
const argv = ['/py2/bin/python3.13', '-c', code];
const enc = new TextEncoder().encode(argv.join('\0') + '\0');
const ap = mod._malloc(enc.length); mod.HEAPU8.set(enc, ap);
const t = Date.now(); out = '';
const rc = mod.ccall('emu_run_path', 'number', ['string','number','number','number','number'],
                     ['/py2/bin/python3.13', ap, enc.length, +(process.argv[2]==='-t'), 5e9]);
mod._free(ap);
const text = out.replace(/\r/g, '');
console.log('--- guest output ---'); process.stdout.write(text || '(no output)\n');
console.log(`--- exit ${rc} in ${((Date.now()-t)/1000).toFixed(1)}s (${mod.ccall('emu_instructions','number',[],[]).toExponential(2)} insns) ---`);
if (rc < 0) console.log('emu_error: ' + mod.ccall('emu_error','string',[],[]));
const ok = rc === 0 && text.includes('py 3.13') &&
           text.includes('sha ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
console.log(ok ? 'DYNAMIC LINUX CPYTHON OK' : 'not yet');
process.exit(ok ? 0 : 1);
