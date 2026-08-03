// The browser CPython milestone, proven headlessly: put the Windows embeddable
// CPython into MEMFS and run `python -S -c "..."` through the same wasm build the
// page loads. If this prints, the browser can too - the rest is DOM wiring.
//
//   node web/test_python.mjs   (expects the embeddable package under pybundle/py)
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const createX86Emu = require(path.join(here, 'x86emu.js'));

const bundle = path.join(root, 'pybundle/py');
if (!fs.existsSync(path.join(bundle, 'python.exe'))) {
  console.error(`missing ${bundle}/python.exe - download the 3.13 embeddable package there`);
  process.exit(2);
}

let out = '';
const decoder = new TextDecoder();
globalThis.x86emuOutput = (fd, bytes) => { out += decoder.decode(bytes, { stream: true }); };
globalThis.x86emuLog = () => {};

const mod = await createX86Emu();

// Materialise the whole bundle into MEMFS at /py (python.exe, python313.dll,
// python313.zip = the stdlib, python313._pth, the vcruntime DLLs).
mod.FS.mkdir('/py');
for (const name of fs.readdirSync(bundle)) {
  const p = path.join(bundle, name);
  if (fs.statSync(p).isFile())
    mod.FS.writeFile('/py/' + name, new Uint8Array(fs.readFileSync(p)));
}

const code = "import sys, hashlib; print('py', sys.version.split()[0]); print('sha', hashlib.sha256(b'abc').hexdigest())";
// argv[0] = /py/python.exe so the DLL search and CPython's own home resolve to /py.
const argv = ['/py/python.exe', '-S', '-c', code];
const enc = new TextEncoder().encode(argv.join('\0') + '\0');
const ap = mod._malloc(enc.length);
mod.HEAPU8.set(enc, ap);

const t = Date.now();
out = '';
const rc = mod.ccall('emu_run_path', 'number',
                     ['string', 'number', 'number', 'number', 'number'],
                     ['/py/python.exe', ap, enc.length, 0, 5e9]);
mod._free(ap);
const secs = ((Date.now() - t) / 1000).toFixed(1);

const text = out.replace(/\r/g, '');
console.log('--- guest output ---');
process.stdout.write(text);
console.log(`--- exit ${rc} in ${secs}s (${mod.ccall('emu_instructions','number',[],[]).toExponential(2)} insns) ---`);

// sha256("abc") = ba7816bf... — the guest's hashlib must match a real one byte for byte.
const ok = rc === 0 && text.includes('py 3.13') &&
           text.includes('sha ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
console.log(ok ? 'CPYTHON IN WASM OK' : 'FAIL: ' + (rc < 0 ? mod.ccall('emu_error','string',[],[]) : 'unexpected output/exit'));
process.exit(ok ? 0 : 1);
