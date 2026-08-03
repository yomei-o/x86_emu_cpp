// First dynamic-linking test: a real dynamically-linked musl ELF (Alpine busybox)
// loaded through its interpreter /lib/ld-musl-x86_64.so.1. Exercises ET_DYN
// loading + PT_INTERP + auxv (AT_BASE/AT_ENTRY/AT_PHDR). No file-backed mmap yet:
// busybox needs only ld-musl (which *is* libc for musl), already mapped by us.
//   node web/test_dynamic.mjs   (expects pylinux/alpine/{bin/busybox,lib/ld-musl-x86_64.so.1})
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const createX86Emu = require(path.join(here, 'x86emu.js'));

const alp = path.join(root, 'pylinux/alpine');
const bb = path.join(alp, 'bin/busybox'), ld = path.join(alp, 'lib/ld-musl-x86_64.so.1');
if (!fs.existsSync(bb) || !fs.existsSync(ld)) { console.error('missing alpine busybox / ld-musl'); process.exit(2); }

let out = '';
const decoder = new TextDecoder();
globalThis.x86emuOutput = (fd, bytes) => { out += decoder.decode(bytes, { stream: true }); };
globalThis.x86emuLog = () => {};

const mod = await createX86Emu();
const FS = mod.FS;
const mkdirp = (p) => { let c=''; for (const s of p.split('/').filter(Boolean)) { c+='/'+s; try { FS.mkdir(c); } catch {} } };
mkdirp('/bin'); mkdirp('/lib');
FS.writeFile('/bin/busybox', new Uint8Array(fs.readFileSync(bb)));
FS.writeFile('/lib/ld-musl-x86_64.so.1', new Uint8Array(fs.readFileSync(ld)));

const argv = ['/bin/busybox', 'echo', 'hello from a dynamically-linked ELF'];
const enc = new TextEncoder().encode(argv.join('\0') + '\0');
const ap = mod._malloc(enc.length); mod.HEAPU8.set(enc, ap);
out = '';
const rc = mod.ccall('emu_run_path', 'number', ['string','number','number','number','number'],
                     ['/bin/busybox', ap, enc.length, +(process.argv[2]==='-t'), 5e9]);
mod._free(ap);
const text = out.replace(/\r/g, '');
console.log('--- guest output ---'); process.stdout.write(text || '(no output)\n');
console.log(`--- exit ${rc} (${mod.ccall('emu_instructions','number',[],[]).toExponential(2)} insns) ---`);
if (rc < 0) console.log('emu_error: ' + mod.ccall('emu_error','string',[],[]));
const ok = rc === 0 && text.includes('hello from a dynamically-linked ELF');
console.log(ok ? 'DYNAMIC LINKING OK' : 'not yet');
process.exit(ok ? 0 : 1);
