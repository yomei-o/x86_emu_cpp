// Exercises the WebAssembly build outside a browser.
//
// This runs the same x86emu.js the demo page loads, through the same C entry
// point and the same output callbacks, so everything except the DOM wiring is
// covered.  Each sample's output is compared against what the native emulator
// produces for the same binary.
//
//   node web/test_node.mjs
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));

require(path.join(here, 'samples.js'));           // defines globalThis.X86EMU_SAMPLES
const createX86Emu = require(path.join(here, 'x86emu.js'));

const expected = {
  hello32: { exit: 0, contains: 'hello from the guest!' },
  hello64: { exit: 0, contains: 'hello from the guest!' },
  arith32: { exit: 0, contains: 'div64    : FFFFFFFFB57E6E2F' },
  arith64: { exit: 0, contains: 'div64    : FFFFFFFFB57E6E2F' },
  elf32:   { exit: 7, contains: 'hello from the ELF guest!' },
  elf64:   { exit: 7, contains: 'hello from the ELF guest!' },
};

let out = '';
const decoder = new TextDecoder();
globalThis.x86emuOutput = (fd, bytes) => { out += decoder.decode(bytes, { stream: true }); };
globalThis.x86emuLog = () => {};

const mod = await createX86Emu();
let pass = 0, fail = 0;

for (const s of globalThis.X86EMU_SAMPLES) {
  const bytes = Buffer.from(s.data, 'base64');
  const ptr = mod._malloc(bytes.length);
  mod.HEAPU8.set(bytes, ptr);
  out = '';
  const code = mod.ccall('emu_run', 'number',
                         ['number', 'number', 'number', 'number'],
                         [ptr, bytes.length, 0, 200000000]);
  mod._free(ptr);

  const want = expected[s.key];
  const text = out.replace(/\r/g, '');
  const ok = want && code === want.exit && text.includes(want.contains);
  if (ok) {
    console.log(`  ok    ${s.key} (exit ${code}, ${text.split('\n')[0]})`);
    pass++;
  } else {
    console.log(`  FAIL  ${s.key} (exit ${code})`);
    if (code < 0) console.log('        ' + mod.ccall('emu_error', 'string', [], []));
    else console.log('        output: ' + JSON.stringify(text.slice(0, 120)));
    fail++;
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
