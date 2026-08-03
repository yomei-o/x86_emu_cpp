// Verifies the *committed* dynamic bundle (web/pylinux-dyn/*) unpacks and runs via
// the same gunzip + tar-parse the page's 'Linux — dynamic' button uses.
//   node web/test_python_linux_dynamic_bundled.mjs
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const createX86Emu = require(path.join(here, 'x86emu.js'));
const B = path.join(here, 'pylinux-dyn');
function untar(buf) { const out=[]; for (let o=0;o+512<=buf.length;) {
  let name=''; for (let i=0;i<100&&buf[o+i];i++) name+=String.fromCharCode(buf[o+i]); if(!name)break;
  let pre=''; for (let i=0;i<155&&buf[o+345+i];i++) pre+=String.fromCharCode(buf[o+345+i]); if(pre)name=pre+'/'+name;
  let sz=0; for (let i=0;i<11&&buf[o+124+i];i++) sz=sz*8+(buf[o+124+i]-48); const t=buf[o+156]; o+=512;
  if (t===0x30||t===0) out.push({name:name.replace(/^\.\//,''),bytes:buf.subarray(o,o+sz)}); o+=Math.ceil(sz/512)*512; } return out; }

let out=''; const dec=new TextDecoder();
globalThis.x86emuOutput=(fd,b)=>{out+=dec.decode(b,{stream:true});}; globalThis.x86emuLog=()=>{};
const mod=await createX86Emu(); const FS=mod.FS;
const mkdirp=(p)=>{let c='';for(const s of p.split('/').filter(Boolean)){c+='/'+s;try{FS.mkdir(c);}catch{}}};
const g=(f)=>zlib.gunzipSync(fs.readFileSync(path.join(B,f)));

mkdirp('/lib'); FS.writeFile('/lib/ld-musl-x86_64.so.1', new Uint8Array(g('ld-musl-x86_64.so.1.gz')));
mkdirp('/pyd/bin'); FS.writeFile('/pyd/bin/python3.13', new Uint8Array(g('python3.13.gz')));
mkdirp('/pyd/lib/python3.13');
const lib=untar(g('stdlib.tar.gz'));
for (const e of lib){ const full='/pyd/lib/python3.13/'+e.name; mkdirp(full.slice(0,full.lastIndexOf('/'))); FS.writeFile(full,new Uint8Array(e.bytes)); }
console.log(`unpacked ld-musl + dynamic python3.13 + ${lib.length} stdlib files`);

const code="import sys, hashlib; print('py', sys.version.split()[0]); print('sha', hashlib.sha256(b'abc').hexdigest())";
const argv=['/pyd/bin/python3.13','-c',code];
const enc=new TextEncoder().encode(argv.join('\0')+'\0'); const ap=mod._malloc(enc.length); mod.HEAPU8.set(enc,ap);
const t=Date.now(); const rc=mod.ccall('emu_run_path','number',['string','number','number','number','number'],['/pyd/bin/python3.13',ap,enc.length,0,5e9]); mod._free(ap);
const text=out.replace(/\r/g,''); process.stdout.write(text);
console.log(`--- exit ${rc} in ${((Date.now()-t)/1000).toFixed(1)}s ---`);
const ok=rc===0&&text.includes('py 3.13')&&text.includes('sha ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
console.log(ok?'DYNAMIC BUNDLE OK':'FAIL'); process.exit(ok?0:1);
