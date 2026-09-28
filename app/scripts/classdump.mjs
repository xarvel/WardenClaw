// SPDX-License-Identifier: GPL-3.0-or-later
// Minimal .class parser: public methods and fields with descriptors.
// Used to compare the API of two jar versions without a JDK (Pi has no javap).
// Usage: node scripts/classdump.mjs <jar> <class/path/Name> [...]
import fs from "node:fs";
import zlib from "node:zlib";
import { execFileSync } from "node:child_process";

const ACC = { 0x0001: "public", 0x0002: "private", 0x0004: "protected", 0x0008: "static", 0x0010: "final", 0x0400: "abstract" };

function parse(buf) {
  let p = 8; // magic + minor/major
  const cpCount = buf.readUInt16BE(p); p += 2;
  const cp = new Array(cpCount);
  for (let i = 1; i < cpCount; i++) {
    const tag = buf[p++];
    if (tag === 1) { const len = buf.readUInt16BE(p); p += 2; cp[i] = buf.toString("utf8", p, p + len); p += len; }
    else if (tag === 7 || tag === 8 || tag === 16 || tag === 19 || tag === 20) { cp[i] = buf.readUInt16BE(p); p += 2; }
    else if (tag === 15) p += 3;
    else if (tag === 5 || tag === 6) { p += 8; i++; } // long/double occupy two slots
    else p += 4;
  }
  p += 2; // access_flags
  const thisClass = cp[cp[buf.readUInt16BE(p)]]; p += 2;
  p += 2; // super
  const ifCount = buf.readUInt16BE(p); p += 2 + ifCount * 2;
  const skipAttrs = () => { const n = buf.readUInt16BE(p); p += 2; for (let i = 0; i < n; i++) { p += 2; const len = buf.readUInt32BE(p); p += 4 + len; } };
  const members = (kind) => {
    const n = buf.readUInt16BE(p); p += 2;
    const out = [];
    for (let i = 0; i < n; i++) {
      const flags = buf.readUInt16BE(p); p += 2;
      const name = cp[buf.readUInt16BE(p)]; p += 2;
      const desc = cp[buf.readUInt16BE(p)]; p += 2;
      skipAttrs();
      if (flags & 0x0005) { // public or protected
        const mods = Object.entries(ACC).filter(([b]) => flags & b).map(([, s]) => s).join(" ");
        out.push(`${kind} ${mods} ${name}${desc}`);
      }
    }
    return out;
  };
  const fields = members("field");
  const methods = members("method");
  return { thisClass, fields, methods };
}

const [jar, ...classes] = process.argv.slice(2);
const zip = fs.readFileSync(jar);
// central directory: locate entries by name
function entries(zip) {
  const out = new Map();
  let i = zip.length - 22;
  while (i >= 0 && zip.readUInt32LE(i) !== 0x06054b50) i--;
  let cd = zip.readUInt32LE(i + 16), n = zip.readUInt16LE(i + 10);
  for (let k = 0; k < n; k++) {
    const nameLen = zip.readUInt16LE(cd + 28), extLen = zip.readUInt16LE(cd + 30), cmtLen = zip.readUInt16LE(cd + 32);
    const name = zip.toString("utf8", cd + 46, cd + 46 + nameLen);
    out.set(name, { method: zip.readUInt16LE(cd + 10), off: zip.readUInt32LE(cd + 42), csize: zip.readUInt32LE(cd + 20) });
    cd += 46 + nameLen + extLen + cmtLen;
  }
  return out;
}
const ents = entries(zip);
function read(name) {
  const e = ents.get(name);
  if (!e) return null;
  const nameLen = zip.readUInt16LE(e.off + 26), extLen = zip.readUInt16LE(e.off + 28);
  const start = e.off + 30 + nameLen + extLen;
  const raw = zip.subarray(start, start + e.csize);
  return e.method === 0 ? raw : zlib.inflateRawSync(raw);
}

for (const c of classes) {
  const buf = read(c.endsWith(".class") ? c : c + ".class");
  if (!buf) { console.log(`### ${c}: NOT IN JAR`); continue; }
  const r = parse(buf);
  console.log(`### ${r.thisClass}`);
  for (const s of [...r.fields, ...r.methods].sort()) console.log(s);
}
