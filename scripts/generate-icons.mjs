import { mkdirSync, writeFileSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import zlib from "node:zlib";

const sizes = [16, 32, 48, 128];
const outDirs = ["public/icons", "extension/icons"];
for (const dir of outDirs) mkdirSync(dir, { recursive: true });

const crcTable = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const name = Buffer.from(type);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([len, name, data, crc]);
}
function png(width, height, pixels) {
  const rows = [];
  for (let y = 0; y < height; y++) {
    const row = Buffer.alloc(1 + width * 4);
    row[0] = 0;
    pixels.copy(row, 1, y * width * 4, (y + 1) * width * 4);
    rows.push(row);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(Buffer.concat(rows), { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}
function mix(a, b, t) {
  return Math.round(a + (b - a) * t);
}
function smooth(edge0, edge1, x) {
  const t = Math.max(0, Math.min(1, (x - edge0) / (edge1 - edge0)));
  return t * t * (3 - 2 * t);
}
function insideShield(x, y) {
  const cy = y < 0.12 ? 0 : y;
  const half = 0.33 * (1 - smooth(0.18, 0.98, cy)) + 0.05;
  const center = 0.5;
  const top = y >= 0.12 && y <= 0.92;
  const bottomSlope = y < 0.72 || Math.abs(x - center) < (0.92 - y) * 1.2;
  return top && bottomSlope && Math.abs(x - center) <= half;
}
function makeIcon(size) {
  const scale = 4;
  const W = size * scale;
  const pix = Buffer.alloc(W * W * 4);
  for (let y = 0; y < W; y++) {
    for (let x = 0; x < W; x++) {
      let r = 0,
        g = 0,
        b = 0,
        a = 0;
      const nx = (x + 0.5) / W;
      const ny = (y + 0.5) / W;
      const dx = nx - 0.5,
        dy = ny - 0.5;
      const bg = smooth(0.54, 0.47, Math.hypot(dx, dy));
      if (bg > 0) {
        r = mix(4, 10, ny);
        g = mix(14, 25, ny);
        b = mix(32, 54, ny);
        a = Math.round(245 * bg);
      }
      const sx = (nx - 0.12) / 0.76;
      const sy = (ny - 0.08) / 0.82;
      if (insideShield(sx, sy)) {
        const t = Math.min(1, Math.max(0, (sx + sy) / 1.7));
        r = mix(34, 48, t);
        g = mix(211, 129, t);
        b = mix(238, 245, t);
        a = 255;
        if (sx > 0.49 && sx < 0.54 && sy > 0.25 && sy < 0.72) {
          r = 230;
          g = 250;
          b = 255;
          a = 220;
        }
      }
      const idx = (y * W + x) * 4;
      pix[idx] = r;
      pix[idx + 1] = g;
      pix[idx + 2] = b;
      pix[idx + 3] = a;
    }
  }
  const small = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++) {
      const sums = [0, 0, 0, 0];
      for (let yy = 0; yy < scale; yy++)
        for (let xx = 0; xx < scale; xx++) {
          const i = ((y * scale + yy) * W + (x * scale + xx)) * 4;
          sums[0] += pix[i];
          sums[1] += pix[i + 1];
          sums[2] += pix[i + 2];
          sums[3] += pix[i + 3];
        }
      const o = (y * size + x) * 4;
      small[o] = Math.round(sums[0] / 16);
      small[o + 1] = Math.round(sums[1] / 16);
      small[o + 2] = Math.round(sums[2] / 16);
      small[o + 3] = Math.round(sums[3] / 16);
    }
  return png(size, size, small);
}
for (const size of sizes) {
  const file = `icon${size}.png`;
  const data = makeIcon(size);
  writeFileSync(join("public/icons", file), data);
  writeFileSync(join("extension/icons", file), data);
}
copyFileSync("public/icons/icon32.png", "public/favicon.png");
console.log("Generated Kedayam PNG icons:", sizes.map((s) => `icon${s}.png`).join(", "));
