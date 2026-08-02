const { WASI } = require('node:wasi');
const fs = require('fs');

const which = process.argv[2];
const path = `/home/claude/work/${which}.wasm`;
const bytes = fs.readFileSync(path);

const wasi = new WASI({
  version: 'preview1',
  args: [],
  env: {},
  returnOnExit: true,
});

(async () => {
  const { instance } = await WebAssembly.instantiate(bytes, {
    wasi_snapshot_preview1: wasi.wasiImport,
  });
  const t0 = process.hrtime.bigint();
  let exitCode;
  try {
    exitCode = wasi.start(instance);
  } catch (e) {
    console.log('TRAP:', e.message);
    process.exit(1);
  }
  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  console.log(`[${which}] exitCode=${exitCode} wall_ms=${ms.toFixed(2)}`);
})();
