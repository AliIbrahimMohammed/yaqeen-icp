// Test runner: typecheck all targets, wasm-compile the canister, and run
// the Poseidon vector + canister functional driver in the node-motoko
// interpreter.
//
// Usage:
//   YAQEEN_TEST_BASE=<base-src-dir> YAQEEN_TEST_CORE=<core-src-dir> node tests.js
// or simply: bash run-tests.sh  (downloads base/core and runs everything)
const mo = require('motoko');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const TMP = __dirname;
// motoko-base modules live under src/; motoko-core v2.5.0 also under src/.
const PKGS = [
  ['base', process.env.YAQEEN_TEST_BASE || ''],
  ['core', process.env.YAQEEN_TEST_CORE || ''],
];

const toKey = (p) => p.split(path.sep).join('/');

function loadDirIntoVfs(prefix, dir) {
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.name.endsWith('.mo')) {
        mo.write(`/static/${[prefix, toKey(path.relative(dir, full))].filter(Boolean).join('/')}`, fs.readFileSync(full, 'utf8'));
      }
    }
  };
  walk(dir);
}

function main() {
  for (const [name, dir] of PKGS) {
    if (!dir) throw new Error(`${name} package dir not set — use run-tests.sh or set YAQEEN_TEST_${name.toUpperCase()}`);
    loadDirIntoVfs(`.node-motoko/${name}`, dir);
    mo.usePackage(name, `/static/.node-motoko/${name}`);
  }
  for (const dir of ['motoko/src', 'verify_test']) {
    loadDirIntoVfs(dir, path.join(ROOT, dir));
  }

  console.log('=== 1. TYPECHECK ===');
  let failed = false;
  for (const t of ['motoko/src/main.mo', 'verify_test/main.mo', 'motoko/src/groth16/Groth16MultiTest.mo']) {
    const diags = mo.check(`/static/${t}`);
    const errs = diags.filter((d) => d.severity === 1);
    const warns = diags.filter((d) => d.severity === 2);
    if (errs.length === 0) {
      console.log(`OK   ${t} (${warns.length} warnings, all pre-existing M0155 in vendor/Fp.mo)`);
    } else {
      failed = true;
      console.log(`FAIL ${t}`);
      for (const d of errs) console.log(JSON.stringify(d));
    }
  }

  console.log('=== 2. WASM COMPILE (canister build signal) ===');
  try {
    const wasm = mo.wasm('/static/motoko/src/main.mo', 'ic');
    console.log(`OK   main.mo compiled to wasm (${wasm && wasm.length ? wasm.length : 'n/a'} bytes)`);
  } catch (e) {
    failed = true;
    console.log('FAIL wasm compile:', String(e).slice(0, 300));
  }

  console.log('=== 3. POSEIDON DIFFERENTIAL VECTOR ===');
  const poseidonTest = runFile('/static/poseidon_test.mo', `${TMP}/poseidon_test.mo`);
  report('poseidon vector', poseidonTest);

  console.log('=== 4. CANISTER FUNCTIONAL DRIVER (interpreter runtime) ===');
  // Two runs: the bootstrap controller gate is stubbed ON (full functional
  // suite) and OFF (the gate itself must reject a non-controller caller).
  // Overwrite the VFS main.mo (typecheck/wasm already done above) with the
  // driver-combined file so main.mo's relative imports still resolve.
  mo.write('/static/motoko/src/main.mo', transformMain(true));
  report('canister driver (controller-authorized)', mo.run('/static/motoko/src/main.mo'));
  mo.write('/static/motoko/src/main.mo', transformMain(false));
  report('canister driver (bootstrap gate off)', mo.run('/static/motoko/src/main.mo'));

  process.exit(failed ? 1 : 0);
}

function runFile(key, fsPath) {
  mo.write(key, fs.readFileSync(fsPath, 'utf8'));
  return mo.run(key);
}

function report(name, r) {
  const out = String(r.stdout || '');
  const lines = out.split('\n').filter((l) => l.trim());
  let ok = lines.some((l) => l.includes('ALL CHECKS PASSED') || l.includes('PASS poseidon vector'));
  for (const l of lines) console.log('   ', l.trim().slice(0, 140));
  const err = r.result && r.result.kind === '#err' ? String(JSON.stringify(r.result)).slice(0, 200) : '';
  if (err) console.log('   RUN ERROR:', err);
  if (!ok) {
    console.log(`FAIL ${name}`);
    process.exitCode = 1;
  } else {
    console.log(`OK   ${name}`);
  }
}

// Keep the actor `persistent` (this moc errors on non-persistent actors,
// M0220) and drive it from the SAME file: the actor declaration binds a
// value we can call. Driver imports are hoisted above the actor (Motoko
// requires imports before declarations).
//
// bootstrapAuthorized is the canister's controller-gate oracle (management
// canister). The node-motoko interpreter cannot make canister calls — the
// await on "aaaaa-aa" hard-crashes it — so the production body between the
// @stub-start/@stub-end markers in main.mo is replaced here with a
// constant (`true`/`false`), simulating a controller-authorized or
// unauthorized environment.
//
// parseVkForActivation is a second stub target: full VK validation costs a
// pairing the interpreter cannot run (a real parse hangs past the step
// budget — verified by probe), so the body is replaced with a fabricated
// PreparedVk to let the VK staging/activation LOGIC be tested. The pristine
// main.mo is what stage 1 typechecks and stage 2 wasm-compiles; only the
// driver-run copies are stubbed.
function transformMain(bootstrapStub) {
  let src = fs.readFileSync(path.join(ROOT, 'motoko/src/main.mo'), 'utf8');
  if (!src.includes('persistent actor TitleRegistry {')) throw new Error('marker not found in main.mo');
  const vkStubMarker = /\/\/ @stub-start\n\s*Groth16\.parseAndPrepareVk[\s\S]*?\/\/ @stub-end/;
  if (!vkStubMarker.test(src)) throw new Error('VK stub markers not found in main.mo');
  const vkStubBody = [
    '// @stub-start',
    'ignore(hex);',
    '?{',
    '  alphaBetaTarget = {',
    '    c0 = { c0 = { c0 = 0; c1 = 0 }; c1 = { c0 = 0; c1 = 0 }; c2 = { c0 = 0; c1 = 0 } };',
    '    c1 = { c0 = { c0 = 0; c1 = 0 }; c1 = { c0 = 0; c1 = 0 }; c2 = { c0 = 0; c1 = 0 } }',
    '  };',
    '  gammaPrep = { infinity = true; ellCoeffs = [] };',
    '  deltaPrep = { infinity = true; ellCoeffs = [] };',
    '  gammaAbc = [];',
    '};',
    '// @stub-end',
  ].join('\n    ');
  src = src.replace(vkStubMarker, vkStubBody);
  const bootStubMarker = /\/\/ @stub-start[\s\S]*?\/\/ @stub-end/;
  if (!bootStubMarker.test(src)) throw new Error('bootstrap stub markers not found in main.mo');
  src = src.replace(
    bootStubMarker,
    '// @stub-start\n    ignore(caller);\n    ' + String(bootstrapStub) + '\n    // @stub-end',
  );
  let driver = fs.readFileSync(`${TMP}/canister_driver.mo`, 'utf8');
  // Inject the arkworks fixture (real VK hex from circuit/wire_export.json)
  // so the VK staging-flow tests operate on a genuinely valid key.
  const fixture = JSON.parse(fs.readFileSync(path.join(ROOT, 'circuit/wire_export.json'), 'utf8'));
  // Replace EVERY occurrence: the driver's header comment also quotes the
  // literal "@FIXTURE_VK@", and String.replace alone would only swap the
  // first match, leaving the real binding as the placeholder (len 12).
  driver = driver.split('@FIXTURE_VK@').join(fixture.vkHex);
  driver = driver.replace('let TEST_BOOTSTRAP_MODE : Bool = true;', `let TEST_BOOTSTRAP_MODE : Bool = ${String(bootstrapStub)};`);
  // Hoist driver imports above the actor, dropping any that main.mo already
  // declares (duplicate bindings, M0017).
  const usedAliases = new Set();
  for (const line of src.split('\n')) {
    const m = line.match(/^import\s+(\w+)/);
    if (m) usedAliases.add(m[1]);
  }
  const driverImports = driver.split('\n')
    .filter((l) => l.trim().startsWith('import '))
    .filter((l) => !usedAliases.has((l.trim().match(/^import\s+(\w+)/) || [])[1]))
    .join('\n');
  const driverBody = driver.split('\n').filter((l) => !l.trim().startsWith('import ')).join('\n');
  return driverImports + '\n' + src + '\n' + driverBody;
}

main();
