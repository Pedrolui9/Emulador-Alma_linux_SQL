#!/usr/bin/env node
// Runner de tests del emulador psql AlmaLinux.
// Ejecuta cada tests/test_*.js en un subproceso, captura salida y código de salida,
// y reporta un resumen global. Uso: npm test
const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const testsDir = __dirname;
const files = fs.readdirSync(testsDir)
  .filter(f => /^test_.*\.js$/.test(f))
  .sort();

if (files.length === 0) {
  console.error('No se encontraron archivos de test (tests/test_*.js)');
  process.exit(1);
}

const nodeBin = process.execPath;
let passed = 0;
let failed = 0;
const failures = [];

for (const f of files) {
  const full = path.join(testsDir, f);
  process.stdout.write(`\n===== ${f} =====\n`);
  const res = spawnSync(nodeBin, [full], { encoding: 'utf8', timeout: 120000 });
  if (res.stdout) process.stdout.write(res.stdout);
  if (res.stderr) process.stderr.write(res.stderr);
  const code = res.status;
  const timedOut = res.error && res.error.code === 'ETIMEDOUT';
  // Un test se considera fallido si: timeout, o sale con código distinto de 0,
  // o imprimió una marca de fracaso ❌ en su salida (los tests usan console.log, no exit codes).
  const hasFailMarker = /❌/.test(res.stdout || '');
  const ok = !timedOut && code === 0 && !hasFailMarker;
  if (ok) {
    passed++;
    console.log(`\n[PASS] ${f}`);
  } else {
    failed++;
    failures.push({ f, code, timedOut, hasFailMarker });
    console.log(`\n[FAIL] ${f}${timedOut ? ' (timeout)' : hasFailMarker ? ' (marca ❌ detectada)' : ` (exit code ${code})`}`);
  }
}

console.log('\n========================================');
console.log(`RESUMEN: ${passed} pasan, ${failed} fallan (de ${files.length})`);
process.exit(failed > 0 ? 1 : 0);
