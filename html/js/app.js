/* ============================================================
   EMULADOR INTERACTIVO DE PSQL — JavaScript puro
   Seguridad de BD: bases, tablas, roles, usuarios y permisos.
   Requerimientos RF-01 .. RF-15 del documento "Emulador PSQL".
   ============================================================ */
'use strict';

/* ================== ESTADO (RF-15: persiste en sesión) ================== */
const ST = {
  roles: {},       // lower -> { name, canLogin, superuser, members:Set(lower) }
  privs: {},       // lower -> { db:{}, schema:{}, atabs:{}, tab:{} } (Sets)
  membership: {},  // userLower -> Set(groupLower)
  dbs: {},         // lower -> { name, owner, tables:{} }
  currentDB: 'postgres',
  currentRole: 'postgres'
};

function rk(n) { return String(n).trim().toLowerCase(); }

function initState() {
  ST.roles = { postgres: { name: 'postgres', canLogin: true, superuser: true, members: new Set() } };
  ST.privs = { postgres: { db: {}, schema: {}, atabs: {}, tab: {} } };
  ST.membership = { postgres: new Set() };
  ST.dbs = { postgres: { name: 'postgres', owner: 'postgres', tables: {} } };
  ST.currentDB = 'postgres';
  ST.currentRole = 'postgres';
}

/* ================== PRIVILEGIOS (RF-07) ================== */
function effRoles(role) {
  const out = new Set([rk(role)]);
  const mem = ST.membership[rk(role)];
  if (mem) for (const g of mem) out.add(g);
  return out;
}

function isSuper(role) {
  for (const r of effRoles(role)) {
    const ro = ST.roles[r];
    if (ro && ro.superuser) return true;
  }
  return false;
}

function roleExists(name) { return !!ST.roles[rk(name)]; }
function dbExists(name) { return !!ST.dbs[rk(name)]; }

function grantInto(role, obj, key, privsArr) {
  const r = rk(role);
  if (!ST.privs[r]) ST.privs[r] = { db: {}, schema: {}, atabs: {}, tab: {} };
  if (!ST.privs[r][obj][key]) ST.privs[r][obj][key] = new Set();
  for (const p of privsArr) ST.privs[r][obj][key].add(p);
}

function hasIn(role, obj, key, priv) {
  for (const r of effRoles(role)) {
    const col = ST.privs[r] && ST.privs[r][obj] && ST.privs[r][obj][key];
    if (col && col.has(priv)) return true;
  }
  return false;
}

function hasDbPriv(role, priv, db) {
  return isSuper(role) || hasIn(role, 'db', rk(db), priv);
}

function hasSchemaPriv(role, priv, db, schema) {
  const key = rk(db) + '.' + rk(schema);
  return isSuper(role) || hasIn(role, 'schema', key, priv);
}

/* SELECT/INSERT/UPDATE/DELETE sobre una tabla (requiere USAGE + privilegio) */
function canTable(role, priv, db, schema, table) {
  if (isSuper(role)) return true;
  if (!hasSchemaPriv(role, 'USAGE', db, schema)) return false;
  const base = rk(db) + '.' + rk(schema);
  for (const r of effRoles(role)) {
    const P = ST.privs[r];
    if (!P) continue;
    const tp = P.tab[base + '.' + rk(table)];
    if (tp && tp.has(priv)) return true;
    const at = P.atabs[base];
    if (at && at.has(priv)) return true;
  }
  return false;
}

const VALID_PRIVS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'USAGE', 'CONNECT'];

function expandPrivs(list, context) {
  const out = new Set();
  for (const raw of list) {
    let p = raw.trim().toUpperCase();
    if (p === 'ALL') {
      if (context === 'db') { out.add('CONNECT'); out.add('CREATE'); }
      else if (context === 'schema') { out.add('USAGE'); out.add('CREATE'); }
      else { out.add('SELECT'); out.add('INSERT'); out.add('UPDATE'); out.add('DELETE'); }
      continue;
    }
    if (!VALID_PRIVS.includes(p)) throw new Error('privilegio no reconocido: ' + p);
    if (context === 'db' && !['CONNECT', 'CREATE'].includes(p)) throw new Error('privilegio no reconocido para DATABASE: ' + p);
    if (context === 'schema' && !['USAGE', 'CREATE'].includes(p)) throw new Error('privilegio no reconocido para SCHEMA: ' + p);
    out.add(p);
  }
  return Array.from(out);
}

/* ================== VALORES SQL ================== */
function splitOuter(s, pattern) {
  const parts = [];
  let cur = '', quote = null, depth = 0;
  const re = new RegExp('^' + pattern, 'i');
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      cur += ch;
      if (ch === quote && s[i - 1] !== '\\') {
        if (s[i + 1] === quote) { cur += s[i + 1]; i++; continue; }
        quote = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; cur += ch; continue; }
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (depth === 0) {
      const mm = s.slice(i).match(re);
      if (mm) {
        parts.push(cur.trim());
        cur = '';
        i += mm[0].length - 1;
        continue;
      }
    }
    cur += ch;
  }
  if (cur.trim() !== '') parts.push(cur.trim());
  return parts;
}

function parseVal(raw) {
  let v = String(raw).trim();
  if (v.length >= 2 && ((v[0] === "'" && v[v.length - 1] === "'") || (v[0] === '"' && v[v.length - 1] === '"'))) {
    v = v.slice(1, -1).replace(/''/g, "'").replace(/\\\\/g, '\\');
    return v;
  }
  if (/^-?\d+(\.\d+)?$/i.test(v)) return Number(v);
  if (/^-?\d+\.?\d*[eE][+-]?\d+$/i.test(v)) return Number(v);
  if (/^(true|false)$/i.test(v)) return v.toLowerCase() === 'true';
  if (/^null$/i.test(v)) return null;
  return v;
}

function compareValue(a, b, op) {
  const num = (x) => (typeof x === 'number') ? x : null;
  const an = num(a), bn = num(b);
  if (an !== null && bn !== null) a = an, b = bn;
  else { a = String(a == null ? '' : a).toLowerCase(); b = String(b == null ? '' : b).toLowerCase(); }
  switch (op) {
    case '=': return a === b;
    case '<>': case '!=': return a !== b;
    case '>': return a > b;
    case '<': return a < b;
    case '>=': return a >= b;
    case '<=': return a <= b;
    default: return true;
  }
}

function evalCond(row, expr) {
  const m = expr.trim().match(/^(\w+)\s*(>=|<=|<>|!=|=|<|>)\s*(.+)$/i);
  if (!m) return true;
  const col = rk(m[1]);
  if (!(col in row)) return true;
  return compareValue(row[col], parseVal(m[3]), m[2]);
}

function matchWhere(row, whereRaw) {
  if (!whereRaw || !whereRaw.trim()) return true;
  const conds = splitOuter(whereRaw, '\\band\\b');
  return conds.every((c) => evalCond(row, c));
}

/* ================== UI ================== */
const outputEl = document.getElementById('output');
const inputEl = document.getElementById('cmd');
const promptEl = document.getElementById('promptLabel');
const winTitle = document.getElementById('winTitle');
const badgeDb = document.getElementById('badgeDb');
const badgeRole = document.getElementById('badgeRole');
const badgeSuper = document.getElementById('badgeSuper');
const statusDb = document.getElementById('statusDb');
const statusRole = document.getElementById('statusRole');
const helpPanel = document.getElementById('helpPanel');
const theoryPanel = document.getElementById('theoryPanel');

function print(text, cls) {
  const div = document.createElement('div');
  div.className = 'line ' + (cls || 'result');
  div.textContent = text;
  outputEl.appendChild(div);
  outputEl.scrollTop = outputEl.scrollHeight;
  return div;
}

function clearTerminal() {
  outputEl.textContent = '';
  print('Terminal limpiada. (Use \\l, \\du, \\dt, \\d tabla, \\c base...)', 'info');
  inputEl.focus();
}

function promptStr() {
  const sym = ST.currentRole === 'postgres' ? '#' : '>';
  return ST.currentDB + '=' + sym;
}

function updatePrompt() {
  const p = promptStr();
  promptEl.textContent = p;
  winTitle.textContent = p;
  badgeDb.innerHTML = '<b>BD:</b> ' + ST.currentDB;
  badgeRole.innerHTML = '<b>ROL:</b> ' + ST.currentRole;
  statusDb.textContent = 'BD: ' + ST.currentDB;
  statusRole.textContent = 'ROL: ' + ST.currentRole;
  const su = isSuper(ST.currentRole);
  badgeSuper.textContent = su ? 'superuser' : 'privilegios';
  badgeSuper.style.borderColor = su ? 'var(--green)' : 'var(--border)';
  badgeSuper.style.color = su ? 'var(--green2)' : 'var(--fg)';
}

function printCmd(raw) {
  print(promptStr() + ' ' + raw, 'cmd');
}

/* ================== FORMATEO DE TABLAS (estilo psql) ================== */
function formatTable(headers, rows) {
  const w = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => String(r[i] == null ? '' : r[i]).length)));
  const sep = '-' + w.map((x) => '-'.repeat(x + 1)).join('+') + '-';
  const lineRow = (r) => ' ' + r.map((c, i) => String(c == null ? '' : c).padEnd(w[i])).join(' | ');
  const lines = [sep];
  lines.push(lineRow(headers));
  lines.push(sep);
  rows.forEach((r) => lines.push(lineRow(r)));
  return lines;
}

function emitTable(headers, rows, nlabel) {
  const lines = formatTable(headers, rows);
  print(lines[1], 'thead');
  lines.forEach((l, i) => { if (i !== 1) print(l, 'result'); });
  print('(' + nlabel + ' rows)', 'info');
}

/* ================== META-COMANDOS ================== */
function listDBs() {
  const names = Object.keys(ST.dbs).sort();
  const rows = names.map((n) => [n, ST.dbs[n].owner, 'UTF8']);
  emitTable(['Name', 'Owner', 'Encoding'], rows, names.length);
}

function listRoles() {
  const names = Object.keys(ST.roles).sort();
  const rows = names.map((n) => {
    const r = ST.roles[n];
    const attrs = [];
    if (r.superuser) attrs.push('Superuser');
    attrs.push(r.canLogin ? 'Login' : 'Cannot login');
    const members = r.members.size ? Array.from(r.members).join(', ') : '';
    return [n, attrs.join(', '), members];
  });
  emitTable(['Role name', 'Attributes', 'Member of'], rows, names.length);
}

function listTables() {
  const db = ST.dbs[ST.currentDB];
  if (!isSuper(ST.currentRole) && !hasSchemaPriv(ST.currentRole, 'USAGE', ST.currentDB, 'public')) {
    return deny('permiso denegado al esquema public');
  }
  const names = Object.keys(db.tables).sort();
  if (!names.length) return print('Did not find any relation.', 'info');
  const rows = names.map((n) => ['public', n, 'table', db.tables[n].owner]);
  emitTable(['Schema', 'Name', 'Type', 'Owner'], rows, names.length);
}

function describeTable(name) {
  const nm = name.replace(/^public\./i, '');
  const t = ST.dbs[ST.currentDB].tables[rk(nm)];
  if (!isSuper(ST.currentRole) && !hasSchemaPriv(ST.currentRole, 'USAGE', ST.currentDB, 'public')) {
    return deny('permiso denegado al esquema public');
  }
  if (!t) return print('ERROR:  la relaci\u00f3n \u00ab' + name + '\u00bb no existe', 'error');
  const rows = t.columns.map((c) => [c.name, c.type, '']);
  emitTable(['\u00ab' + t.name + '\u00bb' + ' \u2014 Column', 'Type', 'Nullable'], rows, rows.length);
}

function connectDB(name) {
  if (!dbExists(name)) return print('ERROR:  la base de datos \u00ab' + name + '\u00bb no existe', 'error');
  if (!hasDbPriv(ST.currentRole, 'CONNECT', name)) {
    return print('psql: error: FATAL:  permission denied for database "' + name + '"\nESTADO SQL: 42501', 'error');
  }
  ST.currentDB = rk(name);
  updatePrompt();
  print('You are now connected to database "' + ST.currentDB + '" as user "' + ST.currentRole + '".', 'success');
}

/* ================== ERRORES (RF-14) ================== */
function deny(msg) {
  print('ERROR:  ' + msg + '\nESTADO SQL: 42501', 'error');
}

function needSuper() {
  if (isSuper(ST.currentRole)) return true;
  deny('se requiere el rol superusuario postgres');
  return false;
}

/* ================== COMANDOS SQL ================== */
function createDatabase(name) {
  if (!needSuper()) return;
  if (dbExists(name)) return print('ERROR:  la base de datos "' + name + '" ya existe', 'error');
  ST.dbs[rk(name)] = { name, owner: 'postgres', tables: {} };
  print('CREATE DATABASE', 'success');
}

function dropDatabase(name) {
  if (!needSuper()) return;
  if (!dbExists(name)) return print('ERROR:  la base de datos "' + name + '" no existe', 'error');
  if (rk(name) === ST.currentDB) return print('ERROR:  no se puede eliminar la base de datos actual. Conecte a otra con \\c', 'error');
  delete ST.dbs[rk(name)];
  print('DROP DATABASE', 'success');
}

function createTable(name, colDefsRaw) {
  const db = ST.dbs[ST.currentDB];
  if (!isSuper(ST.currentRole)) {
    if (!hasSchemaPriv(ST.currentRole, 'USAGE', ST.currentDB, 'public'))
      return deny('no tiene USAGE sobre el esquema public');
    if (!hasSchemaPriv(ST.currentRole, 'CREATE', ST.currentDB, 'public'))
      return deny('no tiene CREATE sobre el esquema public');
  }
  if (db.tables[rk(name)]) return print('ERROR:  la relaci\u00f3n "' + name + '" ya existe', 'error');
  const columns = splitOuter(colDefsRaw, ',').map((cd) => {
    const parts = cd.trim().split(/\s+/);
    const cname = rk(parts[0]);
    const type = parts.slice(1).join(' ') || 'text';
    return { name: cname, type };
  });
  if (!columns.length) return print('ERROR:  sintaxis inv\u00e1lida en el comando CREATE TABLE', 'error');
  db.tables[rk(name)] = { name, owner: ST.currentRole === 'postgres' ? 'postgres' : ST.currentRole, columns, rows: [] };
  print('CREATE TABLE', 'success');
}

function dropTable(name) {
  const db = ST.dbs[ST.currentDB];
  if (!db.tables[rk(name)]) return print('ERROR:  la relaci\u00f3n \u00ab' + name + '\u00bb no existe', 'error');
  if (!isSuper(ST.currentRole)) return deny('permiso denegado: solo el propietario puede eliminar la tabla');
  delete db.tables[rk(name)];
  print('DROP TABLE', 'success');
}

function insertInto(table, colsRaw, valuesRaw) {
  const t = ST.dbs[ST.currentDB].tables[rk(table)];
  if (!t) return print('ERROR:  la relaci\u00f3n \u00ab' + table + '\u00bb no existe', 'error');
  if (!canTable(ST.currentRole, 'INSERT', ST.currentDB, 'public', table))
    return deny('permiso denegado a la tabla ' + table);
  const values = splitOuter(valuesRaw, ',').map(parseVal);
  let row = {};
  if (colsRaw && colsRaw.trim()) {
    const cols = splitOuter(colsRaw, ',').map(rk);
    cols.forEach((c, i) => { row[c] = values[i] !== undefined ? values[i] : null; });
  } else {
    t.columns.forEach((c, i) => { row[c.name] = values[i] !== undefined ? values[i] : null; });
  }
  t.rows.push(row);
  print('INSERT 0 1', 'success');
}

function updateTable(table, setRaw, whereRaw) {
  const t = ST.dbs[ST.currentDB].tables[rk(table)];
  if (!t) return print('ERROR:  la relaci\u00f3n \u00ab' + table + '\u00bb no existe', 'error');
  if (!canTable(ST.currentRole, 'UPDATE', ST.currentDB, 'public', table))
    return deny('permiso denegado a la tabla ' + table);
  const assigns = [];
  for (const pair of splitOuter(setRaw, ',')) {
    const m = pair.match(/^(\w+)\s*=\s*(.+)$/i);
    if (!m) return print('ERROR:  sintaxis inv\u00e1lida en SET', 'error');
    assigns.push([rk(m[1]), parseVal(m[2])]);
  }
  let n = 0;
  t.rows.forEach((r) => {
    if (matchWhere(r, whereRaw)) {
      assigns.forEach(([col, v]) => { r[col] = v; });
      n++;
    }
  });
  print('UPDATE ' + n, 'success');
}

function deleteFrom(table, whereRaw) {
  const t = ST.dbs[ST.currentDB].tables[rk(table)];
  if (!t) return print('ERROR:  la relaci\u00f3n \u00ab' + table + '\u00bb no existe', 'error');
  if (!canTable(ST.currentRole, 'DELETE', ST.currentDB, 'public', table))
    return deny('permiso denegado a la tabla ' + table);
  const kept = t.rows.filter((r) => !matchWhere(r, whereRaw));
  const n = t.rows.length - kept.length;
  t.rows = kept;
  print('DELETE ' + n, 'success');
}

function selectFrom(colsRaw, table) {
  const t = ST.dbs[ST.currentDB].tables[rk(table)];
  if (!t) return print('ERROR:  la relaci\u00f3n \u00ab' + table + '\u00bb no existe', 'error');
  if (!canTable(ST.currentRole, 'SELECT', ST.currentDB, 'public', table))
    return deny('permiso denegado a la tabla ' + table);
  let cols;
  if (!colsRaw || colsRaw.trim() === '*') cols = t.columns.map((c) => c.name);
  else cols = splitOuter(colsRaw, ',').map((c) => c.trim().toLowerCase());
  const headers = cols.map((c) => c);
  const rows = t.rows.map((r) => cols.map((c) => (r[c] == null ? '' : r[c])));
  if (!rows.length) return print('(0 rows)', 'info');
  emitTable(headers, rows, rows.length);
}

/* --- Roles y usuarios (RF-06) --- */
function createRole(name, canLogin) {
  if (!needSuper()) return;
  const k = rk(name);
  if (ST.roles[k]) return print('ERROR:  el rol "' + name + '" ya existe', 'error');
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) return print('ERROR:  nombre de rol inv\u00e1lido', 'error');
  ST.roles[k] = { name, canLogin: !!canLogin, superuser: false, members: new Set() };
  ST.privs[k] = { db: {}, schema: {}, atabs: {}, tab: {} };
  if (canLogin) ST.membership[k] = new Set();
  print('CREATE ROLE', 'success');
}

function createUser(name) {
  if (!needSuper()) return;
  const k = rk(name);
  if (ST.roles[k]) return print('ERROR:  el rol "' + name + '" ya existe', 'error');
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) return print('ERROR:  nombre de usuario inv\u00e1lido', 'error');
  ST.roles[k] = { name, canLogin: true, superuser: false, members: new Set() };
  ST.privs[k] = { db: {}, schema: {}, atabs: {}, tab: {} };
  ST.membership[k] = new Set();
  print('CREATE ROLE', 'success');
}

function dropRoleOrUser(name) {
  if (!needSuper()) return;
  const k = rk(name);
  if (k === 'postgres') return print('ERROR:  no se puede eliminar el rol postgres', 'error');
  if (!ST.roles[k]) return print('ERROR:  no existe el rol \u00ab' + name + '\u00bb', 'error');
  if (ST.roles[k].members.size > 0)
    return print('ERROR:  el rol "' + name + '" no se puede eliminar porque tiene miembros. Rev\u00f3quelos primero', 'error');
  for (const u in ST.membership) {
    if (ST.membership[u].has(k))
      return print('ERROR:  el rol "' + name + '" no se puede eliminar porque "' + u + '" es miembro. Haga REVOKE primero', 'error');
  }
  if (k === ST.currentRole) return print('ERROR:  no se puede eliminar el rol de la sesi\u00f3n actual', 'error');
  delete ST.roles[k];
  delete ST.privs[k];
  delete ST.membership[k];
  print('DROP ROLE', 'success');
}

/* --- GRANT / REVOKE (RF-07) --- */
function grantObject(rawPrivs, scope, targetName, toRole) {
  if (!needSuper()) return;
  if (!roleExists(toRole)) return print('ERROR:  no existe el rol \u00ab' + toRole + '\u00bb', 'error');
  let privs, obj, key;
  if (scope.toLowerCase() === 'database') {
    if (!dbExists(targetName)) return print('ERROR:  la base de datos "' + targetName + '" no existe', 'error');
    try { privs = expandPrivs(rawPrivs.split(','), 'db'); } catch (e) { return print('ERROR:  ' + e.message, 'error'); }
    obj = 'db'; key = rk(targetName);
  } else if (scope.toLowerCase() === 'schema') {
    try { privs = expandPrivs(rawPrivs.split(','), 'schema'); } catch (e) { return print('ERROR:  ' + e.message, 'error'); }
    obj = 'schema'; key = rk(ST.currentDB) + '.' + rk(targetName);
  } else if (/^all\s+tables\s+in\s+schema$/i.test(scope)) {
    try { privs = expandPrivs(rawPrivs.split(','), 'all'); } catch (e) { return print('ERROR:  ' + e.message, 'error'); }
    obj = 'atabs'; key = rk(ST.currentDB) + '.' + rk(targetName);
  } else { /* table */
    try { privs = expandPrivs(rawPrivs.split(','), 'all'); } catch (e) { return print('ERROR:  ' + e.message, 'error'); }
    if (!ST.dbs[ST.currentDB].tables[rk(targetName)]) return print('ERROR:  la relaci\u00f3n \u00ab' + targetName + '\u00bb no existe', 'error');
    obj = 'tab'; key = rk(ST.currentDB) + '.public.' + rk(targetName);
  }
  grantInto(toRole, obj, key, privs);
  print('GRANT', 'success');
}

function revokeObject(rawPrivs, scope, targetName, fromRole) {
  if (!needSuper()) return;
  const r = rk(fromRole);
  if (!ST.roles[r]) return print('ERROR:  no existe el rol \u00ab' + fromRole + '\u00bb', 'error');
  let privs, obj, key;
  if (scope.toLowerCase() === 'database') {
    try { privs = expandPrivs(rawPrivs.split(','), 'db'); } catch (e) { return print('ERROR:  ' + e.message, 'error'); }
    obj = 'db'; key = rk(targetName);
  } else if (scope.toLowerCase() === 'schema') {
    try { privs = expandPrivs(rawPrivs.split(','), 'schema'); } catch (e) { return print('ERROR:  ' + e.message, 'error'); }
    obj = 'schema'; key = rk(ST.currentDB) + '.' + rk(targetName);
  } else if (/^all\s+tables\s+in\s+schema$/i.test(scope)) {
    try { privs = expandPrivs(rawPrivs.split(','), 'all'); } catch (e) { return print('ERROR:  ' + e.message, 'error'); }
    obj = 'atabs'; key = rk(ST.currentDB) + '.' + rk(targetName);
  } else {
    try { privs = expandPrivs(rawPrivs.split(','), 'all'); } catch (e) { return print('ERROR:  ' + e.message, 'error'); }
    obj = 'tab'; key = rk(ST.currentDB) + '.public.' + rk(targetName);
  }
  if (!ST.privs[r] || !ST.privs[r][obj][key]) return print('El rol \u00ab' + fromRole + '\u00bb no ten\u00eda privilegios en ese objeto', 'info');
  privs.forEach((p) => ST.privs[r][obj][key].delete(p));
  print('REVOKE', 'success');
}

function grantMembership(group, user) {
  if (!needSuper()) return;
  const g = rk(group), u = rk(user);
  if (!ST.roles[g]) return print('ERROR:  no existe el rol \u00ab' + group + '\u00bb', 'error');
  if (!ST.roles[u]) return print('ERROR:  no existe el rol \u00ab' + user + '\u00bb', 'error');
  if (!ST.roles[u].canLogin) return print('ERROR:  el rol "' + user + '" es NOLOGIN (grupo) y no puede ser miembro', 'error');
  ST.roles[g].members.add(u);
  if (!ST.membership[u]) ST.membership[u] = new Set();
  ST.membership[u].add(g);
  print('GRANT ROLE', 'success');
}

function revokeMembership(group, user) {
  if (!needSuper()) return;
  const g = rk(group), u = rk(user);
  if (!ST.roles[g]) return print('ERROR:  no existe el rol \u00ab' + group + '\u00bb', 'error');
  if (!ST.roles[u]) return print('ERROR:  no existe el rol \u00ab' + user + '\u00bb', 'error');
  if (!ST.membership[u] || !ST.membership[u].has(g)) return print('ERROR:  el rol "' + user + '" no es miembro de "' + group + '"', 'error');
  ST.roles[g].members.delete(u);
  ST.membership[u].delete(g);
  print('REVOKE ROLE', 'success');
}

function setRole(name) {
  const k = rk(name);
  if (!ST.roles[k]) return print('ERROR:  no existe el rol \u00ab' + name + '\u00bb', 'error');
  const cur = rk(ST.currentRole);
  const isMember = (ST.membership[k] && ST.membership[k].has(cur)) || effRoles(cur).has(k) || cur === k;
  if (!isSuper(cur) && !isMember)
    return print('ERROR:  se requiere la membres\u00eda del rol para hacer SET ROLE', 'error');
  ST.currentRole = k;
  updatePrompt();
  print('SET', 'success');
}

function resetRole() {
  if (ST.currentRole !== 'postgres') {
    ST.currentRole = 'postgres';
    updatePrompt();
  }
  print('RESET', 'success');
}

/* --- BACKUP DATABASE emulado (RF-09) --- */
function backupDB(name) {
  if (!needSuper()) return;
  if (!dbExists(name)) return print('ERROR:  la base de datos "' + name + '" no existe', 'error');
  const db = ST.dbs[rk(name)];
  const lines = [];
  lines.push('--');
  lines.push('-- PostgreSQL database dump (simulado)');
  lines.push('--');
  lines.push('CREATE DATABASE ' + db.name + ';');
  lines.push('\\c ' + db.name);
  lines.push('');
  const tnames = Object.keys(db.tables).sort();
  if (!tnames.length) lines.push('-- (la base de datos no tiene tablas)');
  for (const tn of tnames) {
    const t = db.tables[tn];
    const colDefs = t.columns.map((c) => '    ' + c.name + ' ' + c.type).join(',\n');
    lines.push('CREATE TABLE public.' + t.name + ' (');
    lines.push(colDefs);
    lines.push(');');
    t.rows.forEach((r) => {
      const vals = t.columns.map((c) => {
        const v = r[c.name];
        if (v === null) return 'NULL';
        if (typeof v === 'number') return String(v);
        if (typeof v === 'boolean') return v ? 'true' : 'false';
        return "'" + String(v).replace(/'/g, "''") + "'";
      }).join(', ');
      lines.push("INSERT INTO public." + t.name + " (" + t.columns.map((c) => c.name).join(', ') + ") VALUES (" + vals + ");");
    });
    lines.push('');
  }
  lines.push('-- End of dump');
  lines.forEach((l) => print(l, l.startsWith('--') ? 'info' : 'result'));
  print('BACKUP DATABASE ' + db.name + ' completado.', 'success');
}

/* ================== SISTEMA (RF-10) ================== */
function selectVersion() {
  print('PostgreSQL 16.3 on x86_64-pc-linux-gnu, compiled by gcc 11.3', 'result');
  print('(1 row)', 'info');
}

function selectPgRoles() {
  const names = Object.keys(ST.roles).sort();
  const rows = names.map((n) => {
    const r = ST.roles[n];
    return [n, r.canLogin ? 't' : 'f', r.superuser ? 't' : 'f', r.members.size ? Array.from(r.members).join(',') : ''];
  });
  emitTable(['rolname', 'rolcanlogin', 'rolsuper', 'rolmemberof'], rows, names.length);
}

/* ================== REINICIO (RF-13: \q) ================== */
function resetSession() {
  initState();
  updatePrompt();
  clearTerminal();
  banner();
}

/* ================== DESPACHADOR PRINCIPAL ================== */
function execute(cmd) {
  const C = cmd.replace(/;\s*$/, '').trim();
  let m;

  /* --- meta-comandos (RF-04, RF-05, RF-06, RF-10, RF-13) --- */
  if (/^\\(l|list)$/i.test(C)) return listDBs();
  if (/^\\du$/i.test(C)) return listRoles();
  if (/^\\dt$/i.test(C)) return listTables();
  if ((m = /^\\d\s+([\w.]+)$/i.exec(C))) return describeTable(m[1]);
  if (/^\\d$/i.test(C)) return listTables();
  if ((m = /^\\(?:c|connect)(?:\s+([\w-]+))?\s*$/i.exec(C)))
    return connectDB(m[1] ? m[1] : ST.currentDB);
  if (/^(\\q|quit|exit|salir)$/i.test(C)) return resetSession();
  if (/^(clear|cls)$/i.test(C)) return clearTerminal();
  if (/^(help|\\ayuda)$/i.test(C)) return openHelp();
  if (/^\\teoria$/i.test(C)) return openTheory();

  /* --- consultas de sistema (RF-10) --- */
  if (/^SELECT\s+version\s*\(\s*\)$/i.test(C)) return selectVersion();
  if (/^SELECT\s+\*\s+FROM\s+pg_roles$/i.test(C)) return selectPgRoles();

  /* --- CRUD de bases --- */
  if ((m = /^CREATE\s+DATABASE\s+(\w+)$/i.exec(C))) return createDatabase(m[1]);
  if ((m = /^DROP\s+DATABASE\s+(\w+)$/i.exec(C))) return dropDatabase(m[1]);

  /* --- CREATE/ALTER no soportados accesible --- */
  if (/^CREATE\s+ROLE/i.test(C) || /^CREATE\s+USER/i.test(C)) {
    let mr = /^CREATE\s+ROLE\s+(\w+)(?:\s+WITH)?\s*(LOGIN|NOLOGIN)?$/i.exec(C);
    if (mr) return createRole(mr[1], /^LOGIN$/i.test(mr[2] || ''));
    let mu = /^CREATE\s+USER\s+(\w+)(?:\s+WITH\s+PASSWORD\s+'[^']*')?\s*$/i.exec(C);
    if (mu) return createUser(mu[1]);
    return print('ERROR:  sintaxis inv\u00e1lida. Ej.: CREATE ROLE x NOLOGIN; / CREATE USER u WITH PASSWORD \'clave\';', 'error');
  }

  /* --- CREATE TABLE --- */
  if ((m = /^CREATE\s+TABLE\s+(\w+)\s*\(([\s\S]+)\)$/i.exec(C)))
    return createTable(m[1], m[2]);

  /* --- DROP TABLE / ROLE / USER --- */
  if ((m = /^DROP\s+TABLE\s+(\w+)$/i.exec(C))) return dropTable(m[1]);
  if ((m = /^DROP\s+(?:USER|ROLE)\s+(\w+)$/i.exec(C))) return dropRoleOrUser(m[1]);

  /* --- DML (RF-05) --- */
  if ((m = /^INSERT\s+INTO\s+(\w+)(?:\s*\(([^)]*)\))?\s+VALUES\s*\(([\s\S]+)\)$/i.exec(C)))
    return insertInto(m[1], m[2] || '', m[3]);
  if ((m = /^UPDATE\s+(\w+)\s+SET\s+(.+?)(?:\s+WHERE\s+([\s\S]+))?$/i.exec(C)))
    return updateTable(m[1], m[2], m[3] || '');
  if ((m = /^DELETE\s+FROM\s+(\w+)(?:\s+WHERE\s+([\s\S]+))?$/i.exec(C)))
    return deleteFrom(m[1], m[2] || '');
  if ((m = /^SELECT\s+(.+?)\s+FROM\s+(\w+)$/i.exec(C)))
    return selectFrom(m[1], m[2]);

  /* --- GRANT con objeto (RF-07) --- */
  if ((m = /^GRANT\s+(.+?)\s+ON\s+(DATABASE|SCHEMA|ALL\s+TABLES\s+IN\s+SCHEMA|TABLE)\s+(\w+)\s+TO\s+(\w+)$/i.exec(C)))
    return grantObject(m[1], m[2], m[3], m[4]);

  /* --- GRANT rol TO usuario (RF-06) --- */
  if ((m = /^GRANT\s+(\w+)\s+TO\s+(\w+)$/i.exec(C)))
    return grantMembership(m[1], m[2]);

  /* --- REVOKE (RF-07) --- */
  if ((m = /^REVOKE\s+(.+?)\s+ON\s+(DATABASE|SCHEMA|ALL\s+TABLES\s+IN\s+SCHEMA|TABLE)\s+(\w+)\s+FROM\s+(\w+)$/i.exec(C)))
    return revokeObject(m[1], m[2], m[3], m[4]);
  if ((m = /^REVOKE\s+(\w+)\s+FROM\s+(\w+)$/i.exec(C)))
    return revokeMembership(m[1], m[2]);

  /* --- SET ROLE / RESET ROLE (RF-08) --- */
  if ((m = /^SET\s+ROLE\s+(\w+)$/i.exec(C))) return setRole(m[1]);
  if (/^RESET\s+ROLE$/i.test(C)) return resetRole();

  /* --- BACKUP DATABASE (RF-09) --- */
  if ((m = /^BACKUP\s+DATABASE\s+(\w+)$/i.exec(C))) return backupDB(m[1]);

  /* --- no reconocido --- */
  print('ERROR:  comando no reconocido. Escrib\u00ed "Ayuda" para ver la lista.', 'error');
}

function run(raw) {
  const cmd = raw.trim();
  if (!cmd) return;
  printCmd(raw.replace(/\s+$/, ''));
  execute(cmd);
  inputEl.value = '';
  inputEl.focus();
}

/* ================== PANELES (RF-11, RF-12) ================== */
function openHelp() {
  theoryPanel.classList.remove('open');
  helpPanel.classList.add('open');
  print('Panel de Ayuda abierto.', 'info');
}

function openTheory() {
  helpPanel.classList.remove('open');
  theoryPanel.classList.add('open');
  print('Panel de Explicaciones abierto.', 'info');
}

/* ================== BIENVENIDA ================== */
function banner() {
  print('\u2550'.repeat(60), 'banner');
  print('EMULADOR INTERACTIVO DE PSQL', 'banner');
  print('Administraci\u00f3n de Seguridad de Base de Datos', 'banner2');
  print('psql (16.3) — HTML + CSS + JavaScript puro', 'info');
  print('', 'info');
  print('Comandos r\u00e1pidos: \\l (bases)  \\du (roles)  \\dt (tablas)  \\d tabla', 'result');
  print('Botones: [Ayuda] lista de comandos  [Explicaciones] teor\u00eda de roles y permisos', 'result');
  print('', 'info');
}

/* ================== EVENTOS ================== */
document.getElementById('btnRun').addEventListener('click', () => run(inputEl.value));
document.getElementById('btnHelp').addEventListener('click', openHelp);
document.getElementById('btnTheory').addEventListener('click', openTheory);
document.getElementById('btnClear').addEventListener('click', clearTerminal);

inputEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') run(inputEl.value);
});

outputEl.addEventListener('click', () => inputEl.focus());

/* ================== INICIO ================== */
initState();
updatePrompt();
banner();
inputEl.focus();