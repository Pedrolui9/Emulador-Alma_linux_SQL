global.localStorage = { store:{}, getItem(k){return this.store[k]||null}, setItem(k,v){this.store[k]=v}, removeItem(k){delete this.store[k]} };
const fs=require('fs');
const path=require('path');
const APP_JS=path.join(__dirname,'..','js','app.js');
let code=fs.readFileSync(APP_JS,'utf8');
let cut=code.indexOf('// =============== INIT ===============');
if(cut>0) code=code.substring(0,cut);
eval(code + "\nglobal.RoleManager=RoleManager; global.DatabaseEngine=DatabaseEngine;");
console.log('=== TEST ALTER ROLE SUPERUSER / REVOKE ALL ===');
const rm=new RoleManager();
const eng=new DatabaseEngine(rm);
localStorage.removeItem('alma_psql_v3');
const rm2=new RoleManager();

function expectError(name, fn){
  try{ fn(); console.log(`❌ ${name} -> NO FALLO (BUG)`); }catch(e){ console.log(`✅ ${name} -> denegado: ${e.message.split('\n')[0]}`); }
}
function expectOk(name, fn){
  try{ fn(); console.log(`✅ ${name} -> ok`); }catch(e){ console.log(`❌ ${name} -> fallo inesperado: ${e.message.split('\n')[0]}`); }
}

// Preparar usuario normal
console.log('\n1. Crear usuario ana (no superuser)');
rm2.createRole('ana', true, false);
expectOk('ana NO es superuser al crearse', ()=>{
  if(rm2.isSuperUser('ana')) throw new Error('ana no debería ser superuser');
});

// 1b. ALTER ROLE SUPERUSER
console.log('\n2. ALTER ROLE ana SUPERUSER');
rm2.setSuperuser('ana', true);
expectOk('ana ahora ES superuser', ()=>{
  if(!rm2.isSuperUser('ana')) throw new Error('ana debería ser superuser');
});
// Con SUPERUSER, ana puede operar sin privilegios explícitos (bypass)
function checkSuperBypass(role){
  // un superuser no necesita USAGE/CONNECT para hacer lo que sea
  if(!rm2.isSuperUser(role)) throw new Error(role+' no es superuser');
}
expectOk('ana con superuser permite operar sin privilegios', ()=> checkSuperBypass('ana'));

// 2. ALTER ROLE NOSUPERUSER
console.log('\n3. ALTER ROLE ana NOSUPERUSER vuelve a ser normal');
rm2.setSuperuser('ana', false);
expectOk('ana ya no es superuser', ()=>{
  if(rm2.isSuperUser('ana')) throw new Error('ana no debería ser superuser tras NOSUPERUSER');
});

// 3. Quitar todos los privilegios con REVOKE ALL
console.log('\n4. REVOKE ALL FROM ana limpia privilegios');
rm2.createRole('vendedor', true, false);
rm2.grantDbPriv('vendedor','compras','CONNECT');
rm2.grantSchemaPriv('vendedor','compras','public','USAGE');
rm2.grantAllTablesPriv('vendedor','compras','public','SELECT');
expectOk('vendedor tiene privilegios antes de REVOKE ALL', ()=>{
  if(!rm2.hasAnyPrivilege('vendedor')) throw new Error('vendedor debería tener privilegios');
});
rm2.clearPrivileges('vendedor');
expectOk('vendedor ya no tiene privilegios tras REVOKE ALL', ()=>{
  if(rm2.hasAnyPrivilege('vendedor')) throw new Error('vendedor todavía tiene privilegios');
});
expectError('vendedor sin privilegios ya no puede conectar', ()=>{
  if(!rm2.canConnect('vendedor','compras')) throw new Error('sin CONNECT');
});

// 4. No se puede quitar SUPERUSER a postgres
console.log('\n5. postgres no pierde jamás superuser');
expectError('setSuperuser(postgres,false) debe fallar', ()=> rm2.setSuperuser('postgres', false));
expectOk('postgres sigue superuser', ()=>{
  if(!rm2.isSuperUser('postgres')) throw new Error('postgres debería seguir superuser');
});

console.log('\n=== FIN ALTER SUPERUSER ===');