global.localStorage={store:{},getItem(k){return this.store[k]||null},setItem(k,v){this.store[k]=v},removeItem(k){delete this.store[k]}};
const fs=require('fs');
const path=require('path');
const APP_JS=path.join(__dirname,'..','js','app.js');
let code=fs.readFileSync(APP_JS,'utf8');
let cut=code.indexOf('// =============== INIT ===============');
if(cut>0) code=code.substring(0,cut);
eval(code+"\nglobal.RoleManager=RoleManager; global.DatabaseEngine=DatabaseEngine;");
const rm=new RoleManager(); const eng=new DatabaseEngine(rm);
localStorage.removeItem('alma_psql_v3');
const rm2=new RoleManager(); const eng2=new DatabaseEngine(rm2);
function test(name, fn){
  try{ fn(); console.log(`✅ ${name}`);}catch(e){ console.log(`❌ ${name}: ${e.message.split('\n')[0]}`);}
}
function expectError(name, fn){
  try{ fn(); console.log(`❌ ${name}: DEBIO FALLAR`);}catch(e){ console.log(`✅ ${name}: correctamente bloqueado -> ${e.message.split('\n')[0]}`);}
}
console.log('=== Test flujo REASSIGN + DROP ===');
rm2.createRole('rol_ventas', false, false);
rm2.createRole('vendedor1', true, false);
rm2.grantRole('rol_ventas','vendedor1');
console.log('Creados rol_ventas y vendedor1, grant rol');

expectError('DROP rol_ventas sin privilegio pero con miembro debe fallar (tiene miembros)', ()=> rm2.dropRole('rol_ventas'));
console.log('Hacer REVOKE y luego DROP sin privilegio debe pasar (si no tiene privilegio)');
rm2.revokeRole('rol_ventas','vendedor1');
console.log('REVOKE ok');
test('DROP rol_ventas sin privilegio y sin miembros debe pasar', ()=> rm2.dropRole('rol_ventas'));
console.log('Recrear para test con privilegio');
rm2.createRole('rol_ventas', false, false);
rm2.grantRole('rol_ventas','vendedor1');
rm2.grantDbPriv('rol_ventas','compras','CONNECT');
rm2.grantSchemaPriv('rol_ventas','compras','public','USAGE');
rm2.grantAllTablesPriv('rol_ventas','compras','public','SELECT');
console.log('Con privilegio, hasAnyPrivilege rol_ventas?', rm2.hasAnyPrivilege('rol_ventas'));
expectError('DROP rol_ventas con privilegio y miembro debe pedir REASSIGN', ()=> rm2.dropRole('rol_ventas'));
expectError('DROP vendedor1 (miembro de rol privilegiado) debe pedir REASSIGN', ()=> rm2.dropRole('vendedor1'));

console.log('Hacer REASSIGN OWNED BY rol_ventas TO postgres');
let cnt=eng2.reassignOwnedBy('rol_ventas','postgres');
rm2.markReassigned('rol_ventas');
console.log(`REASSIGN ${cnt} objs`);
expectError('DROP rol_ventas tras REASSIGN pero sin DROP OWNED debe pedir DROP OWNED', ()=> rm2.dropRole('rol_ventas'));

console.log('Hacer DROP OWNED BY rol_ventas');
let dropped=eng2.dropOwnedBy('rol_ventas');
rm2.markDropOwned('rol_ventas');
console.log(`DROP OWNED ${dropped} objs, hasPriv ahora?`, rm2.hasAnyPrivilege('rol_ventas'));

expectError('DROP rol_ventas aún con miembro debe pedir REVOKE', ()=> rm2.dropRole('rol_ventas'));
rm2.revokeRole('rol_ventas','vendedor1');
console.log('REVOKE ok');
test('DROP rol_ventas tras REASSIGN+DROP OWNED+REVOKE debe pasar', ()=> rm2.dropRole('rol_ventas'));
console.log('Intentar DROP vendedor1 que era miembro de rol privilegiado (rol_ventas ya borrado)');

test('DROP vendedor1 tras borrarse su rol privilegiado debe pasar sin REASSIGN (ya no es miembro de ningún rol con privilegio)', ()=> {
  // vendedor1 no tiene privilegios directos ni es miembro de ningún rol con privilegio
  // (porque rol_ventas ya fue eliminado), así que debe poder borrarse sin REASSIGN ni DROP OWNED.
  if(!rm2.hasRole('vendedor1')) throw new Error('vendedor1 no existe');
  rm2.dropRole('vendedor1');
});

console.log('\nTest vendedor1 con privilegio directo');
rm2.createRole('rol_ventas', false, false);
rm2.createRole('vendedor1', true, false);
rm2.grantRole('rol_ventas','vendedor1');
rm2.grantDbPriv('rol_ventas','compras','CONNECT');
rm2.grantSchemaPriv('rol_ventas','compras','public','USAGE');
console.log('vendedor1 isMemberOfPrivileged?', [...(rm2.membership['vendedor1']||[])].some(g=> rm2.hasAnyPrivilege(g)));
expectError('DROP vendedor1 miembro de rol con privilegio debe pedir REASSIGN', ()=> rm2.dropRole('vendedor1'));
rm2.markReassigned('vendedor1');
console.log('REASSIGN vendedor1');
rm2.markDropOwned('vendedor1');
console.log('DROP OWNED vendedor1 (limpia)');
expectError('DROP vendedor1 aún con miembro debe pedir REVOKE', ()=> rm2.dropRole('vendedor1'));
rm2.revokeRole('rol_ventas','vendedor1');
test('DROP vendedor1 tras REASSIGN+DROP OWNED+REVOKE debe pasar', ()=> rm2.dropRole('vendedor1'));

console.log('\nFIN');
