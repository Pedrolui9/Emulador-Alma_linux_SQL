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
// Crear roles como en reporte
console.log('Test REVOKE rol_ventas FROM vendedor1');
rm2.createRole('rol_ventas', false, false);
rm2.createRole('vendedor1', true, false);
rm2.grantRole('rol_ventas','vendedor1');
console.log('Antes REVOKE, vendedor1 es miembro de rol_ventas?', rm2.membership['vendedor1']?.has('rol_ventas'));
console.log('Miembros de rol_ventas:', [...rm2.roles['rol_ventas'].members]);
// Simular REVOKE
try{
  rm2.revokeRole('rol_ventas','vendedor1');
  console.log('✅ REVOKE rol_ventas FROM vendedor1 -> ok, REVOKE');
  console.log('Después, es miembro?', rm2.membership['vendedor1']?.has('rol_ventas'));
  console.log('Miembros restantes:', [...rm2.roles['rol_ventas'].members]);
}catch(e){
  console.log('❌ REVOKE fallo:', e.message);
}
// Probar que al intentar de nuevo falla correctamente sin "e is not defined"
try{
  rm2.revokeRole('rol_ventas','vendedor1');
  console.log('❌ segundo REVOKE deberia fallar pero no fallo');
}catch(e){
  console.log('✅ segundo REVOKE correctamente falla (ya no es miembro):', e.message.split('\n')[0]);
  if(e.message.includes('e is not defined')) console.log('❌ AUN TIENE BUG e is not defined');
  else console.log('✅ No hay ReferenceError');
}
// Probar via handleStatement simulado (usando Terminal logic simplificada)
console.log('\nTest via handleStatement regex');
const stmt='REVOKE rol_ventas FROM vendedor1;';
const m=stmt.match(/^revoke\s+(\w+)\s+from\s+(\w+)\s*;?$/i);
console.log('Regex match:', m);
// Crear de nuevo para test handleStatement
rm2.grantRole('rol_ventas','vendedor1');
console.log('Re-agregado, test handleStatement revoke');
try{
  // Simular lo que hace handleStatement ahora (sin try catch bug)
  rm2.revokeRole(m[1], m[2]);
  console.log('✅ handleStatement REVOKE ok');
}catch(e){
  console.log('❌ handleStatement REVOKE error:', e.message, 'isReferenceError?', e instanceof ReferenceError);
}
console.log('\nFIN TEST REVOKE');
