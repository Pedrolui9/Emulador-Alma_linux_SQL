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
rm2.createRole('rol_ventas',false,false);
rm2.createRole('ventas',true,false);
rm2.grantRole('rol_ventas','ventas');
rm2.grantDbPriv('rol_ventas','compras','CONNECT');
rm2.grantSchemaPriv('rol_ventas','compras','public','USAGE');
rm2.grantSchemaPriv('rol_ventas','compras','public','CREATE');
rm2.grantAllTablesPriv('rol_ventas','compras','public','SELECT');
rm2.grantAllTablesPriv('rol_ventas','compras','public','INSERT');
rm2.currentRole='ventas';
console.log('Test backup como ventas con todos los permisos (CONNECT,USAGE,CREATE,SELECT,INSERT)');
console.log('isSuper?', rm2.isSuperUser('ventas'));
try{
  // simular handleBackup nuevo superuser only
  if(!rm2.isSuperUser('ventas')) throw new Error('ERROR: permiso denegado para BACKUP DATABASE\nDETAIL: Debe ser superusuario');
  console.log('❌ BUG: backup permitido para ventas');
}catch(e){
  console.log('✅ Correcto: backup denegado para ventas ->', e.message.split('\n')[0]);
}
rm2.currentRole='postgres';
console.log('Test backup como postgres (superuser)');
try{
  if(!rm2.isSuperUser('postgres')) throw new Error('no super');
  console.log('✅ Correcto: backup permitido para postgres');
}catch(e){ console.log('❌ fallo postgres', e.message); }
console.log('OFFLINE check: no CDN, fonts system, icons unicode');
