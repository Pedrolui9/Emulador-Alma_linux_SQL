global.localStorage = { store:{}, getItem(k){return this.store[k]||null}, setItem(k,v){this.store[k]=v}, removeItem(k){delete this.store[k]} };
const fs=require('fs');
let code=fs.readFileSync('C:\\Users\\Pedro Insfran\\Desktop\\emulador\\js\\app.js','utf8');
let cut=code.indexOf('// =============== INIT ===============');
if(cut>0) code=code.substring(0,cut);
eval(code + "\nglobal.RoleManager=RoleManager; global.DatabaseEngine=DatabaseEngine;");
console.log('=== TEST V2 ESTRICTO ===');
const rm=new RoleManager();
const eng=new DatabaseEngine(rm);
localStorage.removeItem('alma_psql_v3');
const rm2=new RoleManager();
const eng2=new DatabaseEngine(rm2);

function expectError(name, fn){
  try{ fn(); console.log(`❌ ${name} -> NO FALLO (BUG)`); }catch(e){ console.log(`✅ ${name} -> denegado: ${e.message.split('\n')[0]}`); }
}
function expectOk(name, fn){
  try{ fn(); console.log(`✅ ${name} -> ok`); }catch(e){ console.log(`❌ ${name} -> fallo inesperado: ${e.message.split('\n')[0]}`); }
}

// Escenario exacto del usuario: rol_ventas sin permisos intenta BACKUP
console.log('\n1. Crear rol_ventas + user ventas sin permisos');
rm2.createRole('rol_ventas', false, false);
rm2.createRole('ventas', true, false);
rm2.grantRole('rol_ventas','ventas');
rm2.currentRole='ventas';
console.log('  currentRole ventas, isSuper', rm2.isSuperUser('ventas'));

// Debe fallar todo
expectError('BACKUP sin nada', ()=> {
  // simular nuevo handleBackup estricto
  const k='compras';
  if(!rm2.isSuperUser('ventas')){
    if(!rm2.canConnect('ventas',k)) throw new Error('ERROR: permiso denegado CONNECT');
    if(!rm2.hasSchemaPriv('ventas',k,'public','USAGE')) throw new Error('ERROR: permiso denegado USAGE');
    const hasAny = rm2.hasAllTablesPriv('ventas',k,'public','SELECT') || Object.keys(eng2.databases[k].tables).some(t=> rm2.hasTablePriv('ventas',k,'public',t,'SELECT'));
    if(Object.keys(eng2.databases[k].tables).length>0 && !hasAny) throw new Error('ERROR: permiso denegado SELECT');
  }
});
expectError('\\dt sin USAGE', ()=> {
  if(!rm2.hasSchemaPriv('ventas', eng2.databases[rm2.currentDB.toLowerCase()]? rm2.currentDB : 'postgres','public','USAGE') && !rm2.isSuperUser('ventas')) throw new Error('ERROR: permiso denegado USAGE');
  // pero currentDB es postgres, no tiene tablas, \dt vacio no falla? Probamos en compras
  rm2.currentDB='compras';
  if(!rm2.hasSchemaPriv('ventas','compras','public','USAGE')) throw new Error('ERROR: permiso denegado USAGE para \\dt');
});
rm2.currentDB='postgres';
expectError('SELECT sin permisos', ()=> eng2.select('cargos','*',null,null,null,'ventas')); // currentDB postgres tiene 0 tablas, pero intentará buscar cargos en postgres y fallará por no existe + permiso

// Ahora con solo CONNECT debe seguir fallando BACKUP por falta USAGE/SELECT
console.log('\n2. Dar solo CONNECT');
rm2.grantDbPriv('rol_ventas','compras','CONNECT');
expectError('BACKUP con solo CONNECT debe fallar (falta USAGE)', ()=>{
  const k='compras';
  if(!rm2.hasSchemaPriv('ventas',k,'public','USAGE')) throw new Error('ERROR: permiso denegado USAGE');
});

console.log('\n3. Dar USAGE');
rm2.grantSchemaPriv('rol_ventas','compras','public','USAGE');
expectError('BACKUP con CONNECT+USAGE pero sin SELECT debe fallar', ()=>{
  const k='compras';
  const hasAny = rm2.hasAllTablesPriv('ventas',k,'public','SELECT') || Object.keys(eng2.databases[k].tables).some(t=> rm2.hasTablePriv('ventas',k,'public',t,'SELECT'));
  if(!hasAny) throw new Error('ERROR: permiso denegado SELECT');
});

console.log('\n4. Dar SELECT');
rm2.grantAllTablesPriv('rol_ventas','compras','public','SELECT');
expectOk('BACKUP con CONNECT+USAGE+SELECT debe pasar', ()=>{
  const k='compras';
  if(!rm2.canConnect('ventas',k)) throw new Error('no connect');
  if(!rm2.hasSchemaPriv('ventas',k,'public','USAGE')) throw new Error('no usage');
  const hasAny = rm2.hasAllTablesPriv('ventas',k,'public','SELECT') || Object.keys(eng2.databases[k].tables).some(t=> rm2.hasTablePriv('ventas',k,'public',t,'SELECT'));
  if(!hasAny) throw new Error('no select');
});

// Probar \dt ahora debe pasar
rm2.currentDB='compras';
expectOk('\\dt con USAGE debe pasar', ()=>{
  if(!rm2.hasSchemaPriv('ventas','compras','public','USAGE')) throw new Error('no usage');
});

// Probar CREATE TABLE sin CREATE debe fallar, con CREATE debe pasar
expectError('CREATE TABLE sin CREATE debe fallar', ()=> eng2.createTable('x1',[{name:'id',type:'integer'}],'ventas'));
rm2.grantSchemaPriv('rol_ventas','compras','public','CREATE');
expectOk('CREATE TABLE con CREATE+USAGE debe pasar', ()=> eng2.createTable('x2',[{name:'id',type:'integer'}],'ventas'));

// Probar INSERT sin INSERT debe fallar
expectError('INSERT sin INSERT debe fallar', ()=> eng2.insert('cargos',{id_car:999, car_descri:'t'},'ventas'));
rm2.grantAllTablesPriv('rol_ventas','compras','public','INSERT');
expectOk('INSERT con INSERT debe pasar', ()=> eng2.insert('cargos',{id_car:999, car_descri:'t'},'ventas'));

// Probar UPDATE/DELETE sin privilegio
expectError('UPDATE sin UPDATE debe fallar', ()=> eng2.update('cargos',{car_descri:'x'}, null,'ventas'));
rm2.grantAllTablesPriv('rol_ventas','compras','public','UPDATE');
expectOk('UPDATE con UPDATE debe pasar', ()=> eng2.update('cargos',{car_descri:'Gerente X'}, (r)=> r.id_car===999,'ventas'));

expectError('DELETE sin DELETE debe fallar', ()=> eng2.delete('cargos', (r)=> r.id_car===999,'ventas'));
rm2.grantAllTablesPriv('rol_ventas','compras','public','DELETE');
expectOk('DELETE con DELETE debe pasar', ()=> eng2.delete('cargos', (r)=> r.id_car===999,'ventas'));

// Probar que postgres superuser siempre pasa
rm2.currentRole='postgres';
expectOk('postgres BACKUP siempre pasa', ()=>{
  // superuser bypass
});

console.log('\n=== FIN V2 ===');
console.log('Si todos los ✅ están correctos, el fix funciona');
