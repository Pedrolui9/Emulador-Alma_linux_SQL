// Test harness for emulador - mock localStorage y prueba BACKUP y resto
global.localStorage = {
  store:{},
  getItem(k){ return this.store[k]||null; },
  setItem(k,v){ this.store[k]=v; },
  removeItem(k){ delete this.store[k]; }
};

// Cargar app.js como texto y evalular clases (extraer sin DOM)
const fs=require('fs');
let code=fs.readFileSync('C:\\Users\\Pedro Insfran\\Desktop\\emulador\\js\\app.js','utf8');
// Cortar antes de // =============== INIT =============== (donde empieza DOM)
let cutIndex=code.indexOf('// =============== INIT ===============');
if(cutIndex>0) code=code.substring(0,cutIndex);
// Remover referencias a document/window que no existen en Node para eval
// Solo necesitamos definir clases, no ejecutar terminal
// Eliminar metodos que usan document dentro de clases? No, los mantenemos pero no los llamaremos que usen DOM para permisos
// Pero RoleManager y DatabaseEngine no usan document, solo localStorage, asi que seguro
// Evaluar y exponer globales
eval(code + "\nglobal.RoleManager = RoleManager; global.DatabaseEngine = DatabaseEngine; global.STORAGE_KEY = STORAGE_KEY; global.THEME_KEY = THEME_KEY;");
console.log('Clases cargadas');

// Crear instancias
const rm=new RoleManager();
const engine=new DatabaseEngine(rm);
console.log('Estado inicial:', rm.currentRole, rm.currentDB, 'DBs:', Object.keys(engine.databases));

// Helpers
function test(name, fn){
  try{ fn(); console.log(`✅ ${name}`); } catch(e){ console.log(`❌ ${name} -> ${e.message}`); }
}
function expectError(name, fn){
  try{ fn(); console.log(`❌ ${name} -> DEBIO FALLAR PERO NO FALLO (BUG)`); } catch(e){ console.log(`✅ ${name} -> correctamente denegado: ${e.message.split('\n')[0]}`); }
}

// Limpiar y preparar
localStorage.removeItem('alma_psql_v3');
// Re-crear limpio
const rm2=new RoleManager();
const eng2=new DatabaseEngine(rm2);
console.log('\n--- Test rol_ventas sin permisos debe fallar todo ---');
test('Crear rol_ventas', ()=> rm2.createRole('rol_ventas', false, false));
test('Crear user ventas', ()=> rm2.createRole('ventas', true, false));
test('Grant rol_ventas to ventas', ()=> rm2.grantRole('rol_ventas','ventas'));

// Simular SET ROLE ventas
rm2.currentRole='ventas';
rm2.originalRole='postgres';
console.log('CurrentRole:', rm2.currentRole, 'isSuper?', rm2.isSuperUser(rm2.currentRole));
console.log('Effective roles:', [...rm2.getEffectiveRoles('ventas')]);
console.log('canConnect postgres?', rm2.canConnect('ventas','postgres'));
console.log('canConnect compras?', rm2.canConnect('ventas','compras'));
console.log('canCreate public?', rm2.canCreateInSchema('ventas','compras','public'));
console.log('canSelect cargos?', rm2.canSelect('ventas','compras','public','cargos'));

expectError('BACKUP DATABASE compras sin CONNECT debe fallar', ()=>{
  // Simular handleBackup logic
  if(!rm2.canConnect('ventas','compras') && !rm2.isSuperUser('ventas')) throw new Error('ERROR:  permiso denegado a la base de datos "compras"\nEstado SQL: 42501');
  // si no lanza, es bug
  console.log('BUG: backup permitido');
  throw new Error('backup permitido indebidamente');
});

expectError('CREATE TABLE sin CREATE+USAGE debe fallar', ()=>{
  eng2.createTable('test_fail', [{name:'id', type:'integer'}], 'ventas');
});

expectError('SELECT sin SELECT debe fallar', ()=>{
  eng2.select('cargos','*',null,null,null,'ventas');
});

expectError('INSERT sin INSERT debe fallar', ()=>{
  eng2.insert('cargos',{id_car:99, car_descri:'Test'},'ventas');
});

expectError('\\c compras sin CONNECT debe fallar', ()=>{
  eng2.useDatabase('compras','ventas');
});

// Ahora dar solo CONNECT y probar que BACKUP sigue denegado si falta USAGE? Actualmente backup solo pide CONNECT, pero deberia pedir mas?
console.log('\n--- Dar solo CONNECT a rol_ventas ---');
rm2.grantDbPriv('rol_ventas','compras','CONNECT');
console.log('canConnect compras ahora?', rm2.canConnect('ventas','compras'));
test('BACKUP con solo CONNECT (actual) -> deberia permitir? (revisar)', ()=>{
  if(!rm2.canConnect('ventas','compras') && !rm2.isSuperUser('ventas')) throw new Error('denegado');
  console.log('Permitido con solo CONNECT (comportamiento actual)');
});
console.log('canSelect con solo CONNECT?', rm2.canSelect('ventas','compras','public','cargos')); // debe ser false porque falta USAGE y SELECT
expectError('SELECT con solo CONNECT debe fallar (falta USAGE+SELECT)', ()=>{
  eng2.select('cargos','*',null,null,null,'ventas');
});

// Dar USAGE
console.log('\n--- Dar USAGE ---');
rm2.grantSchemaPriv('rol_ventas','compras','public','USAGE');
console.log('has USAGE?', rm2.hasSchemaPriv('ventas','compras','public','USAGE'));
console.log('canSelect con CONNECT+USAGE pero sin SELECT?', rm2.canSelect('ventas','compras','public','cargos'));
expectError('SELECT con USAGE pero sin SELECT debe fallar', ()=>{
  eng2.select('cargos','*',null,null,null,'ventas');
});

// Dar SELECT
console.log('\n--- Dar SELECT ---');
rm2.grantAllTablesPriv('rol_ventas','compras','public','SELECT');
console.log('canSelect ahora?', rm2.canSelect('ventas','compras','public','cargos'));
test('SELECT con SELECT+USAGE debe pasar', ()=>{
  eng2.select('cargos','*',null,null,null,'ventas');
});
expectError('INSERT con solo SELECT debe fallar', ()=>{
  eng2.insert('cargos',{id_car:100, car_descri:'NoInsert'},'ventas');
});
expectError('CREATE TABLE con solo SELECT+USAGE debe fallar (falta CREATE)', ()=>{
  eng2.createTable('hack',[{name:'id',type:'integer'}],'ventas');
});

// Dar CREATE y probar
console.log('\n--- Dar CREATE ---');
rm2.grantSchemaPriv('rol_ventas','compras','public','CREATE');
console.log('canCreate?', rm2.canCreateInSchema('ventas','compras','public'));
test('CREATE TABLE con CREATE+USAGE debe pasar', ()=>{
  // necesita estar en db compras
  eng2.useDatabase('compras','ventas'); // ahora con CONNECT deberia pasar
  eng2.createTable('prueba_ventas',[{name:'id',type:'integer'}],'ventas');
  console.log('Tabla creada');
});

// Probar BACKUP con privilegios parciales
console.log('\n--- BACKUP con privilegios parciales ---');
test('BACKUP con CONNECT+USAGE+SELECT debe pasar? (actual solo pide CONNECT)', ()=>{
  if(!rm2.canConnect('ventas','compras')) throw new Error('no connect');
  console.log('BACKUP permitido (solo CONNECT)');
});

// Reset: probar rol sin nada no puede hacer nada
console.log('\n--- Resumen: rol_ventas ahora tiene CONNECT,USAGE,SELECT,CREATE ---');
console.log('Privs ventas:', rm2.privs['ventas']);
console.log('Privs rol_ventas:', rm2.privs['rol_ventas']);

// Test DROP
console.log('\n--- Test DROP sin ser owner debe fallar ---');
rm2.createRole('otro', true, false);
expectError('otro intenta DROP tabla prueba_ventas (owner ventas) debe fallar', ()=>{
  eng2.dropTable('prueba_ventas','otro');
});

console.log('\n--- Test \\\\dt sin USAGE debe advertir/denegar ---');
rm2.currentRole='otro';
console.log('otro has USAGE?', rm2.hasSchemaPriv('otro','compras','public','USAGE'));
console.log('Si \\\\dt solo advierte pero muestra tablas, es fuga de info - debe denegar o advertir');

console.log('\n--- FIN TESTS ---');
