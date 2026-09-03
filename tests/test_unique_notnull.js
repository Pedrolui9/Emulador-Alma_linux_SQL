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
rm2.currentRole='postgres';
console.log('Test UNIQUE/NOT NULL');
try{
  eng2.createTable('test_unique', [{name:'id', type:'INTEGER', notNull:true, unique:true, primaryKey:true}, {name:'email', type:'VARCHAR(100)', notNull:true, unique:true, primaryKey:false}, {name:'des', type:'VARCHAR(100)', notNull:false, unique:false, primaryKey:false}], 'postgres');
  console.log('✅ CREATE TABLE con NOT NULL/UNIQUE ok');
}catch(e){ console.log('❌ CREATE fail', e.message); }

try{
  eng2.insert('test_unique', {id:1, email:'a@test.com', des:'x'}, 'postgres');
  console.log('✅ INSERT 1 ok');
}catch(e){ console.log('❌ INSERT1 fail', e.message); }

try{
  eng2.insert('test_unique', {id:1, email:'b@test.com', des:'y'}, 'postgres');
  console.log('❌ INSERT duplicado id 1 debió fallar');
}catch(e){ console.log('✅ INSERT duplicado correctamente falla:', e.message.split('\n')[0]); }

try{
  eng2.insert('test_unique', {id:2, email:null, des:'z'}, 'postgres');
  console.log('❌ INSERT null email debió fallar NOT NULL');
}catch(e){ console.log('✅ INSERT NOT NULL correctamente falla:', e.message.split('\n')[0]); }

try{
  eng2.insert('test_unique', {id:2, email:'a@test.com', des:'w'}, 'postgres');
  console.log('❌ INSERT email duplicado debió fallar');
}catch(e){ console.log('✅ INSERT UNIQUE email correctamente falla:', e.message.split('\n')[0]); }

try{
  eng2.update('test_unique', {email:'a@test.com'}, (r)=> r.id===1, 'postgres');
  console.log('✅ UPDATE mismo valor ok');
}catch(e){ console.log('❌ UPDATE fail', e.message); }

try{
  eng2.insert('test_unique', {id:2, email:'b@test.com', des:'ok'}, 'postgres');
  console.log('✅ INSERT 2 ok');
  eng2.update('test_unique', {email:'a@test.com'}, (r)=> r.id===2, 'postgres');
  console.log('❌ UPDATE a email duplicado debió fallar');
}catch(e){ console.log('✅ UPDATE UNIQUE correctamente falla:', e.message.split('\n')[0]); }

// Test ALTER TABLE
console.log('\nTest ALTER TABLE');
try{
  eng2.createTable('t_alter', [{name:'id', type:'INTEGER', notNull:true, unique:true, primaryKey:true}], 'postgres');
  console.log('✅ CREATE t_alter');
  eng2.alterTableAddColumn('t_alter', {name:'nombre', type:'VARCHAR(100)', notNull:false, unique:false, primaryKey:false}, 'postgres');
  console.log('✅ ALTER ADD COLUMN nombre');
  console.log('Columnas:', eng2.getTable('t_alter').columns.map(c=>c.name+':'+c.type+(c.notNull?' NOT NULL':'')+(c.unique?' UNIQUE':'')));
  eng2.alterTableRenameColumn('t_alter','nombre','nom','postgres');
  console.log('✅ ALTER RENAME COLUMN nombre->nom');
  console.log('Columnas ahora:', eng2.getTable('t_alter').columns.map(c=>c.name));
  eng2.alterTableRename('t_alter','t_nueva','postgres');
  console.log('✅ ALTER RENAME TO t_nueva');
  console.log('Tablas:', Object.keys(eng2.getCurrentTables()));
  eng2.alterTableDropColumn('t_nueva','nom','postgres');
  console.log('✅ ALTER DROP COLUMN nom');
  console.log('Columnas final:', eng2.getTable('t_nueva').columns.map(c=>c.name));
}catch(e){ console.log('❌ ALTER fail', e.message); }

console.log('\nTest buffer ; (simulado)');
console.log('Si CREATE TABLE sin ; debe quedar pendiente y no ejecutar hasta ; - lógica en Terminal.pending');
// No se puede probar sin DOM, pero verificamos que handleCreateTable parsea bien con constraints

console.log('\nFIN');
