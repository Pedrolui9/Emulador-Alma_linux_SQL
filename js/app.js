/* Emulador psql AlmaLinux v3.0 - DDL/LMD Validado - Senior */
const STORAGE_KEY='alma_psql_v3';
const THEME_KEY='alma_theme_v1';

// =============== ERROR SQL CENTRALIZADO ===============
// Genera el mensaje de error con formato estándar psql para unificar el texto:
//   ERROR:  <mensaje>
//   DETAIL:  <detalle>      (opcional)
//   HINT:  <pista>          (opcional)
//   Estado SQL: <código>    (opcional, ej. 42501 / 23502 / 23505)
function sqlError(message, opts={}){
  const {detail, hint, sqlstate} = opts;
  let m = 'ERROR:  ' + message;
  if(detail) m += '\nDETAIL:  ' + detail;
  if(hint) m += '\nHINT:  ' + hint;
  if(sqlstate) m += '\nEstado SQL: ' + sqlstate;
  return new Error(m);
}

// =============== ROLE MANAGER ===============
class RoleManager{
  constructor(){
    this.roles={}; // name_lower -> {nameOriginal, canLogin, superuser, members:Set}
    this.privs={}; // name_lower -> { db:{db: Set}, schema:{'db.schema':Set}, allTables:{'db.schema':Set}, table:{'db.schema.table':Set} }
    this.membership={}; // user_lower -> Set(group_lower)
    this.reassignedDone={}; // track REASSIGN OWNED BY para validación
    this.dropOwnedDone={}; // track DROP OWNED BY
    this.loadSeed();
  }
  loadSeed(){
    // try load from storage
    try{
      const raw=localStorage.getItem(STORAGE_KEY);
      if(raw){
        const obj=JSON.parse(raw);
        if(obj.roles){
          // restore roles
          for(let k in obj.roles){
            const r=obj.roles[k];
            this.roles[k]={...r, members:new Set(r.members||[])};
          }
          for(let k in obj.privs){
            const p=obj.privs[k];
            this.privs[k]={
              db: {}, schema:{}, allTables:{}, table:{}
            };
            for(let db in (p.db||{})) this.privs[k].db[db]=new Set(p.db[db]);
            for(let s in (p.schema||{})) this.privs[k].schema[s]=new Set(p.schema[s]);
            for(let s in (p.allTables||{})) this.privs[k].allTables[s]=new Set(p.allTables[s]);
            for(let t in (p.table||{})) this.privs[k].table[t]=new Set(p.table[t]);
          }
          for(let k in (obj.membership||{})){
            this.membership[k]=new Set(obj.membership[k]);
          }
          this.reassignedDone=obj.reassignedDone||{};
          this.dropOwnedDone=obj.dropOwnedDone||{};
          this.currentDB=obj.currentDB||'postgres';
          this.currentRole=obj.currentRole||'postgres';
          this.originalRole=obj.originalRole||'postgres';
          return;
        }
      }
    }catch(e){ console.warn('load fail',e)}
    // seed
    this.roles['postgres']={nameOriginal:'postgres', canLogin:true, superuser:true, members:new Set()};
    this.privs['postgres']={db:{}, schema:{}, allTables:{}, table:{}};
    this.membership['postgres']=new Set();
    this.reassignedDone={};
    this.dropOwnedDone={};
    // seed
    this.roles['postgres']={nameOriginal:'postgres', canLogin:true, superuser:true, members:new Set()};
    this.privs['postgres']={db:{}, schema:{}, allTables:{}, table:{}};
    this.membership['postgres']=new Set();
    this.currentDB='postgres';
    this.currentRole='postgres';
    this.originalRole='postgres';
    this.save();
  }
  save(extra){
    const toSave={
      roles:{}, privs:{}, membership:{},
      reassignedDone: this.reassignedDone,
      dropOwnedDone: this.dropOwnedDone,
      currentDB: (extra&&extra.currentDB!==undefined)? extra.currentDB : this.currentDB,
      currentRole: (extra&&extra.currentRole!==undefined)? extra.currentRole : this.currentRole,
      originalRole: this.originalRole,
      databases: extra? extra.databases : undefined
    };
    for(let k in this.roles){
      toSave.roles[k]={...this.roles[k], members:[...this.roles[k].members]};
    }
    for(let k in this.privs){
      toSave.privs[k]={ db:{}, schema:{}, allTables:{}, table:{}};
      for(let db in this.privs[k].db) toSave.privs[k].db[db]=[...this.privs[k].db[db]];
      for(let s in this.privs[k].schema) toSave.privs[k].schema[s]=[...this.privs[k].schema[s]];
      for(let s in this.privs[k].allTables) toSave.privs[k].allTables[s]=[...this.privs[k].allTables[s]];
      for(let t in this.privs[k].table) toSave.privs[k].table[t]=[...this.privs[k].table[t]];
    }
    for(let k in this.membership) toSave.membership[k]=[...this.membership[k]];
    // databases stored via DatabaseEngine, but we need to merge
    if(extra && extra.databases){
      // keep databases in same key for easy load by engine? engine will handle separately but we store together
      const existing = JSON.parse(localStorage.getItem(STORAGE_KEY)||'{}');
      // We'll let engine save handle it, but store roles part separately? For now store combined
      const combined = {...existing, ...toSave, databases: extra.databases};
      localStorage.setItem(STORAGE_KEY, JSON.stringify(combined));
    } else {
      const existingRaw=localStorage.getItem(STORAGE_KEY);
      let existing={};
      try{ existing=JSON.parse(existingRaw||'{}')}catch(e){}
      const combined={...existing, ...toSave};
      localStorage.setItem(STORAGE_KEY, JSON.stringify(combined));
    }
  }
  hasRole(name){ return !!this.roles[name.toLowerCase()]; }
  getRole(name){ return this.roles[name.toLowerCase()]; }
  ensurePrivEntry(role){
    const k=role.toLowerCase();
    if(!this.privs[k]) this.privs[k]={db:{}, schema:{}, allTables:{}, table:{}};
  }
  createRole(name, canLogin, superuser=false){
    const k=name.toLowerCase();
    if(this.hasRole(k)) throw new Error(`ERROR:  el rol "${name}" ya existe`);
    if(!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) throw new Error('Nombre de rol inválido');
    this.roles[k]={nameOriginal:name, canLogin, superuser, members:new Set()};
    this.privs[k]={db:{}, schema:{}, allTables:{}, table:{}};
    if(canLogin) this.membership[k]=new Set();
    this.save();
  }
  hasAnyPrivilege(role){
    const k=role.toLowerCase();
    const p=this.privs[k];
    if(!p) return false;
    if(Object.keys(p.db).some(db=> p.db[db].size>0)) return true;
    if(Object.keys(p.schema).some(s=> p.schema[s].size>0)) return true;
    if(Object.keys(p.allTables).some(s=> p.allTables[s].size>0)) return true;
    if(Object.keys(p.table).some(t=> p.table[t].size>0)) return true;
    return false;
  }
  // REASSIGN OWNED resuelve los objetos poseídos (no revoca privilegios GRANT).
  markReassigned(role){ this.reassignedDone[role.toLowerCase()]=true; this.save(); }
  // DROP OWNED elimina objetos Y revoca privilegios: resuelve ambas partes.
  markDropOwned(role){
    const k=role.toLowerCase();
    this.reassignedDone[k]=true;
    this.dropOwnedDone[k]=true;
    this.save();
  }
  clearReassignMarks(role){ delete this.reassignedDone[role.toLowerCase()]; delete this.dropOwnedDone[role.toLowerCase()]; }
  dropRole(name){
    const k=name.toLowerCase();
    if(!this.hasRole(k)) throw new Error(`ERROR:  no existe el rol «${name}»`);
    if(k==='postgres') throw new Error('ERROR:  no se puede eliminar el rol postgres');
    const r=this.roles[k];
    // Validación estricta y fiel a PostgreSQL:
    //  - REASSIGN OWNED BY x TO y  ->  resuelve objetos poseídos.
    //  - DROP OWNED BY x           ->  resuelve objetos poseídos Y revoca privilegios GRANT.
    // Cualquiera de los dos (o ambos) desbloquea la parte de "objetos"; el DROP
    // de un rol con privilegios GRANT exige DROP OWNED (lo único que los revoca).
    const hasPriv=this.hasAnyPrivilege(k);
    if(hasPriv && !this.dropOwnedDone[k]){
      throw new Error(`ERROR:  el rol "${name}" tiene privilegios. Debe hacer DROP OWNED BY ${name} antes de DROP\nHINT:  DROP OWNED BY ${name};`);
    }
    // Si es miembro de un rol privilegiado, debe resolver sus objetos antes de DROP
    const memberOfPrivileged = [...(this.membership[k]||[])].some(g=> this.hasAnyPrivilege(g));
    if(memberOfPrivileged && !this.reassignedDone[k]){
      throw new Error(`ERROR:  el usuario "${name}" es miembro de un rol con privilegios. Debe hacer REASSIGN OWNED BY ${name} TO postgres o DROP OWNED BY ${name} antes de DROP`);
    }
    // check members (si es grupo con miembros)
    if(r.members.size>0) throw new Error(`ERROR:  el rol "${name}" no puede ser eliminado porque tiene miembros. Haga REVOKE ${name} FROM usuario primero`);
    // check if any user is member of this role (si es grupo, alguien lo tiene)
    for(let user in this.membership){
      if(this.membership[user].has(k)) throw new Error(`ERROR:  el rol "${name}" no puede ser eliminado porque el usuario "${user}" es miembro. Haga REVOKE ${name} FROM ${user}`);
    }
    // check if this role is still member of any group (si es usuario miembro)
    if(this.membership[k] && this.membership[k].size>0){
      const groups=[...this.membership[k]].join(', ');
      throw new Error(`ERROR:  el rol "${name}" aún es miembro de ${groups}. Haga REVOKE ${groups} FROM ${name} primero`);
    }
    delete this.roles[k];
    delete this.privs[k];
    delete this.membership[k];
    delete this.reassignedDone[k];
    delete this.dropOwnedDone[k];
    // remove from other memberships
    for(let u in this.membership) this.membership[u].delete(k);
    this.save();
  }
  grantRole(group, user){
    const g=group.toLowerCase(), u=user.toLowerCase();
    if(!this.hasRole(g)) throw new Error(`ERROR:  no existe el rol «${group}»`);
    if(!this.hasRole(u)) throw new Error(`ERROR:  no existe el rol «${user}»`);
    if(!this.getRole(u).canLogin) throw new Error(`ERROR:  el rol "${user}" no puede ser miembro porque es NOLOGIN (grupo)`);
    this.roles[g].members.add(u);
    if(!this.membership[u]) this.membership[u]=new Set();
    this.membership[u].add(g);
    this.save();
  }
  revokeRole(group, user){
    const g=group.toLowerCase(), u=user.toLowerCase();
    if(!this.hasRole(g)) throw new Error(`ERROR:  no existe el rol «${group}»`);
    if(!this.hasRole(u)) throw new Error(`ERROR:  no existe el rol «${user}»`);
    if(!this.membership[u] || !this.membership[u].has(g)) throw new Error(`ERROR:  el rol "${user}" no es miembro de "${group}"`);
    this.roles[g].members.delete(u);
    this.membership[u].delete(g);
    this.save();
  }
  clearPrivileges(role){
    const k=role.toLowerCase();
    if(this.privs[k]){
      this.privs[k]={db:{}, schema:{}, allTables:{}, table:{}};
      this.save();
    }
  }
  setSuperuser(name, bool){
    const k=name.toLowerCase();
    if(!this.hasRole(k)) throw new Error(`ERROR:  no existe el rol «${name}»`);
    if(k==='postgres') throw new Error('ERROR:  no se puede quitar el rol superusuario a postgres');
    this.roles[k].superuser=bool;
    this.save();
  }
  // privilege grants - al otorgar nuevo privilegio, se invalida REASSIGN/DROP previo
  grantDbPriv(role, db, priv){
    this.ensurePrivEntry(role);
    const k=role.toLowerCase();
    const d=db.toLowerCase();
    if(!this.privs[k].db[d]) this.privs[k].db[d]=new Set();
    this.privs[k].db[d].add(priv.toUpperCase());
    delete this.reassignedDone[k]; delete this.dropOwnedDone[k];
    this.save();
  }
  grantSchemaPriv(role, db, schema, priv){
    this.ensurePrivEntry(role);
    const k=role.toLowerCase();
    const key=`${db.toLowerCase()}.${schema.toLowerCase()}`;
    if(!this.privs[k].schema[key]) this.privs[k].schema[key]=new Set();
    this.privs[k].schema[key].add(priv.toUpperCase());
    delete this.reassignedDone[k]; delete this.dropOwnedDone[k];
    this.save();
  }
  grantAllTablesPriv(role, db, schema, priv){
    this.ensurePrivEntry(role);
    const k=role.toLowerCase();
    const key=`${db.toLowerCase()}.${schema.toLowerCase()}`;
    if(!this.privs[k].allTables[key]) this.privs[k].allTables[key]=new Set();
    this.privs[k].allTables[key].add(priv.toUpperCase());
    delete this.reassignedDone[k]; delete this.dropOwnedDone[k];
    this.save();
  }
  grantTablePriv(role, db, schema, table, priv){
    this.ensurePrivEntry(role);
    const k=role.toLowerCase();
    const key=`${db.toLowerCase()}.${schema.toLowerCase()}.${table.toLowerCase()}`;
    if(!this.privs[k].table[key]) this.privs[k].table[key]=new Set();
    this.privs[k].table[key].add(priv.toUpperCase());
    delete this.reassignedDone[k]; delete this.dropOwnedDone[k];
    this.save();
  }
  revokeDbPriv(role, db, priv){
    const k=role.toLowerCase();
    if(!this.privs[k]||!this.privs[k].db[db.toLowerCase()]) throw new Error(`No tiene privilegio ${priv} en ${db}`);
    this.privs[k].db[db.toLowerCase()].delete(priv.toUpperCase());
    this.save();
  }
  revokeSchemaPriv(role, db, schema, priv){
    const k=role.toLowerCase();
    const key=`${db.toLowerCase()}.${schema.toLowerCase()}`;
    if(!this.privs[k]||!this.privs[k].schema[key]||!this.privs[k].schema[key].has(priv.toUpperCase())) throw new Error(`No tiene privilegio ${priv} en schema ${schema}`);
    this.privs[k].schema[key].delete(priv.toUpperCase());
    this.save();
  }
  revokeAllTablesPriv(role, db, schema, priv){
    const k=role.toLowerCase();
    const key=`${db.toLowerCase()}.${schema.toLowerCase()}`;
    if(!this.privs[k]||!this.privs[k].allTables[key]||!this.privs[k].allTables[key].has(priv.toUpperCase())) throw new Error(`No tiene privilegio ${priv} en ALL TABLES IN SCHEMA ${schema}`);
    this.privs[k].allTables[key].delete(priv.toUpperCase());
    this.save();
  }
  revokeTablePriv(role, db, schema, table, priv){
    const k=role.toLowerCase();
    const key=`${db.toLowerCase()}.${schema.toLowerCase()}.${table.toLowerCase()}`;
    if(!this.privs[k]||!this.privs[k].table[key]||!this.privs[k].table[key].has(priv.toUpperCase())) throw new Error(`No tiene privilegio ${priv} en tabla ${table}`);
    this.privs[k].table[key].delete(priv.toUpperCase());
    this.save();
  }

  // effective roles
  getEffectiveRoles(role){
    const start=role.toLowerCase();
    const res=new Set([start]);
    const queue=[start];
    const visited=new Set();
    while(queue.length){
      const cur=queue.shift();
      if(visited.has(cur)) continue;
      visited.add(cur);
      const mem=this.membership[cur];
      if(mem){
        for(let g of mem){
          if(!res.has(g)){ res.add(g); queue.push(g); }
        }
      }
    }
    return res;
  }
  isSuperUser(role){
    const eff=this.getEffectiveRoles(role);
    for(let r of eff){
      const obj=this.roles[r];
      if(obj && obj.superuser) return true;
    }
    return role.toLowerCase()==='postgres' || (this.roles[role.toLowerCase()] && this.roles[role.toLowerCase()].superuser);
  }
  // checks
  hasDbPriv(role, db, priv){
    if(this.isSuperUser(role)) return true;
    const eff=this.getEffectiveRoles(role);
    priv=priv.toUpperCase(); db=db.toLowerCase();
    for(let r of eff){
      const p=this.privs[r];
      if(p && p.db[db] && p.db[db].has(priv)) return true;
    }
    return false;
  }
  hasSchemaPriv(role, db, schema, priv){
    if(this.isSuperUser(role)) return true;
    const eff=this.getEffectiveRoles(role);
    priv=priv.toUpperCase();
    const key=`${db.toLowerCase()}.${schema.toLowerCase()}`;
    for(let r of eff){
      const p=this.privs[r];
      if(p && p.schema[key] && p.schema[key].has(priv)) return true;
    }
    return false;
  }
  hasAllTablesPriv(role, db, schema, priv){
    if(this.isSuperUser(role)) return true;
    const eff=this.getEffectiveRoles(role);
    priv=priv.toUpperCase();
    const key=`${db.toLowerCase()}.${schema.toLowerCase()}`;
    for(let r of eff){
      const p=this.privs[r];
      if(p && p.allTables[key] && p.allTables[key].has(priv)) return true;
    }
    return false;
  }
  hasTablePriv(role, db, schema, table, priv){
    if(this.isSuperUser(role)) return true;
    const eff=this.getEffectiveRoles(role);
    priv=priv.toUpperCase();
    const tkey=`${db.toLowerCase()}.${schema.toLowerCase()}.${table.toLowerCase()}`;
    const skey=`${db.toLowerCase()}.${schema.toLowerCase()}`;
    for(let r of eff){
      const p=this.privs[r];
      if(!p) continue;
      if(p.table[tkey] && p.table[tkey].has(priv)) return true;
      if(p.allTables[skey] && p.allTables[skey].has(priv)) return true;
    }
    return false;
  }
  // high level checks with USAGE requirement
  canConnect(role, db){
    if(this.isSuperUser(role)) return true;
    return this.hasDbPriv(role, db, 'CONNECT');
  }
  canCreateInSchema(role, db, schema='public'){
    if(this.isSuperUser(role)) return true;
    // needs CREATE and USAGE
    return this.hasSchemaPriv(role, db, schema, 'CREATE') && this.hasSchemaPriv(role, db, schema, 'USAGE');
  }
  canSelect(role, db, schema, table){
    if(this.isSuperUser(role)) return true;
    if(!this.hasSchemaPriv(role, db, schema, 'USAGE')) return false;
    return this.hasTablePriv(role, db, schema, table, 'SELECT');
  }
  canInsert(role, db, schema, table){ 
    if(this.isSuperUser(role)) return true;
    if(!this.hasSchemaPriv(role, db, schema, 'USAGE')) return false;
    return this.hasTablePriv(role, db, schema, table, 'INSERT');
  }
  canUpdate(role, db, schema, table){ 
    if(this.isSuperUser(role)) return true;
    if(!this.hasSchemaPriv(role, db, schema, 'USAGE')) return false;
    return this.hasTablePriv(role, db, schema, table, 'UPDATE');
  }
  canDelete(role, db, schema, table){ 
    if(this.isSuperUser(role)) return true;
    if(!this.hasSchemaPriv(role, db, schema, 'USAGE')) return false;
    return this.hasTablePriv(role, db, schema, table, 'DELETE');
  }

  listPrivsForStatus(role, db){
    const eff=this.getEffectiveRoles(role);
    let lines=[];
    for(let r of eff){
      const p=this.privs[r];
      if(!p) continue;
      for(let d in p.db) if(d===db.toLowerCase()) lines.push(`${r}: CONNECT/DB privs on ${d}: ${[...p.db[d]].join(',')}`);
      for(let s in p.schema) if(s.startsWith(db.toLowerCase()+'.')) lines.push(`${r}: SCHEMA ${s}: ${[...p.schema[s]].join(',')}`);
      for(let s in p.allTables) if(s.startsWith(db.toLowerCase()+'.')) lines.push(`${r}: ALL TABLES IN ${s}: ${[...p.allTables[s]].join(',')}`);
      for(let t in p.table) if(t.startsWith(db.toLowerCase()+'.')) lines.push(`${r}: TABLE ${t}: ${[...p.table[t]].join(',')}`);
    }
    return lines;
  }
}

// =============== DATABASE ENGINE ===============
class DatabaseEngine{
  constructor(roleManager){
    this.rm=roleManager;
    this.databases={}; // dbLower -> {nameOriginal, tables:{tableLower->{nameOriginal, columns, rows, owner}}}
    this.load();
    if(Object.keys(this.databases).length===0) this.seed();
  }
  load(){
    try{
      const raw=localStorage.getItem(STORAGE_KEY);
      if(raw){
        const obj=JSON.parse(raw);
        if(obj.databases){
          this.databases=obj.databases;
          // ensure owner y constraints por compatibilidad
          for(let db in this.databases) for(let t in this.databases[db].tables){
            if(!this.databases[db].tables[t].owner) this.databases[db].tables[t].owner='postgres';
            this.databases[db].tables[t].columns.forEach(c=>{
              if(c.notNull===undefined) c.notNull=false;
              if(c.unique===undefined) c.unique=false;
              if(c.primaryKey===undefined) c.primaryKey=false;
            });
          }
        }
        if(obj.currentDB) this.rm.currentDB=obj.currentDB;
        if(obj.currentRole) this.rm.currentRole=obj.currentRole;
      }
    }catch(e){}
  }
  save(){
    this.rm.save({databases:this.databases, currentDB:this.rm.currentDB, currentRole:this.rm.currentRole});
  }
  seed(){
    this.databases['postgres']={nameOriginal:'postgres', tables:{}};
    // compras with cargos
    this.databases['compras']={nameOriginal:'compras', tables:{
      'cargos':{nameOriginal:'cargos', owner:'postgres', columns:[{name:'id_car', type:'integer'},{name:'car_descri', type:'character varying(100)'}], rows:[{id_car:1, car_descri:'Gerente'},{id_car:2, car_descri:'Supervisor'}]},
      'ciudad':{nameOriginal:'ciudad', owner:'postgres', columns:[{name:'id', type:'integer'},{name:'des', type:'character varying(100)'}], rows:[{id:1, des:'Asunción'}]}
    }};
    this.save();
  }
  listDatabases(){ return Object.keys(this.databases).map(k=>this.databases[k].nameOriginal); }
  hasDatabase(name){ return !!this.databases[name.toLowerCase()]; }
  createDatabase(name, creator){
    const k=name.toLowerCase();
    if(this.hasDatabase(k)) throw new Error(`ERROR:  la base de datos "${name}" ya existe`);
    if(!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) throw new Error('Nombre de BD inválido');
    if(!this.rm.isSuperUser(creator)) throw sqlError('permiso denegado para crear base de datos', {sqlstate:'42501'});
    this.databases[k]={nameOriginal:name, tables:{}};
    this.save();
  }
  dropDatabase(name, actor){
    const k=name.toLowerCase();
    if(!this.hasDatabase(k)) throw new Error(`ERROR:  no existe la base de datos «${name}»`);
    if(!this.rm.isSuperUser(actor)) throw new Error('ERROR:  debe ser superusuario para eliminar bases de datos');
    if(k==='postgres') throw new Error('ERROR:  no se puede eliminar la base postgres');
    delete this.databases[k];
    if(this.rm.currentDB.toLowerCase()===k) this.rm.currentDB='postgres';
    this.save();
  }
  useDatabase(name, actor){
    const k=name.toLowerCase();
    if(!this.hasDatabase(k)) throw new Error(`ERROR:  no existe la base de datos «${name}»`);
    if(!this.rm.canConnect(actor, k)) throw sqlError(`permiso denegado a la base de datos "${name}"`, {detail:'El usuario no tiene privilegio CONNECT.', sqlstate:'42501'});
    this.rm.currentDB=this.databases[k].nameOriginal;
    this.save();
  }
  getCurrentTables(){
    const db=this.databases[this.rm.currentDB.toLowerCase()];
    if(!db) throw new Error('No hay BD seleccionada');
    return db.tables;
  }
  getCurrentDBObj(){ return this.databases[this.rm.currentDB.toLowerCase()]; }
  hasTable(name){
    const tbls=this.getCurrentTables();
    return !!tbls[name.toLowerCase()];
  }
  getTable(name){
    const tbls=this.getCurrentTables();
    const k=name.toLowerCase();
    if(!tbls[k]) throw new Error(`ERROR:  la relación «${name}» no existe`);
    return tbls[k];
  }
  // ¿El actor es dueño de la tabla (o es superuser)? Permite delegar GRANT sobre ella.
  isOwnerOfTable(actor, tableName){
    if(this.rm.isSuperUser(actor)) return true;
    const tbls=this.getCurrentTables();
    const t=tbls[tableName.toLowerCase()];
    return !!t && t.owner.toLowerCase()===actor.toLowerCase();
  }
  // ¿El actor puede otorgar sobre TODAS las tablas del esquema? (superuser, o dueño de todas).
  canGrantOnAllTables(actor, schema='public'){
    if(this.rm.isSuperUser(actor)) return true;
    const tbls=this.getCurrentTables();
    const db=this.rm.currentDB.toLowerCase();
    if(!Object.keys(tbls).length) return true; // sin tablas no hay objetos que proteger
    return Object.values(tbls).every(t=> t.owner.toLowerCase()===actor.toLowerCase());
  }
  createTable(name, columns, creator){
    const db=this.rm.currentDB;
    if(!this.rm.canCreateInSchema(creator, db, 'public')) throw sqlError('permiso denegado para esquema public', {detail:'El usuario no tiene privilegio CREATE ni USAGE en el esquema.', sqlstate:'42501'});
    const tbls=this.getCurrentTables();
    const k=name.toLowerCase();
    if(tbls[k]) throw new Error(`ERROR:  la relación "${name}" ya existe`);
    if(!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) throw new Error('Nombre de tabla inválido');
    tbls[k]={nameOriginal:name, columns, rows:[], owner:creator.toLowerCase()};
    this.save();
  }
  dropTable(name, actor){
    const tbls=this.getCurrentTables();
    const k=name.toLowerCase();
    if(!tbls[k]) throw new Error(`ERROR:  la relación «${name}» no existe`);
    const owner=tbls[k].owner;
    if(!this.rm.isSuperUser(actor) && owner!==actor.toLowerCase()) throw new Error(`ERROR:  debe ser dueño de la relación ${name} o superusuario`);
    // also need CREATE privilege? In postgres, owner can drop regardless
    delete tbls[k];
    this.save();
  }
  truncate(name, actor){
    const t=this.getTable(name);
    // need DELETE or TRUNCATE? We'll require DELETE or owner
    if(!this.rm.isSuperUser(actor) && t.owner!==actor.toLowerCase()){
      if(!this.rm.canDelete(actor, this.rm.currentDB, 'public', name)) throw sqlError('permiso denegado a la tabla '+name, {sqlstate:'42501'});
    }
    t.rows=[];
    this.save();
  }
  // ALTER TABLE - DDL para UPDATE/DELETE de estructura
  alterTableAddColumn(tableName, colDef, actor){
    const db=this.rm.currentDB;
    if(!this.rm.canCreateInSchema(actor, db, 'public')) throw sqlError('permiso denegado para esquema public', {sqlstate:'42501'});
    const table=this.getTable(tableName);
    if(!this.rm.isSuperUser(actor) && table.owner!==actor.toLowerCase()) throw new Error(`ERROR:  debe ser dueño de la relación ${tableName} o superusuario`);
    if(table.columns.find(c=>c.name.toLowerCase()===colDef.name.toLowerCase())) throw new Error(`ERROR:  la columna «${colDef.name}» ya existe`);
    table.columns.push(colDef);
    // Añadir null a filas existentes, pero si NOT NULL sin default, debe fallar si hay filas
    if((colDef.notNull || colDef.primaryKey) && table.rows.length>0){
      throw new Error(`ERROR:  la columna «${colDef.name}» contiene restricción NOT NULL y la tabla no está vacía\nHINT:  Añada la columna sin NOT NULL primero, luego actualice valores.`);
    }
    table.rows.forEach(r=> r[colDef.name]=null);
    this.save();
  }
  alterTableDropColumn(tableName, colName, actor){
    const db=this.rm.currentDB;
    if(!this.rm.canCreateInSchema(actor, db, 'public')) throw sqlError('permiso denegado para esquema public', {sqlstate:'42501'});
    const table=this.getTable(tableName);
    if(!this.rm.isSuperUser(actor) && table.owner!==actor.toLowerCase()) throw new Error(`ERROR:  debe ser dueño de la relación ${tableName} o superusuario`);
    const idx=table.columns.findIndex(c=>c.name.toLowerCase()===colName.toLowerCase());
    if(idx===-1) throw new Error(`ERROR:  la columna «${colName}» no existe`);
    const realName=table.columns[idx].name;
    table.columns.splice(idx,1);
    // Borrar de cada fila la referencia a la columna eliminada usando su nombre real
    table.rows.forEach(r=> delete r[realName]);
    this.save();
  }
  alterTableRename(tableName, newName, actor){
    const tbls=this.getCurrentTables();
    const k=tableName.toLowerCase();
    const nk=newName.toLowerCase();
    if(!tbls[k]) throw new Error(`ERROR:  la relación «${tableName}» no existe`);
    if(tbls[nk]) throw new Error(`ERROR:  la relación «${newName}» ya existe`);
    if(!this.rm.canCreateInSchema(actor, this.rm.currentDB, 'public')) throw sqlError('permiso denegado para esquema public', {sqlstate:'42501'});
    if(!this.rm.isSuperUser(actor) && tbls[k].owner!==actor.toLowerCase()) throw new Error(`ERROR:  debe ser dueño de la relación ${tableName} o superusuario`);
    tbls[nk]=tbls[k];
    tbls[nk].nameOriginal=newName;
    delete tbls[k];
    this.save();
  }
  alterTableRenameColumn(tableName, oldCol, newCol, actor){
    const table=this.getTable(tableName);
    if(!this.rm.canCreateInSchema(actor, this.rm.currentDB, 'public')) throw sqlError('permiso denegado para esquema public', {sqlstate:'42501'});
    if(!this.rm.isSuperUser(actor) && table.owner!==actor.toLowerCase()) throw new Error(`ERROR:  debe ser dueño de la relación ${tableName} o superusuario`);
    const col=table.columns.find(c=>c.name.toLowerCase()===oldCol.toLowerCase());
    if(!col) throw new Error(`ERROR:  la columna «${oldCol}» no existe`);
    if(table.columns.find(c=>c.name.toLowerCase()===newCol.toLowerCase())) throw new Error(`ERROR:  la columna «${newCol}» ya existe`);
    const oldName=col.name;
    col.name=newCol;
    table.rows.forEach(r=>{ if(r[oldName]!==undefined){ r[newCol]=r[oldName]; delete r[oldName]; }});
    this.save();
  }
  reassignOwnedBy(oldRole, newRole){
    const oldL=oldRole.toLowerCase(), newL=newRole.toLowerCase();
    if(!this.rm.hasRole(oldRole)) throw new Error(`ERROR:  no existe el rol «${oldRole}»`);
    if(!this.rm.hasRole(newRole)) throw new Error(`ERROR:  no existe el rol «${newRole}»`);
    let count=0;
    for(let db in this.databases){
      for(let t in this.databases[db].tables){
        if(this.databases[db].tables[t].owner===oldL){
          this.databases[db].tables[t].owner=newL;
          count++;
        }
      }
    }
    this.save();
    return count;
  }
  dropOwnedBy(role){
    const k=role.toLowerCase();
    if(!this.rm.hasRole(role)) throw new Error(`ERROR:  no existe el rol «${role}»`);
    // Eliminar tablas donde owner == role
    let dropped=0;
    for(let db in this.databases){
      for(let t in this.databases[db].tables){
        if(this.databases[db].tables[t].owner===k){
          delete this.databases[db].tables[t];
          dropped++;
        }
      }
    }
    // Limpiar privilegios del rol
    this.rm.clearPrivileges(role);
    this.save();
    return dropped;
  }
  ownsObjects(role){
    const k=role.toLowerCase();
    for(let db in this.databases){
      for(let t in this.databases[db].tables){
        if(this.databases[db].tables[t].owner===k) return true;
      }
    }
    return false;
  }
  describe(name){ return this.getTable(name); }
  insert(tableName, obj, actor){
    const db=this.rm.currentDB;
    if(!this.rm.canInsert(actor, db, 'public', tableName)) throw sqlError('permiso denegado a la tabla '+tableName, {sqlstate:'42501'});
    const table=this.getTable(tableName);
    const row={};
    table.columns.forEach(col=>{
      let val=obj[col.name]!==undefined? obj[col.name] : obj[col.name.toLowerCase()];
      if(val===undefined){
        for(let k in obj) if(k.toLowerCase()===col.name.toLowerCase()){ val=obj[k]; break; }
      }
      if(val===undefined) val=null;
      const coerced=this.coerce(val, col.type);
      // NOT NULL validación
      if((col.notNull || col.primaryKey) && (coerced===null || coerced===undefined)){
        throw sqlError(`el valor nulo en la columna «${col.name}» viola la restricción not-null`, {detail:`La columna «${col.name}» de la relación «${tableName}» contiene restricción NOT NULL.`, sqlstate:'23502'});
      }
      row[col.name]=coerced;
    });
    // UNIQUE / PRIMARY KEY validación
    table.columns.forEach(col=>{
      if((col.unique || col.primaryKey) && row[col.name]!==null){
        const exists=table.rows.some(r=> String(r[col.name])===String(row[col.name]));
        if(exists){
          throw sqlError(`llave duplicada viola restricción de unicidad «${tableName}_${col.name}_key»`, {detail:`La llave (${col.name})=(${row[col.name]}) ya existe.`, sqlstate:'23505'});
        }
      }
    });
    table.rows.push(row);
    this.save();
  }
  coerce(val, type){
    if(val===null||val===undefined) return null;
    const t=type.toLowerCase();
    if(t.startsWith('int')){
      if(val==='null') return null;
      const n=parseInt(val,10);
      if(isNaN(n)) throw new Error(`Valor INT inválido '${val}'`);
      return n;
    }
    if(t.startsWith('float')||t.startsWith('double')||t.startsWith('decimal')||t.startsWith('numeric')){
      const n=parseFloat(val);
      if(isNaN(n)) throw new Error(`Valor numérico inválido '${val}'`);
      return n;
    }
    if(t.startsWith('bool')){
      if(typeof val==='boolean') return val;
      const s=String(val).toLowerCase();
      if(['true','1','t','yes'].includes(s)) return true;
      if(['false','0','f','no'].includes(s)) return false;
      return Boolean(val);
    }
    if(typeof val==='string'){
      if((val.startsWith("'")&&val.endsWith("'"))||(val.startsWith('"')&&val.endsWith('"'))) return val.slice(1,-1);
      return val;
    }
    return String(val);
  }
  select(tableName, cols, whereFn, orderBy, limit, actor){
    const db=this.rm.currentDB;
    if(!this.rm.canSelect(actor, db, 'public', tableName)) throw sqlError('permiso denegado a la tabla '+tableName, {sqlstate:'42501'});
    const table=this.getTable(tableName);
    let rows=[...table.rows];
    if(whereFn) rows=rows.filter(whereFn);
    if(orderBy){
      const {col, dir}=orderBy;
      rows.sort((a,b)=>{
        let av=a[col], bv=b[col];
        if(av===bv) return 0;
        if(av===null) return 1;
        if(bv===null) return -1;
        if(typeof av==='number'&& typeof bv==='number') return dir==='ASC'? av-bv : bv-av;
        return dir==='ASC'? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
      });
    }
    if(limit!==null) rows=rows.slice(0,limit);
    let outCols;
    if(cols==='*'||!cols) outCols=table.columns.map(c=>c.name);
    else outCols=cols;
    // validate cols exist
    outCols.forEach(c=>{ if(!table.columns.find(col=>col.name.toLowerCase()===c.toLowerCase())) throw new Error(`ERROR:  la columna «${c}» no existe`);});
    // map to real column names case
    const realCols=outCols.map(c=>{
      const real=table.columns.find(col=>col.name.toLowerCase()===c.toLowerCase());
      return real? real.name : c;
    });
    return {columns:realCols, rows: rows.map(r=>{
      const o={};
      realCols.forEach(c=> o[c]=r[c]!==undefined? r[c]: null);
      return o;
    })};
  }
  update(tableName, setObj, whereFn, actor){
    const db=this.rm.currentDB;
    if(!this.rm.canUpdate(actor, db, 'public', tableName)) throw sqlError('permiso denegado a la tabla '+tableName, {sqlstate:'42501'});
    const table=this.getTable(tableName);
    // Pre-validar NOT NULL y UNIQUE antes de modificar
    const rowsToUpdate=table.rows.filter(r=> !whereFn || whereFn(r));
    // Validar cada fila
    for(let row of rowsToUpdate){
      for(let k in setObj){
        const real=table.columns.find(c=>c.name.toLowerCase()===k.toLowerCase());
        if(!real) throw new Error(`ERROR:  la columna «${k}» no existe`);
        const newVal=this.coerce(setObj[k], real.type);
        if((real.notNull || real.primaryKey) && (newVal===null || newVal===undefined)){
          throw sqlError(`el valor nulo en la columna «${real.name}» viola la restricción not-null`, {sqlstate:'23502'});
        }
        if((real.unique || real.primaryKey) && newVal!==null){
          const conflict=table.rows.some(r=> r!==row && String(r[real.name])===String(newVal));
          // También verificar conflicto entre filas que se actualizan al mismo valor
          const conflictInBatch=rowsToUpdate.some(r=> r!==row && String(this.coerce(setObj[k], real.type))===String(newVal) && String(r[real.name])!==String(newVal));
          // Si el nuevo valor ya existe en otra fila (incluyendo no actualizadas) -> error
          if(conflict){
            throw sqlError(`llave duplicada viola restricción de unicidad «${tableName}_${real.name}_key»`, {detail:`La llave (${real.name})=(${newVal}) ya existe.`, sqlstate:'23505'});
          }
        }
      }
    }
    let count=0;
    table.rows.forEach(row=>{
      if(!whereFn || whereFn(row)){
        for(let k in setObj){
          const real=table.columns.find(c=>c.name.toLowerCase()===k.toLowerCase());
          row[real.name]=this.coerce(setObj[k], real.type);
        }
        count++;
      }
    });
    if(count>0) this.save();
    return count;
  }
  delete(tableName, whereFn, actor){
    const db=this.rm.currentDB;
    if(!this.rm.canDelete(actor, db, 'public', tableName)) throw sqlError('permiso denegado a la tabla '+tableName, {sqlstate:'42501'});
    const table=this.getTable(tableName);
    const before=table.rows.length;
    if(!whereFn) table.rows=[];
    else table.rows=table.rows.filter(r=>!whereFn(r));
    const del=before-table.rows.length;
    if(del>0) this.save();
    return del;
  }
  stats(){
    let totalTables=0, totalRows=0;
    for(let k in this.databases){
      totalTables+=Object.keys(this.databases[k].tables).length;
      for(let t in this.databases[k].tables) totalRows+=this.databases[k].tables[t].rows.length;
    }
    return {dbs:Object.keys(this.databases).length, totalTables, totalRows, current:this.rm.currentDB, role:this.rm.currentRole};
  }
  exportData(){
    const raw=localStorage.getItem(STORAGE_KEY);
    return raw? JSON.stringify(JSON.parse(raw), null, 2) : '{}';
  }
  importData(json, actor){
    if(!this.rm.isSuperUser(actor)) throw new Error('Solo superuser puede importar');
    const obj=JSON.parse(json);
    if(!obj.databases) throw new Error('JSON inválido');
    localStorage.setItem(STORAGE_KEY, JSON.stringify(obj));
    location.reload();
  }
  wipe(){
    localStorage.removeItem(STORAGE_KEY);
    location.reload();
  }
}

// =============== TERMINAL ===============
class Terminal{
  constructor(engine, rm){
    this.engine=engine;
    this.rm=rm;
    this.history=[];
    this.histIndex=-1;
    this.pending=''; // buffer para sentencias sin ;
    this.isPending=false;
    this.outputEl=document.getElementById('output');
    this.inputEl=document.getElementById('cmdInput');
    this.promptEl=document.getElementById('prompt');
    this.bindEvents();
    this.updatePrompt();
    this.updateStatus();
    this.renderTree();
    this.printWelcome();
  }
  bindEvents(){
    this.inputEl.addEventListener('keydown', e=>{
      if(e.key==='Enter'){ const v=this.inputEl.value; this.exec(v); this.inputEl.value=''; e.preventDefault();}
      else if(e.key==='ArrowUp'){ if(this.history.length){ if(this.histIndex===-1) this.histIndex=this.history.length-1; else if(this.histIndex>0) this.histIndex--; this.inputEl.value=this.history[this.histIndex]||''; setTimeout(()=>this.inputEl.selectionStart=this.inputEl.value.length,0);} e.preventDefault();}
      else if(e.key==='ArrowDown'){ if(this.histIndex!==-1){ if(this.histIndex < this.history.length-1){ this.histIndex++; this.inputEl.value=this.history[this.histIndex];} else {this.histIndex=-1; this.inputEl.value='';}} e.preventDefault();}
      else if(e.key==='Tab'){ e.preventDefault(); this.autocomplete();}
      else if(e.key==='l' && e.ctrlKey){ e.preventDefault(); this.clear();}
    });
    document.getElementById('terminal').addEventListener('click', ()=>this.inputEl.focus());
  }
  updatePrompt(){
    const db=this.rm.currentDB;
    const role=this.rm.currentRole;
    const sym = this.rm.isSuperUser(role) ? '#' : '>';
    // RF-02: prompt dinámico + continuación si falta ;
    const basePrompt = this.isPending ? `${db}-${sym} ` : `${db}=${sym} `;
    this.promptEl.textContent=basePrompt;
    this.promptEl.style.color=this.rm.isSuperUser(role)? 'var(--accent)' : 'var(--accent2)';
    document.getElementById('windowTitle').textContent=`${db}=${sym} — ${role} — psql — AlmaLinux — 80x24`;
    const promptLabel=document.getElementById('prompt-label');
    if(promptLabel) promptLabel.textContent= this.isPending ? `${db}-${sym}` : `${db}=${sym}`;
    // badge mantiene rol
    document.getElementById('roleBadge').textContent=`● ${role}${sym}`;
    const sess=document.getElementById('sessionInfo');
    const isSuper=this.rm.isSuperUser(role);
    sess.innerHTML=`Rol: <b style="color:var(--accent)">${role}</b> ${isSuper? '(superuser)':''}<br>BD: <b style="color:var(--accent2)">${db}</b> <span style="color:var(--fg-dim)">${this.rm.canConnect(role, db)? '✓ CONNECT': '✗ CONNECT'}</span><br>Esquema: public <span style="color:var(--fg-dim)">${this.rm.hasSchemaPriv(role,db,'public','USAGE')?'✓ USAGE':'✗ USAGE'} ${this.rm.hasSchemaPriv(role,db,'public','CREATE')?'✓ CREATE':'✗ CREATE'}</span>`;
    document.getElementById('statusDb').textContent=`● ${db}`;
    document.getElementById('statusRole').textContent=`● ${role}`;
    document.getElementById('statusPrivs').textContent= isSuper? 'superuser' : this.getPrivSummary(role, db);
  }
  getPrivSummary(role, db){
    const parts=[];
    if(this.rm.hasSchemaPriv(role,db,'public','USAGE')) parts.push('USAGE');
    if(this.rm.hasSchemaPriv(role,db,'public','CREATE')) parts.push('CREATE');
    if(this.rm.hasAllTablesPriv(role,db,'public','SELECT')) parts.push('SELECT');
    if(this.rm.hasAllTablesPriv(role,db,'public','INSERT')) parts.push('INSERT');
    if(this.rm.hasAllTablesPriv(role,db,'public','UPDATE')) parts.push('UPDATE');
    if(this.rm.hasAllTablesPriv(role,db,'public','DELETE')) parts.push('DELETE');
    // also table specific
    if(parts.length===0) return 'sin privilegios';
    return parts.join(',');
  }
  updateStatus(){
    const s=this.engine.stats();
    this.renderTree();
    this.updatePrompt();
  }
  renderTree(){
    const el=document.getElementById('dbTree');
    if(!el) return; // sin sidebar - esquina hace el trabajo
    const dbs=Object.keys(this.engine.databases);
    if(!dbs.length){ el.textContent='(sin BD)'; return;}
    let txt='';
    dbs.forEach(k=>{
      const db=this.engine.databases[k];
      const isCur=this.rm.currentDB.toLowerCase()===k;
      txt+=`${isCur?'●':'○'} ${db.nameOriginal}${isCur?'  ← actual':''}\n`;
      const tables=Object.values(db.tables);
      if(!tables.length) txt+=`   └─ (sin tablas)\n`;
      else tables.forEach((t,i)=>{
        const last=i===tables.length-1;
        const pre=last?'   └─':'   ├─';
        txt+=`${pre} ${t.nameOriginal} [${t.rows.length} filas] owner:${t.owner}\n`;
      });
    });
    // add roles summary
    txt+=`\nRoles:\n`;
    for(let r in this.rm.roles){
      const ro=this.rm.roles[r];
      txt+=` ${ro.nameOriginal} ${ro.superuser?'[superuser]':''} ${ro.canLogin?'':'[NOLOGIN]'} \n`;
    }
    el.textContent=txt;
  }
  print(html, cls='line'){ const d=document.createElement('div'); d.className=cls; d.innerHTML=html; this.outputEl.appendChild(d); this.scroll();}
  printText(t,cls='line'){ const d=document.createElement('div'); d.className=cls; d.textContent=t; this.outputEl.appendChild(d); this.scroll();}
  printTable(cols, rows){
    if(!rows.length){ this.print('(0 rows)','line muted'); return;}
    const wrap=document.createElement('div'); wrap.className='table-wrap';
    const table=document.createElement('table'); table.className='db-table';
    const thead=document.createElement('thead'); const trh=document.createElement('tr');
    cols.forEach(c=>{ const th=document.createElement('th'); th.textContent=c; trh.appendChild(th);}); thead.appendChild(trh); table.appendChild(thead);
    const tbody=document.createElement('tbody');
    rows.forEach(r=>{
      const tr=document.createElement('tr');
      cols.forEach(c=>{
        const td=document.createElement('td');
        let v=r[c];
        if(v===null||v===undefined) td.innerHTML='<span style="opacity:0.4">NULL</span>';
        else if(typeof v==='boolean') td.innerHTML=v?'<span style="color:var(--success)">t</span>':'<span style="color:var(--error)">f</span>';
        else td.textContent=String(v);
        tr.appendChild(td);
      }); tbody.appendChild(tr);
    }); table.appendChild(tbody); wrap.appendChild(table); this.outputEl.appendChild(wrap);
    this.print(`(${rows.length} rows)`, 'line muted'); this.scroll();
  }
  scroll(){ const t=document.getElementById('terminal'); t.scrollTop=t.scrollHeight; }
  clear(){ this.outputEl.innerHTML=''; }
  escapeHtml(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  printWelcome(){
    this.print(`<span style="color:var(--accent)">██████╗ ██████╗  ██╗██╗</span>`, 'line');
    this.print(`<span style="color:var(--accent)">██╔══██╗██╔══██╗ ██║██║</span>`, 'line');
    this.print(`<span style="color:var(--accent)">██████╔╝██║  ██║ ██║██║</span>`, 'line');
    this.print(`<span style="color:var(--accent)">██╔══██╗██║  ██║ ██║██║</span>`, 'line');
    this.print(`<span style="color:var(--accent)">██████╔╝██████╔╝ ██║██║</span>`, 'line');
    this.print(`<span style="color:var(--accent)">╚═════╝ ╚═════╝  ╚═╝╚═╝</span>`, 'line');
    this.print(``, 'line');
    this.print(`<span class="muted">psql (16.3, server 15.7) — Escriba \\q para salir</span>`, 'line muted');
    const sym=this.rm.isSuperUser(this.rm.currentRole)? '#': '>';
   
  }
  exec(raw){
    let cmd=raw.trim();
    if(!cmd) return;
    this.history.push(cmd);
    if(this.history.length>200) this.history.shift();
    this.histIndex=-1;
    const sym=this.rm.isSuperUser(this.rm.currentRole)? '#': '>';

    // Si hay sentencia pendiente (sin ;), concatenar con espacio (sin mensaje extra)
    if(this.pending){
      this.print(`<span style="color:var(--accent)">${this.escapeHtml(this.rm.currentDB)}-${sym}</span> ${this.escapeHtml(cmd)}`, 'line input');
      this.pending += ' ' + cmd;
      if(!this.pending.trim().endsWith(';')){
        this.isPending=true;
        this.updatePrompt();
        return;
      } else {
        const full=this.pending;
        this.pending='';
        this.isPending=false;
        this.updatePrompt();
        // Ejecutar el buffer completo sin re-imprimir (ya se imprimió línea a línea)
        const statements=this.splitStatements(full);
        for(let stmt of statements){
          if(!stmt.trim()) continue;
          try{ this.handleStatement(stmt.trim()); }catch(e){ this.print(this.escapeHtml(e.message), 'line error'); }
        }
        this.updateStatus();
        return;
      }
    }

    // No hay pendiente: verificar si necesita ; - bash NO necesita ;, psql/SQL SÍ (como en AlmaLinux real)
    // Whitelist bash/linux que entra sin ; : help, clear, status, neofetch, whoami, pwd, date, uname, ls, echo, history, theme/color y paneles
    const isNoSemiWhitelist=/^(help|clear|cls|history|status|neofetch|whoami|pwd|date|uname|ls|echo|theme|color|\\tema|\\color|\\acciones|\\ayuda|\\teoria|\\proyecto|\\q|quit|exit|salir)(\s|;|$)/i.test(cmd);
    if(!isNoSemiWhitelist && !cmd.endsWith(';')){
      this.pending=cmd;
      this.isPending=true;
      this.print(`<span style="color:var(--accent)">${this.escapeHtml(this.rm.currentDB)}=${sym}</span> ${this.escapeHtml(cmd)}`, 'line input');
      this.updatePrompt();
      return;
    }

    // Ejecución normal
    this.print(`<span style="color:var(--accent)">${this.escapeHtml(this.rm.currentDB)}=${sym}</span> ${this.escapeHtml(cmd)}`, 'line input');
    const statements=this.splitStatements(cmd);
    for(let stmt of statements){
      if(!stmt.trim()) continue;
      try{ this.handleStatement(stmt.trim()); }catch(e){ this.print(this.escapeHtml(e.message), 'line error'); }
    }
    this.updateStatus();
  }
  splitStatements(cmd){
    const res=[]; let cur=''; let inS=false,inD=false;
    for(let i=0;i<cmd.length;i++){
      const ch=cmd[i];
      if(ch==="'"&&!inD) inS=!inS;
      else if(ch==='"'&&!inS) inD=!inD;
      if(ch===';'&&!inS&&!inD){ res.push(cur); cur='';} else cur+=ch;
    }
    if(cur.trim()) res.push(cur);
    return res;
  }
  autocomplete(){
    const val=this.inputEl.value.toLowerCase();
    const candidates=['\\l','\\dt','\\d ','\\du','\\c ','\\ayuda','\\teoria','\\proyecto','\\acciones','\\tema','\\color','SELECT * FROM ','INSERT INTO ','UPDATE ','DELETE FROM ','CREATE TABLE ','CREATE DATABASE ','CREATE ROLE ','CREATE USER ','GRANT ','REVOKE ','SET ROLE ','RESET ROLE','DROP TABLE ','DROP DATABASE ','help','clear','status','neofetch','theme list','theme set '];
    const m=candidates.find(c=>c.toLowerCase().startsWith(val));
    if(m) this.inputEl.value=m;
  }
  handleTema(stmt){
    const raw=stmt.replace(/^\\tema\s*/i,'').trim().replace(/;$/,'');
    if(!raw){
      this.print(`<b>Temas disponibles:</b>`, 'line');
      this.print(`  alma (default)  •  hacker  •  light  •  dracula  •  amber  •  matrix  •  redalert  •  solarized`, 'line muted');
      this.print(`Uso: <code>\\tema set &lt;nombre&gt;</code>  o  <code>\\tema &lt;nombre&gt;</code>  — Ejemplo: <code>\\tema hacker</code>`, 'line');
      this.print(`Actual: <b style="color:var(--accent)">${(localStorage.getItem(THEME_KEY)||'alma')}</b>`, 'line');
      return;
    }
    let name=raw;
    if(name.toLowerCase().startsWith('set ')) name=name.slice(4).trim();
    name=name.toLowerCase();
    const valid=['alma','hacker','light','dracula','amber','matrix','redalert','solarized'];
    if(!valid.includes(name)){ this.print(`Tema '${name}' no existe. Usa \\tema para listar.`,'line error'); return; }
    this.applyTheme(name);
    this.print(`Tema cambiado a <b style="color:var(--accent)">${name}</b> — `+'`\\tema` para ver todos','line success');
  }
  handleColor(stmt){
    const raw=stmt.replace(/^\\color\s*/i,'').trim().replace(/;$/,'');
    if(!raw){
      this.print(`<b>Colores:</b>`, 'line');
      this.print(`  Uso: <code>\\color bg #0a0e14 fg #c5c8c6 accent #00ff66</code>`, 'line muted');
      this.print(`  Ejemplos: <code>\\color bg #000 fg #00ff00</code>  •  <code>\\color accent #ff0000</code>  •  <code>\\color reset</code>`, 'line');
      this.print(`Actual: bg=<span style="color:var(--accent)">${getComputedStyle(document.documentElement).getPropertyValue('--bg')||'#0a0e14'}</span> fg=<span style="color:var(--accent)">${getComputedStyle(document.documentElement).getPropertyValue('--fg')||'#c5c8c6'}</span> accent=<span style="color:var(--accent)">${getComputedStyle(document.documentElement).getPropertyValue('--accent')||'#00ff66'}</span>`, 'line');
      return;
    }
    // delega a handleColor original que ya parsea bg/fg/accent
    this.handleColorLegacy(stmt.replace(/^\\/,''));
  }
  handleColorLegacy(stmt){
    const low=stmt.toLowerCase();
    if(low.includes('reset')){ const cur=localStorage.getItem(THEME_KEY)||'alma'; this.applyTheme(cur); document.documentElement.style.removeProperty('--bg'); document.documentElement.style.removeProperty('--fg'); document.documentElement.style.removeProperty('--accent'); document.body.style.removeProperty('background'); this.print('Colores restaurados','line success'); return;}
    const bgM=stmt.match(/bg\s+([#\w]+)/i); const fgM=stmt.match(/fg\s+([#\w]+)/i); const acM=stmt.match(/accent\s+([#\w]+)/i);
    if(bgM){ document.documentElement.style.setProperty('--bg', bgM[1]); document.body.style.background=bgM[1];}
    if(fgM) document.documentElement.style.setProperty('--fg', fgM[1]);
    if(acM) document.documentElement.style.setProperty('--accent', acM[1]);
    this.print(`Colores aplicados ${bgM?'bg='+bgM[1]:''} ${fgM?'fg='+fgM[1]:''} ${acM?'accent='+acM[1]:''}`,'line success');
  }
  handleAcciones(){
    this.print(`<b style="color:var(--accent)">── \\acciones — Acciones rápidas ─────────────</b>`, 'line');
    this.print(`  <code>\\l</code>              Listar bases`, 'line');
    this.print(`  <code>\\dt</code>             Listar tablas`, 'line');
    this.print(`  <code>\\du</code>             Listar roles`, 'line');
    this.print(`  <code>\\d &lt;tabla&gt;</code>       Ver estructura`, 'line');
    this.print(`  <code>status</code>          Estado BD + privilegios`, 'line');
    this.print(`  <code>neofetch</code>        Info sistema`, 'line');
    this.print(`  <code>BACKUP DATABASE &lt;db&gt;;</code>  Dump`, 'line');
    this.print(`  <code>clear</code>           Limpiar pantalla`, 'line');
    this.print(`  <code>\\tema</code> / <code>\\color</code>  Temas y colores`, 'line');
    this.print(`  Usa <code>\\ayuda</code> para lista completa`, 'line muted');
  }
  handleStatement(stmt){
    const low=stmt.toLowerCase().trim();
    if(/^clear$|^cls$/i.test(low)){ this.clear(); return; }
    if(low==='help' || low==='\\h' || low==='?'){ this.showHelp(); return; }
    if(low==='history'){ this.showHistory(); return; }
    if(low==='status'){ this.showStatus(); return; }
    if(low==='neofetch'){ this.neofetch(); return; }
    if(low.startsWith('echo ')){ this.print(stmt.slice(5), 'line'); return; }
    if(low==='whoami'){ this.print(this.rm.currentRole, 'line'); return; }
    if(low==='pwd'){ this.print(`/home/${this.rm.currentRole}/${this.rm.currentDB}`, 'line'); return; }
    if(low==='date'){ this.print(new Date().toString(), 'line'); return; }
    if(low==='uname -a' || low==='uname'){ this.print('Linux alma 5.14.0-427.el9.x86_64 #1 SMP AlmaLinux 9.4 x86_64 GNU/Linux', 'line'); return; }
    if(low==='ls' || low==='ls -la'){ this.handleLs(); return; }
    // Temas y colores por comando (sin sidebar - nativo linux)
    if(low.startsWith('\\tema')){ this.handleTema(stmt); return; }
    if(low.startsWith('\\color')){ this.handleColor(stmt); return; }
    if(low==='\\acciones' || low==='\\acciones;' || low.startsWith('\\acciones ')){ this.handleAcciones(); return; }
    if(low==='\\ayuda' || low==='\\ayuda;'){ togglePanel('ayuda'); this.print('<span class="muted">Panel Ayuda mostrado — \\ayuda para ocultar</span>','line muted'); return; }
    if(low==='\\teoria' || low==='\\teoria;'){ togglePanel('teoria'); this.print('<span class="muted">Panel Teoría mostrado — \\teoria para ocultar</span>','line muted'); return; }
    if(low==='\\proyecto' || low==='\\proyecto;' || low.startsWith('\\proyecto ')){ togglePanel('proyecto'); this.print('<span class="muted">Panel Proyecto mostrado — \\proyecto para ocultar</span>','line muted'); return; }
    if(low.startsWith('theme')){ this.handleTheme(stmt); return; }
    if(low.startsWith('color')){ this.handleColorLegacy(stmt); return; }

    // psql meta
    if(/^(\\q|quit|exit|salir)\s*;?$/i.test(stmt)){ if(confirm('¿Reiniciar emulador?')) location.reload(); return; }
    if(/^\\l\s*;?$/i.test(stmt) || /^\\list\s*;?$/i.test(stmt)){ this.handleListDB(); return; }
    if(/^\\du\s*;?$/i.test(stmt)){ this.handleDu(); return; }
    if(/^\\dt\s*;?$/i.test(stmt)){ this.handleDt(); return; }
    let m;
    m=stmt.match(/^\\d\s+(\w+)\s*;?$/i); if(m){ this.handleD(m[1]); return; }
    m=stmt.match(/^\\c(?:onnect)?\s+(\w+)\s*;?$/i); if(m){ this.engine.useDatabase(m[1], this.rm.currentRole); this.print(`You are now connected to database "${m[1]}" as user "${this.rm.currentRole}".`, 'line success'); return; }
    if(/^select\s+version\s*\(\s*\)\s*;?$/i.test(stmt)){ this.print(" PostgreSQL 16.3 on x86_64-pc-linux-gnu, compiled by gcc (GCC) 11.4.1\n(1 row)", 'line'); return; }
    if(/^select\s+\*\s+from\s+pg_roles\s*;?$/i.test(stmt)){ this.handlePgRoles(); return; }

    // ROLE MANAGEMENT
    m=stmt.match(/^create\s+role\s+(\w+)\s+nologin\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw sqlError('permiso denegado para crear rol', {sqlstate:'42501'});
      this.rm.createRole(m[1], false, false); this.print('CREATE ROLE','line success'); return;
    }
    m=stmt.match(/^create\s+user\s+(\w+)\s+with\s+password\s+'[^']*'\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw sqlError('permiso denegado para crear rol', {sqlstate:'42501'});
      this.rm.createRole(m[1], true, false); this.print('CREATE ROLE','line success'); return;
    }
    m=stmt.match(/^create\s+role\s+(\w+)\s+with\s+login\s+password\s+'[^']*'\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado');
      this.rm.createRole(m[1], true, false); this.print('CREATE ROLE','line success'); return;
    }
    // ALTER ROLE <rol> SUPERUSER / NOSUPERUSER
    m=stmt.match(/^alter\s+role\s+(\w+)\s+(superuser|nosuperuser)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw sqlError('permiso denegado para ALTER ROLE', {sqlstate:'42501'});
      const doSuper=m[2].toLowerCase()==='superuser';
      this.rm.setSuperuser(m[1], doSuper);
      this.print(`ALTER ROLE — ${m[1]} ahora es ${doSuper?'SUPERUSER':'usuario normal (NOSUPERUSER)'}`,'line success'); return;
    }
    // DROP ROLE: solo superuser, exige REASSIGN/DROP OWNED según corresponda
    m=stmt.match(/^drop\s+(?:user|role)\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  debe ser superusuario para eliminar roles');
      this.rm.dropRole(m[1]); this.print('DROP ROLE','line success'); return;
    }
    // REVOKE ALL ... FROM rol  ->  quita todos los privilegios del rol (no la membresía)
    const revokeAll=stmt.match(/^revoke\s+all(?:\s+(?:privileges?|on\s+(?:all\s+)?tables?\s+in\s+schema\s+\w+))?\s+from\s+(\w+)\s*;?$/i);
    if(revokeAll){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw sqlError('permiso denegado para REVOKE', {sqlstate:'42501'});
      const r=revokeAll[1].toLowerCase();
      if(!this.rm.hasRole(r)) throw new Error(`ERROR:  no existe el rol «${r}»`);
      this.rm.clearPrivileges(r);
      this.print(`REVOKE — privilegios de tablas/esquema/db revocados de ${r}`,'line success');
      return;
    }
    // GRANT role TO user
    m=stmt.match(/^grant\s+(\w+)\s+to\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw sqlError('permiso denegado para GRANT', {sqlstate:'42501'});
      this.rm.grantRole(m[1], m[2]); this.print('GRANT ROLE','line success'); return;
    }
    // REVOKE role FROM user (membresía)
    m=stmt.match(/^revoke\s+(\w+)\s+from\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado para REVOKE');
      this.rm.revokeRole(m[1], m[2]);
      this.print('REVOKE','line success');
      return;
    }
    // GRANT CONNECT ON DATABASE db TO role
    m=stmt.match(/^grant\s+connect\s+on\s+database\s+(\w+)\s+to\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado para GRANT');
      if(!this.rm.hasRole(m[2])) throw new Error(`ERROR:  no existe el rol «${m[2]}»`);
      if(!this.engine.hasDatabase(m[1])) throw new Error(`ERROR:  no existe la base de datos «${m[1]}»`);
      this.rm.grantDbPriv(m[2], m[1], 'CONNECT'); this.print('GRANT','line success'); return;
    }
    // GRANT CREATE ON DATABASE db TO role
    m=stmt.match(/^grant\s+create\s+on\s+database\s+(\w+)\s+to\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado');
      this.rm.grantDbPriv(m[2], m[1], 'CREATE'); this.print('GRANT','line success'); return;
    }
    // GRANT USAGE ON SCHEMA schema TO role
    m=stmt.match(/^grant\s+usage\s+on\s+schema\s+(\w+)\s+to\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado');
      if(!this.rm.hasRole(m[2])) throw new Error(`ERROR:  no existe el rol «${m[2]}»`);
      this.rm.grantSchemaPriv(m[2], this.rm.currentDB, m[1], 'USAGE'); this.print('GRANT','line success'); return;
    }
    // GRANT CREATE ON SCHEMA schema TO role
    m=stmt.match(/^grant\s+create\s+on\s+schema\s+(\w+)\s+to\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado');
      if(!this.rm.hasRole(m[2])) throw new Error(`ERROR:  no existe el rol «${m[2]}»`);
      this.rm.grantSchemaPriv(m[2], this.rm.currentDB, m[1], 'CREATE'); this.print('GRANT','line success'); return;
    }
    // GRANT privs ON ALL TABLES IN SCHEMA schema TO role
    m=stmt.match(/^grant\s+([\w\s,]+)\s+on\s+all\s+tables\s+in\s+schema\s+(\w+)\s+to\s+(\w+)\s*;?$/i); if(m){
      const privs=m[1].split(',').map(s=>s.trim().toUpperCase()).filter(Boolean);
      const schema=m[2]; const role=m[3];
      if(!this.rm.hasRole(role)) throw new Error(`ERROR:  no existe el rol «${role}»`);
      if(!this.rm.isSuperUser(this.rm.currentRole) && !this.engine.canGrantOnAllTables(this.rm.currentRole, schema)){
        throw sqlError('permiso denegado para GRANT', {detail:`Debe ser superusuario o dueño de todas las tablas del esquema «${schema}» para otorgar privilegios.`, sqlstate:'42501'});
      }
      const valid=['SELECT','INSERT','UPDATE','DELETE'];
      privs.forEach(p=>{ if(!valid.includes(p)) throw new Error(`ERROR:  privilegio no reconocido: ${p}`); this.rm.grantAllTablesPriv(role, this.rm.currentDB, schema, p); });
      this.print('GRANT','line success'); return;
    }
    // GRANT SELECT ON table TO role (specific table)
    m=stmt.match(/^grant\s+([\w\s,]+)\s+on\s+(\w+)\s+to\s+(\w+)\s*;?$/i); if(m){
      const privs=m[1].split(',').map(s=>s.trim().toUpperCase()).filter(Boolean);
      const table=m[2]; const role=m[3];
      if(!this.rm.hasRole(role)) throw new Error(`ERROR:  no existe el rol «${role}»`);
      if(!this.rm.isSuperUser(this.rm.currentRole) && !this.engine.isOwnerOfTable(this.rm.currentRole, table)){
        throw sqlError(`permiso denegado para GRANT`, {detail:`Debe ser superusuario o dueño de la relación «${table}» para otorgar privilegios.`, sqlstate:'42501'});
      }
      const valid=['SELECT','INSERT','UPDATE','DELETE'];
      privs.forEach(p=>{ if(!valid.includes(p)) throw new Error(`ERROR:  privilegio no reconocido: ${p}`); this.rm.grantTablePriv(role, this.rm.currentDB, 'public', table, p); });
      this.print('GRANT','line success'); return;
    }
    // REVOKE CONNECT ON DATABASE db FROM role
    m=stmt.match(/^revoke\s+connect\s+on\s+database\s+(\w+)\s+from\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado');
      this.rm.revokeDbPriv(m[2], m[1], 'CONNECT'); this.print('REVOKE','line success'); return;
    }
    m=stmt.match(/^revoke\s+create\s+on\s+schema\s+(\w+)\s+from\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado');
      this.rm.revokeSchemaPriv(m[2], this.rm.currentDB, m[1], 'CREATE'); this.print('REVOKE','line success'); return;
    }
    m=stmt.match(/^revoke\s+usage\s+on\s+schema\s+(\w+)\s+from\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado');
      this.rm.revokeSchemaPriv(m[2], this.rm.currentDB, m[1], 'USAGE'); this.print('REVOKE','line success'); return;
    }
    m=stmt.match(/^revoke\s+([\w\s,]+)\s+on\s+all\s+tables\s+in\s+schema\s+(\w+)\s+from\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado');
      const privs=m[1].split(',').map(s=>s.trim().toUpperCase()).filter(Boolean);
      const schema=m[2]; const role=m[3];
      privs.forEach(p=> this.rm.revokeAllTablesPriv(role, this.rm.currentDB, schema, p));
      this.print('REVOKE','line success'); return;
    }
    m=stmt.match(/^revoke\s+([\w\s,]+)\s+on\s+(\w+)\s+from\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  permiso denegado');
      const privs=m[1].split(',').map(s=>s.trim().toUpperCase()).filter(Boolean);
      const table=m[2]; const role=m[3];
      privs.forEach(p=> this.rm.revokeTablePriv(role, this.rm.currentDB, 'public', table, p));
      this.print('REVOKE','line success'); return;
    }
    // SET ROLE / RESET ROLE
    m=stmt.match(/^set\s+role\s+(\w+)\s*;?$/i); if(m){
      const target=m[1].toLowerCase();
      if(!this.rm.hasRole(target)) throw new Error(`ERROR:  no existe el rol «${m[1]}»`);
      if(!this.rm.isSuperUser(this.rm.currentRole)){
        const eff=this.rm.getEffectiveRoles(this.rm.currentRole);
        if(!eff.has(target) && this.rm.currentRole.toLowerCase()!==target) throw new Error(`ERROR:  permiso denegado para hacer SET ROLE\nDETAIL: No es miembro del rol "${m[1]}"`);
      }
      // check canLogin? In real psql you can SET ROLE to NOLOGIN role if member
      if(this.rm.originalRole==='postgres' && this.rm.currentRole==='postgres'){
        // save original
        this.rm.originalRole=this.rm.currentRole;
      }
      this.rm.currentRole=this.rm.getRole(target).nameOriginal;
      this.engine.save();
      this.print(`SET`, 'line success'); return;
    }
    if(/^reset\s+role\s*;?$/i.test(stmt)){
      this.rm.currentRole=this.rm.originalRole||'postgres';
      this.engine.save();
      this.print('RESET','line success'); return;
    }

    // SQL
    if(/^show\s+databases;?$/i.test(stmt)){ this.handleListDB(); return; }
    if(/^create\s+database\s+/i.test(stmt)){ this.handleCreateDatabase(stmt); return; }
    if(/^drop\s+database\s+/i.test(stmt)){ this.handleDropDatabase(stmt); return; }
    if(/^use\s+/i.test(stmt)){ const mm=stmt.match(/use\s+(\w+)/i); this.engine.useDatabase(mm[1], this.rm.currentRole); this.print(`Database changed → <b>${mm[1]}</b>`, 'line success'); return; }
    if(/^show\s+tables;?$/i.test(stmt)){ this.handleDt(); return; }
    if(/^create\s+table\s+/i.test(stmt)){ this.handleCreateTable(stmt); return; }
    if(/^drop\s+table\s+/i.test(stmt)){ this.handleDropTable(stmt); return; }
    if(/^truncate\s+table\s+/i.test(stmt) || /^truncate\s+/i.test(stmt)){ this.handleTruncate(stmt); return; }
    if(/^describe\s+/i.test(stmt) || /^desc\s+/i.test(stmt) || /^show\s+columns\s+from\s+/i.test(stmt)){ this.handleDescribe(stmt); return; }
    if(/^select\s+/i.test(stmt)){ this.handleSelect(stmt); return; }
    if(/^insert\s+into\s+/i.test(stmt)){ this.handleInsert(stmt); return; }
    if(/^update\s+/i.test(stmt)){ this.handleUpdate(stmt); return; }
    if(/^delete\s+from\s+/i.test(stmt) || /^delete\s+/i.test(stmt)){ this.handleDelete(stmt); return; }
    if(/^alter\s+table\s+/i.test(stmt)){ this.handleAlterTable(stmt); return; }
    // REASSIGN OWNED BY old TO new;
    m=stmt.match(/^reassign\s+owned\s+by\s+(\w+)\s+to\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  debe ser superusuario para REASSIGN OWNED');
      if(!this.rm.hasRole(m[1])) throw new Error(`ERROR:  no existe el rol «${m[1]}»`);
      if(!this.rm.hasRole(m[2])) throw new Error(`ERROR:  no existe el rol «${m[2]}»`);
      const cnt=this.engine.reassignOwnedBy(m[1], m[2]);
      this.rm.markReassigned(m[1]);
      this.print(`REASSIGN OWNED: ${cnt} objeto(s) reasignado(s) de ${m[1]} a ${m[2]}`, 'line success');
      return;
    }
    // DROP OWNED BY role;
    m=stmt.match(/^drop\s+owned\s+by\s+(\w+)\s*;?$/i); if(m){
      if(!this.rm.isSuperUser(this.rm.currentRole)) throw new Error('ERROR:  debe ser superusuario para DROP OWNED');
      if(!this.rm.hasRole(m[1])) throw new Error(`ERROR:  no existe el rol «${m[1]}»`);
      const dropped=this.engine.dropOwnedBy(m[1]);
      this.rm.markDropOwned(m[1]);
      // Limpiar marcas de REASSIGN también para permitir DROP después
      this.print(`DROP OWNED: ${dropped} objeto(s) eliminado(s) y privilegios revocados para ${m[1]}`, 'line success');
      return;
    }

    // RF-09 BACKUP DATABASE
    m=stmt.match(/^backup\s+database\s+(\w+)\s*;?$/i); if(m){ this.handleBackup(m[1]); return; }

    throw new Error(`ERROR:  error de sintaxis en «${stmt}»`);
  }

  // handlers
  showHelp(){
    const h=`
<div class="ascii-box">
<b style="color:var(--accent)">── COMANDOS VALIDADOS v3.0 ─────────────────────────────</b>
<b style="color:var(--accent2)">BASES</b>  CREATE DATABASE (solo superuser) | \\l | \\c db (requiere CONNECT)
<b style="color:var(--accent2)">ROLES</b>  CREATE ROLE x NOLOGIN | CREATE USER x WITH PASSWORD '...' | GRANT rol TO user | SET/RESET ROLE
<b style="color:var(--accent2)">PERMISOS DDL</b>  GRANT USAGE/CREATE ON SCHEMA public TO rol  → valida CREATE TABLE
<b style="color:var(--accent2)">PERMISOS LMD</b>  GRANT SELECT/INSERT/UPDATE/DELETE ON ALL TABLES IN SCHEMA public TO rol
<b style="color:var(--accent2)">VALIDACIÓN</b>  SELECT requiere SELECT+USAGE | INSERT requiere INSERT+USAGE | CREATE TABLE requiere CREATE+USAGE
<b style="color:var(--accent2)">REVOKE</b>  REVOKE SELECT ON ALL TABLES IN SCHEMA public FROM rol  
<b style="color:var(--warning)">EJEMPLO FIX:</b> Si das solo SELECT, INSERT fallará con 42501 y CREATE TABLE fallará con 42501
</div>`;
    this.print(h,'line');
  }
  showHistory(){ if(!this.history.length) this.print('(sin historial)','line muted'); else this.history.forEach((h,i)=> this.print(`${String(i+1).padStart(3,' ')}  ${this.escapeHtml(h)}`,'line muted'));}
  showStatus(){
    const s=this.engine.stats();
    this.print(`<b style="color:var(--accent)">── STATUS ─────────────────────────────</b>`,'line');
    this.print(`Rol: <b>${this.rm.currentRole}</b> ${this.rm.isSuperUser(this.rm.currentRole)?'(superuser)':''} • BD: <b>${s.current}</b> • Bases: ${s.dbs} • Tablas: ${s.totalTables} • Filas: ${s.totalRows}`,'line');
    const lines=this.rm.listPrivsForStatus(this.rm.currentRole, s.current);
    if(lines.length) this.print(`Privilegios efectivos:\n ${lines.join('\n ')}`,'line muted');
    else this.print('Sin privilegios explícitos (solo superuser bypass)','line muted');
  }
  neofetch(){
    const art=`<pre style="line-height:1.3;font-size:12px"><span style="color:var(--accent)">       .--.           </span>  <b>${this.rm.currentRole}@alma</b>
<span style="color:var(--accent)">      |o_o |          </span>  OS: AlmaLinux 9.4 (Seafoam Ocelot)
<span style="color:var(--accent)">      |:_/ |          </span>  Kernel: 5.14.0-427.el9.x86_64
<span style="color:var(--accent)">     //   \\\\ \\        </span>  psql: 16.3 • DDL/LMD validado
<span style="color:var(--accent)">    (|     | )       </span>  Role: ${this.rm.currentRole} ${this.rm.isSuperUser(this.rm.currentRole)?'(superuser)':''}
<span style="color:var(--accent)">   /'\\\\_   _/\\\\\`\\\\      </span>  DB: ${this.rm.currentDB} • Schema: public
<span style="color:var(--accent)">   \\\\___)=(___/       </span>  Theme: ${document.body.className}
</pre>`;
    this.print(art,'line');
  }
  handleBackup(dbName){
    const k=dbName.toLowerCase();
    if(!this.engine.hasDatabase(k)) throw new Error(`ERROR:  no existe la base de datos «${dbName}»`);
    // RF-07 ESTRICTO OFFLINE: BACKUP solo superuser (postgres). Cualquier usuario creado, aunque tenga CONNECT/USAGE/SELECT, NO puede hacer backup.
    if(!this.rm.isSuperUser(this.rm.currentRole)){
      throw sqlError('permiso denegado para BACKUP DATABASE', {detail:`Debe ser superusuario para ejecutar BACKUP. El rol "${this.rm.currentRole}" no es superuser.`, sqlstate:'42501'});
    }
    const db=this.engine.databases[k];
    let dump=`-- =====================================================\n`;
    dump+=`-- BACKUP DATABASE ${db.nameOriginal}\n`;
    dump+=`-- Generado: ${new Date().toLocaleString('es-PY')}  •  Por: ${this.rm.currentRole}  •  AlmaLinux psql 16.3\n`;
    dump+=`-- =====================================================\n\n`;
    dump+=`CREATE DATABASE ${db.nameOriginal};\n`;
    dump+=`\\c ${db.nameOriginal}\n\n`;
    const tables=Object.values(db.tables);
    if(tables.length===0) dump+=`-- (sin tablas)\n`;
    tables.forEach(t=>{
      const colsDef=t.columns.map(c=>`${c.name} ${c.type}`).join(', ');
      dump+=`CREATE TABLE ${t.nameOriginal} (${colsDef});\n`;
      if(t.rows.length===0) dump+=`-- 0 filas\n`;
      else {
        t.rows.forEach(r=>{
          const cols=t.columns.map(c=>c.name).join(', ');
          const vals=t.columns.map(c=>{
            const v=r[c.name];
            if(v===null||v===undefined) return 'NULL';
            if(typeof v==='boolean') return v? 'true':'false';
            if(typeof v==='number') return String(v);
            return `'${String(v).replace(/'/g,"''")}'`;
          }).join(', ');
          dump+=`INSERT INTO ${t.nameOriginal} (${cols}) VALUES (${vals});\n`;
        });
      }
      dump+=`\n`;
    });
    dump+=`-- Fin backup (${tables.length} tablas, ${tables.reduce((a,t)=>a+t.rows.length,0)} filas)\n`;
    // Mostrar en terminal con estilo
    this.print(`<b style="color:var(--success)">-- BACKUP DATABASE ${db.nameOriginal} — dump simulado (RF-09)</b>`, 'line success');
    const pre=document.createElement('pre');
    pre.style.cssText='background:var(--bg);border:1px solid var(--border);padding:10px;border-radius:6px;overflow:auto;max-height:300px;font-size:11px;line-height:1.4;white-space:pre-wrap;word-break:break-all;margin:8px 0';
    pre.textContent=dump;
    this.outputEl.appendChild(pre);
    this.print(`<span class="muted">Backup generado: ${tables.length} tablas, ${tables.reduce((a,t)=>a+t.rows.length,0)} filas — descargando .sql...</span>`, 'line muted');
    this.scroll();
    // Descargar archivo
    try{
      const blob=new Blob([dump],{type:'text/sql'});
      const url=URL.createObjectURL(blob);
      const a=document.createElement('a');
      a.href=url; a.download=`backup_${db.nameOriginal}_${new Date().toISOString().slice(0,10)}.sql`;
      a.click(); URL.revokeObjectURL(url);
    }catch(e){}
  }
  handleLs(){
    try{
      const db=this.engine.getCurrentDBObj();
      if(!db){ this.print('databases/', 'line system'); this.engine.listDatabases().forEach(d=>this.print(d,'line'));}
      else {
        this.print('total '+Object.keys(db.tables).length,'line muted');
        Object.values(db.tables).forEach(t=> this.print(`-rw-r--r-- 1 ${t.owner} ${t.owner} ${t.rows.length*128} Aug 24 10:00 ${t.nameOriginal}.frm`, 'line'));
      }
    }catch(e){ this.print(e.message,'line error'); }
  }
  handleTheme(stmt){
    const p=stmt.trim().split(/\s+/);
    if(p.length===1 || p[1].toLowerCase()==='list'){ this.print(`<b>Temas:</b> <span style="color:var(--accent)">alma</span>, hacker, light, dracula, amber, matrix, redalert, solarized`,'line'); return; }
    if(p[1].toLowerCase()==='set'){
      const n=(p[2]||'').toLowerCase();
      const valid=['alma','hacker','light','dracula','amber','matrix','redalert','solarized'];
      if(!valid.includes(n)){ this.print(`Tema '${n}' no existe. Usa: theme list`,'line error'); return;}
      this.applyTheme(n); this.print(`Tema cambiado a <b>${n}</b>`,'line success'); return;
    }
  }
  applyTheme(n){ document.body.className='theme-'+n; localStorage.setItem(THEME_KEY,n); const els=document.querySelectorAll('.theme-btn'); if(els.length) els.forEach(b=> b.classList.toggle('active', b.dataset.theme===n));}
  handleListDB(){
    let out="                                  List of databases\n";
    out+="   Name    | Owner    | Encoding\n";
    out+="-----------+----------+----------\n";
    Object.values(this.engine.databases).forEach(db=>{ out+=` ${db.nameOriginal.padEnd(9)} | postgres | UTF8\n`;});
    out+=`(${Object.keys(this.engine.databases).length} rows)`;
    this.print(out);
  }
  handleDu(){
    let out="                                   List of roles\n";
    out+=" Role name        | Attributes          | Member of\n";
    out+="------------------+---------------------+------------\n";
    Object.keys(this.rm.roles).sort().forEach(name=>{
      const r=this.rm.roles[name];
      let attrs=[];
      if(r.superuser) attrs.push("Superuser");
      if(!r.canLogin) attrs.push("Cannot login");
      const mem=this.rm.membership[name]? [...this.rm.membership[name]].join(", ") : "";
      out+=` ${r.nameOriginal.padEnd(16)} | ${attrs.join(", ").padEnd(19)} | ${mem}\n`;
    });
    this.print(out);
  }
  handlePgRoles(){
    let out=" rolname          | rolcanlogin | rolsuper \n";
    out+="------------------+-------------+----------\n";
    Object.keys(this.rm.roles).sort().forEach(name=>{
      const r=this.rm.roles[name];
      out+=` ${r.nameOriginal.padEnd(16)} | ${(r.canLogin?"t":"f").padEnd(11)} | ${r.superuser?"t":"f"}\n`;
    });
    out+=`(${Object.keys(this.rm.roles).length} rows)`;
    this.print(out);
  }
  handleDt(){
    const tbls=this.engine.getCurrentTables();
    const names=Object.keys(tbls);
    // RF-07 ESTRICTO: \dt requiere USAGE, si no → 42501 y no muestra nada (antes solo advertía)
    if(!this.rm.hasSchemaPriv(this.rm.currentRole, this.rm.currentDB, 'public', 'USAGE') && !this.rm.isSuperUser(this.rm.currentRole)){
      throw sqlError('permiso denegado para esquema public', {detail:'El usuario no tiene privilegio USAGE en el esquema.', sqlstate:'42501'});
    }
    if(names.length===0){ this.print("Did not find any relation.",'line info'); return; }
    let out="             List of relations\n";
    out+=" Schema | Name   | Type  | Owner\n";
    out+="--------+--------+-------+----------\n";
    names.forEach(k=>{
      const t=tbls[k];
      out+=` public | ${t.nameOriginal.padEnd(6)} | table | ${t.owner}\n`;
    });
    out+=`(${names.length} rows)`;
    this.print(out);
  }
  handleD(tname){
    const tbls=this.engine.getCurrentTables();
    const k=tname.toLowerCase();
    if(!tbls[k]){ this.print(`Did not find any relation named "${tname}".`,'line error'); return; }
    if(!this.rm.hasSchemaPriv(this.rm.currentRole, this.rm.currentDB, 'public', 'USAGE') && !this.rm.isSuperUser(this.rm.currentRole)){
      this.print(`ERROR:  permiso denegado para esquema public\nEstado SQL: 42501`,'line error'); return;
    }
    const t=tbls[k];
    let out=`                            Table "public.${t.nameOriginal}"\n`;
    out+="  Column    |          Type          | Collation | Nullable | Default | Extra\n";
    out+="------------+------------------------+-----------+----------+---------+-------\n";
    t.columns.forEach(c=>{
      const nullable=(c.notNull||c.primaryKey)? 'not null' : '';
      const extra=[c.primaryKey?'PRIMARY KEY':'', c.unique?'UNIQUE':''].filter(Boolean).join(' ');
      out+=` ${c.name.padEnd(10)} | ${c.type.padEnd(22)} |           | ${nullable.padEnd(8)} |         | ${extra}\n`;
    });
    out+=`Owner: ${t.owner}`;
    this.print(out);
  }
  handleCreateDatabase(stmt){
    const m=stmt.match(/create\s+database\s+(\w+)\s*;?$/i);
    if(!m) throw new Error('Sintaxis: CREATE DATABASE <nombre>');
    this.engine.createDatabase(m[1], this.rm.currentRole);
    // auto grant CONNECT+USAGE+CREATE to creator? In postgres owner gets all, but we keep simple
    this.print(`CREATE DATABASE`,'line success');
  }
  handleDropDatabase(stmt){
    const m=stmt.match(/drop\s+database\s+(\w+)\s*;?$/i);
    if(!m) throw new Error('Sintaxis: DROP DATABASE <nombre>');
    this.engine.dropDatabase(m[1], this.rm.currentRole);
    this.print(`DROP DATABASE`,'line success');
  }
  handleCreateTable(stmt){
    const m=stmt.match(/create\s+table\s+(\w+)\s*\(([\s\S]+)\)\s*;?$/i);
    if(!m) throw new Error('Sintaxis: CREATE TABLE <nombre> (col TIPO [NOT NULL] [UNIQUE] [PRIMARY KEY], ...)');
    const tableName=m[1];
    const colsDef=m[2];
    const colsRaw=this.splitCols(colsDef);
    const columns=colsRaw.map(c=>{
      const colStr=c.trim();
      // Nombre y tipo + resto de constraints
      const cm=colStr.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z0-9_()]+)(.*)$/i);
      if(!cm) throw new Error(`Definición inválida: '${c}'`);
      const name=cm[1];
      const type=cm[2].toUpperCase();
      const rest=(cm[3]||'').toUpperCase();
      const notNull=/NOT\s+NULL/.test(rest);
      const unique=/\bUNIQUE\b/.test(rest);
      const primaryKey=/PRIMARY\s+KEY/.test(rest);
      return {name, type, notNull: notNull || primaryKey, unique: unique || primaryKey, primaryKey};
    });
    this.engine.createTable(tableName, columns, this.rm.currentRole);
    this.print(`CREATE TABLE`,'line success');
  }
  splitCols(s){
    const res=[]; let cur=''; let depth=0; let inS=false,inD=false;
    for(let i=0;i<s.length;i++){
      const ch=s[i];
      if(ch==="'"&&!inD) inS=!inS;
      else if(ch==='"'&&!inS) inD=!inD;
      else if(!inS&&!inD){
        if(ch==='(') depth++;
        else if(ch===')') depth--;
        else if(ch===','&&depth===0){ res.push(cur); cur=''; continue;}
      }
      cur+=ch;
    }
    if(cur.trim()) res.push(cur);
    return res;
  }
  handleDropTable(stmt){
    const m=stmt.match(/drop\s+table\s+(\w+)\s*;?$/i);
    if(!m) throw new Error('Sintaxis: DROP TABLE <nombre>');
    this.engine.dropTable(m[1], this.rm.currentRole);
    this.print(`DROP TABLE`,'line success');
  }
  handleTruncate(stmt){
    const m=stmt.match(/truncate\s+(?:table\s+)?(\w+)\s*;?$/i);
    if(!m) throw new Error('Sintaxis: TRUNCATE TABLE <nombre>');
    this.engine.truncate(m[1], this.rm.currentRole);
    this.print(`TRUNCATE TABLE`,'line success');
  }
  handleAlterTable(stmt){
    // ALTER TABLE tabla ADD COLUMN col TYPE [NOT NULL] [UNIQUE] [PRIMARY KEY]
    let m=stmt.match(/^alter\s+table\s+(\w+)\s+add\s+column\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z0-9_()]+)(.*)$/i);
    if(m){
      const table=m[1];
      const colName=m[2];
      const colType=m[3].toUpperCase();
      const rest=(m[4]||'').toUpperCase();
      const notNull=/NOT\s+NULL/.test(rest);
      const unique=/\bUNIQUE\b/.test(rest);
      const primaryKey=/PRIMARY\s+KEY/.test(rest);
      const colDef={name:colName, type:colType, notNull: notNull||primaryKey, unique: unique||primaryKey, primaryKey};
      this.engine.alterTableAddColumn(table, colDef, this.rm.currentRole);
      this.print(`ALTER TABLE`,'line success');
      return;
    }
    // ALTER TABLE tabla DROP COLUMN col
    m=stmt.match(/^alter\s+table\s+(\w+)\s+drop\s+column\s+(\w+)\s*;?$/i);
    if(m){
      this.engine.alterTableDropColumn(m[1], m[2], this.rm.currentRole);
      this.print(`ALTER TABLE`,'line success');
      return;
    }
    // ALTER TABLE tabla RENAME TO new
    m=stmt.match(/^alter\s+table\s+(\w+)\s+rename\s+to\s+(\w+)\s*;?$/i);
    if(m){
      this.engine.alterTableRename(m[1], m[2], this.rm.currentRole);
      this.print(`ALTER TABLE`,'line success');
      return;
    }
    // ALTER TABLE tabla RENAME COLUMN old TO new
    m=stmt.match(/^alter\s+table\s+(\w+)\s+rename\s+column\s+(\w+)\s+to\s+(\w+)\s*;?$/i);
    if(m){
      this.engine.alterTableRenameColumn(m[1], m[2], m[3], this.rm.currentRole);
      this.print(`ALTER TABLE`,'line success');
      return;
    }
    throw new Error(`ERROR:  sintaxis ALTER TABLE no reconocida. Usa: ALTER TABLE t ADD COLUMN c TYPE [NOT NULL] [UNIQUE]; | ALTER TABLE t DROP COLUMN c; | ALTER TABLE t RENAME TO new; | ALTER TABLE t RENAME COLUMN old TO new;`);
  }
  handleDescribe(stmt){
    const m=stmt.match(/(?:describe|desc|show\s+columns\s+from)\s+(\w+)\s*;?$/i);
    if(!m) throw new Error('Sintaxis: DESCRIBE <tabla>');
    const t=this.engine.describe(m[1]);
    if(!this.rm.hasSchemaPriv(this.rm.currentRole, this.rm.currentDB, 'public', 'USAGE') && !this.rm.isSuperUser(this.rm.currentRole)) throw sqlError('permiso denegado para esquema public', {sqlstate:'42501'});
    const rows=t.columns.map(c=>({Field:c.name, Type:c.type, Null:'YES', Key:'', Default:null, Owner:t.owner}));
    this.printTable(['Field','Type','Null','Key','Default','Owner'], rows);
  }
  handleSelect(stmt){
    const m=stmt.match(/select\s+(.+?)\s+from\s+(?:public\.)?(\w+)\s*([\s\S]*)/i);
    if(!m) throw new Error('Sintaxis: SELECT ... FROM ...');
    let colsStr=m[1].trim();
    const tableName=m[2];
    let rest=m[3]||'';
    rest=rest.replace(/;$/,'').trim();
    let cols=null;
    if(colsStr==='*') cols='*';
    else cols=colsStr.split(',').map(s=>s.trim().replace(/["'`]/g,'')).filter(Boolean);
    let whereStr=null, orderBy=null, limit=null;
    const limitM=rest.match(/limit\s+(\d+)\s*$/i); if(limitM){ limit=parseInt(limitM[1],10); rest=rest.slice(0,limitM.index).trim();}
    const orderM=rest.match(/order\s+by\s+(\w+)(?:\s+(asc|desc))?/i); if(orderM){ orderBy={col:orderM[1], dir:(orderM[2]||'ASC').toUpperCase()}; rest=rest.slice(0,orderM.index).trim();}
    const whereM=rest.match(/where\s+([\s\S]+)/i); if(whereM) whereStr=whereM[1].trim();
    let whereFn=null;
    if(whereStr) whereFn=this.buildWhereFn(whereStr);
    const res=this.engine.select(tableName, cols, whereFn, orderBy, limit, this.rm.currentRole);
    this.printTable(res.columns, res.rows);
  }
  buildWhereFn(whereStr){
    const conditions=whereStr.split(/\s+and\s+/i);
    const fns=conditions.map(cond=>{
      cond=cond.trim();
      let m=cond.match(/^(\w+)\s+like\s+('[^']*'|"[^"]*"|\S+)/i);
      if(m){
        const col=m[1];
        let pat=m[2].replace(/^['"]|['"]$/g,'');
        const re=new RegExp('^'+pat.replace(/%/g,'.*').replace(/_/g,'.')+'$','i');
        return row=>{
          const v=row[col]!==undefined? row[col] : row[Object.keys(row).find(k=>k.toLowerCase()===col.toLowerCase())];
          if(v===null||v===undefined) return false;
          return re.test(String(v));
        };
      }
      m=cond.match(/^(\w+)\s*(=|!=|<>|>=|<=|>|<)\s*(.+)$/);
      if(!m) throw new Error(`WHERE inválido: '${cond}'`);
      const col=m[1]; const op=m[2]; let raw=m[3].trim();
      let val;
      if((raw.startsWith("'")&&raw.endsWith("'"))||(raw.startsWith('"')&&raw.endsWith('"'))) val=raw.slice(1,-1);
      else if(/^(true|false)$/i.test(raw)) val=raw.toLowerCase()==='true';
      else if(!isNaN(raw) && raw!=='') val=Number(raw);
      else val=raw;
      return row=>{
        let rv=row[col];
        if(rv===undefined) rv=row[Object.keys(row).find(k=>k.toLowerCase()===col.toLowerCase())];
        if(rv===null||rv===undefined) return op==='='? val===null : false;
        let cmp;
        if(typeof rv==='number'&& typeof val==='number') cmp=rv-val;
        else if(!isNaN(rv)&&!isNaN(val) && typeof val==='number') cmp=Number(rv)-val;
        else cmp=String(rv).localeCompare(String(val));
        switch(op){
          case '=': return String(rv).toLowerCase()===String(val).toLowerCase() || rv===val;
          case '!=': case '<>': return String(rv).toLowerCase()!==String(val).toLowerCase();
          case '>': return cmp>0;
          case '<': return cmp<0;
          case '>=': return cmp>=0;
          case '<=': return cmp<=0;
        }
        return false;
      };
    });
    return row=> fns.every(fn=>fn(row));
  }
  handleInsert(stmt){
    const m=stmt.match(/insert\s+into\s+(\w+)(?:\s*\(([^)]+)\))?\s+values\s*([\s\S]+)/i);
    if(!m) throw new Error('Sintaxis: INSERT INTO tabla [(cols)] VALUES (vals)');
    const tableName=m[1];
    const colsPart=m[2];
    let valuesStr=m[3].trim().replace(/;$/,'');
    let cols=null;
    if(colsPart) cols=colsPart.split(',').map(s=>s.trim().replace(/["'`]/g,''));
    const tuples=this.parseValuesTuples(valuesStr);
    const table=this.engine.getTable(tableName); // check exists before priv? priv will check again
    let count=0;
    tuples.forEach(tup=>{
      let obj={};
      if(cols){
        if(tup.length!==cols.length) throw new Error(`Columnas (${cols.length}) no coinciden con valores (${tup.length})`);
        cols.forEach((c,i)=> obj[c]=this.parseValue(tup[i]));
      } else {
        if(tup.length!==table.columns.length) throw new Error(`La tabla tiene ${table.columns.length} columnas pero se dieron ${tup.length} valores`);
        table.columns.forEach((c,i)=> obj[c.name]=this.parseValue(tup[i]));
      }
      this.engine.insert(tableName, obj, this.rm.currentRole);
      count++;
    });
    this.print(`INSERT 0 ${count}`,'line success');
  }
  parseValuesTuples(str){
    const tuples=[]; let i=0;
    while(i<str.length){
      while(i<str.length && (str[i]===' '||str[i]==='\n'||str[i]==='\t'||str[i]===',')) i++;
      if(i>=str.length) break;
      if(str[i]!=='(') throw new Error('Se esperaba "(" en VALUES');
      i++;
      let cur=''; let inS=false,inD=false; let tuple=[];
      while(i<str.length){
        const ch=str[i];
        if(ch==="'"&&!inD){
          if(inS && str[i+1]==="'"){ cur+="''"; i+=2; continue; }
          inS=!inS; cur+=ch; i++; continue;
        }
        if(ch==='"'&&!inS){ inD=!inD; cur+=ch; i++; continue; }
        if(!inS&&!inD){
          if(ch===','){ tuple.push(cur.trim()); cur=''; i++; continue; }
          if(ch===')'){ tuple.push(cur.trim()); cur=''; i++; break; }
        }
        cur+=ch; i++;
      }
      tuples.push(tuple);
    }
    return tuples;
  }
  parseValue(raw){
    raw=raw.trim();
    if(raw.toLowerCase()==='null') return null;
    if(raw.toLowerCase()==='true') return true;
    if(raw.toLowerCase()==='false') return false;
    if((raw.startsWith("'")&&raw.endsWith("'"))||(raw.startsWith('"')&&raw.endsWith('"'))){
      let inner=raw.slice(1,-1).replace(/''/g,"'");
      return inner;
    }
    if(!isNaN(raw) && raw!=='' ) return raw.includes('.')? parseFloat(raw): parseInt(raw,10);
    return raw;
  }
  handleUpdate(stmt){
    const m=stmt.match(/update\s+(\w+)\s+set\s+([\s\S]+?)(?:\s+where\s+([\s\S]+))?\s*;?$/i);
    if(!m) throw new Error('Sintaxis: UPDATE tabla SET col=val,... [WHERE ...]');
    const tableName=m[1];
    const setStr=m[2];
    const whereStr=m[3]||null;
    const assigns=setStr.split(',').map(s=>s.trim());
    const setObj={};
    assigns.forEach(a=>{
      const mm=a.match(/^(\w+)\s*=\s*(.+)$/);
      if(!mm) throw new Error(`SET inválido: '${a}'`);
      setObj[mm[1]]=this.parseValue(mm[2].trim());
    });
    const whereFn=whereStr? this.buildWhereFn(whereStr.trim()) : null;
    const count=this.engine.update(tableName, setObj, whereFn, this.rm.currentRole);
    this.print(`UPDATE ${count}`,'line success');
  }
  handleDelete(stmt){
    const m=stmt.match(/delete\s+from\s+(\w+)(?:\s+where\s+([\s\S]+))?/i);
    if(!m){
      const m2=stmt.match(/delete\s+(\w+)(?:\s+where\s+([\s\S]+))?/i);
      if(!m2) throw new Error('Sintaxis: DELETE FROM tabla [WHERE ...]');
      const tableName=m2[1];
      const whereStr=m2[2]||null;
      const whereFn=whereStr? this.buildWhereFn(whereStr.trim()) : null;
      const c=this.engine.delete(tableName, whereFn, this.rm.currentRole);
      this.print(`DELETE ${c}`,'line success'); return;
    }
    const tableName=m[1];
    const whereStr=m[2]||null;
    const whereFn=whereStr? this.buildWhereFn(whereStr.trim()) : null;
    const c=this.engine.delete(tableName, whereFn, this.rm.currentRole);
    this.print(`DELETE ${c}`,'line success');
  }
}

// =============== INIT ===============
const rm=new RoleManager();
const engine=new DatabaseEngine(rm);
const term=new Terminal(engine, rm);

// Themes - ahora por comando \tema \color (sidebar eliminada)
const savedTheme=localStorage.getItem(THEME_KEY);
if(savedTheme) term.applyTheme(savedTheme);

// Alternar/mostrar paneles (Ayuda/Teoría/Proyecto). Solo uno visible a la vez.
// Hace scroll para que el panel abierto quede a la vista y reenfoca la barra de comandos.
const PANEL_IDS={ayuda:'help-panel', teoria:'teoria-panel', proyecto:'proyecto-panel'};
function togglePanel(name){
  const id=PANEL_IDS[name]; if(!id) return false;
  const target=document.getElementById(id); if(!target) return false;
  const willShow=target.style.display!=='block';
  ['help-panel','teoria-panel','proyecto-panel'].forEach(pid=>{
    const el=document.getElementById(pid); if(el) el.style.display=(pid===id && willShow)?'block':'none';
  });
  const input=document.getElementById('cmdInput');
  if(input) input.focus();
  if(willShow){
    // Bajar el scroll para que el panel abierto quede visible (si está desplazado el contenedor).
    target.scrollTop=target.scrollHeight;
    const cont=target.closest('.terminal-block, .workspace, .terminal');
    if(cont && cont.scrollTop>0) cont.scrollTop=cont.scrollHeight;
    if(target.scrollIntoView) target.scrollIntoView({block:'nearest', behavior:'smooth'});
  }
  return willShow;
}

// Nuevos botones input-area (sin sidebar)
const btnEj=document.getElementById('btnEjecutar');
if(btnEj) btnEj.addEventListener('click', ()=>{ term.exec(document.getElementById('cmdInput').value); document.getElementById('cmdInput').value=''; document.getElementById('cmdInput').focus(); });
const btnHelpMini=document.getElementById('btnHelpMini');
if(btnHelpMini) btnHelpMini.addEventListener('click', ()=>{ togglePanel('ayuda'); if(document.getElementById('cmdInput')) document.getElementById('cmdInput').focus(); });
const btnProyectoMini=document.getElementById('btnProyectoMini');
if(btnProyectoMini) btnProyectoMini.addEventListener('click', ()=>{ togglePanel('proyecto'); if(document.getElementById('cmdInput')) document.getElementById('cmdInput').focus(); });
const btnTeoriaMini=document.getElementById('btnTeoriaMini');
if(btnTeoriaMini) btnTeoriaMini.addEventListener('click', ()=>{ togglePanel('teoria'); if(document.getElementById('cmdInput')) document.getElementById('cmdInput').focus(); });
function updClock(){ const n=new Date(); document.getElementById('clock').textContent=n.toLocaleString('es-PY',{weekday:'short',hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
setInterval(updClock,1000); updClock();
document.getElementById('btnFullscreen').addEventListener('click', ()=>{
  const el=document.querySelector('.terminal-window');
  if(!document.fullscreenElement) el.requestFullscreen(); else document.exitFullscreen();
});
document.getElementById('btnCopy').addEventListener('click', ()=>{
  const t=document.getElementById('output').innerText;
  navigator.clipboard.writeText(t).then(()=> term.print('Copiado','line success'));
});

// ===== Sentencias clicables en el panel de Ayuda =====
// Un clic sobre un comando lo carga en la barra de entrada (si mensaje), listo para modificar o darle Enter.
// Solo los <code> cuyo texto comience con un comando SQL/psql reconocido son clickables.
const SQL_CMD_PREFIX = /^(create|grant|revoke|set|reset\s+role|alter|select|insert|update|delete|backup|drop\s+(database|table|owned)|truncate|describe|desc|show|use|\\c(?:onnect)?|\\list|\\l|\\dt|\\du|\\d|\\q|\\tema|\\color|\\acciones|\\ayuda|\\teoria|\\proyecto|\\h|status|help|neofetch|clear)(?=$|[\s;\\])/i;
const helpPanel=document.getElementById('help-panel');
if(helpPanel){
  const input=document.getElementById('cmdInput');
  // Marcar visualmente los comandos clicables
  helpPanel.querySelectorAll('code').forEach(codeEl=>{
    if(SQL_CMD_PREFIX.test(codeEl.textContent.trim())) codeEl.classList.add('clickable');
  });
  helpPanel.addEventListener('click', e=>{
    const codeEl=e.target.closest('code.clickable');
    if(!codeEl) return;
    e.preventDefault();
    const sql=codeEl.textContent.trim();
    input.value=sql;
    input.focus();
    input.setSelectionRange(sql.length, sql.length);
  });
}
setTimeout(()=> document.getElementById('cmdInput').focus(),100);
