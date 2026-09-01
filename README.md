# Emulador psql - AlmaLinux

Emulador 100% offline de psql 16.3 sobre AlmaLinux 9.4. Sin CDNs, responsive Android/Tablet.

## Características
- Prompt dinámico postgres=# / compras=>
- DDL/LMD con validación estricta 42501 (CONNECT, USAGE, CREATE, SELECT, INSERT, UPDATE, DELETE)
- Roles: CREATE ROLE ... NOLOGIN, CREATE USER ... WITH PASSWORD, GRANT/REVOKE, SET/RESET ROLE, \du
- Bases: CREATE DATABASE, \c, \l
- Tablas: CREATE TABLE, \dt, \d, BACKUP DATABASE (solo superuser)
- Temas por comando: \tema, \color, \acciones, \ayuda, \teoria
- Entrada fija abajo, info sube, 100% offline (sin Google Fonts ni Font Awesome)

## Uso
Abrir index.html en el navegador (doble click). Todo es localStorage.

## Comandos clave
`sql
CREATE ROLE rol_ventas NOLOGIN;
CREATE USER vendedor1 WITH PASSWORD '123';
GRANT rol_ventas TO vendedor1;
GRANT CONNECT ON DATABASE compras TO rol_ventas;
GRANT USAGE ON SCHEMA public TO rol_ventas;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO rol_ventas;
SET ROLE vendedor1;
SELECT * FROM cargos; -- ok
INSERT INTO cargos VALUES (3,'X'); -- ERROR 42501 sin INSERT
BACKUP DATABASE compras; -- solo postgres
`

## Estructura
- index.html - Consola
- css/style.css - Estilos offline
- js/app.js - Motor JS (RoleManager + DatabaseEngine)
