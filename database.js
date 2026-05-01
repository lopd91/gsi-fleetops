'use strict';
const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');
const DB_PATH = path.join(__dirname, 'data', 'gsifleetops.db');
const fs = require('fs');
if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL COLLATE NOCASE,full_name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',department TEXT DEFAULT '',active INTEGER DEFAULT 1,last_login TEXT,created_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS bookings (id TEXT PRIMARY KEY,job TEXT UNIQUE NOT NULL,date TEXT,client TEXT,contact TEXT,origin TEXT,destination TEXT,pickup TEXT,delivery TEXT,truck_id TEXT,driver_id TEXT,cargo TEXT,weight TEXT,amount TEXT,status TEXT DEFAULT 'pending',notes TEXT,doc TEXT,created_by TEXT,updated_by TEXT,created_at TEXT DEFAULT (datetime('now')),updated_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS drivers (id TEXT PRIMARY KEY,name TEXT NOT NULL,ic TEXT,phone TEXT,license TEXT,expiry TEXT,status TEXT DEFAULT 'available',cicpa TEXT DEFAULT 'non-cicpa',cicpa_expiry TEXT,created_by TEXT,updated_by TEXT,created_at TEXT DEFAULT (datetime('now')),updated_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS trucks (id TEXT PRIMARY KEY,plate TEXT NOT NULL,model TEXT,type TEXT,capacity TEXT,roadtax TEXT,status TEXT DEFAULT 'available'.owner TEXT DEFAULT 'gsi',vendor_id TEXT,created_by TEXT,updated_by TEXT,created_at TEXT DEFAULT (datetime('now')),updated_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS vendors (id TEXT PRIMARY KEY,num TEXT,name TEXT NOT NULL,cat TEXT,contact TEXT,phone TEXT,email TEXT,trn TEXT,terms TEXT,status TEXT DEFAULT 'active',notes TEXT,created_by TEXT,updated_by TEXT,created_at TEXT DEFAULT (datetime('now')),updated_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY,num TEXT,type TEXT DEFAULT 'company',name TEXT NOT NULL,contact TEXT,phone TEXT,email TEXT,trn TEXT,address TEXT,credit TEXT,terms TEXT,notes TEXT,created_by TEXT,updated_by TEXT,created_at TEXT DEFAULT (datetime('now')),updated_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS vouchers (id TEXT PRIMARY KEY,num TEXT,date TEXT,cat TEXT,description TEXT,requested_by TEXT,amount TEXT,job_ref TEXT,status TEXT DEFAULT 'review',photo TEXT,created_by TEXT,updated_by TEXT,created_at TEXT DEFAULT (datetime('now')),updated_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY,num TEXT,date TEXT,cat TEXT,vendor TEXT,job_ref TEXT,driver_id TEXT,description TEXT,amount TEXT,photo TEXT,created_by TEXT,updated_by TEXT,created_at TEXT DEFAULT (datetime('now')),updated_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY,value INTEGER DEFAULT 1000);
  INSERT OR IGNORE INTO counters VALUES ('job',1000),('voucher',1000),('receipt',1000),('client',1000),('vendor',1000);
`);
const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get();
if (userCount.c === 0) { const hash = bcrypt.hashSync('Admin@GSI2025',12); db.prepare('INSERT INTO users (id,username,full_name,password_hash,role,active) VALUES (?,?,?,?,?,1)').run(uid(),'admin','System Administrator',hash,'admin'); console.log('✅ Default admin created'); }
function uid() { return Date.now().toString(36)+Math.random().toString(36).substr(2,9); }
function incrementCounter(name) { db.prepare('UPDATE counters SET value=value+1 WHERE name=?').run(name); return db.prepare('SELECT value FROM counters WHERE name=?').get(name).value; }
function makeRepo(table) { return { all:()=>db.prepare(`SELECT * FROM ${table} ORDER BY created_at DESC`).all(), byId:'id'=>>db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(id), insert:y=>{ const k=Object.keys(y); db.prepare(`INSERT INTO ${table} (${k.join(',')}) VALUES (${k.map(()=>'?').join(',')})`).run(Object.values(y)); return y; }, update:(id,y)=>{ const k=Object.keys(y); db.prepare(`UPDATE ${table} SET ${k.map(k=>k+'=?').join(',')},updated_at=datetime('now') WHERE id=?`).run([...Object.values(y),id]); return db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(id); }, delete:id=>>db.prepare(`DELETE FROM ${table} WHERE id=?`).run(id) }; }
module.exports = { db, uid, incrementCounter, users:makeRepo('users'), bookings:makeRepo('bookings'), drivers:makeRepo('drivers'), trucks:makeRepo('trucks'), vendors:makeRepo('vendors'), clients:makeRepo('clients'), vouchers:makeRepo('vouchers'), receipts:makeRepo('receipts') };
