'use strict';
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH  = path.join(DATA_DIR, 'gsifleetops.db');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

let db;

function saveDb() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function run(sql, params=[]) {
  db.run(sql, params);
  saveDb();
}

function get(sql, params=[]) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) { const r = stmt.getAsObject(); stmt.free(); return r; }
  stmt.free(); return undefined;
}

function all(sql, params=[]) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function uid() { return Date.now().toString(36) + Math.random().toString(36).substr(2,9); }

function incrementCounter(name) {
  run('UPDATE counters SET value=value+1 WHERE name=?', [name]);
  return get('SELECT value FROM counters WHERE name=?', [name]).value;
}

function makeRepo(table) {
  return {
    all:    ()      => all(`SELECT * FROM ${table} ORDER BY created_at DESC`),
    byId:   (id)    => get(`SELECT * FROM ${table} WHERE id=?`, [id]),
    insert: (row)   => { const k=Object.keys(row); run(`INSERT INTO ${table} (${k.join(',')}) VALUES (${k.map(()=>'?').join(',')})`, Object.values(row)); return row; },
    update: (id,row)=> { const k=Object.keys(row); run(`UPDATE ${table} SET ${k.map(x=>x+'=?').join(',')},updated_at=datetime('now') WHERE id=?`, [...Object.values(row),id]); return get(`SELECT * FROM ${table} WHERE id=?`,[id]); },
    delete: (id)    => run(`DELETE FROM ${table} WHERE id=?`, [id])
  };
}

async function init() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE, full_name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', department TEXT DEFAULT '', active INTEGER DEFAULT 1, last_login TEXT, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS bookings (id TEXT PRIMARY KEY, job TEXT UNIQUE NOT NULL, date TEXT, client TEXT, contact TEXT, origin TEXT, destination TEXT, pickup TEXT, delivery TEXT, truck_id TEXT, driver_id TEXT, cargo TEXT, weight TEXT, amount TEXT, status TEXT DEFAULT 'pending', notes TEXT, doc TEXT, created_by TEXT, updated_by TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS drivers (id TEXT PRIMARY KEY, name TEXT NOT NULL, ic TEXT, phone TEXT, license TEXT, expiry TEXT, status TEXT DEFAULT 'available', cicpa TEXT DEFAULT 'non-cicpa', cicpa_expiry TEXT, created_by TEXT, updated_by TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS trucks (id TEXT PRIMARY KEY, plate TEXT NOT NULL, model TEXT, type TEXT, capacity TEXT, roadtax TEXT, status TEXT DEFAULT 'available', owner TEXT DEFAULT 'gsi', vendor_id TEXT, created_by TEXT, updated_by TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS vendors (id TEXT PRIMARY KEY, num TEXT, name TEXT NOT NULL, cat TEXT, contact TEXT, phone TEXT, email TEXT, trn TEXT, terms TEXT, status TEXT DEFAULT 'active', notes TEXT, created_by TEXT, updated_by TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, num TEXT, type TEXT DEFAULT 'company', name TEXT NOT NULL, contact TEXT, phone TEXT, email TEXT, trn TEXT, address TEXT, credit TEXT, terms TEXT, notes TEXT, created_by TEXT, updated_by TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS vouchers (id TEXT PRIMARY KEY, num TEXT, date TEXT, cat TEXT, description TEXT, requested_by TEXT, amount TEXT, job_ref TEXT, status TEXT DEFAULT 'review', photo TEXT, created_by TEXT, updated_by TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, num TEXT, date TEXT, cat TEXT, vendor TEXT, job_ref TEXT, driver_id TEXT, description TEXT, amount TEXT, photo TEXT, created_by TEXT, updated_by TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER DEFAULT 1000);
    INSERT OR IGNORE INTO counters VALUES ('job',1000),('voucher',1000),('receipt',1000),('client',1000),('vendor',1000);
    CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, sess TEXT, expired TEXT);
  `);

  const uc = get('SELECT COUNT(*) as c FROM users');
  if (!uc || uc.c === 0) {
    const hash = bcrypt.hashSync('Admin@GSI2025', 12);
    run('INSERT INTO users (id,username,full_name,password_hash,role,active) VALUES (?,?,?,?,?,1)', [uid(),'admin','System Administrator',hash,'admin']);
    console.log('Default admin created — username: admin  password: Admin@GSI2025');
  }
  saveDb();
  console.log('Database ready at', DB_PATH);
}

module.exports = { init, run, get, all, uid, incrementCounter, saveDb,
  users: null, bookings: null, drivers: null, trucks: null,
  vendors: null, clients: null, vouchers: null, receipts: null,
  setup() {
    this.users    = makeRepo('users');
    this.bookings = makeRepo('bookings');
    this.drivers  = makeRepo('drivers');
    this.trucks   = makeRepo('trucks');
    this.vendors  = makeRepo('vendors');
    this.clients  = makeRepo('clients');
    this.vouchers = makeRepo('vouchers');
    this.receipts = makeRepo('receipts');
  }
};
