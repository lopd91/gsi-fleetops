'use strict';
require('dotenv').config();
const express    = require('express');
const session    = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt     = require('bcryptjs');
const helmet     = require('helmet');
const compression = require('compression');
const path       = require('path');
const fs         = require('fs');

const repo = require('./database');

const app  = express();
const PORT = process.env.PORT || 3000;

// Ensure data dir exists for session store
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'data') }),
  secret: process.env.SESSION_SECRET || 'gsi-fleetops-change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000
  }
}));

function auth(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function admin(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: 'Not authenticated' });
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const user = repo.db.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE AND active=1').get(username.trim());
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });
    const match = bcrypt.compareSync(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid username or password' });
    repo.db.prepare('UPDATE users SET last_login=datetime("now") WHERE id=?').run(user.id);
    req.session.user = { id: user.id, username: user.username, full_name: user.full_name, role: user.role, department: user.department };
    res.json({ success: true, user: req.session.user });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/auth/logout', (req, res) => { req.session.destroy(() => res.json({ success: true })); });
app.get('/api/auth/me', (req, res) => { res.json({ user: req.session?.user || null }); });
app.post('/api/auth/change-password', auth, (req, res) => {
  const { current, newpass } = req.body;
  const user = repo.db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  if (!bcrypt.compareSync(current, user.password_hash)) return res.status(400).json({ error: 'Current password incorrect' });
  if (!newpass || newpass.length < 6) return res.status(400).json({ error: 'Min length 6' });
  repo.db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(newpass,12), user.id);
  res.json({ success: true });
});
app.get('/api/users', admin, (req, res) => { res.json(repo.db.prepare('SELECT id,username,full_name,role,department,active,last_login,created_at FROM users ORDER BY username').all()); });
app.post('/api/users', admin, (req, res) => {
  try {
    const { username, full_name, password, role, department } = req.body;
    if (!username || !full_name || !password) return res.status(400).json({ error: 'username, full_name and password required' });
    if (repo.db.prepare('SELECT id FROM users WHERE username=? COLLATE NOCASE').get(username)) return res.status(400).json({ error: 'Username already exists' });
    const hash = bcrypt.hashSync(password,12);
    const id = repo.uid();
    repo.db.prepare('INSERT INTO users (id,username,full_name,password_hash,role,department,active) VALUES (?,?,?,?,?,?,1)').run(id, username.toLowerCase().trim(), full_name, hash, role||'user', department||'');
    res.json(repo.db.prepare('SELECT id,username,full_name,role,department,active FROM users WHERE id=?').get(id));
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.put('/api/users/:id', admin, (req, res) => {
  try {
    const { full_name, role, department, active, password } = req.body;
    if (password) repo.db.prepare('UPDATE users SET full_name=?,role=?,department=?,active=?,password_hash=? WHERE id=?').run(full_name,role,department||'',active?1:0,bcrypt.hashSync(password,12),req.params.id);
    else repo.db.prepare('UPDATE users SET full_name=?,role=?,department=?,active=? WHERE id=?').run(full_name,role,department||'',active?1:0,req.params.id);
    res.json(repo.db.prepare('SELECT id,username,full_name,role,department,active FROM users WHERE id=?').get(req.params.id));
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/users/:id', admin, (req, res) => {
  if (req.params.id === req.session.user.id) return res.status(400).json({ error: "Can't deactivate yourself" });
  repo.db.prepare('UPDATE users SET active=0 WHERE id=?').run(req.params.id);
  res.json({ success: true });
});
app.post('/api/counters/increment', auth, (req, res) => { res.json({ value: repo.incrementCounter(req.body.name) }); });
const TABLES = { bookings:repo.bookings, drivers:repo.drivers, trucks:repo.trucks, vendors:repo.vendors, clients:repo.clients, vouchers:repo.vouchers, receipts:repo.receipts };
Object.entries(TABLES).forEach(([name,r]) => {
  app.get(`/api/${name}`, auth, (req,res) => { res.json(r.all()); });
  app.get(`/api/${name}/:id`, auth, (req,res) => { const row=r.byId(req.params.id); if(!row) return res.status(404).json({error:'Not found'}); res.json(row); });
  app.post(`/api/${name}`, auth, (req,res) => { try { r.insert({...req.body,created_by:req.session.user.id,created_at:new Date().toISOString()}); res.json(req.body); } catch(e) { res.status(400).json({error:e.message}); } });
  app.put(`/api/${name}/:id`, auth, (req,res) => { try { res.json(r.update(req.params.id,{...req.body,updated_by:req.session.user.id})); } catch(e) { res.status(400).json({error:e.message}); } });
  app.delete(`/api/${name}/:id`, auth, (req,res) => { r.delete(req.params.id); res.json({success:true}); });
});
app.get('*', (req,res) => { res.sendFile(path.join(__dirname,'public','index.html')); });
app.listen(PORT, () => { console.log(`\n✅  GSI FleetOps running on port ${PORT}`); });
