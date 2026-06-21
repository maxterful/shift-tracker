const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');

function ensure(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); }
ensure(path.join(DATA, 'users'));

function read(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function write(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
function hashPin(pin) {
  return crypto.createHash('sha256').update('st-2024:' + pin).digest('hex');
}
function udir(id) {
  const d = path.join(DATA, 'users', id);
  ensure(d);
  return d;
}
function safeUser(u) { const { pinHash, ...s } = u; return s; }

// In-memory sessions (token → userId). Users re-login after server restart.
const sessions = new Map();

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  const uid   = sessions.get(token);
  if (!uid) return res.status(401).json({ error: 'Not authenticated' });
  req.uid = uid;
  next();
}

function adminAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  const uid   = sessions.get(token);
  if (!uid) return res.status(401).json({ error: 'Not authenticated' });
  const user  = read(path.join(DATA, 'users.json'), []).find(u => u.id === uid);
  if (!user?.isAdmin) return res.status(403).json({ error: 'Admin only' });
  req.uid = uid;
  next();
}

// ── Users (public — no PIN hashes) ────────────────────────
app.get('/api/users', (_req, res) => {
  res.json(read(path.join(DATA, 'users.json'), []).map(safeUser));
});

app.post('/api/users', (req, res) => {
  const { name, color, emoji, pin } = req.body;
  if (!name?.trim() || !pin) return res.status(400).json({ error: 'name and pin required' });
  const all = read(path.join(DATA, 'users.json'), []);
  if (all.find(u => u.name.toLowerCase() === name.trim().toLowerCase()))
    return res.status(409).json({ error: 'Name already taken' });
  const user = {
    id: crypto.randomUUID(), name: name.trim(),
    color: color || '#2563EB', emoji: emoji || '👤',
    pinHash: hashPin(String(pin)), isAdmin: false, createdAt: Date.now()
  };
  all.push(user);
  write(path.join(DATA, 'users.json'), all);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, user.id);
  res.json({ token, user: safeUser(user) });
});

// ── Auth ──────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { userId, pin } = req.body;
  const all  = read(path.join(DATA, 'users.json'), []);
  const user = all.find(u => u.id === userId);
  if (!user)                                 return res.status(404).json({ error: 'User not found' });
  if (user.pinHash !== hashPin(String(pin))) return res.status(401).json({ error: 'Wrong PIN' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, user.id);
  res.json({ token, user: safeUser(user) });
});

app.post('/api/logout', auth, (req, res) => {
  sessions.delete((req.headers.authorization || '').replace('Bearer ', '').trim());
  res.json({ ok: true });
});

// Refresh own profile (picks up isAdmin changes without re-login)
app.get('/api/me', auth, (req, res) => {
  const user = read(path.join(DATA, 'users.json'), []).find(u => u.id === req.uid);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(safeUser(user));
});

// ── Admin: claim admin role ────────────────────────────────
app.post('/api/admin/promote', auth, (req, res) => {
  const secret = (process.env.ADMIN_SECRET || '').trim();
  if (!secret)                    return res.status(503).json({ error: 'ADMIN_SECRET not configured on server' });
  if (req.body.secret !== secret) return res.status(403).json({ error: 'Wrong secret' });
  const all = read(path.join(DATA, 'users.json'), []);
  const idx = all.findIndex(u => u.id === req.uid);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  all[idx].isAdmin = true;
  write(path.join(DATA, 'users.json'), all);
  res.json({ ok: true, user: safeUser(all[idx]) });
});

// ── Admin: list all users with stats ──────────────────────
app.get('/api/admin/users', adminAuth, (_req, res) => {
  const all = read(path.join(DATA, 'users.json'), []);
  res.json(all.map(user => {
    const hist  = read(path.join(DATA, 'users', user.id, 'history.json'), []);
    const state = read(path.join(DATA, 'users', user.id, 'state.json'), null);
    return {
      ...safeUser(user),
      shiftCount: hist.length,
      totalSales: hist.reduce((a, h) => a + (h.totalSales || 0), 0),
      lastActive: state?.updatedAt || user.createdAt || 0
    };
  }));
});

// ── Admin: delete user ────────────────────────────────────
app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  if (req.params.id === req.uid) return res.status(400).json({ error: 'Cannot delete yourself' });
  const all = read(path.join(DATA, 'users.json'), []);
  const idx = all.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  all.splice(idx, 1);
  write(path.join(DATA, 'users.json'), all);
  const userDir = path.join(DATA, 'users', req.params.id);
  if (fs.existsSync(userDir)) fs.rmSync(userDir, { recursive: true });
  res.json({ ok: true });
});

// ── Admin: revoke admin from another user ─────────────────
app.post('/api/admin/demote/:id', adminAuth, (req, res) => {
  if (req.params.id === req.uid) return res.status(400).json({ error: 'Cannot demote yourself' });
  const all = read(path.join(DATA, 'users.json'), []);
  const idx = all.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  all[idx].isAdmin = false;
  write(path.join(DATA, 'users.json'), all);
  res.json({ ok: true });
});

// ── Per-user shift state ───────────────────────────────────
app.get('/api/me/state', auth, (req, res) => {
  res.json(read(path.join(udir(req.uid), 'state.json'), null));
});
app.put('/api/me/state', auth, (req, res) => {
  write(path.join(udir(req.uid), 'state.json'), req.body);
  res.json({ ok: true });
});

// ── Per-user history ───────────────────────────────────────
app.get('/api/me/history', auth, (req, res) => {
  res.json(read(path.join(udir(req.uid), 'history.json'), []));
});
app.post('/api/me/history', auth, (req, res) => {
  const f = path.join(udir(req.uid), 'history.json');
  const h = read(f, []);
  const e = { id: Date.now(), ...req.body };
  h.unshift(e);
  write(f, h);
  res.json({ id: e.id });
});
app.delete('/api/me/history/:id', auth, (req, res) => {
  const f = path.join(udir(req.uid), 'history.json');
  write(f, read(f, []).filter(h => h.id !== Number(req.params.id)));
  res.json({ ok: true });
});
app.delete('/api/me/history', auth, (req, res) => {
  write(path.join(udir(req.uid), 'history.json'), []);
  res.json({ ok: true });
});

// Add a sale to a past shift entry and recalculate totals
app.patch('/api/me/history/:id', auth, (req, res) => {
  const f   = path.join(udir(req.uid), 'history.json');
  const h   = read(f, []);
  const idx = h.findIndex(e => e.id === Number(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const sales       = [...(h[idx].sales || []), req.body];
  const guestsSold  = sales.reduce((a, s) => a + (s.guests || 0), 0);
  const totalGuests = guestsSold + (h[idx].guestsExtra || 0);
  const pt          = {};
  sales.forEach(s => { pt[s.product] = (pt[s.product] || 0) + s.amount; });
  h[idx] = {
    ...h[idx], sales,
    totalSales:      Math.round(sales.reduce((a, s) => a + s.amount,               0) * 100) / 100,
    totalCommission: Math.round(sales.reduce((a, s) => a + (s.commission || 0),    0) * 100) / 100,
    guestsSold, totalGuests, txCount: guestsSold, saleCount: sales.length,
    topProduct: Object.keys(pt).sort((a, b) => pt[b] - pt[a])[0] || null,
  };
  write(f, h);
  res.json({ ok: true, entry: h[idx] });
});

// ── Leaderboard ───────────────────────────────────────────
app.get('/api/leaderboard', (_req, res) => {
  const { period = 'alltime' } = _req.query;
  const users    = read(path.join(DATA, 'users.json'), []);
  const now      = new Date();
  const dayStart = new Date(now).setHours(0, 0, 0, 0);
  const wkStart  = dayStart - now.getDay() * 86400000;
  const moStart  = new Date(now.getFullYear(), now.getMonth(), 1).getTime();

  const board = users.map(user => {
    const hist = read(path.join(DATA, 'users', user.id, 'history.json'), []);
    const rows = hist.filter(h => {
      if (period === 'today') return (h.shiftEnd || 0) >= dayStart;
      if (period === 'week')  return (h.shiftEnd || 0) >= wkStart;
      if (period === 'month') return (h.shiftEnd || 0) >= moStart;
      return true;
    });
    const totalSales      = rows.reduce((a, h) => a + (h.totalSales      || 0), 0);
    const totalCommission = rows.reduce((a, h) => a + (h.totalCommission  || 0), 0);
    const txCount         = rows.reduce((a, h) => a + (h.txCount         || 0), 0);
    const totalGuests     = rows.reduce((a, h) => a + (h.totalGuests     || 0), 0);
    const guestsSold      = rows.reduce((a, h) => a + (h.guestsSold      || 0), 0);
    const bestShift       = rows.reduce((a, h) => Math.max(a, h.totalSales || 0), 0);
    const bestSale        = rows.reduce((a, h) =>
      Math.max(a, (h.sales || []).reduce((b, s) => Math.max(b, s.amount || 0), 0)), 0);
    const conv = totalGuests > 0 ? Math.round((guestsSold / totalGuests) * 100) : null;
    return {
      user: safeUser(user), shiftCount: rows.length,
      totalSales, totalCommission, txCount, totalGuests, guestsSold, conv,
      bestShift, bestSale,
      avgPerShift: rows.length ? Math.round(totalSales / rows.length) : 0
    };
  }).sort((a, b) => b.totalSales - a.totalSales);

  res.json(board);
});

// ── Start ─────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  const nets = Object.values(require('os').networkInterfaces()).flat()
    .filter(n => n.family === 'IPv4' && !n.internal);
  console.log('\n  Shift Tracker');
  console.log(`  Local:   http://localhost:${PORT}`);
  nets.forEach(n => console.log(`  Network: http://${n.address}:${PORT}`));
  if (!process.env.ADMIN_SECRET) console.log('  ⚠  ADMIN_SECRET not set — admin promotion disabled');
  console.log();
});
