const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const https   = require('https');

function httpGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'shift-tracker/1.0' } }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { reject(e); } });
    }).on('error', reject);
  });
}

const app  = express();
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');

function ensure(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); }
ensure(path.join(DATA, 'users'));

function read(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function write(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
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

// ── Sessions (in-memory; users re-login after server restart) ─
const sessions = new Map(); // token → { userId, createdAt }
const SESSION_TTL = 12 * 60 * 60 * 1000; // 12 hours

// ── Rate limiting for login ────────────────────────────────────
const loginAttempts = new Map(); // ip → { count, lockUntil }
const MAX_ATTEMPTS  = 5;
const LOCK_DURATION = 15 * 60 * 1000; // 15 min
setInterval(() => {
  const now = Date.now();
  for (const [ip, a] of loginAttempts) if (now > a.lockUntil && a.count === 0) loginAttempts.delete(ip);
}, 60 * 60 * 1000);

app.use(express.json({ limit: '10mb' }));

// ── Security headers ───────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com",
    "font-src https://cdn.jsdelivr.net https://unpkg.com",
    "img-src 'self' data:",
    "connect-src 'self'",
  ].join('; '));
  if (req.headers['x-forwarded-proto'] === 'https')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

function getToken(req) { return (req.headers.authorization || '').replace('Bearer ', '').trim(); }

function auth(req, res, next) {
  const token = getToken(req);
  const sess  = sessions.get(token);
  if (!sess) return res.status(401).json({ error: 'Not authenticated' });
  if (Date.now() - sess.createdAt > SESSION_TTL) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Session expired — please log in again' });
  }
  req.uid = sess.userId;
  next();
}

function adminAuth(req, res, next) {
  const token = getToken(req);
  const sess  = sessions.get(token);
  if (!sess) return res.status(401).json({ error: 'Not authenticated' });
  if (Date.now() - sess.createdAt > SESSION_TTL) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Session expired — please log in again' });
  }
  const user = read(path.join(DATA, 'users.json'), []).find(u => u.id === sess.userId);
  if (!user?.isAdmin) return res.status(403).json({ error: 'Admin only' });
  req.uid = sess.userId;
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
  sessions.set(token, { userId: user.id, createdAt: Date.now() });
  res.json({ token, user: safeUser(user) });
});

// ── Auth ──────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const attempt = loginAttempts.get(ip) || { count: 0, lockUntil: 0 };
  if (Date.now() < attempt.lockUntil)
    return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });

  const { userId, pin } = req.body;
  const all  = read(path.join(DATA, 'users.json'), []);
  const user = all.find(u => u.id === userId);
  if (!user || user.pinHash !== hashPin(String(pin))) {
    attempt.count++;
    if (attempt.count >= MAX_ATTEMPTS) { attempt.lockUntil = Date.now() + LOCK_DURATION; attempt.count = 0; }
    loginAttempts.set(ip, attempt);
    return res.status(401).json({ error: 'Wrong PIN', attemptsLeft: Math.max(0, MAX_ATTEMPTS - attempt.count) });
  }
  loginAttempts.delete(ip);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { userId: user.id, createdAt: Date.now() });
  res.json({ token, user: safeUser(user) });
});

app.post('/api/logout', auth, (req, res) => {
  sessions.delete(getToken(req));
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
  if (!secret) return res.status(503).json({ error: 'ADMIN_SECRET not configured on server' });
  const provided = Buffer.from(String(req.body.secret || ''));
  const expected = Buffer.from(secret);
  const match = provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
  if (!match) return res.status(403).json({ error: 'Wrong secret' });
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

// ── Admin: full history for a specific user ────────────────
app.get('/api/admin/users/:id/history', adminAuth, (req, res) => {
  const f = path.join(DATA, 'users', req.params.id, 'history.json');
  res.json(read(f, []));
});

// ── Admin: current state for a specific user ───────────────
app.get('/api/admin/users/:id/state', adminAuth, (req, res) => {
  const f = path.join(DATA, 'users', req.params.id, 'state.json');
  res.json(read(f, null));
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

// ── Update a past shift (edit sales) ─────────────────────
app.put('/api/me/history/:id', auth, (req, res) => {
  const f   = path.join(udir(req.uid), 'history.json');
  const h   = read(f, []);
  const idx = h.findIndex(e => e.id === Number(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const sales = req.body.sales || h[idx].sales || [];
  const guestsSold = sales.reduce((a, s) => a + (s.guests || 0), 0);
  const pt = {};
  sales.forEach(s => { pt[s.product] = (pt[s.product] || 0) + s.amount; });
  h[idx] = {
    ...h[idx], ...req.body, id: h[idx].id, sales,
    totalSales:      Math.round(sales.reduce((a, s) => a + s.amount,            0) * 100) / 100,
    totalCommission: Math.round(sales.reduce((a, s) => a + (s.commission || 0), 0) * 100) / 100,
    guestsSold, txCount: guestsSold, saleCount: sales.length,
    topProduct: Object.keys(pt).sort((a, b) => pt[b] - pt[a])[0] || null,
  };
  write(f, h);
  res.json({ ok: true, entry: h[idx] });
});

// ── Commission logic (mirrored from client) ───────────────
const COMM_RATES = {
  admission:     { Premier: 0.005,  'Non-Premier': 0.0045, UPH: 0.0055 },
  express:       { Premier: 0.015,  'Non-Premier': 0.01,   UPH: 0.015  },
  upgrades:      { Premier: 0.0125, 'Non-Premier': 0.01,   UPH: 0.0225 },
  vipPrivate:    { Premier: 0.025,  'Non-Premier': 0.025,  UPH: 0.025  },
  vipNonPrivate: { Premier: 0.025,  'Non-Premier': 0.02,   UPH: 0.025  },
  lanyards:      { Premier: 0.03,   'Non-Premier': 0.03,   UPH: 0.03   },
  ancillary:     { Premier: 0.0125, 'Non-Premier': 0.0125, UPH: 0.0175 },
  thirdParty:    { Premier: 0.01,   'Non-Premier': 0.01,   UPH: 0.01   },
  none:          { Premier: 0,      'Non-Premier': 0,       UPH: 0      },
};
function commTypeFor(product, tier) {
  if (product.includes('VIP TOUR: PRIVATE'))     return 'vipPrivate';
  if (product.includes('VIP TOUR: NON-PRIVATE')) return 'vipNonPrivate';
  if (product.includes('EXPRESS'))               return 'express';
  if (product.includes('LANYARD') || product === 'POUCH ONLY' || product === 'EVENT LANYARD') return 'lanyards';
  if (product.includes('CONV'))                  return 'none';
  if (product === 'SeaWorld 1D' || product.includes('I-RIDE')) return 'thirdParty';
  if (product.includes('PARKING') || product.includes('Superstar Shuttle') ||
      product === '1D MILITARY FREEDOM PASS' || product === 'Epic After 2PM Guest Recovery') return 'none';
  if (product.includes('PHOTOS') || product.includes('CABANA') ||
      product.includes('PREMIUM SEATING') || product.includes('FREESTYLE') ||
      product.includes('DARKMOOR') || product.includes('BREAKFAST') ||
      product.includes('CHARACTER DINING') || product.includes('HHN')) return 'ancillary';
  if (product.startsWith('1D VB')) return 'admission';
  if ((product.includes('1D') || product.includes('1 DAY')) && product.includes('PTP'))
    return tier === 'UPH' ? 'admission' : 'none';
  if (product.includes('1D') || product.includes('1 DAY')) return 'none';
  return 'admission';
}
function calcCommission(product, preTax, tier, isUpgrade) {
  if (isUpgrade) return Math.round(preTax * (COMM_RATES.upgrades[tier] ?? 0) * 100) / 100;
  const rate = (COMM_RATES[commTypeFor(product, tier)] || COMM_RATES.none)[tier] ?? 0;
  return Math.round(preTax * rate * 100) / 100;
}

// ── Admin: recalculate commissions for all users ──────────
app.post('/api/admin/recalc-commissions', adminAuth, (_req, res) => {
  const users = read(path.join(DATA, 'users.json'), []);
  let shiftsUpdated = 0, salesUpdated = 0;
  users.forEach(user => {
    const f = path.join(DATA, 'users', user.id, 'history.json');
    const history = read(f, []);
    let changed = false;
    history.forEach(shift => {
      const tier = shift.hotelTier || 'Premier';
      const sales = (shift.sales || []).map(sale => {
        const preTax = sale.preTax ?? (sale.amount / 1.065);
        const newComm = calcCommission(sale.product || '', preTax, tier, sale.isUpgrade);
        if (newComm !== sale.commission) { salesUpdated++; changed = true; }
        return { ...sale, commission: newComm };
      });
      if (changed) {
        shift.sales = sales;
        shift.totalCommission = Math.round(sales.reduce((a, s) => a + (s.commission || 0), 0) * 100) / 100;
        shiftsUpdated++;
      }
    });
    if (changed) write(f, history);
  });
  res.json({ ok: true, shiftsUpdated, salesUpdated, usersProcessed: users.length });
});

// ── Insights: top products + hourly data across all users ─
app.get('/api/insights', (_req, res) => {
  const users = read(path.join(DATA, 'users.json'), []);
  const productStats = {};
  const hourly = Array.from({ length: 24 }, () => ({ count: 0, total: 0 }));
  users.forEach(user => {
    read(path.join(DATA, 'users', user.id, 'history.json'), []).forEach(shift => {
      (shift.sales || []).forEach(sale => {
        if (!sale.product) return;
        if (!productStats[sale.product]) productStats[sale.product] = { count: 0, revenue: 0, commission: 0 };
        productStats[sale.product].count    += (sale.guests || 1);
        productStats[sale.product].revenue  += (sale.amount || 0);
        productStats[sale.product].commission += (sale.commission || 0);
        if (sale.ts) {
          const hr = new Date(sale.ts).getHours();
          hourly[hr].count++;
          hourly[hr].total += (sale.amount || 0);
        }
      });
    });
  });
  const topProducts = Object.entries(productStats)
    .map(([product, s]) => ({ product, ...s }))
    .sort((a, b) => b.revenue - a.revenue)
    .slice(0, 15);
  res.json({ topProducts, hourly });
});

function localPeriodBounds(tzOffset) {
  // tzOffset = minutes behind UTC (e.g. 240 for EDT)
  const tzMs   = (tzOffset || 0) * 60000;
  const nowLocal = new Date(Date.now() - tzMs);
  nowLocal.setUTCHours(0, 0, 0, 0);
  const dayStart = nowLocal.getTime() + tzMs;               // local midnight in UTC
  const wkStart  = dayStart - nowLocal.getUTCDay() * 86400000;
  const moStart  = dayStart - (nowLocal.getUTCDate() - 1) * 86400000;
  return { dayStart, wkStart, moStart };
}

// ── Leaderboard ───────────────────────────────────────────
app.get('/api/leaderboard', (_req, res) => {
  const { period = 'alltime', tz = '0' } = _req.query;
  const users    = read(path.join(DATA, 'users.json'), []);
  const { dayStart, wkStart, moStart } = localPeriodBounds(parseInt(tz, 10));

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
    // Most recent shift hotel for the period (for display on leaderboard)
    const mostRecent = rows.length ? rows.reduce((a, h) => (h.shiftEnd||0) > (a.shiftEnd||0) ? h : a, rows[0]) : null;
    return {
      user: safeUser(user), shiftCount: rows.length,
      totalSales, totalCommission, txCount, totalGuests, guestsSold, conv,
      bestShift, bestSale,
      avgPerShift: rows.length ? Math.round(totalSales / rows.length) : 0,
      hotel: mostRecent?.hotel || null,
      hotelTier: mostRecent?.hotelTier || null,
    };
  }).sort((a, b) => b.totalSales - a.totalSales);

  res.json(board);
});

// ── Hotel leaderboard ────────────────────────────────────
app.get('/api/hotel-leaderboard', (_req, res) => {
  const { period = 'today', tz = '0' } = _req.query;
  const users    = read(path.join(DATA, 'users.json'), []);
  const { dayStart, wkStart, moStart } = localPeriodBounds(parseInt(tz, 10));

  const hotels = {};
  users.forEach(user => {
    read(path.join(DATA, 'users', user.id, 'history.json'), [])
      .filter(h => {
        if (period === 'today') return (h.shiftEnd || 0) >= dayStart;
        if (period === 'week')  return (h.shiftEnd || 0) >= wkStart;
        if (period === 'month') return (h.shiftEnd || 0) >= moStart;
        return true;
      })
      .forEach(h => {
        if (!h.hotel) return;
        if (!hotels[h.hotel]) hotels[h.hotel] = { hotel: h.hotel, hotelTier: h.hotelTier || null, totalSales: 0, shiftCount: 0, txCount: 0, topUser: null, topUserSales: 0 };
        hotels[h.hotel].totalSales  += h.totalSales || 0;
        hotels[h.hotel].shiftCount  += 1;
        hotels[h.hotel].txCount     += h.txCount || 0;
        if ((h.totalSales || 0) > hotels[h.hotel].topUserSales) {
          hotels[h.hotel].topUserSales = h.totalSales || 0;
          hotels[h.hotel].topUser = user.name;
        }
      });
  });

  const board = Object.values(hotels)
    .map(h => ({ ...h, totalSales: Math.round(h.totalSales * 100) / 100 }))
    .sort((a, b) => b.totalSales - a.totalSales);

  res.json(board);
});

// ── Park info: weather + hours (cached 30 min) ────────────
let _parkCache = null, _parkCacheTs = 0;
const WX_CODE = code => {
  if (code === 0) return '☀️';
  if (code <= 3)  return '⛅';
  if (code <= 48) return '🌫️';
  if (code <= 67) return '🌧️';
  if (code <= 82) return '🌦️';
  return '⛈️';
};
app.get('/api/park-info', async (_req, res) => {
  if (_parkCache && Date.now() - _parkCacheTs < 30 * 60 * 1000)
    return res.json(_parkCache);
  const fmtTime = t => t ? new Date(t).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', timeZone: 'America/New_York' }) : null;
  const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/New_York' });
  const UOR_PARKS = [
    { id: 'eb3f4560-2383-4a36-9152-6b3e5ed6bc57', name: 'Universal Studios Florida' },
    { id: '267615cc-8943-4c2a-ae2c-5da728ca591f', name: 'Islands of Adventure' },
    { id: '12dbb85b-265f-44e6-bccf-f1faa17211fc', name: 'Epic Universe' },
    { id: 'fe78a026-b91b-470c-b906-9d2266b692da', name: 'Volcano Bay' },
  ];
  const [wxResult, ...schedResults] = await Promise.allSettled([
    httpGet('https://api.open-meteo.com/v1/forecast?latitude=28.5383&longitude=-81.3792&current=temperature_2m,apparent_temperature,weather_code&temperature_unit=fahrenheit&timezone=America%2FNew_York'),
    ...UOR_PARKS.map(p => httpGet(`https://api.themeparks.wiki/v1/entity/${p.id}/schedule`)),
  ]);
  let weather = null;
  if (wxResult.status === 'fulfilled') {
    const wx = wxResult.value;
    weather = { temp: Math.round(wx.current.temperature_2m), feels: Math.round(wx.current.apparent_temperature), icon: WX_CODE(wx.current.weather_code) };
  }
  const parkHours = UOR_PARKS.map((p, i) => {
    const sched = schedResults[i].status === 'fulfilled' ? schedResults[i].value : null;
    const op = (sched?.schedule || []).find(s => s.date === today && s.type === 'OPERATING');
    return { name: p.name, open: fmtTime(op?.openingTime), close: fmtTime(op?.closingTime) };
  });
  _parkCache = { weather, parkHours, fetchedAt: Date.now() };
  _parkCacheTs = Date.now();
  res.json(_parkCache);
});

// ── Admin announcements ────────────────────────────────────
app.get('/api/announcement', (_req, res) => {
  res.json(read(path.join(DATA, 'announcement.json'), { text: '', updatedAt: 0 }));
});
app.put('/api/announcement', adminAuth, (req, res) => {
  const ann = { text: (req.body.text || '').trim().slice(0, 500), updatedAt: Date.now() };
  write(path.join(DATA, 'announcement.json'), ann);
  res.json({ ok: true, ann });
});

// ── Change PIN ─────────────────────────────────────────────
app.post('/api/me/pin', auth, (req, res) => {
  const { currentPin, newPin } = req.body;
  if (!currentPin || !newPin || String(newPin).length !== 4) return res.status(400).json({ error: 'New PIN must be 4 digits' });
  const all = read(path.join(DATA, 'users.json'), []);
  const idx = all.findIndex(u => u.id === req.uid);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  if (all[idx].pinHash !== hashPin(String(currentPin))) return res.status(401).json({ error: 'Current PIN is wrong' });
  all[idx].pinHash = hashPin(String(newPin));
  write(path.join(DATA, 'users.json'), all);
  res.json({ ok: true });
});

// ── Time-off requests ─────────────────────────────────────
const TIMEOFF_FILE = path.join(DATA, 'time-off.json');

app.get('/api/time-off', auth, (req, res) => {
  res.json(read(TIMEOFF_FILE, []));
});

app.post('/api/time-off', auth, (req, res) => {
  const { date, note } = req.body;
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Invalid date' });
  const users = read(path.join(DATA, 'users.json'), []);
  const user  = users.find(u => u.id === req.uid);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const requests = read(TIMEOFF_FILE, []);
  if (requests.some(r => r.userId === req.uid && r.date === date))
    return res.status(409).json({ error: 'Already requested' });
  const entry = { id: Date.now(), userId: req.uid, userName: user.name, userEmoji: user.emoji, userColor: user.color, date, note: (note||'').trim().slice(0,200), ts: Date.now() };
  requests.push(entry);
  write(TIMEOFF_FILE, requests);
  res.json({ ok: true, entry });
});

app.delete('/api/time-off/:id', auth, (req, res) => {
  const requests = read(TIMEOFF_FILE, []);
  const idx = requests.findIndex(r => r.id === Number(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (requests[idx].userId !== req.uid) return res.status(403).json({ error: 'Not yours' });
  requests.splice(idx, 1);
  write(TIMEOFF_FILE, requests);
  res.json({ ok: true });
});

// ── Chat ──────────────────────────────────────────────────
const CHAT_FILE = path.join(DATA, 'chat.json');
const MAX_CHAT  = 500;

app.get('/api/chat', auth, (req, res) => {
  const since = parseInt(req.query.since) || 0;
  const msgs  = read(CHAT_FILE, []);
  res.json(since ? msgs.filter(m => m.ts > since) : msgs.slice(-100));
});

app.post('/api/chat', auth, (req, res) => {
  const text = (req.body.text || '').trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: 'Empty message' });
  const users = read(path.join(DATA, 'users.json'), []);
  const user  = users.find(u => u.id === req.uid);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const msgs = read(CHAT_FILE, []);
  const msg  = { id: Date.now(), userId: req.uid, userName: user.name, userEmoji: user.emoji, userColor: user.color, text, ts: Date.now() };
  msgs.push(msg);
  if (msgs.length > MAX_CHAT) msgs.splice(0, msgs.length - MAX_CHAT);
  write(CHAT_FILE, msgs);
  res.json({ ok: true, msg });
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
