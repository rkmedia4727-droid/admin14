const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const PORT = parseInt(process.env.PORT || '4000', 10);
const ADMIN_PIN = String(process.env.ADMIN_PIN || '123456');
const ADMIN_TOKEN_SECRET = String(process.env.ADMIN_TOKEN_SECRET || 'change-this-secret');

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DB_PATH = path.join(__dirname, 'license-db.json');

const defaultDb = {
  settings: {
    latestVersion: '1.0.0',
    forceUpdate: false,
    downloadUrl: '',
    updateMessage: 'New version available. Please download and install the latest version to continue.'
  },
  licenses: [],
  devices: [],
  heartbeats: [],
  ipCache: {}
};

function readDb() {
  try {
    if (!fs.existsSync(DB_PATH)) {
      fs.writeFileSync(DB_PATH, JSON.stringify(defaultDb, null, 2));
      return JSON.parse(JSON.stringify(defaultDb));
    }
    const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    db.settings = db.settings || defaultDb.settings;
    db.licenses = Array.isArray(db.licenses) ? db.licenses : [];
    db.devices = Array.isArray(db.devices) ? db.devices : [];
    db.heartbeats = Array.isArray(db.heartbeats) ? db.heartbeats : [];
    db.ipCache = db.ipCache || {};
    return db;
  } catch (e) {
    console.error('[DB ERROR]', e.message);
    return JSON.parse(JSON.stringify(defaultDb));
  }
}

function writeDb(db) {
  const tmp = DB_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_PATH);
}

function nowIso() { return new Date().toISOString(); }
function hashKey(key) {
  return crypto.createHash('sha256').update(String(key || '').trim()).digest('hex');
}

function hashAdminPin(pin) {
  return crypto.createHash('sha256').update(String(pin || '')).digest('hex');
}
function getAdminPinHash(db) {
  if (db && db.settings && db.settings.adminPinHash) return db.settings.adminPinHash;
  return hashAdminPin(ADMIN_PIN);
}
function verifyAdminPin(db, pin) {
  return hashAdminPin(pin) === getAdminPinHash(db);
}

function hashAdminPassword(password) {
  return crypto.createHash('sha256').update(String(password || '')).digest('hex');
}
function hasAdminPassword(db) {
  return !!(db && db.settings && db.settings.adminPasswordHash);
}
function verifyAdminPassword(db, password) {
  if (!hasAdminPassword(db)) return true; // first setup / backward compatible
  return hashAdminPassword(password) === db.settings.adminPasswordHash;
}
function getAllowedAdminFingerprints(db) {
  return (db && db.settings && Array.isArray(db.settings.adminFingerprints)) ? db.settings.adminFingerprints : [];
}
function hasFingerprintLock(db) {
  return getAllowedAdminFingerprints(db).length > 0;
}
function verifyAdminFingerprint(db, fingerprintHash) {
  const list = getAllowedAdminFingerprints(db);
  if (list.length === 0) return true; // not enabled yet
  return list.some(f => f.hash === fingerprintHash && f.enabled !== false);
}

function getAdminSecurityModes(db) {
  const s = (db && db.settings) ? db.settings : {};
  // Backward-compatible defaults: PIN required, password/fingerprint optional until admin enables them.
  return {
    requirePin: s.requireAdminPin !== false,
    requirePassword: s.requireAdminPassword === true,
    requireFingerprint: s.requireAdminFingerprint === true
  };
}
function publicAdminSecurityModes(db) {
  const modes = getAdminSecurityModes(db);
  return {
    ...modes,
    pinSet: true,
    passwordSet: hasAdminPassword(db),
    fingerprintSet: hasFingerprintLock(db)
  };
}

function publicAdminSecurity(db) {
  return {
    modes: publicAdminSecurityModes(db),
    passwordEnabled: hasAdminPassword(db),
    fingerprintEnabled: hasFingerprintLock(db),
    fingerprints: getAllowedAdminFingerprints(db).map(f => ({
      id: f.id,
      label: f.label || '',
      hashPreview: String(f.hash || '').slice(0, 12) + '...',
      createdAt: f.createdAt,
      lastUsedAt: f.lastUsedAt || '',
      enabled: f.enabled !== false
    }))
  };
}


function makeToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', ADMIN_TOKEN_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyToken(token) {
  try {
    const [body, sig] = String(token || '').split('.');
    const expected = crypto.createHmac('sha256', ADMIN_TOKEN_SECRET).update(body).digest('base64url');
    if (!body || !sig || sig !== expected) return null;
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch (e) { return null; }
}
function requireAdmin(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const payload = verifyToken(token);
  if (!payload || payload.role !== 'admin') return res.status(401).json({ ok: false, reason: 'UNAUTHORIZED' });
  next();
}
function getIp(req) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  let raw = xff || req.socket.remoteAddress || req.ip || '';

  raw = String(raw)
    .replace(/^::ffff:/, '')
    .replace(/^::1$/, '127.0.0.1')
    .trim();

  // Express/Windows/local network can sometimes return IPv6 or invalid IP text.
  // Keep local testing stable and prevent ip-api URL parser crashes.
  if (!raw || raw === 'localhost' || raw.includes(':')) return '127.0.0.1';

  // Strip accidental port suffix from IPv4, e.g. 127.0.0.1:51234
  const ipv4WithPort = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$/);
  if (ipv4WithPort) return ipv4WithPort[1];

  // Only allow clean IPv4 here. Everything else becomes local/unknown-safe.
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(raw)) return '127.0.0.1';

  return raw;
}
function versionLess(a, b) {
  const pa = String(a || '0').split('.').map(n => parseInt(n, 10) || 0);
  const pb = String(b || '0').split('.').map(n => parseInt(n, 10) || 0);
  const max = Math.max(pa.length, pb.length);
  for (let i = 0; i < max; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}
function randomLicense() {
  return 'INFOSY-' + crypto.randomBytes(3).toString('hex').toUpperCase() + '-' +
    crypto.randomBytes(3).toString('hex').toUpperCase() + '-' +
    crypto.randomBytes(3).toString('hex').toUpperCase();
}
function addDays(date, days) {
  const d = new Date(date);
  d.setDate(d.getDate() + Number(days || 0));
  return d.toISOString();
}
function safePublicLicense(lic) {
  return {
    id: lic.id,
    keyPreview: lic.keyPreview,
    customerName: lic.customerName || '',
    contact: lic.contact || '',
    note: lic.note || '',
    maxDevices: lic.maxDevices,
    expiresAt: lic.expiresAt,
    banned: !!lic.banned,
    createdAt: lic.createdAt,
    updatedAt: lic.updatedAt
  };
}
function devicePublic(d) {
  return {
    id: d.id,
    licenseId: d.licenseId,
    deviceHash: d.deviceHash,
    deviceLabel: d.deviceLabel || '',
    os: d.os || '',
    appVersion: d.appVersion || '',
    ip: d.ip || '',
    location: d.location || { country: 'Unknown', region: '', city: '', isp: '', timezone: '' },
    firstSeen: d.firstSeen,
    lastSeen: d.lastSeen,
    banned: !!d.banned,
    revoked: !!d.revoked
  };
}
function lookupIp(ip) {
  return new Promise((resolve) => {
    if (!ip || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.')) {
      return resolve({ country: 'Local', region: '', city: 'Localhost', isp: 'Local Network', timezone: '' });
    }
    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,regionName,city,isp,org,timezone,query`;
    const req = http.get(url, { timeout: 5000 }, (r) => {
      let data = '';
      r.on('data', c => data += c);
      r.on('end', () => {
        try {
          const j = JSON.parse(data);
          if (j.status === 'success') {
            return resolve({ country: j.country || 'Unknown', region: j.regionName || '', city: j.city || '', isp: j.isp || j.org || '', timezone: j.timezone || '' });
          }
        } catch(e) {}
        resolve({ country: 'Unknown', region: '', city: '', isp: '', timezone: '' });
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ country: 'Unknown', region: '', city: '', isp: '', timezone: '' }); });
    req.on('error', () => resolve({ country: 'Unknown', region: '', city: '', isp: '', timezone: '' }));
  });
}
async function getLocationForIp(db, ip) {
  db.ipCache = db.ipCache || {};

  try {
    if (!ip || ip === '127.0.0.1' || ip === 'localhost') {
      return { country: 'Local', region: '', city: 'Localhost', isp: 'Local Network', timezone: '' };
    }

    // Never send malformed/IPv6 values into ip-api URL construction.
    if (String(ip).includes(':') || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(ip))) {
      return { country: 'Unknown', region: '', city: '', isp: '', timezone: '' };
    }

    const cached = db.ipCache[ip];
    const maxAge = 1000 * 60 * 60 * 24;
    if (cached && cached.lookupAt && Date.now() - new Date(cached.lookupAt).getTime() < maxAge) return cached.location;

    const location = await lookupIp(ip);
    db.ipCache[ip] = { lookupAt: nowIso(), location };
    return location;
  } catch (e) {
    console.error('[IP LOOKUP ERROR]', e.message);
    return { country: 'Unknown', region: '', city: '', isp: '', timezone: '' };
  }
}
function cleanupHeartbeats(db) {
  const keepAfter = Date.now() - 1000 * 60 * 60 * 24 * 14;
  db.heartbeats = db.heartbeats.filter(h => new Date(h.at).getTime() >= keepAfter);
}
function usageStats(db) {
  const since = Date.now() - 1000 * 60 * 60 * 24;
  const byLicense = {};
  const byDevice = {};
  db.heartbeats
    .filter(h => new Date(h.at).getTime() >= since)
    .forEach(h => {
      const minutes = Math.max(1, Math.min(5, Number(h.minutes || 1)));
      byLicense[h.licenseId] = (byLicense[h.licenseId] || 0) + minutes;
      byDevice[h.deviceId] = (byDevice[h.deviceId] || 0) + minutes;
    });
  return { byLicense, byDevice };
}

app.post('/api/admin/login', (req, res) => {
  const db = readDb();
  const pin = String(req.body.pin || '');
  const password = String(req.body.password || '');
  const fingerprintHash = String(req.body.fingerprintHash || '');
  const modes = getAdminSecurityModes(db);

  if (modes.requirePin && !verifyAdminPin(db, pin)) {
    return res.status(401).json({ ok: false, reason: 'INVALID_PIN' });
  }
  if (modes.requirePassword) {
    if (!hasAdminPassword(db)) {
      return res.status(401).json({ ok: false, reason: 'PASSWORD_NOT_SET' });
    }
    if (!verifyAdminPassword(db, password)) {
      return res.status(401).json({ ok: false, reason: 'INVALID_PASSWORD' });
    }
  }
  if (modes.requireFingerprint) {
    if (!hasFingerprintLock(db)) {
      return res.status(401).json({ ok: false, reason: 'FINGERPRINT_NOT_SET' });
    }
    if (!verifyAdminFingerprint(db, fingerprintHash)) {
      return res.status(401).json({ ok: false, reason: 'FINGERPRINT_NOT_ALLOWED' });
    }
  }

  const matched = getAllowedAdminFingerprints(db).find(f => f.hash === fingerprintHash);
  if (matched) matched.lastUsedAt = nowIso();
  writeDb(db);

  res.json({ ok: true, token: makeToken({ role: 'admin', at: Date.now() }), security: publicAdminSecurity(db) });
});


app.post('/api/admin/change-pin', requireAdmin, (req, res) => {
  const currentPin = String(req.body.currentPin || '');
  const newPin = String(req.body.newPin || '');
  if (newPin.length < 4) {
    return res.status(400).json({ ok: false, reason: 'PIN_TOO_SHORT' });
  }
  const db = readDb();
  if (!verifyAdminPin(db, currentPin)) {
    return res.status(403).json({ ok: false, reason: 'CURRENT_PIN_WRONG' });
  }
  db.settings = db.settings || {};
  db.settings.adminPinHash = hashAdminPin(newPin);
  db.settings.adminPinChangedAt = nowIso();
  writeDb(db);
  res.json({ ok: true, message: 'Admin PIN changed successfully' });
});

app.get('/api/admin/state', requireAdmin, (req, res) => {
  const db = readDb();
  cleanupHeartbeats(db);
  writeDb(db);
  const usage = usageStats(db);
  res.json({
    ok: true,
    settings: db.settings,
    security: publicAdminSecurity(db),
    licenses: db.licenses.map(l => ({
      ...safePublicLicense(l),
      devices: db.devices.filter(d => d.licenseId === l.id).map(devicePublic),
      usage24hMinutes: usage.byLicense[l.id] || 0
    })),
    devices: db.devices.map(d => ({ ...devicePublic(d), usage24hMinutes: usage.byDevice[d.id] || 0 })),
    usage24h: {
      licenses: usage.byLicense,
      devices: usage.byDevice,
      totalMinutes: Object.values(usage.byLicense).reduce((a,b)=>a+b,0)
    }
  });
});


app.post('/api/admin/change-password', requireAdmin, (req, res) => {
  const db = readDb();
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');
  if (newPassword.length < 6) {
    return res.status(400).json({ ok: false, reason: 'PASSWORD_TOO_SHORT' });
  }
  if (hasAdminPassword(db) && !verifyAdminPassword(db, currentPassword)) {
    return res.status(403).json({ ok: false, reason: 'CURRENT_PASSWORD_WRONG' });
  }
  db.settings = db.settings || {};
  db.settings.adminPasswordHash = hashAdminPassword(newPassword);
  db.settings.adminPasswordChangedAt = nowIso();
  writeDb(db);
  res.json({ ok: true, message: 'Admin password changed successfully', security: publicAdminSecurity(db) });
});

app.post('/api/admin/register-fingerprint', requireAdmin, (req, res) => {
  const db = readDb();
  const fingerprintHash = String(req.body.fingerprintHash || '');
  const label = String(req.body.label || 'Admin Device');
  if (!fingerprintHash || fingerprintHash.length < 20) {
    return res.status(400).json({ ok: false, reason: 'INVALID_FINGERPRINT' });
  }
  db.settings = db.settings || {};
  db.settings.adminFingerprints = Array.isArray(db.settings.adminFingerprints) ? db.settings.adminFingerprints : [];
  const existing = db.settings.adminFingerprints.find(f => f.hash === fingerprintHash);
  if (existing) {
    existing.label = label || existing.label;
    existing.enabled = true;
    existing.lastUsedAt = nowIso();
  } else {
    db.settings.adminFingerprints.push({
      id: crypto.randomUUID(),
      label,
      hash: fingerprintHash,
      createdAt: nowIso(),
      lastUsedAt: nowIso(),
      enabled: true
    });
  }
  writeDb(db);
  res.json({ ok: true, security: publicAdminSecurity(db) });
});

app.delete('/api/admin/fingerprints/:id', requireAdmin, (req, res) => {
  const db = readDb();
  db.settings = db.settings || {};
  db.settings.adminFingerprints = Array.isArray(db.settings.adminFingerprints) ? db.settings.adminFingerprints : [];
  const before = db.settings.adminFingerprints.length;
  db.settings.adminFingerprints = db.settings.adminFingerprints.filter(f => f.id !== req.params.id);
  writeDb(db);
  res.json({ ok: true, deleted: before !== db.settings.adminFingerprints.length, security: publicAdminSecurity(db) });
});

app.get('/api/admin/security', requireAdmin, (req, res) => {
  const db = readDb();
  res.json({ ok: true, security: publicAdminSecurity(db) });
});



app.post('/api/admin/security-modes', requireAdmin, (req, res) => {
  const db = readDb();
  db.settings = db.settings || {};
  const requirePin = req.body.requirePin !== false;
  const requirePassword = req.body.requirePassword === true;
  const requireFingerprint = req.body.requireFingerprint === true;

  if (requirePassword && !hasAdminPassword(db)) {
    return res.status(400).json({ ok: false, reason: 'SET_PASSWORD_FIRST' });
  }
  if (requireFingerprint && !hasFingerprintLock(db)) {
    return res.status(400).json({ ok: false, reason: 'REGISTER_FINGERPRINT_FIRST' });
  }

  db.settings.requireAdminPin = requirePin;
  db.settings.requireAdminPassword = requirePassword;
  db.settings.requireAdminFingerprint = requireFingerprint;
  db.settings.adminSecurityModesUpdatedAt = nowIso();
  writeDb(db);
  res.json({ ok: true, security: publicAdminSecurity(db) });
});

app.post('/api/admin/update-settings', requireAdmin, (req, res) => {
  const db = readDb();
  db.settings = {
    latestVersion: String(req.body.latestVersion || db.settings.latestVersion || '1.0.0'),
    forceUpdate: !!req.body.forceUpdate,
    downloadUrl: String(req.body.downloadUrl || ''),
    updateMessage: String(req.body.updateMessage || 'New version available.')
  };
  writeDb(db);
  res.json({ ok: true, settings: db.settings });
});

app.post('/api/admin/licenses', requireAdmin, (req, res) => {
  const db = readDb();
  const key = String(req.body.key || '').trim() || randomLicense();
  const days = Math.max(1, parseInt(req.body.days || '30', 10));
  const id = crypto.randomUUID();
  const lic = {
    id,
    keyHash: hashKey(key),
    keyPreview: key.slice(0, 8) + '...' + key.slice(-4),
    customerName: String(req.body.customerName || ''),
    contact: String(req.body.contact || ''),
    note: String(req.body.note || ''),
    maxDevices: Math.max(1, parseInt(req.body.maxDevices || '1', 10)),
    expiresAt: addDays(new Date(), days),
    banned: false,
    createdAt: nowIso(),
    updatedAt: nowIso()
  };
  db.licenses.push(lic);
  writeDb(db);
  res.json({ ok: true, licenseKey: key, license: safePublicLicense(lic) });
});

app.patch('/api/admin/licenses/:id', requireAdmin, (req, res) => {
  const db = readDb();
  const lic = db.licenses.find(l => l.id === req.params.id);
  if (!lic) return res.status(404).json({ ok: false, reason: 'NOT_FOUND' });
  if (req.body.customerName !== undefined) lic.customerName = String(req.body.customerName || '');
  if (req.body.contact !== undefined) lic.contact = String(req.body.contact || '');
  if (req.body.note !== undefined) lic.note = String(req.body.note || '');
  if (req.body.maxDevices !== undefined) lic.maxDevices = Math.max(1, parseInt(req.body.maxDevices, 10) || 1);
  if (req.body.expiresAt !== undefined) lic.expiresAt = new Date(req.body.expiresAt).toISOString();
  if (req.body.addDays !== undefined) lic.expiresAt = addDays(lic.expiresAt || new Date(), parseInt(req.body.addDays, 10) || 0);
  if (req.body.banned !== undefined) lic.banned = !!req.body.banned;
  lic.updatedAt = nowIso();
  writeDb(db);
  res.json({ ok: true, license: safePublicLicense(lic) });
});

app.delete('/api/admin/licenses/:id', requireAdmin, (req, res) => {
  const db = readDb();
  const before = db.licenses.length;
  db.licenses = db.licenses.filter(l => l.id !== req.params.id);
  db.devices = db.devices.filter(d => d.licenseId !== req.params.id);
  db.heartbeats = db.heartbeats.filter(h => h.licenseId !== req.params.id);
  writeDb(db);
  res.json({ ok: true, deleted: before !== db.licenses.length });
});

app.patch('/api/admin/devices/:id', requireAdmin, (req, res) => {
  const db = readDb();
  const dev = db.devices.find(d => d.id === req.params.id);
  if (!dev) return res.status(404).json({ ok: false, reason: 'NOT_FOUND' });
  if (req.body.banned !== undefined) dev.banned = !!req.body.banned;
  if (req.body.revoked !== undefined) dev.revoked = !!req.body.revoked;
  if (req.body.deviceLabel !== undefined) dev.deviceLabel = String(req.body.deviceLabel || '');
  dev.updatedAt = nowIso();
  writeDb(db);
  res.json({ ok: true, device: devicePublic(dev) });
});

app.delete('/api/admin/devices/:id', requireAdmin, (req, res) => {
  const db = readDb();
  const before = db.devices.length;
  db.devices = db.devices.filter(d => d.id !== req.params.id);
  db.heartbeats = db.heartbeats.filter(h => h.deviceId !== req.params.id);
  writeDb(db);
  res.json({ ok: true, deleted: before !== db.devices.length });
});

async function activateOrVerify(req, res, mode) {
  const db = readDb();
  cleanupHeartbeats(db);

  const appVersion = String(req.body.appVersion || '0.0.0');
  if (db.settings.forceUpdate && versionLess(appVersion, db.settings.latestVersion)) {
    return res.json({
      ok: false,
      reason: 'UPDATE_REQUIRED',
      latestVersion: db.settings.latestVersion,
      downloadUrl: db.settings.downloadUrl,
      updateMessage: db.settings.updateMessage
    });
  }

  const licenseKey = String(req.body.licenseKey || '').trim();
  const deviceHash = String(req.body.deviceHash || '').trim();
  if (!licenseKey || !deviceHash) return res.status(400).json({ ok: false, reason: 'MISSING_LICENSE_OR_DEVICE' });

  const lic = db.licenses.find(l => l.keyHash === hashKey(licenseKey));
  if (!lic) return res.json({ ok: false, reason: 'INVALID_LICENSE' });
  if (lic.banned) return res.json({ ok: false, reason: 'LICENSE_BANNED' });
  if (new Date(lic.expiresAt).getTime() < Date.now()) return res.json({ ok: false, reason: 'LICENSE_EXPIRED', expiresAt: lic.expiresAt });

  let dev = db.devices.find(d => d.licenseId === lic.id && d.deviceHash === deviceHash);
  const activeDevices = db.devices.filter(d => d.licenseId === lic.id && !d.revoked && !d.banned);

  if (!dev && activeDevices.length >= lic.maxDevices) {
    return res.json({ ok: false, reason: 'DEVICE_LIMIT_REACHED', maxDevices: lic.maxDevices, activeDevices: activeDevices.length });
  }

  const ip = getIp(req);
  const location = await getLocationForIp(db, ip);

  if (!dev) {
    dev = {
      id: crypto.randomUUID(),
      licenseId: lic.id,
      deviceHash,
      deviceLabel: String(req.body.deviceLabel || ''),
      os: String(req.body.os || ''),
      appVersion,
      ip,
      location,
      firstSeen: nowIso(),
      lastSeen: nowIso(),
      banned: false,
      revoked: false
    };
    db.devices.push(dev);
  } else {
    if (dev.banned) return res.json({ ok: false, reason: 'DEVICE_BANNED' });
    if (dev.revoked) return res.json({ ok: false, reason: 'DEVICE_REVOKED' });
    dev.ip = ip;
    dev.location = location;
    dev.os = String(req.body.os || dev.os || '');
    dev.appVersion = appVersion;
    dev.deviceLabel = String(req.body.deviceLabel || dev.deviceLabel || '');
    dev.lastSeen = nowIso();
  }

  writeDb(db);
  res.json({
    ok: true,
    license: { expiresAt: lic.expiresAt, maxDevices: lic.maxDevices, customerName: lic.customerName || '' },
    device: { id: dev.id, lastSeen: dev.lastSeen },
    settings: db.settings
  });
}

app.post('/api/license/activate', async (req, res) => {
  try {
    await activateOrVerify(req, res, 'activate');
  } catch (e) {
    console.error('[LICENSE ACTIVATE ERROR]', e);
    res.status(500).json({
      ok: false,
      reason: 'LICENSE_SERVER_INTERNAL_ERROR',
      error: e.message
    });
  }
});

app.post('/api/license/verify', async (req, res) => {
  try {
    await activateOrVerify(req, res, 'verify');
  } catch (e) {
    console.error('[LICENSE VERIFY ERROR]', e);
    res.status(500).json({
      ok: false,
      reason: 'LICENSE_SERVER_INTERNAL_ERROR',
      error: e.message
    });
  }
});

app.post('/api/license/heartbeat', async (req, res) => {
  try {
    const db = readDb();
    db.heartbeats = Array.isArray(db.heartbeats) ? db.heartbeats : [];
    const licenseKey = String(req.body.licenseKey || '').trim();
    const deviceHash = String(req.body.deviceHash || '').trim();
    const lic = db.licenses.find(l => l.keyHash === hashKey(licenseKey));
    if (!lic) return res.json({ ok: false, reason: 'INVALID_LICENSE' });
    const dev = db.devices.find(d => d.licenseId === lic.id && d.deviceHash === deviceHash);
    if (!dev) return res.json({ ok: false, reason: 'DEVICE_NOT_ACTIVATED' });
    if (lic.banned) return res.json({ ok: false, reason: 'LICENSE_BANNED' });
    if (dev.banned) return res.json({ ok: false, reason: 'DEVICE_BANNED' });
    if (dev.revoked) return res.json({ ok: false, reason: 'DEVICE_REVOKED' });
    const ip = getIp(req);
    dev.ip = ip;
    dev.location = await getLocationForIp(db, ip);
    dev.lastSeen = nowIso();
    const minutes = Math.max(1, Math.min(5, parseInt(req.body.minutes || '1', 10)));
    db.heartbeats.push({ at: nowIso(), licenseId: lic.id, deviceId: dev.id, minutes });
    cleanupHeartbeats(db);
    writeDb(db);
    res.json({ ok: true });
  } catch (e) {
    console.error('[LICENSE HEARTBEAT ERROR]', e);
    res.status(500).json({ ok: false, reason: 'LICENSE_HEARTBEAT_INTERNAL_ERROR', error: e.message });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

// Keep API errors JSON-only, so client apps never receive Express HTML error pages.
app.use('/api', (req, res) => {
  res.status(404).json({ ok: false, reason: 'API_ROUTE_NOT_FOUND', path: req.path });
});

app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err);
  if (req.path && req.path.startsWith('/api')) {
    return res.status(500).json({ ok: false, reason: 'SERVER_INTERNAL_ERROR', error: err.message });
  }
  next(err);
});

app.listen(PORT, () => {
  console.log(`[LICENSE SERVER] Running at http://127.0.0.1:${PORT}`);
});
