const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const sharp = require('sharp');
const crypto = require('crypto');

// TOTP Helpers (Google Authenticator RFC 6238)
function base32Decode(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  let hex = '';
  const cleaned = base32.replace(/=+$/, '').toUpperCase();
  for (let i = 0; i < cleaned.length; i++) {
    const val = alphabet.indexOf(cleaned.charAt(i));
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    const chunk = bits.substr(i, 8);
    hex += parseInt(chunk, 2).toString(16).padStart(2, '0');
  }
  return Buffer.from(hex, 'hex');
}

function generateBase32Secret(length = 16) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const randomBytes = crypto.randomBytes(length);
  let secret = '';
  for (let i = 0; i < length; i++) {
    secret += alphabet[randomBytes[i] % alphabet.length];
  }
  return secret;
}

function getTOTP(secret, time = Math.floor(Date.now() / 1000)) {
  const timeStep = 30;
  const counter = Math.floor(time / timeStep);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const key = base32Decode(secret);
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24 |
                (hmac[offset + 1] & 0xff) << 16 |
                (hmac[offset + 2] & 0xff) << 8 |
                (hmac[offset + 3] & 0xff)) % 1000000;
  return code.toString().padStart(6, '0');
}

function verifyTOTP(token, secret) {
  if (!token || !secret) return false;
  const now = Math.floor(Date.now() / 1000);
  for (let win = -1; win <= 1; win++) {
    if (getTOTP(secret, now + win * 30) === token.trim()) return true;
  }
  return false;
}

const app = express();
const PORT = process.env.PORT || 3001;

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const IMAGES_FILE = path.join(DATA_DIR, 'images.json');

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const DEFAULT_PUBLYTICS_SCRIPT = `<script defer data-domain="k.infucar.com/JFwuP9" src="https://api.publytics.net/js/script.manual.min.js"></script>\n<script>\n    window.publytics = window.publytics || function() { (window.publytics.q = window.publytics.q || []).push(arguments) };\n    publytics('pageview');\n</script>`;

// Initial files if missing
if (!fs.existsSync(CONFIG_FILE)) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({
    targetUrl: "https://www.google.com",
    autoRedirectSeconds: 0,
    publyticsCode: DEFAULT_PUBLYTICS_SCRIPT,
    siteTitle: "Trending Stories & Viral Content",
    headerText: "🔥 Trending Today",
    footerText: "© 2026 Infucar Media. All rights reserved.",
    adminPassword: "admin"
  }, null, 2));
}

if (!fs.existsSync(IMAGES_FILE)) {
  fs.writeFileSync(IMAGES_FILE, JSON.stringify([], null, 2));
}

// Helpers
function getConfig() {
  try {
    const cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    if (!cfg.publyticsCode) cfg.publyticsCode = DEFAULT_PUBLYTICS_SCRIPT;
    return cfg;
  } catch (e) {
    return {
      targetUrl: "https://www.google.com",
      autoRedirectSeconds: 0,
      publyticsCode: DEFAULT_PUBLYTICS_SCRIPT,
      siteTitle: "Trending Stories & Viral Content",
      headerText: "🔥 Trending Today",
      footerText: "© 2026 Infucar Media. All rights reserved.",
      adminPassword: "admin"
    };
  }
}

function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

function getImages() {
  try {
    return JSON.parse(fs.readFileSync(IMAGES_FILE, 'utf8'));
  } catch (e) {
    return [];
  }
}

function saveImages(imgs) {
  fs.writeFileSync(IMAGES_FILE, JSON.stringify(imgs, null, 2));
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'infucar_landing_secret_key_2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Storage configuration for Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueName = `img_${Date.now()}_${Math.random().toString(36).substring(2, 8)}${ext}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB max
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Admin Authentication Middleware
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  return res.status(401).json({ success: false, error: 'Unauthorized. Please login.' });
}

// Serve Static Files with 30-day Browser Caching for Instant Load
app.use('/uploads', express.static(UPLOADS_DIR, {
  maxAge: '30d',
  immutable: true,
  etag: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// Social Media Bot / Crawler Detection
// Facebook, WhatsApp, Telegram, Google bots will get full HTML with OG tags — NO redirect
const SOCIAL_BOTS = [
  'facebookexternalhit', 'facebot', 'whatsapp', 'telegrambot',
  'twitterbot', 'linkedinbot', 'slackbot', 'discordbot',
  'googlebot', 'bingbot', 'yandexbot', 'duckduckbot',
  'applebot', 'ia_archiver', 'scrapy', 'curl', 'wget',
  'python-requests', 'axios', 'go-http', 'java/'
];

function isSocialBot(userAgent) {
  if (!userAgent) return false;
  const ua = userAgent.toLowerCase();
  return SOCIAL_BOTS.some(bot => ua.includes(bot));
}

// Serve index.html directly for bots (with full OG meta tags, no JS redirect)
app.get('/', (req, res, next) => {
  const ua = req.headers['user-agent'] || '';
  if (isSocialBot(ua)) {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
  next();
});


app.get('/api/public-settings', (req, res) => {
  const config = getConfig();
  const images = getImages();
  res.json({
    success: true,
    targetUrl: config.targetUrl,
    autoRedirectSeconds: config.autoRedirectSeconds,
    publyticsCode: config.publyticsCode || '',
    siteTitle: config.siteTitle || 'Trending Stories & Viral Content',
    headerText: config.headerText || '🔥 Trending Today',
    footerText: config.footerText || '© 2026 Infucar Media. All rights reserved.',
    images: images
  });
});

// Public 2FA Status
app.get('/api/2fa/status', (req, res) => {
  const config = getConfig();
  const isEnabled = !!(config.totpSecret && config.totpSecret.length >= 10);
  res.json({ isEnabled });
});

// Protected 2FA Setup API (Requires logged-in admin session)
app.get('/api/admin/2fa/setup', requireAdmin, (req, res) => {
  const config = getConfig();
  const isEnabled = !!(config.totpSecret && config.totpSecret.length >= 10);

  if (!req.session.tempTotpSecret) {
    req.session.tempTotpSecret = generateBase32Secret(16);
  }
  const secret = req.session.tempTotpSecret;
  const otpauthUrl = `otpauth://totp/Infucar%20Admin:k.infucar.com?secret=${secret}&issuer=Infucar`;
  const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(otpauthUrl)}`;

  return res.json({
    isEnabled: isEnabled,
    secret: secret,
    qrCodeUrl: qrCodeUrl
  });
});

app.post('/api/admin/2fa/enable', requireAdmin, (req, res) => {
  const { code, secret } = req.body;
  const config = getConfig();

  if (!code || code.trim().length !== 6) {
    return res.status(400).json({ success: false, error: 'Please enter a valid 6-digit code.' });
  }

  const setupSecret = secret || req.session.tempTotpSecret;
  if (!setupSecret) {
    return res.status(400).json({ success: false, error: 'Setup secret not found. Please refresh page.' });
  }

  if (verifyTOTP(code, setupSecret)) {
    config.totpSecret = setupSecret;
    saveConfig(config);
    delete req.session.tempTotpSecret;
    return res.json({ success: true, message: 'Google Authenticator 2FA enabled successfully!' });
  }

  return res.status(400).json({ success: false, error: 'Invalid 6-digit code. Check your Google Authenticator app.' });
});

app.post('/api/admin/2fa/disable', requireAdmin, (req, res) => {
  const config = getConfig();
  delete config.totpSecret;
  saveConfig(config);
  res.json({ success: true, message: 'Google Authenticator 2FA disabled.' });
});

// Secure Login Handler (Password + 2FA Code if enabled)
app.post('/api/login', (req, res) => {
  const { password, code } = req.body;
  const config = getConfig();
  const is2FAEnabled = !!(config.totpSecret && config.totpSecret.length >= 10);

  // 1. Verify Password
  if (!password || password !== config.adminPassword) {
    return res.status(401).json({ success: false, error: 'Invalid password' });
  }

  // 2. If 2FA is enabled, verify TOTP 6-digit code
  if (is2FAEnabled) {
    if (!code || code.trim().length !== 6) {
      return res.status(401).json({ success: false, error: 'Google Authenticator 6-digit code required.', requires2FA: true });
    }

    if (!verifyTOTP(code, config.totpSecret)) {
      return res.status(401).json({ success: false, error: 'Invalid 6-digit Google Authenticator code.', requires2FA: true });
    }
  }

  req.session.isAdmin = true;
  return res.json({ success: true, message: 'Logged in successfully' });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true, message: 'Logged out' });
});

app.get('/api/auth-check', (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.isAdmin) });
});

// Admin API Routes
app.get('/api/admin/config', requireAdmin, (req, res) => {
  const config = getConfig();
  const { adminPassword, ...safeConfig } = config;
  res.json({ success: true, config: safeConfig });
});

app.post('/api/admin/config', requireAdmin, (req, res) => {
  const { targetUrl, autoRedirectSeconds, publyticsCode, siteTitle, headerText, footerText, newPassword } = req.body;
  const config = getConfig();

  if (targetUrl !== undefined) config.targetUrl = targetUrl;
  if (autoRedirectSeconds !== undefined) config.autoRedirectSeconds = parseInt(autoRedirectSeconds, 10) || 0;
  if (publyticsCode !== undefined) config.publyticsCode = publyticsCode;
  if (siteTitle !== undefined) config.siteTitle = siteTitle.trim();
  if (headerText !== undefined) config.headerText = headerText.trim();
  if (footerText !== undefined) config.footerText = footerText.trim();
  if (newPassword && newPassword.trim().length > 0) config.adminPassword = newPassword.trim();

  saveConfig(config);
  res.json({ success: true, message: 'Settings saved successfully' });
});

app.get('/api/admin/images', requireAdmin, (req, res) => {
  const images = getImages();
  res.json({ success: true, images });
});

app.post('/api/admin/upload', requireAdmin, upload.array('images', 50), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ success: false, error: 'No image files uploaded.' });
    }

    const singleTargetUrl = req.body.targetUrl || "";
    const singleTimerSeconds = parseInt(req.body.timerSeconds, 10) || 0;
    const currentImages = getImages();
    const newItems = [];

    for (let idx = 0; idx < req.files.length; idx++) {
      const file = req.files[idx];
      const rawPath = file.path;
      const webpFilename = `opt_${Date.now()}_${Math.random().toString(36).substring(2, 6)}.webp`;
      const webpPath = path.join(UPLOADS_DIR, webpFilename);

      let finalFilename = file.filename;
      try {
        await sharp(rawPath)
          .resize(540, 960, { fit: 'cover' }) // 9:16 vertical TikTok resolution
          .webp({ quality: 75 })
          .toFile(webpPath);
        try { fs.unlinkSync(rawPath); } catch(e){}
        finalFilename = webpFilename;
      } catch(err) {
        console.error('Sharp compression error:', err);
      }

      newItems.push({
        id: `img_${Date.now()}__${Math.random().toString(36).substring(2, 6)}`,
        url: `/uploads/${finalFilename}`,
        filename: finalFilename,
        targetUrl: singleTargetUrl ? singleTargetUrl.trim() : "",
        timerSeconds: singleTimerSeconds,
        order: currentImages.length + idx,
        createdAt: new Date().toISOString()
      });
    }

    const updated = [...currentImages, ...newItems];
    saveImages(updated);

    res.json({ success: true, message: `${newItems.length} image(s) uploaded`, images: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/admin/images/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  let images = getImages();
  const target = images.find(img => img.id === id);

  if (target) {
    const filePath = path.join(UPLOADS_DIR, target.filename);
    if (fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch(e){}
    }
    images = images.filter(img => img.id !== id);
    saveImages(images);
  }

  res.json({ success: true, message: 'Image deleted', images });
});

app.post('/api/admin/images/reorder', requireAdmin, (req, res) => {
  const { orderList } = req.body;
  if (!Array.isArray(orderList)) {
    return res.status(400).json({ success: false, error: 'Invalid order list' });
  }

  let images = getImages();
  const imageMap = new Map(images.map(img => [img.id, img]));
  const reordered = [];

  orderList.forEach((id, index) => {
    if (imageMap.has(id)) {
      const img = imageMap.get(id);
      img.order = index;
      reordered.push(img);
      imageMap.delete(id);
    }
  });

  imageMap.forEach((img) => reordered.push(img));

  saveImages(reordered);
  res.json({ success: true, message: 'Image order updated', images: reordered });
});

app.post('/api/admin/images/update', requireAdmin, (req, res) => {
  const { id, targetUrl, timerSeconds, order } = req.body;
  let images = getImages();
  const img = images.find(i => i.id === id);
  if (img) {
    if (targetUrl !== undefined) img.targetUrl = targetUrl.trim();
    if (timerSeconds !== undefined) img.timerSeconds = parseInt(timerSeconds, 10) || 0;
    if (order !== undefined) img.order = parseInt(order, 10) || 0;

    images.sort((a, b) => (a.order || 0) - (b.order || 0));
    saveImages(images);
    return res.json({ success: true, message: 'Image updated', images });
  }
  return res.status(404).json({ success: false, error: 'Image not found' });
});

// Fallback to index.html for root, admin.html for /admin
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Infucar Landing Page running on port ${PORT}`);
});
