const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const IMAGES_FILE = path.join(DATA_DIR, 'images.json');

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Initial files if missing
if (!fs.existsSync(CONFIG_FILE)) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({
    targetUrl: "https://www.google.com",
    autoRedirectSeconds: 0,
    publyticsCode: "",
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
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch (e) {
    return {
      targetUrl: "https://www.google.com",
      autoRedirectSeconds: 0,
      publyticsCode: "",
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

// Serve Static Files
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(path.join(__dirname, 'public')));

// Public Routes
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

// Admin Auth Routes
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  const config = getConfig();
  
  if (password === config.adminPassword) {
    req.session.isAdmin = true;
    return res.json({ success: true, message: 'Logged in successfully' });
  }
  
  return res.status(401).json({ success: false, error: 'Invalid password' });
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

app.post('/api/admin/upload', requireAdmin, upload.array('images', 50), (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ success: false, error: 'No image files uploaded.' });
    }

    const singleTargetUrl = req.body.targetUrl || "";
    const currentImages = getImages();
    const newItems = req.files.map((file, idx) => ({
      id: `img_${Date.now()}__${Math.random().toString(36).substring(2, 6)}`,
      url: `/uploads/${file.filename}`,
      filename: file.filename,
      targetUrl: singleTargetUrl ? singleTargetUrl.trim() : "",
      order: currentImages.length + idx,
      createdAt: new Date().toISOString()
    }));

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
  const { id, targetUrl, order } = req.body;
  let images = getImages();
  const img = images.find(i => i.id === id);
  if (img) {
    if (targetUrl !== undefined) img.targetUrl = targetUrl.trim();
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
