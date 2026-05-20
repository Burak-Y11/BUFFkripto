'use strict';

require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit    = require('express-rate-limit');
const Database     = require('better-sqlite3');
const path         = require('path');

const app  = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET     = process.env.JWT_SECRET;
const GROQ_API_KEY   = process.env.GROQ_API_KEY;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5500';
const IS_PROD        = process.env.NODE_ENV === 'production';

// ─── SQLite Veritabanı ────────────────────────────────────────────────────────
const DB_PATH = path.join(__dirname, 'buff.db');
const db = new Database(DB_PATH);

// Tablo oluştur (yoksa)
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// Hazır sorgular
const stmtFindUser   = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE');
const stmtInsertUser = db.prepare(
  'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
);

console.log(`✅ SQLite veritabanı bağlandı: ${DB_PATH}`);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
    origin: ALLOWED_ORIGIN,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
    credentials: true,   // Cookie'lerin karşı tarafa geçmesi için zorunlu
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// ─── Rate Limiters ────────────────────────────────────────────────────────────

// Login: IP başına 15 dakikada maks 10 deneme
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Çok fazla giriş denemesi. Lütfen 15 dakika sonra tekrar deneyin.' },
});

// Register: IP başına 1 saatte maks 5 kayıt
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Çok fazla kayıt isteği. Lütfen 1 saat sonra tekrar deneyin.' },
});

// Analiz: IP başına dakikada maks 5 istek
const analyzeLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Çok fazla analiz isteği. Lütfen 1 dakika bekleyin.' },
});

// ─── Yardımcı: Cookie seçenekleri ────────────────────────────────────────────
function cookieOptions() {
    return {
        httpOnly : true,          // JS tarafından okunamaz → XSS koruması
        secure   : IS_PROD,       // Prod'da HTTPS zorunlu, dev'de false
        sameSite : 'strict',      // CSRF koruması
        maxAge   : 7 * 24 * 60 * 60 * 1000, // 7 gün (ms)
        path     : '/',
    };
}

// ─── Yardımcı: JWT Doğrulama (Cookie üzerinden) ───────────────────────────────
function requireAuth(req, res, next) {
    const token = req.cookies?.buff_token;
    if (!token) {
        return res.status(401).json({ error: 'Oturum bulunamadı. Lütfen giriş yapın.' });
    }
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.clearCookie('buff_token');
        return res.status(401).json({ error: 'Oturum süresi dolmuş. Lütfen tekrar giriş yapın.' });
    }
}

// ─── AUTH: Kayıt ─────────────────────────────────────────────────────────────
app.post('/api/auth/register', registerLimiter, async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password)
            return res.status(400).json({ error: 'Ad, e-posta ve şifre zorunludur.' });
        if (typeof email !== 'string' || !email.includes('@'))
            return res.status(400).json({ error: 'Geçerli bir e-posta adresi girin.' });
        if (typeof password !== 'string' || password.length < 8)
            return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır.' });

        // Mevcut kullanıcı kontrolü (senkron SQLite)
        const existing = stmtFindUser.get(email);
        if (existing)
            return res.status(409).json({ error: 'Bu e-posta adresi zaten kayıtlı.' });

        const passwordHash = await bcrypt.hash(password, 12);
        stmtInsertUser.run(name.trim(), email.toLowerCase(), passwordHash);

        // HttpOnly Cookie olarak JWT set et
        const token = jwt.sign({ email: email.toLowerCase(), name }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('buff_token', token, cookieOptions());

        res.status(201).json({ message: 'Kayıt başarılı.', name });
    } catch (err) {
        console.error('[Register Error]', err.message);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// ─── AUTH: Giriş ─────────────────────────────────────────────────────────────
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password)
            return res.status(400).json({ error: 'E-posta ve şifre zorunludur.' });

        const user = stmtFindUser.get(email);

        // Kullanıcı bulunamasa bile sabit süreli hash ile timing attack engelle
        const hashToCheck = user?.password_hash || '$2a$12$invalidhashplaceholder00000000000000000000';
        const isMatch = await bcrypt.compare(password, hashToCheck);

        if (!user || !isMatch)
            return res.status(401).json({ error: 'E-posta veya şifre hatalı.' });

        const token = jwt.sign({ email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('buff_token', token, cookieOptions());

        res.json({ message: 'Giriş başarılı.', name: user.name });
    } catch (err) {
        console.error('[Login Error]', err.message);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// ─── AUTH: Çıkış ─────────────────────────────────────────────────────────────
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('buff_token', { path: '/' });
    res.json({ message: 'Çıkış yapıldı.' });
});

// ─── AUTH: Oturum durumu ─────────────────────────────────────────────────────
app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json({ email: req.user.email, name: req.user.name });
});

// ─── GROQ API PROXY ──────────────────────────────────────────────────────────
app.post('/api/analyze', requireAuth, analyzeLimiter, async (req, res) => {
    try {
        const { prompt } = req.body;

        if (!prompt || typeof prompt !== 'string' || prompt.length > 5000)
            return res.status(400).json({ error: 'Geçersiz analiz isteği.' });

        if (!GROQ_API_KEY || GROQ_API_KEY.startsWith('gsk_BURAYA'))
            return res.status(503).json({ error: 'Sunucuda API anahtarı yapılandırılmamış.' });

        const groqResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${GROQ_API_KEY}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                messages: [{ role: 'user', content: prompt }],
                model: 'llama-3.3-70b-versatile',
                temperature: 0.7,
                max_tokens: 1024,
            }),
        });

        if (!groqResponse.ok) {
            const errBody = await groqResponse.text();
            console.error('[Groq Error]', groqResponse.status, errBody);
            return res.status(502).json({ error: `Groq API hatası: ${groqResponse.status}` });
        }

        const data    = await groqResponse.json();
        const content = data?.choices?.[0]?.message?.content;
        if (!content) return res.status(502).json({ error: 'Groq API geçersiz yanıt döndürdü.' });

        res.json({ result: content });
    } catch (err) {
        console.error('[Analyze Error]', err.message);
        res.status(500).json({ error: 'Analiz sırasında sunucu hatası oluştu.' });
    }
});

// ─── Sağlık kontrolü ─────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── 404 ─────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Endpoint bulunamadı.' }));

// ─── Global hata yakalayıcı ───────────────────────────────────────────────────
app.use((err, req, res, _next) => {
    console.error('[Unhandled Error]', err);
    res.status(500).json({ error: 'Beklenmeyen bir hata oluştu.' });
});

app.listen(PORT, () => {
    console.log(`✅ BUFF Backend → http://localhost:${PORT}`);
    console.log(`📦 Veritabanı: ${DB_PATH}`);
});
