'use strict';

// ─── 1. KRİTİK ORTAM DEĞİŞKENLERİ KONTROLÜ ───────────────────────────────────
require('dotenv').config();

const REQUIRED_ENV = ['JWT_SECRET', 'GROQ_API_KEY', 'DATABASE_URL'];
const missing = REQUIRED_ENV.filter(k => !process.env[k] || process.env[k].startsWith('BURAYA'));
if (missing.length > 0) {
    console.error('❌ KRİTİK GÜVENLİK HATASI: Eksik ortam değişkenleri:', missing.join(', '));
    console.error('   .env dosyasını kontrol edin ve sunucuyu yeniden başlatın.');
    process.exit(1);
}

const express      = require('express');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit    = require('express-rate-limit');
const NodeCache    = require('node-cache');

// ─── 2. PRİSMA (PostgreSQL — adaptör gerekmez) ───────────────────────────────
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// ─── 3. ÖNBELLEKLEME (1 saat TTL) ────────────────────────────────────────────
const analysisCache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });

// ─── Sabitler ─────────────────────────────────────────────────────────────────
const app        = express();
const PORT       = process.env.PORT        || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const IS_PROD    = process.env.NODE_ENV === 'production';

// ─── Şifre Politikası (min 8 kar, büyük+küçük harf, rakam) ───────────────────
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

// ─── CORS (virgülle ayrılmış birden fazla kaynak desteklenir) ─────────────────
const rawOrigins = (process.env.ALLOWED_ORIGIN || 'http://localhost:5500').split(',').map(o => o.trim());

app.use(cors({
    origin(origin, callback) {
        // origin boş = curl/Postman/same-origin → izin ver
        if (!origin) return callback(null, true);
        if (rawOrigins.includes('*') || rawOrigins.includes(origin)) {
            return callback(null, true);
        }
        callback(new Error(`CORS: izin verilmeyen kaynak → ${origin}`));
    },
    methods      : ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
    credentials  : true,
}));

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// ─── Rate Limiters ────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max     : 10,
    standardHeaders: true,
    legacyHeaders  : false,
    message : { error: 'Çok fazla giriş denemesi. 15 dakika sonra tekrar deneyin.' },
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max     : 5,
    standardHeaders: true,
    legacyHeaders  : false,
    message : { error: 'Çok fazla kayıt isteği. 1 saat sonra tekrar deneyin.' },
});

const analyzeLimiter = rateLimit({
    windowMs: 60 * 1000,
    max     : 5,
    standardHeaders: true,
    legacyHeaders  : false,
    message : { error: 'Çok fazla analiz isteği. 1 dakika bekleyin.' },
});

// ─── Cookie seçenekleri ───────────────────────────────────────────────────────
const cookieOptions = () => ({
    httpOnly: true,
    secure  : IS_PROD,        // prod'da HTTPS zorunlu
    sameSite: IS_PROD ? 'none' : 'strict',  // cross-site cookie için none (HTTPS gerekir)
    maxAge  : 7 * 24 * 60 * 60 * 1000,
    path    : '/',
});

// ─── JWT Auth Middleware ──────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    const token = req.cookies?.buff_token;
    if (!token) return res.status(401).json({ error: 'Oturum bulunamadı. Lütfen giriş yapın.' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.clearCookie('buff_token');
        return res.status(401).json({ error: 'Oturum süresi dolmuş.' });
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
        if (!PASSWORD_REGEX.test(password))
            return res.status(400).json({
                error: 'Şifre en az 8 karakter olmalı ve en az 1 büyük harf, 1 küçük harf, 1 rakam içermelidir.',
            });

        const existing = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
        if (existing)
            return res.status(409).json({ error: 'Bu e-posta adresi zaten kayıtlı.' });

        const passwordHash = await bcrypt.hash(password, 12);
        await prisma.user.create({
            data: { name: name.trim(), email: email.toLowerCase(), passwordHash },
        });

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

        const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });

        const hashToCheck = user?.passwordHash || '$2a$12$invalidhashplaceholder00000000000000000000';
        const isMatch     = await bcrypt.compare(password, hashToCheck);

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

// ─── AUTH: Oturum Durumu ─────────────────────────────────────────────────────
app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json({ email: req.user.email, name: req.user.name });
});

// ─── GROQ API PROXY (Önbellekli) ─────────────────────────────────────────────
app.post('/api/analyze', requireAuth, analyzeLimiter, async (req, res) => {
    try {
        const { prompt } = req.body;
        if (!prompt || typeof prompt !== 'string' || prompt.length > 5000)
            return res.status(400).json({ error: 'Geçersiz analiz isteği.' });

        // Önbellek kontrolü
        const cacheKey = `analysis:${Buffer.from(prompt).toString('base64').slice(0, 64)}`;
        const cached   = analysisCache.get(cacheKey);
        if (cached) {
            console.log(`📦 Önbellekten servis edildi`);
            return res.json({ result: cached, cached: true });
        }

        const groqResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method : 'POST',
            headers: {
                'Authorization': `Bearer ${GROQ_API_KEY}`,
                'Content-Type' : 'application/json',
            },
            body: JSON.stringify({
                messages   : [{ role: 'user', content: prompt }],
                model      : 'llama-3.3-70b-versatile',
                temperature: 0.7,
                max_tokens : 1024,
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

        analysisCache.set(cacheKey, content);
        console.log(`✨ Groq yanıtı önbelleğe alındı (${analysisCache.getStats().keys} key)`);

        res.json({ result: content, cached: false });
    } catch (err) {
        console.error('[Analyze Error]', err.message);
        res.status(500).json({ error: 'Analiz sırasında sunucu hatası oluştu.' });
    }
});

// ─── Sağlık Kontrolü ─────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
    res.json({
        status   : 'ok',
        timestamp: new Date().toISOString(),
        env      : process.env.NODE_ENV || 'development',
        cache    : analysisCache.getStats(),
    });
});

// ─── 404 ─────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Endpoint bulunamadı.' }));

// ─── Global Hata Yakalayıcı ───────────────────────────────────────────────────
app.use((err, req, res, _next) => {
    console.error('[Unhandled Error]', err);
    res.status(500).json({ error: 'Beklenmeyen bir hata oluştu.' });
});

// ─── Sunucu Başlatma ─────────────────────────────────────────────────────────
async function start() {
    await prisma.$connect();
    console.log('✅ PostgreSQL bağlantısı kuruldu (Prisma)');

    app.listen(PORT, () => {
        console.log(`🚀 BUFF Backend → http://localhost:${PORT}`);
        console.log(`📦 Önbellek: 1 saat TTL aktif`);
        console.log(`🔐 HttpOnly Cookie | Rate Limiting | CORS aktif`);
    });
}

start().catch(err => {
    console.error('❌ Sunucu başlatılamadı:', err.message);
    process.exit(1);
});
