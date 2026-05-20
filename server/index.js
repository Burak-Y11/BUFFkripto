'use strict';

// ─── 1. KRİTİK ORTAM DEĞİŞKENLERİ KONTROLÜ (Sunucu başlamadan) ──────────────
require('dotenv').config();

const REQUIRED_ENV = ['JWT_SECRET', 'GROQ_API_KEY'];
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
const path         = require('path');

// ─── 2. PRİSMA ORM (SQLite → PostgreSQL geçişi tek satır değişiklik) ─────────
const { PrismaClient }  = require('@prisma/client');
const { PrismaLibSql }  = require('@prisma/adapter-libsql');
const { createClient }  = require('@libsql/client');

// Prisma instance — başlatma start() içinde yapılır
let prisma;

// ─── 3. ÖNBELLEKLEME (Groq API kotasını koruma) ───────────────────────────────
// TTL: 3600 saniye (1 saat). Aynı analiz isteği 1 saat boyunca önbellekten gelir.
const analysisCache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });

// ─── Sabitler ─────────────────────────────────────────────────────────────────
const app            = express();
const PORT           = process.env.PORT        || 3001;
const JWT_SECRET     = process.env.JWT_SECRET;
const GROQ_API_KEY   = process.env.GROQ_API_KEY;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5500';
const IS_PROD        = process.env.NODE_ENV === 'production';

// ─── Şifre Politikası Regex ───────────────────────────────────────────────────
// En az 8 karakter, 1 büyük harf, 1 küçük harf, 1 rakam
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
    origin      : ALLOWED_ORIGIN,
    methods     : ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
    credentials : true,
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// ─── Rate Limiters ────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
    windowMs : 15 * 60 * 1000,  // 15 dakika
    max      : 10,               // IP başına 10 deneme
    standardHeaders: true,
    legacyHeaders  : false,
    message  : { error: 'Çok fazla giriş denemesi. 15 dakika sonra tekrar deneyin.' },
});

const registerLimiter = rateLimit({
    windowMs : 60 * 60 * 1000,  // 1 saat
    max      : 5,
    standardHeaders: true,
    legacyHeaders  : false,
    message  : { error: 'Çok fazla kayıt isteği. 1 saat sonra tekrar deneyin.' },
});

const analyzeLimiter = rateLimit({
    windowMs : 60 * 1000,  // 1 dakika
    max      : 5,
    standardHeaders: true,
    legacyHeaders  : false,
    message  : { error: 'Çok fazla analiz isteği. 1 dakika bekleyin.' },
});

// ─── Cookie seçenekleri ───────────────────────────────────────────────────────
const cookieOptions = () => ({
    httpOnly : true,
    secure   : IS_PROD,
    sameSite : 'strict',
    maxAge   : 7 * 24 * 60 * 60 * 1000,
    path     : '/',
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

        // 4. Güçlü şifre politikası
        if (!PASSWORD_REGEX.test(password)) {
            return res.status(400).json({
                error: 'Şifre en az 8 karakter olmalı ve en az 1 büyük harf, 1 küçük harf, 1 rakam içermelidir.',
            });
        }

        // Prisma ile kullanıcı kontrolü
        const existing = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
        if (existing) return res.status(409).json({ error: 'Bu e-posta adresi zaten kayıtlı.' });

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

        // Timing attack koruması — kullanıcı bulunamasa bile bcrypt çalıştır
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

        // 3. Önbellek kontrolü — aynı prompt için Groq'a gitme
        const cacheKey = `analysis:${Buffer.from(prompt).toString('base64').slice(0, 64)}`;
        const cached   = analysisCache.get(cacheKey);
        if (cached) {
            console.log(`📦 Önbellekten servis edildi (key: ${cacheKey.slice(0, 20)}...)`);
            return res.json({ result: cached, cached: true });
        }

        // Groq API isteği (önbellekte yoksa)
        const groqResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method  : 'POST',
            headers : {
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

        // Sonucu 1 saatliğine önbelleğe al
        analysisCache.set(cacheKey, content);
        console.log(`✨ Groq API yanıtı önbelleğe alındı (${analysisCache.getStats().keys} toplam key)`);

        res.json({ result: content, cached: false });
    } catch (err) {
        console.error('[Analyze Error]', err.message);
        res.status(500).json({ error: 'Analiz sırasında sunucu hatası oluştu.' });
    }
});

// ─── Önbellek istatistikleri (sadece geliştirme) ──────────────────────────────
app.get('/api/cache/stats', requireAuth, (req, res) => {
    res.json(analysisCache.getStats());
});

// ─── Sağlık Kontrolü ─────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
    res.json({
        status   : 'ok',
        timestamp: new Date().toISOString(),
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
    // Prisma'yı burada başlat — process.cwd() runtime'da kesinlikle doğrudur
    const dbPath  = path.resolve(process.cwd(), 'buff.db');
    const adapter = new PrismaLibSql({ url: `file:${dbPath}` });
    prisma        = new PrismaClient({ adapter });

    await prisma.$connect();
    console.log(`✅ Prisma → SQLite bağlantısı kuruldu: ${dbPath}`);

    app.listen(PORT, () => {
        console.log(`🚀 BUFF Backend → http://localhost:${PORT}`);
        console.log(`📦 Önbellek: 1 saat TTL (Groq API kota koruması aktif)`);
        console.log(`🔐 JWT HttpOnly Cookie aktif | Rate Limiting aktif`);
    });
}

start().catch(err => {
    console.error('❌ Sunucu başlatılamadı:', err.message);
    process.exit(1);
});
