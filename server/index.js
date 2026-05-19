'use strict';

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET     = process.env.JWT_SECRET;
const GROQ_API_KEY   = process.env.GROQ_API_KEY;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5500';

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
    origin: ALLOWED_ORIGIN,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '10kb' })); // DoS koruması için payload limiti

// ─── In-Memory "DB" (Gerçek projede PostgreSQL/MongoDB kullanılmalı) ──────────
// Kullanıcılar: { email, passwordHash, name }
const users = new Map();

// ─── Yardımcı: JWT Doğrulama Middleware ──────────────────────────────────────
function requireAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Yetkilendirme başlığı eksik.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş token.' });
    }
}

// ─── AUTH: Kayıt (Register) ───────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Basit doğrulama
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Ad, e-posta ve şifre zorunludur.' });
        }
        if (typeof email !== 'string' || !email.includes('@')) {
            return res.status(400).json({ error: 'Geçerli bir e-posta adresi girin.' });
        }
        if (typeof password !== 'string' || password.length < 8) {
            return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır.' });
        }
        if (users.has(email.toLowerCase())) {
            return res.status(409).json({ error: 'Bu e-posta adresi zaten kayıtlı.' });
        }

        // Şifreyi bcrypt ile hashle (salt rounds: 12)
        const passwordHash = await bcrypt.hash(password, 12);
        users.set(email.toLowerCase(), { name, email: email.toLowerCase(), passwordHash });

        // JWT oluştur
        const token = jwt.sign(
            { email: email.toLowerCase(), name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({ message: 'Kayıt başarılı.', token, name });
    } catch (err) {
        console.error('[Register Error]', err.message);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// ─── AUTH: Giriş (Login) ──────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'E-posta ve şifre zorunludur.' });
        }

        const user = users.get(email.toLowerCase());
        if (!user) {
            // Timing attack'e karşı sabit süre bekle
            await bcrypt.compare(password, '$2a$12$invalidhashplaceholder00000000000000000000');
            return res.status(401).json({ error: 'E-posta veya şifre hatalı.' });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            return res.status(401).json({ error: 'E-posta veya şifre hatalı.' });
        }

        const token = jwt.sign(
            { email: user.email, name: user.name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ message: 'Giriş başarılı.', token, name: user.name });
    } catch (err) {
        console.error('[Login Error]', err.message);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// ─── GROQ API PROXY (Korumalı endpoint) ──────────────────────────────────────
app.post('/api/analyze', requireAuth, async (req, res) => {
    try {
        const { prompt } = req.body;

        if (!prompt || typeof prompt !== 'string' || prompt.length > 5000) {
            return res.status(400).json({ error: 'Geçersiz analiz isteği.' });
        }

        if (!GROQ_API_KEY || GROQ_API_KEY.startsWith('gsk_BURAYA')) {
            return res.status(503).json({ error: 'Sunucuda API anahtarı yapılandırılmamış. Lütfen yönetici ile iletişime geçin.' });
        }

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

        const data = await groqResponse.json();
        const content = data?.choices?.[0]?.message?.content;
        if (!content) {
            return res.status(502).json({ error: 'Groq API geçersiz yanıt döndürdü.' });
        }

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

// ─── 404 handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint bulunamadı.' });
});

// ─── Global hata yakalayıcı ───────────────────────────────────────────────────
app.use((err, req, res, _next) => {
    console.error('[Unhandled Error]', err);
    res.status(500).json({ error: 'Beklenmeyen bir hata oluştu.' });
});

app.listen(PORT, () => {
    console.log(`✅ BUFF Backend sunucusu http://localhost:${PORT} adresinde çalışıyor`);
    if (!GROQ_API_KEY || GROQ_API_KEY.startsWith('gsk_BURAYA')) {
        console.warn('⚠️  UYARI: .env dosyasına gerçek GROQ_API_KEY değerini girmeyi unutmayın!');
    }
});
