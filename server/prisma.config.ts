import { defineConfig } from 'prisma/config';

// ─────────────────────────────────────────────────────────────────────────────
// Prisma v7 yapılandırması — PostgreSQL
// DATABASE_URL ortam değişkeninden okunur.
// Railway bu değişkeni otomatik enjekte eder.
// ─────────────────────────────────────────────────────────────────────────────
export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrate: {
    url: process.env.DATABASE_URL!,
  },
});
