import path from 'path';
import { defineConfig } from 'prisma/config';

// ──────────────────────────────────────────────────────────────────────────────
// Prisma v7 yapılandırması.
// PostgreSQL'e geçmek için:
//   adapter'ı kaldırın ve url'i env('DATABASE_URL') olarak ayarlayın,
//   schema.prisma'da provider = "postgresql" yapın.
// ──────────────────────────────────────────────────────────────────────────────
export default defineConfig({
  schema: path.join(__dirname, 'prisma', 'schema.prisma'),
  migrate: {
    async adapter() {
      const { PrismaLibSQL } = await import('@prisma/adapter-libsql');
      const { createClient } = await import('@libsql/client');
      const dbPath = path.join(__dirname, 'buff.db');
      const client = createClient({ url: `file:${dbPath}` });
      return new PrismaLibSQL(client);
    },
  },
});
