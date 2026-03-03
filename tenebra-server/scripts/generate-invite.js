const knex = require('knex');
const crypto = require('crypto');
const path = require('path');

const config = {
  client: 'pg',
  connection: {
    host: process.env.DB_HOST || 'postgres',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    database: process.env.DB_NAME || 'tenebra',
    user: process.env.DB_USER || 'tenebra_user',
    password: process.env.DB_PASSWORD || 'your_secure_password_here',
  },
};

function generateCode() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}

async function main() {
  const db = knex(config);
  try {
    const code = generateCode();
    await db('invite_codes').insert({ code });
    console.log(`\n✅ Invite code generated: ${code}\n`);
  } catch (error) {
    console.error('❌ Failed to generate invite code:', error.message);
    process.exit(1);
  } finally {
    await db.destroy();
  }
}

main();
