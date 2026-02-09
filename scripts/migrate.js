const knex = require("knex");
const path = require("path");

const config = {
  client: "pg",
  connection: {
    host: process.env.DB_HOST || "postgres",
    port: parseInt(process.env.DB_PORT || "5432", 10),
    database: process.env.DB_NAME || "tenebra",
    user: process.env.DB_USER || "tenebra_user",
    password: process.env.DB_PASSWORD || "your_secure_password_here",
  },
  migrations: {
    tableName: "knex_migrations",
    directory: path.join(__dirname, "../dist/database/migrations"),
    loadExtensions: [".js"],
  },
};

async function runMigrations() {
  const db = knex(config);

  try {
    console.log("🔄 Running database migrations...");
    const [batch, migrations] = await db.migrate.latest();

    if (migrations.length === 0) {
      console.log("✅ Database is already up to date");
    } else {
      console.log(`✅ Batch ${batch} ran ${migrations.length} migrations:`);
      migrations.forEach((m) => console.log(`   - ${m}`));
    }
  } catch (error) {
    console.error("❌ Migration failed:", error.message);
    process.exit(1);
  } finally {
    await db.destroy();
  }
}

runMigrations();
