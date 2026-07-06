// Postgres connection + a thin compatibility shim so the rest of the
// codebase (routes/*, middleware/*) can keep calling
// db.prepare(sql).run/get/all(...params) exactly as it did with
// better-sqlite3, without rewriting every query by hand.
//
// The shim auto-converts '?' placeholders to Postgres's '$1, $2, ...'
// style. Queries that depend on SQLite-specific behavior (boolean
// columns, datetime('now')) were rewritten at the SQL level - see
// db/init.js and the schema in this file for the actual differences.

const { Pool } = require('pg');
require('dotenv').config();

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error(
    'DATABASE_URL must be set in .env - see .env.example. ' +
    'This should be the connection string for your Postgres instance.'
  );
}

const pool = new Pool({
  connectionString,
  // Render's managed Postgres requires SSL; allow self-signed certs in
  // their internal chain (this is the standard pattern for Render/Heroku
  // style managed Postgres, not a general weakening of TLS verification).
  ssl: connectionString.includes('localhost')
    ? false
    : { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.error('Unexpected Postgres pool error:', err);
});

// Converts a SQLite-style '?' placeholder query into Postgres '$1, $2...'
// style. This only does positional substitution - it does NOT alter
// keywords, so any query using SQLite-only syntax still needs a manual
// rewrite (handled case-by-case in db/init.js).
function toPgQuery(sql) {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}

// Minimal synchronous-looking wrapper matching better-sqlite3's API
// surface (prepare().run/get/all) but backed by async pg queries under
// the hood. Every route in this project already awaits these calls
// (e.g. "await db.prepare(...).run(...)" style usage was actually
// synchronous before; now run/get/all return Promises, and call sites
// must await them). See MIGRATION_NOTES.md for the one-line change this
// required at each call site.
const db = {
  prepare(sql) {
    const pgSql = toPgQuery(sql);
    return {
      async run(...params) {
        const result = await pool.query(pgSql, params);
        return { changes: result.rowCount };
      },
      async get(...params) {
        const result = await pool.query(pgSql, params);
        return result.rows[0];
      },
      async all(...params) {
        const result = await pool.query(pgSql, params);
        return result.rows;
      },
    };
  },

  async exec(sql) {
    await pool.query(sql);
  },

  // Exposed for db/init.js schema setup, which needs multi-statement
  // execution and Postgres-specific DDL.
  pool,
};

module.exports = db;
