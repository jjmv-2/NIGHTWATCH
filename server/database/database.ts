import Database from "better-sqlite3"

const database =
  new Database("nightwatch.db")

database.pragma("journal_mode = WAL")
database.pragma("foreign_keys = ON")

database.exec(`
  CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    case_number TEXT,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    original_indicator TEXT NOT NULL,
    original_indicator_type TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS case_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    value TEXT NOT NULL,
    type TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (case_id)
      REFERENCES cases(id)
      ON DELETE CASCADE,

    UNIQUE(case_id, value)
  );

  CREATE TABLE IF NOT EXISTS case_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    source TEXT NOT NULL,
    type TEXT NOT NULL,
    description TEXT NOT NULL,
    malware TEXT,
    confidence INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    tags TEXT NOT NULL DEFAULT '[]',

    FOREIGN KEY (case_id)
      REFERENCES cases(id)
      ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS case_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    source TEXT NOT NULL,
    from_indicator TEXT NOT NULL,
    to_indicator TEXT NOT NULL,
    relationship TEXT NOT NULL,
    node_type TEXT NOT NULL,

    FOREIGN KEY (case_id)
      REFERENCES cases(id)
      ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS case_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,

    FOREIGN KEY (case_id)
      REFERENCES cases(id)
      ON DELETE CASCADE
  );
`)

/*
 * MIGRATIONS
 */

const caseColumns =
  database
    .prepare("PRAGMA table_info(cases)")
    .all() as {
      name: string
    }[]

if (
  !caseColumns.some(
    (column) =>
      column.name === "case_number",
  )
) {
  database.exec(`
    ALTER TABLE cases
    ADD COLUMN case_number TEXT;
  `)
}

/*
 * Give old cases readable case numbers.
 */

const oldCases =
  database
    .prepare(`
      SELECT id, created_at
      FROM cases
      WHERE case_number IS NULL
         OR case_number = ''
      ORDER BY created_at ASC
    `)
    .all() as {
      id: string
      created_at: string
    }[]

const updateOldCase =
  database.prepare(`
    UPDATE cases
    SET case_number = ?
    WHERE id = ?
  `)

oldCases.forEach(
  (researchCase, index) => {
    const year =
      new Date(
        researchCase.created_at,
      ).getFullYear()

    const number =
      String(index + 1).padStart(
        4,
        "0",
      )

    updateOldCase.run(
      `NW-${year}-${number}`,
      researchCase.id,
    )
  },
)

database.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS
  idx_cases_case_number
  ON cases(case_number);
`)

export default database