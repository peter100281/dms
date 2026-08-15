const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const { ImapFlow } = require('imapflow');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const app = express();

if (process.env.TRUST_PROXY) {
  app.set(
    'trust proxy',
    process.env.TRUST_PROXY
  );
}

const PORT = Number(process.env.APP_PORT || 3000);
const ADMIN_USER =
  process.env.ADMIN_USER || 'admin';

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || '';

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL fehlt');
}

if (!process.env.APP_SECRET) {
  throw new Error('APP_SECRET fehlt');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

pool.on('error', err => {
  console.error('PostgreSQL Pool Fehler:', err);
});

const settingsCache = {
  app_name: 'Dokumentenarchiv',
  ocr_languages: 'deu+eng+nld+swe',
  require_document_date: 'false',
  default_category_id: ''
};


async function loadAppSettings() {
  const result = await pool.query(`
    SELECT key, value
    FROM app_settings
  `);

  for (const row of result.rows) {
    settingsCache[row.key] = row.value;
  }
}


async function saveAppSetting(key, value, client = pool) {
  await client.query(
    `
    INSERT INTO app_settings (
      key,
      value,
      updated_at
    )
    VALUES ($1, $2, NOW())

    ON CONFLICT (key)
    DO UPDATE SET
      value = EXCLUDED.value,
      updated_at = NOW()
    `,
    [
      key,
      String(value)
    ]
  );

  settingsCache[key] =
    String(value);
}


/*
  Verschlüsselte Speicherung des IMAP-Kennworts.
  Der Schlüssel wird aus APP_SECRET abgeleitet.
*/
function encryptMailPassword(password) {

  const key =
    crypto
      .createHash('sha256')
      .update(
        'dms-mail-settings:' +
        process.env.APP_SECRET
      )
      .digest();

  const iv =
    crypto.randomBytes(12);

  const cipher =
    crypto.createCipheriv(
      'aes-256-gcm',
      key,
      iv
    );

  const encrypted =
    Buffer.concat([
      cipher.update(
        String(password),
        'utf8'
      ),
      cipher.final()
    ]);

  const tag =
    cipher.getAuthTag();

  return [
    'v1',
    iv.toString('base64'),
    tag.toString('base64'),
    encrypted.toString('base64')
  ].join(':');
}


function decryptMailPassword(value) {

  if (!value) {
    return '';
  }

  const parts =
    String(value).split(':');

  if (
    parts.length !== 4 ||
    parts[0] !== 'v1'
  ) {
    throw new Error(
      'Ungültiges Format des gespeicherten IMAP-Kennworts.'
    );
  }

  const key =
    crypto
      .createHash('sha256')
      .update(
        'dms-mail-settings:' +
        process.env.APP_SECRET
      )
      .digest();

  const iv =
    Buffer.from(
      parts[1],
      'base64'
    );

  const tag =
    Buffer.from(
      parts[2],
      'base64'
    );

  const encrypted =
    Buffer.from(
      parts[3],
      'base64'
    );

  const decipher =
    crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      iv
    );

  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]).toString('utf8');
}


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"],
      frameSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'"],
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'"],
      styleSrcAttr: ["'none'"]
    }
  },

  /*
    Das DMS läuft derzeit auch direkt über HTTP.
    HSTS darf daher erst mit vollständigem HTTPS-
    Betrieb aktiviert werden.
  */
  strictTransportSecurity: false,

  xFrameOptions: {
    action: 'sameorigin'
  }
}));

app.use(express.urlencoded({ extended: false }));
app.use('/static', express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.locals.appName =
    settingsCache.app_name ||
    'Dokumentenarchiv';

  next();
});


app.use(session({
  store: new pgSession({
    pool,
    createTableIfMissing: true
  }),
  secret: process.env.APP_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: 1000 * 60 * 60 * 12
  }
}));



/* DMS-CSRF-BASE */

/*
  CSRF-Token pro Sitzung.
  Noch keine globale POST-Prüfung:
  Schutz wird Route für Route aktiviert.
*/
app.use((req, res, next) => {

  if (!req.session.csrfToken) {

    req.session.csrfToken =
      crypto
        .randomBytes(32)
        .toString('hex');
  }

  res.locals.csrfToken =
    req.session.csrfToken;

  next();
});


function validCsrfToken(
  expected,
  received
) {

  if (
    typeof expected !== 'string' ||
    typeof received !== 'string'
  ) {
    return false;
  }

  const a =
    Buffer.from(
      expected,
      'utf8'
    );

  const b =
    Buffer.from(
      received,
      'utf8'
    );

  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    a,
    b
  );
}


function requireCsrf(
  req,
  res,
  next
) {

  const received =
    String(
      req.body?._csrf || ''
    );

  if (
    !validCsrfToken(
      req.session?.csrfToken,
      received
    )
  ) {

    console.warn(
      'CSRF-Prüfung fehlgeschlagen:',
      req.method,
      req.originalUrl,
      req.ip
    );

    return res
      .status(403)
      .send(
        'Sicherheitsprüfung fehlgeschlagen. ' +
        'Bitte die Seite neu laden und erneut versuchen.'
      );
  }

  next();
}


/* DMS-AUTH-CONTEXT */

/*
  Benutzerinformationen zentral für alle Views laden.

  Dadurch stehen in jedem Template zuverlässig zur Verfügung:
    isAdmin
    displayName

  Zusätzlich greifen Rollenänderungen und Kontodeaktivierungen
  ohne erneute Anmeldung.
*/
app.use(async (req, res, next) => {
  try {
    /*
      Auch für nicht angemeldete Seiten wie /login
      müssen die Variablen definiert sein.
    */
    res.locals.isAdmin = false;
    res.locals.displayName = '';
    res.locals.mustChangePassword = false;

    if (!req.session || !req.session.userId) {
      return next();
    }

    const result = await pool.query(
      `
      SELECT
        id,
        username,
        display_name,
        is_admin,
        is_active,
        must_change_password
      FROM users
      WHERE id = $1
      `,
      [req.session.userId]
    );

    /*
      Benutzer gelöscht oder deaktiviert:
      bestehende Sitzung beenden.
    */
    if (
      result.rowCount !== 1 ||
      !result.rows[0].is_active
    ) {
      return req.session.destroy(() => {
        res.redirect('/login');
      });
    }

    const user = result.rows[0];

    req.session.username =
      user.username;

    req.session.displayName =
      user.display_name ||
      user.username;

    req.session.isAdmin =
      Boolean(user.is_admin);

    req.session.mustChangePassword =
      Boolean(user.must_change_password);

    res.locals.displayName =
      req.session.displayName;

    res.locals.isAdmin =
      req.session.isAdmin;

    res.locals.mustChangePassword =
      req.session.mustChangePassword;

    next();

  } catch (err) {
    next(err);
  }
});


/*
  Benutzer mit Standardkennwort dürfen ausschließlich
  Konto/Passwortänderung und Logout verwenden.
*/
app.use((req, res, next) => {

  if (
    !req.session ||
    !req.session.userId ||
    !req.session.mustChangePassword
  ) {
    return next();
  }

  const allowedPaths = new Set([
    '/account',
    '/account/password/change',
    '/logout'
  ]);

  if (allowedPaths.has(req.path)) {
    return next();
  }

  return res.redirect(
    '/account?error=' +
    encodeURIComponent(
      'Bitte ändere zuerst das Standardkennwort.'
    )
  );
});


async function initDatabase() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    INSERT INTO app_settings (key, value)
    VALUES
      ('app_name', 'Dokumentenarchiv'),
      ('ocr_languages', 'deu+eng+nld+swe'),
      ('require_document_date', 'false'),
      ('default_category_id', '')
    ON CONFLICT (key) DO NOTHING
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS mail_settings (
      id SMALLINT PRIMARY KEY,
      enabled BOOLEAN NOT NULL DEFAULT FALSE,
      host TEXT NOT NULL DEFAULT '',
      port INTEGER NOT NULL DEFAULT 993,
      secure BOOLEAN NOT NULL DEFAULT TRUE,
      username TEXT NOT NULL DEFAULT '',
      password_enc TEXT NOT NULL DEFAULT '',
      mailbox TEXT NOT NULL DEFAULT 'INBOX',
      processed_folder TEXT NOT NULL DEFAULT 'DMS-Importiert',
      poll_seconds INTEGER NOT NULL DEFAULT 30,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    INSERT INTO mail_settings (
      id,
      enabled,
      host,
      port,
      secure,
      username,
      password_enc,
      mailbox,
      processed_folder,
      poll_seconds
    )
    VALUES (
      1,
      FALSE,
      '',
      993,
      TRUE,
      '',
      '',
      'INBOX',
      'DMS-Importiert',
      30
    )
    ON CONFLICT (id) DO NOTHING
  `);


  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      display_name TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      last_login_at TIMESTAMPTZ,
      must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS display_name TEXT,
      ADD COLUMN IF NOT EXISTS is_active
        BOOLEAN NOT NULL DEFAULT TRUE,
      ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS must_change_password
        BOOLEAN NOT NULL DEFAULT FALSE
  `);


  await pool.query(`
    CREATE TABLE IF NOT EXISTS documents (
      id UUID PRIMARY KEY,
      title TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      storage_path TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size BIGINT NOT NULL,
      sha256 TEXT UNIQUE NOT NULL,

      source TEXT NOT NULL DEFAULT 'upload',
      status TEXT NOT NULL DEFAULT 'inbox',

      document_date DATE,
      sender TEXT,
      reference TEXT,
      notes TEXT,

      received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      archived_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_status
    ON documents(status);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_received_at
    ON documents(received_at DESC);
  `);


  await pool.query(`
    ALTER TABLE documents
      ADD COLUMN IF NOT EXISTS ocr_status
      TEXT NOT NULL DEFAULT 'pending'
  `);

  await pool.query(`
    ALTER TABLE documents
      ADD COLUMN IF NOT EXISTS ocr_text TEXT
  `);

  await pool.query(`
    ALTER TABLE documents
      ADD COLUMN IF NOT EXISTS ocr_path TEXT
  `);

  await pool.query(`
    ALTER TABLE documents
      ADD COLUMN IF NOT EXISTS ocr_error TEXT
  `);

  await pool.query(`
    ALTER TABLE documents
      ADD COLUMN IF NOT EXISTS ocr_processed_at TIMESTAMPTZ
  `);


  /*
    Metadatenanalyse / Vorschläge.
    Diese Spalten müssen auch bei einer komplett
    neuen Installation angelegt werden.
  */
  await pool.query(`
    ALTER TABLE documents
      ADD COLUMN IF NOT EXISTS suggestion_status
        TEXT NOT NULL DEFAULT 'pending',
      ADD COLUMN IF NOT EXISTS suggestion_error TEXT,
      ADD COLUMN IF NOT EXISTS suggestion_processed_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS metadata_suggestions
        JSONB NOT NULL DEFAULT '{}'::jsonb
  `);

  /*
    Vollständiges Fresh-Install-Schema.

    Diese Migration ergänzt alle Tabellen, Spalten,
    Constraints und Indizes, die eine gewachsene
    Installation bereits besitzt.
  */

  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS pg_trgm
  `);


  await pool.query(`
    CREATE TABLE IF NOT EXISTS categories (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      parent_id UUID,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  await pool.query(`
    CREATE TABLE IF NOT EXISTS tags (
      id UUID PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  await pool.query(`
    ALTER TABLE documents
      ADD COLUMN IF NOT EXISTS category_id UUID,
      ADD COLUMN IF NOT EXISTS source_email_from TEXT,
      ADD COLUMN IF NOT EXISTS source_email_subject TEXT,
      ADD COLUMN IF NOT EXISTS source_email_message_id TEXT,
      ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS previous_status TEXT,
      ADD COLUMN IF NOT EXISTS page_count INTEGER
  `);


  await pool.query(`
    CREATE TABLE IF NOT EXISTS document_tags (
      document_id UUID NOT NULL,
      tag_id UUID NOT NULL,
      PRIMARY KEY (document_id, tag_id)
    )
  `);


  await pool.query(`
    CREATE TABLE IF NOT EXISTS mail_imports (
      id UUID PRIMARY KEY,
      mailbox TEXT NOT NULL,
      uidvalidity TEXT NOT NULL,
      uid BIGINT NOT NULL,
      message_id TEXT,
      sender TEXT,
      subject TEXT,
      received_at TIMESTAMPTZ,
      eml_path TEXT,
      attachment_count INTEGER NOT NULL DEFAULT 0,
      imported_count INTEGER NOT NULL DEFAULT 0,
      duplicate_count INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'processing',
      error TEXT,
      imported_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (mailbox, uidvalidity, uid)
    )
  `);


  /*
    ALTER TABLE ... ADD CONSTRAINT unterstützt in PostgreSQL
    kein allgemeines IF NOT EXISTS. Deshalb werden die
    vorhandenen Constraints über pg_constraint geprüft.
  */

  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'categories_parent_id_fkey'
      ) THEN
        ALTER TABLE categories
          ADD CONSTRAINT categories_parent_id_fkey
          FOREIGN KEY (parent_id)
          REFERENCES categories(id)
          ON DELETE SET NULL;
      END IF;
    END
    $$
  `);


  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'documents_category_id_fkey'
      ) THEN
        ALTER TABLE documents
          ADD CONSTRAINT documents_category_id_fkey
          FOREIGN KEY (category_id)
          REFERENCES categories(id)
          ON DELETE SET NULL;
      END IF;
    END
    $$
  `);


  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'document_tags_document_id_fkey'
      ) THEN
        ALTER TABLE document_tags
          ADD CONSTRAINT document_tags_document_id_fkey
          FOREIGN KEY (document_id)
          REFERENCES documents(id)
          ON DELETE CASCADE;
      END IF;
    END
    $$
  `);


  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'document_tags_tag_id_fkey'
      ) THEN
        ALTER TABLE document_tags
          ADD CONSTRAINT document_tags_tag_id_fkey
          FOREIGN KEY (tag_id)
          REFERENCES tags(id)
          ON DELETE CASCADE;
      END IF;
    END
    $$
  `);


  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_categories_parent_id
      ON categories(parent_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_document_tags_tag_id
      ON document_tags(tag_id, document_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_category
      ON documents(category_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_deleted_at
      ON documents(deleted_at)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_document_date
      ON documents(document_date DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_inbox_received
      ON documents(received_at DESC)
      WHERE status = 'inbox'
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_metadata_errors
      ON documents(created_at DESC)
      WHERE suggestion_status = 'error'
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_metadata_queue
      ON documents(created_at)
      WHERE
        status = 'inbox'
        AND ocr_status = 'done'
        AND suggestion_status = 'pending'
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_notes_trgm
      ON documents
      USING gin (notes gin_trgm_ops)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_ocr_errors
      ON documents(created_at DESC)
      WHERE ocr_status = 'error'
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_ocr_queue
      ON documents(created_at)
      WHERE ocr_status = 'pending'
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_ocr_text_trgm
      ON documents
      USING gin (ocr_text gin_trgm_ops)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_reference_trgm
      ON documents
      USING gin (reference gin_trgm_ops)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_sender_trgm
      ON documents
      USING gin (sender gin_trgm_ops)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_documents_title_trgm
      ON documents
      USING gin (title gin_trgm_ops)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_mail_imports_status
      ON mail_imports(status)
  `);



  /*
    Standard-Administrator für eine neue Installation.

    Benutzer: admin
    Passwort: admin

    Das Kennwort muss nach der ersten Anmeldung
    zwingend geändert werden.
  */
  const existingAdmin = await pool.query(
    `
    SELECT id
    FROM users
    WHERE is_admin = TRUE
    LIMIT 1
    `
  );

  if (existingAdmin.rowCount === 0) {

    const hash =
      await bcrypt.hash(
        'admin',
        12
      );

    await pool.query(
      `
      INSERT INTO users (
        id,
        username,
        password_hash,
        is_admin,
        display_name,
        is_active,
        must_change_password
      )
      VALUES (
        $1,
        'admin',
        $2,
        TRUE,
        'Administrator',
        TRUE,
        TRUE
      )
      `,
      [
        crypto.randomUUID(),
        hash
      ]
    );

    console.warn(
      'Initialer Administrator angelegt. ' +
      'Das Standardkennwort muss nach der ersten ' +
      'Anmeldung geändert werden.'
    );

  } else {

    console.log(
      'Administrator vorhanden – kein Bootstrap erforderlich.'
    );
  }
}


/* DMS-OCR-WORKER */

let ocrBusy = false;

async function processOcrQueue() {
  if (ocrBusy) {
    return;
  }

  ocrBusy = true;

  let document = null;

  try {
    const result = await pool.query(`
      WITH next_document AS (
        SELECT id
        FROM documents
        WHERE ocr_status = 'pending'
        ORDER BY created_at ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
      )

      UPDATE documents d
      SET
        ocr_status = 'processing',
        ocr_error = NULL

      FROM next_document n

      WHERE d.id = n.id

      RETURNING
        d.id,
        d.storage_path,
        d.original_filename
    `);

    if (result.rowCount === 0) {
      return;
    }

    document = result.rows[0];

    const outputPath =
      `/data/documents/${document.id}.pdf`;

    console.log(
      `OCR gestartet: ${document.original_filename}`
    );

    if (fs.existsSync(outputPath)) {
      fs.unlinkSync(outputPath);
    }

    /*
      --skip-text:
      Bereits vorhandene Textseiten werden nicht neu OCRt.

      deu+eng:
      Deutsche und englische Texterkennung.

      --output-type pdf:
      Normale PDF mit durchsuchbarer Textebene.
    */
    await execFileAsync(
      'ocrmypdf',
      [
        '--skip-text',
        '--language',
        settingsCache.ocr_languages || 'deu+eng+nld+swe',
        '--output-type',
        'pdf',
        '--optimize',
        '1',
        document.storage_path,
        outputPath
      ],
      {
        timeout: 10 * 60 * 1000,
        maxBuffer: 20 * 1024 * 1024
      }
    );

    /*
      OCRmyPDF-Sidecars enthalten nur OCR-generierten Text.
      pdftotext liefert uns dagegen auch Text, der vorher
      schon im PDF vorhanden war.
    */
    const textResult = await execFileAsync(
      'pdftotext',
      [
        '-layout',
        outputPath,
        '-'
      ],
      {
        timeout: 2 * 60 * 1000,
        maxBuffer: 50 * 1024 * 1024
      }
    );

    const text =
      String(textResult.stdout || '').trim();

    await pool.query(
      `
      UPDATE documents
      SET
        ocr_status = 'done',
        ocr_text = $1,
        ocr_path = $2,
        ocr_error = NULL,
        ocr_processed_at = NOW()

      WHERE id = $3
      `,
      [
        text,
        outputPath,
        document.id
      ]
    );

    console.log(
      `OCR abgeschlossen: ${document.original_filename} (${text.length} Zeichen)`
    );

  } catch (err) {
    console.error(
      'OCR fehlgeschlagen:',
      err.stderr || err.message || err
    );

    if (document) {
      const errorText =
        String(
          err.stderr ||
          err.message ||
          err
        ).slice(0, 4000);

      await pool.query(
        `
        UPDATE documents
        SET
          ocr_status = 'error',
          ocr_error = $1

        WHERE id = $2
        `,
        [
          errorText,
          document.id
        ]
      );
    }

  } finally {
    ocrBusy = false;
  }
}



async function requireAdmin(req, res, next) {
  try {
    if (!req.session || !req.session.userId) {
      return res.redirect('/login');
    }

    const result = await pool.query(
      `
      SELECT
        username,
        display_name,
        is_admin,
        is_active
      FROM users
      WHERE id = $1
      `,
      [req.session.userId]
    );

    if (
      result.rowCount !== 1 ||
      !result.rows[0].is_active
    ) {
      return req.session.destroy(() => {
        res.redirect('/login');
      });
    }

    const user = result.rows[0];

    if (!user.is_admin) {
      return res
        .status(403)
        .send(
          'Für diese Funktion sind Administratorrechte erforderlich.'
        );
    }

    req.session.username =
      user.username;

    req.session.displayName =
      user.display_name ||
      user.username;

    req.session.isAdmin = true;

    res.locals.isAdmin = true;

    res.locals.displayName =
      req.session.displayName;

    next();

  } catch (err) {
    next(err);
  }
}



/* DMS-METADATA-SUGGESTIONS */

const MONTH_NAMES = {
  januar: 1,
  january: 1,
  januari: 1,

  februar: 2,
  february: 2,
  februari: 2,

  märz: 3,
  maerz: 3,
  march: 3,
  maart: 3,
  mars: 3,

  april: 4,

  mai: 5,
  may: 5,
  mei: 5,

  juni: 6,
  june: 6,

  juli: 7,
  july: 7,

  august: 8,

  september: 9,

  oktober: 10,
  october: 10,

  november: 11,

  dezember: 12,
  december: 12
};


function validIsoDate(year, month, day) {
  const y = Number(year);
  const m = Number(month);
  const d = Number(day);

  if (
    y < 1990 ||
    y > 2100 ||
    m < 1 ||
    m > 12 ||
    d < 1 ||
    d > 31
  ) {
    return null;
  }

  const date =
    new Date(Date.UTC(y, m - 1, d));

  if (
    date.getUTCFullYear() !== y ||
    date.getUTCMonth() !== m - 1 ||
    date.getUTCDate() !== d
  ) {
    return null;
  }

  return (
    String(y).padStart(4, '0') +
    '-' +
    String(m).padStart(2, '0') +
    '-' +
    String(d).padStart(2, '0')
  );
}


function dateLabelDE(iso) {
  if (!iso) {
    return '';
  }

  const parts = iso.split('-');

  if (parts.length !== 3) {
    return iso;
  }

  return `${parts[2]}.${parts[1]}.${parts[0]}`;
}


function extractDateFromText(text) {
  const lines =
    String(text || '')
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean)
      .slice(0, 100);

  const dateLabels =
    /(?:rechnungsdatum|bescheiddatum|briefdatum|datum|date|factuurdatum|fakturadatum)/i;


  /*
    Zuerst Zeilen bevorzugen, die explizit als
    Datum gekennzeichnet sind.
  */
  const ordered = [
    ...lines.filter(line => dateLabels.test(line)),
    ...lines.filter(line => !dateLabels.test(line))
  ];


  for (const line of ordered) {

    /*
      14.08.2026
      14-08-2026
      14/08/2026
    */
    let m = line.match(
      /\b([0-3]?\d)[.\-/]([01]?\d)[.\-/](20\d{2})\b/
    );

    if (m) {
      const iso =
        validIsoDate(
          m[3],
          m[2],
          m[1]
        );

      if (iso) {
        return {
          value: iso,
          confidence:
            dateLabels.test(line)
              ? 0.96
              : 0.78
        };
      }
    }


    /*
      ISO: 2026-08-14
    */
    m = line.match(
      /\b(20\d{2})-([01]\d)-([0-3]\d)\b/
    );

    if (m) {
      const iso =
        validIsoDate(
          m[1],
          m[2],
          m[3]
        );

      if (iso) {
        return {
          value: iso,
          confidence:
            dateLabels.test(line)
              ? 0.96
              : 0.78
        };
      }
    }


    /*
      14. August 2026
      14 August 2026
      14 augustus 2026 etc.
    */
    m = line.match(
      /\b([0-3]?\d)\.?\s+([A-Za-zÄÖÜäöüß]+)\s+(20\d{2})\b/i
    );

    if (m) {
      const month =
        MONTH_NAMES[
          m[2].toLocaleLowerCase('de-DE')
        ];

      if (month) {
        const iso =
          validIsoDate(
            m[3],
            month,
            m[1]
          );

        if (iso) {
          return {
            value: iso,
            confidence:
              dateLabels.test(line)
                ? 0.96
                : 0.80
          };
        }
      }
    }
  }

  return null;
}


function extractReference(text) {
  const lines =
    String(text || '')
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean)
      .slice(0, 180);


  const labels = [
    'aktenzeichen',
    'geschäftszeichen',
    'zeichen',
    'kundennummer',
    'kunden-nr',
    'kundennr',
    'vertragsnummer',
    'vertrags-nr',
    'rechnungsnummer',
    'rechnungs-nr',
    'vorgangsnummer',
    'vorgangs-nr',
    'referenz',
    'reference',
    'bestellnummer',
    'auftragsnummer',
    'invoice number',
    'customer number',
    'contract number',
    'klantnummer',
    'factuurnummer',
    'referentie',
    'kundnummer',
    'fakturanummer',
    'referens'
  ];


  const escaped =
    labels
      .map(value =>
        value.replace(
          /[.*+?^${}()|[\]\\]/g,
          '\\$&'
        )
      )
      .join('|');


  const pattern =
    new RegExp(
      `(?:${escaped})\\s*[:#]?\\s+([A-Za-z0-9][A-Za-z0-9./_\\- ]{1,50})`,
      'i'
    );


  for (const line of lines) {
    const match =
      line.match(pattern);

    if (!match) {
      continue;
    }

    let value =
      match[1]
        .trim()
        .replace(/\s{2,}.*/, '')
        .trim();

    if (value.length > 50) {
      value =
        value.slice(0, 50).trim();
    }

    if (value.length >= 2) {
      return {
        value,
        confidence: 0.93
      };
    }
  }

  return null;
}


function detectDocumentType(text) {
  const value =
    String(text || '')
      .toLocaleLowerCase('de-DE');


  const types = [
    {
      label: 'Rechnung',
      terms: [
        'rechnung',
        'rechnungsnummer',
        'invoice',
        'factuur',
        'faktura'
      ]
    },
    {
      label: 'Mahnung',
      terms: [
        'mahnung',
        'zahlungserinnerung',
        'payment reminder'
      ]
    },
    {
      label: 'Bescheid',
      terms: [
        'bescheid',
        'steuerbescheid'
      ]
    },
    {
      label: 'Vertrag',
      terms: [
        'vertrag',
        'vertragsnummer',
        'contract'
      ]
    },
    {
      label: 'Kündigung',
      terms: [
        'kündigung',
        'kuendigung',
        'termination'
      ]
    },
    {
      label: 'Angebot',
      terms: [
        'angebot',
        'quotation',
        'offerte'
      ]
    },
    {
      label: 'Auftragsbestätigung',
      terms: [
        'auftragsbestätigung',
        'auftragsbestaetigung',
        'order confirmation'
      ]
    },
    {
      label: 'Kontoauszug',
      terms: [
        'kontoauszug',
        'account statement'
      ]
    },
    {
      label: 'Versicherungsschreiben',
      terms: [
        'versicherungsschein',
        'versicherungsnummer',
        'versicherung'
      ]
    }
  ];


  for (const type of types) {
    if (
      type.terms.some(
        term => value.includes(term)
      )
    ) {
      return {
        value: type.label,
        confidence: 0.86
      };
    }
  }

  return null;
}


function extractSender(text) {
  const lines =
    String(text || '')
      .split(/\r?\n/)
      .map(line =>
        line
          .replace(/\s+/g, ' ')
          .trim()
      )
      .filter(Boolean)
      .slice(0, 30);


  const reject =
    /^(rechnung|mahnung|bescheid|vertrag|angebot|datum|date|seite|page|kundennummer|aktenzeichen|rechnungsnummer|betreff|subject)\b/i;


  const organisation =
    /\b(gmbh|ag|kg|gbr|ohg|e\.?\s?v\.?|mbh|bank|sparkasse|versicherung|finanzamt|stadt|gemeinde|kreis|ministerium|behörde|behoerde|universität|universitaet|telekom|vodafone|energie|werke)\b/i;


  let best = null;


  lines.forEach((line, index) => {

    if (
      line.length < 3 ||
      line.length > 100 ||
      reject.test(line) ||
      /^[0-9 .:/-]+$/.test(line) ||
      /@/.test(line) ||
      /^www\./i.test(line)
    ) {
      return;
    }


    let score = 0;

    if (organisation.test(line)) {
      score += 5;
    }

    if (index < 8) {
      score += 2;
    }

    if (/^[A-ZÄÖÜ]/.test(line)) {
      score += 1;
    }

    if (
      line.split(/\s+/).length >= 2 &&
      line.split(/\s+/).length <= 10
    ) {
      score += 1;
    }


    if (
      !best ||
      score > best.score
    ) {
      best = {
        value: line,
        score
      };
    }
  });


  /*
    Unter diesem Wert lassen wir das Feld lieber leer,
    statt einen schlechten Absender vorzuschlagen.
  */
  if (!best || best.score < 6) {
    return null;
  }

  return {
    value: best.value,
    confidence:
      best.score >= 8
        ? 0.90
        : 0.76
  };
}


async function learnFromArchive(
  sender,
  documentType
) {
  let categoryId = null;
  let categoryConfidence = null;
  let tags = [];


  if (sender && sender.length >= 4) {

    const category =
      await pool.query(
        `
        SELECT
          d.category_id,
          COUNT(*)::int AS hits

        FROM documents d

        WHERE
          d.status = 'archived'
          AND d.category_id IS NOT NULL
          AND d.sender IS NOT NULL
          AND (
            LOWER(TRIM(d.sender)) = LOWER(TRIM($1))
            OR LOWER(d.sender) LIKE '%' || LOWER($1) || '%'
            OR LOWER($1) LIKE '%' || LOWER(d.sender) || '%'
          )

        GROUP BY d.category_id

        ORDER BY hits DESC

        LIMIT 1
        `,
        [sender]
      );


    if (category.rowCount === 1) {
      categoryId =
        category.rows[0].category_id;

      categoryConfidence =
        Math.min(
          0.95,
          0.68 +
          Number(category.rows[0].hits) * 0.05
        );
    }


    const tagResult =
      await pool.query(
        `
        SELECT
          t.name,
          COUNT(*)::int AS hits

        FROM documents d

        JOIN document_tags dt
          ON dt.document_id = d.id

        JOIN tags t
          ON t.id = dt.tag_id

        WHERE
          d.status = 'archived'
          AND d.sender IS NOT NULL
          AND (
            LOWER(TRIM(d.sender)) = LOWER(TRIM($1))
            OR LOWER(d.sender) LIKE '%' || LOWER($1) || '%'
            OR LOWER($1) LIKE '%' || LOWER(d.sender) || '%'
          )

        GROUP BY t.id, t.name

        ORDER BY
          hits DESC,
          t.name

        LIMIT 5
        `,
        [sender]
      );

    tags =
      tagResult.rows.map(row => row.name);
  }


  /*
    Wenn wir den Absender noch nicht kennen, kann ein
    häufiger Dokumenttyp wenigstens eine schwächere
    Kategorie-Empfehlung liefern.
  */
  if (
    !categoryId &&
    documentType
  ) {
    const category =
      await pool.query(
        `
        SELECT
          category_id,
          COUNT(*)::int AS hits

        FROM documents

        WHERE
          status = 'archived'
          AND category_id IS NOT NULL
          AND title ILIKE $1

        GROUP BY category_id

        ORDER BY hits DESC

        LIMIT 1
        `,
        [`%${documentType}%`]
      );

    if (
      category.rowCount === 1 &&
      Number(category.rows[0].hits) >= 2
    ) {
      categoryId =
        category.rows[0].category_id;

      categoryConfidence = 0.62;
    }
  }


  /*
    Existiert ein Tag mit exakt dem erkannten Dokumenttyp,
    wird er ebenfalls vorgeschlagen.
  */
  if (documentType) {
    const typeTag =
      await pool.query(
        `
        SELECT name
        FROM tags
        WHERE LOWER(name) = LOWER($1)
        LIMIT 1
        `,
        [documentType]
      );

    if (
      typeTag.rowCount === 1 &&
      !tags.some(
        tag =>
          tag.toLocaleLowerCase('de-DE') ===
          typeTag.rows[0].name.toLocaleLowerCase('de-DE')
      )
    ) {
      tags.push(
        typeTag.rows[0].name
      );
    }
  }


  return {
    categoryId,
    categoryConfidence,
    tags
  };
}


async function analyzeMetadataSuggestions(document) {
  const text =
    String(document.ocr_text || '');

  const date =
    extractDateFromText(text);

  const sender =
    extractSender(text);

  const reference =
    extractReference(text);

  const documentType =
    detectDocumentType(text);


  const learned =
    await learnFromArchive(
      sender?.value || null,
      documentType?.value || null
    );


  const suggestions = {};
  const confidence = {};


  if (date) {
    suggestions.document_date =
      date.value;

    confidence.document_date =
      date.confidence;
  }


  if (sender) {
    suggestions.sender =
      sender.value;

    confidence.sender =
      sender.confidence;
  }


  if (reference) {
    suggestions.reference =
      reference.value;

    confidence.reference =
      reference.confidence;
  }


  if (documentType) {
    suggestions.document_type =
      documentType.value;
  }


  if (learned.categoryId) {
    suggestions.category_id =
      learned.categoryId;

    confidence.category =
      learned.categoryConfidence;
  }


  if (learned.tags.length > 0) {
    suggestions.tags =
      learned.tags;
  }


  /*
    Titel bewusst ohne Absender erzeugen.
    Der Absender besitzt ein eigenes Feld und soll
    im Titel nicht doppelt erscheinen.
  */
  const titleParts = [];

  if (documentType?.value) {
    titleParts.push(
      documentType.value
    );
  }

  if (date?.value) {
    titleParts.push(
      dateLabelDE(date.value)
    );
  }


  /*
    Nur einen Titel vorschlagen, wenn zumindest
    die Dokumentart erkannt wurde.

    Beispiel:
      Rechnung – 12.08.2026
      Bescheid – 03.07.2026
      Vertrag – 21.05.2026
  */
  if (documentType?.value) {
    suggestions.title =
      titleParts.join(' – ');

    confidence.title =
      date?.value
        ? 0.88
        : 0.78;
  }


  suggestions.confidence =
    confidence;


  return suggestions;
}


let suggestionBusy = false;


async function processSuggestionQueue() {
  if (suggestionBusy) {
    return;
  }

  suggestionBusy = true;

  let document = null;


  try {
    const result =
      await pool.query(`
        WITH next_document AS (
          SELECT id

          FROM documents

          WHERE
            status = 'inbox'
            AND ocr_status = 'done'
            AND suggestion_status = 'pending'

          ORDER BY created_at ASC

          LIMIT 1

          FOR UPDATE SKIP LOCKED
        )

        UPDATE documents d

        SET
          suggestion_status = 'processing',
          suggestion_error = NULL

        FROM next_document n

        WHERE d.id = n.id

        RETURNING
          d.id,
          d.original_filename,
          d.ocr_text
      `);


    if (result.rowCount === 0) {
      return;
    }


    document =
      result.rows[0];


    console.log(
      `Metadatenanalyse gestartet: ${document.original_filename}`
    );


    const suggestions =
      await analyzeMetadataSuggestions(
        document
      );


    await pool.query(
      `
      UPDATE documents

      SET
        metadata_suggestions = $1::jsonb,
        suggestion_status = 'done',
        suggestion_error = NULL,
        suggestion_processed_at = NOW()

      WHERE id = $2
      `,
      [
        JSON.stringify(suggestions),
        document.id
      ]
    );


    console.log(
      `Metadatenanalyse abgeschlossen: ${document.original_filename}`
    );


  } catch (err) {

    console.error(
      'Metadatenanalyse fehlgeschlagen:',
      err.message || err
    );


    if (document) {
      await pool.query(
        `
        UPDATE documents

        SET
          suggestion_status = 'error',
          suggestion_error = $1

        WHERE id = $2
        `,
        [
          String(
            err.stack ||
            err.message ||
            err
          ).slice(0, 4000),

          document.id
        ]
      );
    }


  } finally {
    suggestionBusy = false;
  }
}


async function requireLogin(req, res, next) {
  try {
    if (!req.session || !req.session.userId) {
      return res.redirect('/login');
    }

    const result = await pool.query(
      `
      SELECT
        username,
        display_name,
        is_admin,
        is_active
      FROM users
      WHERE id = $1
      `,
      [req.session.userId]
    );

    if (
      result.rowCount !== 1 ||
      !result.rows[0].is_active
    ) {
      return req.session.destroy(() => {
        res.redirect('/login');
      });
    }

    const user = result.rows[0];

    /*
      Sitzungsdaten mit dem aktuellen
      Datenbankstand synchron halten.
    */
    req.session.username =
      user.username;

    req.session.displayName =
      user.display_name ||
      user.username;

    req.session.isAdmin =
      Boolean(user.is_admin);

    res.locals.isAdmin =
      Boolean(user.is_admin);

    res.locals.displayName =
      req.session.displayName;

    next();

  } catch (err) {
    next(err);
  }
}

const upload = multer({
  dest: '/data/temp',
  limits: {
    fileSize: 50 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype === 'application/pdf' ||
      file.originalname.toLowerCase().endsWith('.pdf')
    ) {
      return cb(null, true);
    }

    cb(new Error('Zurzeit werden nur PDF-Dateien unterstützt.'));
  }
});

async function hasPdfSignature(filename) {
  const handle =
    await fs.promises.open(
      filename,
      'r'
    );

  try {
    const buffer =
      Buffer.alloc(5);

    const result =
      await handle.read(
        buffer,
        0,
        5,
        0
      );

    if (result.bytesRead !== 5) {
      return false;
    }

    return (
      buffer.toString(
        'ascii',
        0,
        5
      ) === '%PDF-'
    );

  } finally {
    await handle.close();
  }
}


async function sha256File(filename) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filename);

    stream.on('error', reject);

    stream.on('data', chunk => {
      hash.update(chunk);
    });

    stream.on('end', () => {
      resolve(hash.digest('hex'));
    });
  });
}


async function getPdfPageCount(filename) {
  try {
    const result = await execFileAsync(
      'pdfinfo',
      [filename],
      {
        timeout: 30000,
        maxBuffer: 1024 * 1024
      }
    );

    const match =
      String(result.stdout || '')
        .match(/^Pages:\s+(\d+)/mi);

    return match
      ? Number(match[1])
      : null;

  } catch (err) {
    console.warn(
      `Seitenzahl konnte nicht ermittelt werden: ${filename}`,
      err.message || err
    );

    return null;
  }
}


app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/inbox');
  }

  res.redirect('/login');
});


/* DMS-LOGIN-RATE-LIMIT */

const loginLimiter =
  rateLimit({

    windowMs:
      15 * 60 * 1000,

    limit: 10,

    standardHeaders: true,
    legacyHeaders: false,

    /*
      Erfolgreiche Logins zählen nicht zum Limit.
    */
    skipSuccessfulRequests: true,

    handler: (
      req,
      res
    ) => {

      console.warn(
        'Login-Rate-Limit erreicht:',
        req.ip
      );

      return res
        .status(429)
        .render(
          'login',
          {
            error:
              'Zu viele fehlgeschlagene Anmeldeversuche. ' +
              'Bitte warte einige Minuten und versuche es erneut.'
          }
        );
    }

  });


app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/inbox');
  }

  res.render('login', {
    error: null
  });
});

app.post('/login', loginLimiter, requireCsrf, async (req, res) => {
  try {
    const username =
      String(req.body.username || '').trim();

    const password =
      String(req.body.password || '');

    const result = await pool.query(
      `
      SELECT
        id,
        username,
        password_hash,
        must_change_password
      FROM users
      WHERE username = $1
        AND is_active = TRUE
      `,
      [username]
    );

    if (result.rowCount !== 1) {
      return res.status(401).render('login', {
        error: 'Benutzername oder Passwort falsch.'
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).render('login', {
        error: 'Benutzername oder Passwort falsch.'
      });
    }

    /*
      Nach erfolgreicher Anmeldung neue Session-ID
      erzeugen. Schutz gegen Session-Fixation.
    */
    req.session.regenerate(err => {
      if (err) {
        console.error(err);

        return res.status(500).render('login', {
          error: 'Interner Fehler.'
        });
      }

      req.session.userId = user.id;
      req.session.username = user.username;

      req.session.mustChangePassword =
        Boolean(user.must_change_password);

      req.session.save(err => {
        if (err) {
          console.error(err);

          return res.status(500).render('login', {
            error: 'Interner Fehler.'
          });
        }

        if (req.session.mustChangePassword) {
          return res.redirect(
            '/account?error=' +
            encodeURIComponent(
              'Bitte ändere zuerst das Standardkennwort.'
            )
          );
        }

        res.redirect('/inbox');
      });
    });

  } catch (err) {
    console.error(err);

    res.status(500).render('login', {
      error: 'Interner Fehler.'
    });
  }
});

app.post('/logout', requireLogin, requireCsrf, (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/inbox', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id,
        title,
        original_filename,
        file_size,
        page_count,
        source,
        received_at
      FROM documents
      WHERE status = 'inbox'
      ORDER BY received_at DESC
    `);

    res.render('inbox', {
      username: req.session.username,
      documents: result.rows,
      message: req.query.message || null
    });
  } catch (err) {
    console.error(err);

    res.status(500).send('Interner Fehler');
  }
});

app.post(
  '/upload',
  requireLogin,
  upload.single('document'),
  requireCsrf,
  async (req, res) => {
    if (!req.file) {
      return res.redirect(
        '/inbox?message=' +
        encodeURIComponent('Keine Datei ausgewählt.')
      );
    }

    try {
      const validPdf =
        await hasPdfSignature(
          req.file.path
        );

      if (!validPdf) {
        try {
          fs.unlinkSync(
            req.file.path
          );
        } catch (unlinkErr) {
          console.warn(
            'Ungültige Upload-Datei konnte nicht gelöscht werden:',
            unlinkErr.message || unlinkErr
          );
        }

        return res.status(400).send(
          'Die hochgeladene Datei ist keine gültige PDF-Datei.'
        );
      }

      const checksum = await sha256File(req.file.path);
      const pageCount = await getPdfPageCount(req.file.path);

      const duplicate = await pool.query(
        `
        SELECT
          id,
          title,
          original_filename,
          status,
          document_date,
          received_at,
          archived_at

        FROM documents

        WHERE sha256 = $1

        LIMIT 1
        `,
        [checksum]
      );


      if (duplicate.rowCount > 0) {

        fs.unlinkSync(
          req.file.path
        );


        const existing =
          duplicate.rows[0];


        const statusLabel =
          existing.status === 'archived'
            ? 'Archiv'
            : (
                existing.status === 'inbox'
                  ? 'Sammler'
                  : (
                      existing.status === 'trash'
                        ? 'Papierkorb'
                        : existing.status
                    )
              );


        const dateValue =
          existing.document_date ||
          existing.archived_at ||
          existing.received_at;


        let dateLabel = '';

        if (dateValue) {

          const date =
            new Date(dateValue);

          if (
            !Number.isNaN(
              date.getTime()
            )
          ) {

            dateLabel =
              date.toLocaleDateString(
                'de-DE'
              );
          }
        }


        const existingTitle =
          existing.title ||
          existing.original_filename ||
          'Unbenanntes Dokument';


        let duplicateMessage =
          `Dokument bereits vorhanden: „${existingTitle}“ · ${statusLabel}`;


        if (dateLabel) {

          duplicateMessage +=
            ` · ${dateLabel}`;
        }


        return res.redirect(
          '/inbox?message=' +
          encodeURIComponent(
            duplicateMessage
          )
        );
      }

      const id = crypto.randomUUID();
      const storedFilename = `${id}.pdf`;
      const destination = path.join(
        '/data/originals',
        storedFilename
      );

try {
  fs.renameSync(
    req.file.path,
    destination
  );
} catch (err) {
  if (err.code === 'EXDEV') {
    fs.copyFileSync(
      req.file.path,
      destination
    );

    fs.unlinkSync(
      req.file.path
    );
  } else {
    throw err;
  }
}

      const title =
        path.parse(req.file.originalname).name ||
        'Unbenanntes Dokument';

      await pool.query(
        `
        INSERT INTO documents (
          id,
          title,
          original_filename,
          storage_path,
          mime_type,
          file_size,
          sha256,
          page_count,
          source,
          status
        )
        VALUES (
          $1, $2, $3, $4, $5,
          $6, $7, $8, 'upload', 'inbox'
        )
        `,
        [
          id,
          title,
          req.file.originalname,
          destination,
          req.file.mimetype || 'application/pdf',
          req.file.size,
          checksum,
          pageCount
        ]
      );

      res.redirect(
        '/inbox?message=' +
        encodeURIComponent(
          'Dokument wurde dem Sammler hinzugefügt.'
        )
      );
    } catch (err) {
      console.error(err);

      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }

      res.status(500).send('Upload fehlgeschlagen.');
    }
  }
);

app.get(
  '/documents/:id/file',
  requireLogin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          storage_path,
          ocr_path,
          ocr_status,
          original_filename
        FROM documents
        WHERE id = $1
        `,
        [req.params.id]
      );

      if (result.rowCount !== 1) {
        return res.status(404).send('Dokument nicht gefunden.');
      }

      const document = result.rows[0];

      const filePath =
        document.ocr_status === 'done' &&
        document.ocr_path &&
        fs.existsSync(document.ocr_path)
          ? document.ocr_path
          : document.storage_path;

      if (!fs.existsSync(filePath)) {
        return res.status(404).send('Datei nicht gefunden.');
      }

      res.setHeader(
        'Content-Disposition',
        `inline; filename*=UTF-8''${encodeURIComponent(document.original_filename)}`
      );

      res.type('application/pdf');
      fs.createReadStream(filePath).pipe(res);
    } catch (err) {
      console.error(err);
      res.status(500).send('Interner Fehler.');
    }
  }
);


/* -------------------------------------------------------
   Dokument einsortieren
------------------------------------------------------- */

/* -------------------------------------------------------
   Kategorien
------------------------------------------------------- */

/* DMS-SORT-ROUTES */

/* -------------------------------------------------------
   Dokument einsortieren / bearbeiten
------------------------------------------------------- */

app.get('/documents/:id/sort', requireLogin, async (req, res) => {
  try {
    const documentResult = await pool.query(
      `
      SELECT *
      FROM documents
      WHERE id = $1
      `,
      [req.params.id]
    );

    if (documentResult.rowCount !== 1) {
      return res.status(404).send('Dokument nicht gefunden.');
    }

    const categoriesResult = await pool.query(`
      SELECT
        c.id,
        c.name,
        c.parent_id,
        p.name AS parent_name
      FROM categories c
      LEFT JOIN categories p
        ON p.id = c.parent_id
      ORDER BY
        COALESCE(p.name, c.name),
        CASE WHEN c.parent_id IS NULL THEN 0 ELSE 1 END,
        c.name
    `);

    const tagsResult = await pool.query(
      `
      SELECT t.name
      FROM tags t
      JOIN document_tags dt
        ON dt.tag_id = t.id
      WHERE dt.document_id = $1
      ORDER BY t.name
      `,
      [req.params.id]
    );

    res.render('sort', {
      username: req.session.username,
      document: documentResult.rows[0],
      categories: categoriesResult.rows,
      tags: tagsResult.rows.map(row => row.name).join(', '),
      defaultCategoryId: settingsCache.default_category_id || ''
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Interner Fehler.');
  }
});


app.post('/documents/:id/archive', requireLogin, requireCsrf, async (req, res) => {
  const client = await pool.connect();

  try {
    const title = String(req.body.title || '').trim();
    const documentDate = req.body.document_date || null;
    const sender = String(req.body.sender || '').trim() || null;
    const reference = String(req.body.reference || '').trim() || null;
    const notes = String(req.body.notes || '').trim() || null;
    const categoryId = req.body.category_id || null;

    if (!title) {
      return res.status(400).send('Ein Titel ist erforderlich.');
    }

    const tagNames = [];
    const seenTags = new Set();

    for (const rawTag of String(req.body.tags || '').split(',')) {
      const tag = rawTag.trim();

      if (!tag) continue;

      const key = tag.toLocaleLowerCase('de-DE');

      if (!seenTags.has(key)) {
        seenTags.add(key);
        tagNames.push(tag);
      }
    }

    await client.query('BEGIN');

    const updateResult = await client.query(
      `
      UPDATE documents
      SET
        title = $1,
        document_date = $2,
        sender = $3,
        reference = $4,
        notes = $5,
        category_id = $6,
        status = 'archived',
        archived_at = COALESCE(archived_at, NOW())
      WHERE id = $7
      RETURNING id
      `,
      [
        title,
        documentDate,
        sender,
        reference,
        notes,
        categoryId,
        req.params.id
      ]
    );

    if (updateResult.rowCount !== 1) {
      throw new Error('Dokument nicht gefunden.');
    }

    await client.query(
      'DELETE FROM document_tags WHERE document_id = $1',
      [req.params.id]
    );

    for (const tagName of tagNames) {
      const existing = await client.query(
        `
        SELECT id
        FROM tags
        WHERE LOWER(name) = LOWER($1)
        LIMIT 1
        `,
        [tagName]
      );

      let tagId;

      if (existing.rowCount === 1) {
        tagId = existing.rows[0].id;
      } else {
        tagId = crypto.randomUUID();

        await client.query(
          `
          INSERT INTO tags (id, name)
          VALUES ($1, $2)
          `,
          [tagId, tagName]
        );
      }

      await client.query(
        `
        INSERT INTO document_tags (document_id, tag_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        `,
        [req.params.id, tagId]
      );
    }

    await client.query('COMMIT');


    const afterArchive =
      String(
        req.body.after_archive || ''
      ).trim();


    /*
      Stapelverarbeitung:
      Nach dem Archivieren direkt das nächste
      Dokument aus dem Sammler öffnen.
    */
    if (afterArchive === 'next') {

      const nextResult =
        await pool.query(`
          SELECT id

          FROM documents

          WHERE status = 'inbox'

          ORDER BY
            received_at DESC,
            created_at DESC

          LIMIT 1
        `);


      if (nextResult.rowCount === 1) {

        return res.redirect(
          `/documents/${nextResult.rows[0].id}/sort`
        );
      }


      return res.redirect(
        '/inbox?message=' +
        encodeURIComponent(
          'Dokument wurde archiviert. Der Sammler ist leer.'
        )
      );
    }


    res.redirect(
      '/documents?message=' +
      encodeURIComponent(
        'Dokument wurde archiviert.'
      )
    );

  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).send('Archivieren fehlgeschlagen.');

  } finally {
    client.release();
  }
});


/* -------------------------------------------------------
   Kategorien
------------------------------------------------------- */

app.get('/categories', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        c.id,
        c.name,
        c.parent_id,
        p.name AS parent_name
      FROM categories c
      LEFT JOIN categories p
        ON p.id = c.parent_id
      ORDER BY
        COALESCE(p.name, c.name),
        CASE WHEN c.parent_id IS NULL THEN 0 ELSE 1 END,
        c.name
    `);

    res.render('categories', {
      username: req.session.username,
      categories: result.rows
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Interner Fehler.');
  }
});


app.post('/categories/create', requireLogin, requireCsrf, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const parentId = req.body.parent_id || null;

    const requestedReturn = String(
      req.body.return_to || '/categories'
    );

    const returnTo =
      requestedReturn === '/categories' ||
      requestedReturn.startsWith('/documents/')
        ? requestedReturn
        : '/categories';

    if (!name) {
      return res.status(400).send('Kategoriename fehlt.');
    }

    const duplicate = await pool.query(
      `
      SELECT id
      FROM categories
      WHERE LOWER(name) = LOWER($1)
        AND parent_id IS NOT DISTINCT FROM $2::uuid
      `,
      [name, parentId]
    );

    if (duplicate.rowCount === 0) {
      await pool.query(
        `
        INSERT INTO categories (
          id,
          name,
          parent_id
        )
        VALUES ($1, $2, $3)
        `,
        [
          crypto.randomUUID(),
          name,
          parentId
        ]
      );
    }

    res.redirect(returnTo);

  } catch (err) {
    console.error(err);
    res.status(500).send('Kategorie konnte nicht angelegt werden.');
  }
});


/* -------------------------------------------------------
   Dokumentenarchiv
------------------------------------------------------- */

app.get('/documents', requireLogin, async (req, res) => {
  try {
    const categoryId =
      String(req.query.category || '').trim();

    const from =
      String(req.query.from || '').trim();

    const to =
      String(req.query.to || '').trim();


    const conditions = [
      `d.status = 'archived'`
    ];

    const params = [];


    /*
      Wird eine Hauptkategorie gewählt,
      werden ihre direkten Unterkategorien
      automatisch mit eingeschlossen.
    */
    if (categoryId) {
      params.push(categoryId);

      conditions.push(`
        (
          d.category_id = $${params.length}::uuid
          OR c.parent_id = $${params.length}::uuid
        )
      `);
    }


    if (from) {
      params.push(from);

      conditions.push(`
        COALESCE(
          d.document_date,
          d.received_at::date
        ) >= $${params.length}::date
      `);
    }


    if (to) {
      params.push(to);

      conditions.push(`
        COALESCE(
          d.document_date,
          d.received_at::date
        ) <= $${params.length}::date
      `);
    }


    const documentsResult =
      await pool.query(
        `
        SELECT
          d.id,
          d.title,
          d.original_filename,
          d.document_date,
          d.received_at,
          d.archived_at,
          d.sender,
          d.reference,
          d.file_size,
          d.page_count,
          d.ocr_status,

          c.name AS category_name,
          c.parent_id AS category_parent_id,
          p.name AS parent_category_name,

          COALESCE(
            (
              SELECT STRING_AGG(
                t.name,
                ', '
                ORDER BY t.name
              )
              FROM document_tags dt
              JOIN tags t
                ON t.id = dt.tag_id
              WHERE dt.document_id = d.id
            ),
            ''
          ) AS tags

        FROM documents d

        LEFT JOIN categories c
          ON c.id = d.category_id

        LEFT JOIN categories p
          ON p.id = c.parent_id

        WHERE
          ${conditions.join('\n AND ')}

        ORDER BY
          COALESCE(
            d.document_date,
            d.received_at::date
          ) DESC,
          d.archived_at DESC
        `,
        params
      );


    const archiveStatsResult =
      await pool.query(`
        SELECT
          COUNT(*)::int AS document_count,

          COALESCE(
            SUM(file_size),
            0
          )::bigint AS total_bytes,

          COALESCE(
            SUM(page_count),
            0
          )::bigint AS total_pages

        FROM documents

        WHERE status = 'archived'
      `);


    const archiveStats =
      archiveStatsResult.rows[0];


    const categoriesResult =
      await pool.query(`
        SELECT
          c.id,
          c.name,
          c.parent_id,
          p.name AS parent_name

        FROM categories c

        LEFT JOIN categories p
          ON p.id = c.parent_id

        ORDER BY
          COALESCE(p.name, c.name),
          CASE
            WHEN c.parent_id IS NULL THEN 0
            ELSE 1
          END,
          c.name
      `);


    res.render('archive', {
      username: req.session.username,

      documents: documentsResult.rows,
      categories: categoriesResult.rows,
      archiveStats,

      filters: {
        category: categoryId,
        from,
        to
      },

      message:
        req.query.message || null
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Interner Fehler.');
  }
});


/* -------------------------------------------------------
   Dokument-Detailansicht
------------------------------------------------------- */

app.get('/documents/:id', requireLogin, async (req, res) => {
  try {
    const result =
      await pool.query(
        `
        SELECT
          d.id,
          d.title,
          d.original_filename,
          d.document_date,
          d.received_at,
          d.archived_at,
          d.sender,
          d.reference,
          d.notes,
          d.source,
          d.file_size,
          d.page_count,
          d.sha256,
          d.ocr_status,
          d.ocr_processed_at,
          LENGTH(
            COALESCE(
              d.ocr_text,
              ''
            )
          ) AS ocr_chars,

          c.name AS category_name,
          p.name AS parent_category_name,

          COALESCE(
            (
              SELECT STRING_AGG(
                t.name,
                ', '
                ORDER BY t.name
              )
              FROM document_tags dt
              JOIN tags t
                ON t.id = dt.tag_id
              WHERE dt.document_id = d.id
            ),
            ''
          ) AS tags

        FROM documents d

        LEFT JOIN categories c
          ON c.id = d.category_id

        LEFT JOIN categories p
          ON p.id = c.parent_id

        WHERE
          d.id = $1
          AND d.status = 'archived'
        `,
        [req.params.id]
      );


    if (result.rowCount !== 1) {
      return res
        .status(404)
        .send('Dokument nicht gefunden.');
    }


    res.render('document', {
      username: req.session.username,
      document: result.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Interner Fehler.');
  }
});


/* DMS-TIMELINE-SEARCH */

/* -------------------------------------------------------
   Chronologische Ansicht
------------------------------------------------------- */

app.get('/timeline', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        d.id,
        d.title,
        d.sender,
        d.reference,
        d.file_size,

        TO_CHAR(
          d.document_date,
          'YYYY-MM-DD'
        ) AS document_date_iso,

        TO_CHAR(
          COALESCE(
            d.document_date,
            d.received_at::date
          ),
          'YYYY-MM-DD'
        ) AS sort_date_iso,

        c.name AS category_name,
        p.name AS parent_category_name,

        COALESCE(
          (
            SELECT STRING_AGG(
              t.name,
              ', '
              ORDER BY t.name
            )
            FROM document_tags dt
            JOIN tags t
              ON t.id = dt.tag_id
            WHERE dt.document_id = d.id
          ),
          ''
        ) AS tags

      FROM documents d

      LEFT JOIN categories c
        ON c.id = d.category_id

      LEFT JOIN categories p
        ON p.id = c.parent_id

      WHERE d.status = 'archived'

      ORDER BY
        COALESCE(
          d.document_date,
          d.received_at::date
        ) DESC,
        d.archived_at DESC
    `);

    const formatterMonth =
      new Intl.DateTimeFormat(
        'de-DE',
        {
          month: 'long',
          year: 'numeric',
          timeZone: 'UTC'
        }
      );

    const formatterDate =
      new Intl.DateTimeFormat(
        'de-DE',
        {
          day: '2-digit',
          month: '2-digit',
          year: 'numeric',
          timeZone: 'UTC'
        }
      );

    const groups = [];

    for (const doc of result.rows) {
      const [year, month, day] =
        doc.sort_date_iso.split('-').map(Number);

      const date = new Date(
        Date.UTC(
          year,
          month - 1,
          day
        )
      );

      const monthKey =
        `${year}-${String(month).padStart(2, '0')}`;

      const monthLabel =
        formatterMonth.format(date);

      doc.date_label =
        formatterDate.format(date);

      let group =
        groups[groups.length - 1];

      if (!group || group.key !== monthKey) {
        group = {
          key: monthKey,
          label: monthLabel,
          documents: []
        };

        groups.push(group);
      }

      group.documents.push(doc);
    }

    res.render('timeline', {
      username: req.session.username,
      groups
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Interner Fehler.');
  }
});


/* -------------------------------------------------------
   Suche
------------------------------------------------------- */

app.get('/search', requireLogin, async (req, res) => {
  try {
    const q =
      String(req.query.q || '').trim();

    let documents = [];

    if (q) {
      const pattern = `%${q}%`;

      const result = await pool.query(
        `
        SELECT
          d.id,
          d.title,
          d.sender,
          d.reference,
          d.notes,

          TO_CHAR(
            d.document_date,
            'YYYY-MM-DD'
          ) AS document_date_iso,

          c.name AS category_name,
          p.name AS parent_category_name,

          COALESCE(
            (
              SELECT STRING_AGG(
                t.name,
                ', '
                ORDER BY t.name
              )
              FROM document_tags dt
              JOIN tags t
                ON t.id = dt.tag_id
              WHERE dt.document_id = d.id
            ),
            ''
          ) AS tags

        FROM documents d

        LEFT JOIN categories c
          ON c.id = d.category_id

        LEFT JOIN categories p
          ON p.id = c.parent_id

        WHERE d.status = 'archived'

          AND (
            d.title ILIKE $1

            OR COALESCE(
              d.sender,
              ''
            ) ILIKE $1

            OR COALESCE(
              d.reference,
              ''
            ) ILIKE $1

            OR COALESCE(
              d.notes,
              ''
            ) ILIKE $1

            OR COALESCE(
              d.ocr_text,
              ''
            ) ILIKE $1

            OR COALESCE(
              c.name,
              ''
            ) ILIKE $1

            OR COALESCE(
              p.name,
              ''
            ) ILIKE $1

            OR EXISTS (
              SELECT 1
              FROM document_tags dt2
              JOIN tags t2
                ON t2.id = dt2.tag_id
              WHERE
                dt2.document_id = d.id
                AND t2.name ILIKE $1
            )
          )

        ORDER BY
          d.document_date DESC NULLS LAST,
          d.archived_at DESC

        LIMIT 500
        `,
        [pattern]
      );

      documents = result.rows;
    }

    res.render('search', {
      username: req.session.username,
      q,
      documents
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Suche fehlgeschlagen.');
  }
});



/* DMS-TRASH-CATEGORY-EDIT */

/* -------------------------------------------------------
   Papierkorb
------------------------------------------------------- */

app.post('/documents/:id/trash', requireLogin, requireCsrf, async (req, res) => {
  try {
    const result = await pool.query(
      `
      UPDATE documents
      SET
        previous_status = status,
        status = 'trash',
        deleted_at = NOW()
      WHERE
        id = $1
        AND status <> 'trash'
      RETURNING id
      `,
      [req.params.id]
    );

    if (result.rowCount !== 1) {
      return res.status(404).send('Dokument nicht gefunden.');
    }

    const returnTo =
      String(req.body.return_to || '/documents');

    const allowed =
      returnTo === '/inbox' ||
      returnTo === '/documents' ||
      returnTo === '/timeline';

    const destination =
      allowed
        ? returnTo
        : '/documents';


    res.redirect(
      destination +
      '?message=' +
      encodeURIComponent(
        'Dokument wurde in den Papierkorb verschoben.'
      )
    );

  } catch (err) {
    console.error(err);
    res.status(500).send('Dokument konnte nicht gelöscht werden.');
  }
});


app.get('/trash', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        d.id,
        d.title,
        d.original_filename,
        d.document_date,
        d.received_at,
        d.deleted_at,
        d.previous_status,
        d.sender,
        d.file_size,

        c.name AS category_name,
        p.name AS parent_category_name

      FROM documents d

      LEFT JOIN categories c
        ON c.id = d.category_id

      LEFT JOIN categories p
        ON p.id = c.parent_id

      WHERE d.status = 'trash'

      ORDER BY d.deleted_at DESC
    `);

    res.render('trash', {
      username: req.session.username,
      documents: result.rows,
      message: req.query.message || null
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Papierkorb konnte nicht geladen werden.');
  }
});


app.post('/trash/:id/restore', requireLogin, requireCsrf, async (req, res) => {
  try {
    const result = await pool.query(
      `
      UPDATE documents
      SET
        status = CASE
          WHEN previous_status IN ('inbox', 'archived')
            THEN previous_status
          ELSE 'archived'
        END,
        previous_status = NULL,
        deleted_at = NULL
      WHERE
        id = $1
        AND status = 'trash'
      RETURNING id
      `,
      [req.params.id]
    );

    if (result.rowCount !== 1) {
      return res.status(404).send('Dokument nicht gefunden.');
    }

    res.redirect(
      '/trash?message=' +
      encodeURIComponent('Dokument wurde wiederhergestellt.')
    );

  } catch (err) {
    console.error(err);
    res.status(500).send('Wiederherstellung fehlgeschlagen.');
  }
});


app.post('/trash/:id/delete', requireAdmin, requireCsrf, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const result = await client.query(
      `
      SELECT
        storage_path,
        ocr_path
      FROM documents
      WHERE
        id = $1
        AND status = 'trash'
      FOR UPDATE
      `,
      [req.params.id]
    );

    if (result.rowCount !== 1) {
      await client.query('ROLLBACK');
      return res.status(404).send('Dokument nicht gefunden.');
    }

    const document = result.rows[0];

    await client.query(
      `
      DELETE FROM documents
      WHERE
        id = $1
        AND status = 'trash'
      `,
      [req.params.id]
    );

    await client.query('COMMIT');

    for (const filePath of [
      document.storage_path,
      document.ocr_path
    ]) {
      if (
        filePath &&
        fs.existsSync(filePath)
      ) {
        fs.unlinkSync(filePath);
      }
    }

    res.redirect(
      '/trash?message=' +
      encodeURIComponent('Dokument wurde endgültig gelöscht.')
    );

  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).send('Endgültiges Löschen fehlgeschlagen.');

  } finally {
    client.release();
  }
});


/* -------------------------------------------------------
   Kategorien bearbeiten
------------------------------------------------------- */

app.post('/categories/:id/update', requireLogin, requireCsrf, async (req, res) => {
  try {
    const id = req.params.id;
    const name = String(req.body.name || '').trim();
    const parentId = req.body.parent_id || null;

    if (!name) {
      return res.status(400).send('Kategoriename fehlt.');
    }

    if (parentId === id) {
      return res.status(400).send(
        'Eine Kategorie kann nicht ihre eigene Oberkategorie sein.'
      );
    }

    /*
      Kategorien mit Unterkategorien bleiben Hauptkategorien,
      damit wir keine dritte Hierarchieebene erzeugen.
    */
    if (parentId) {
      const children = await pool.query(
        `
        SELECT COUNT(*)::int AS count
        FROM categories
        WHERE parent_id = $1
        `,
        [id]
      );

      if (children.rows[0].count > 0) {
        return res.status(400).send(
          'Eine Hauptkategorie mit Unterkategorien kann nicht selbst Unterkategorie werden.'
        );
      }

      const validParent = await pool.query(
        `
        SELECT id
        FROM categories
        WHERE
          id = $1
          AND parent_id IS NULL
        `,
        [parentId]
      );

      if (validParent.rowCount !== 1) {
        return res.status(400).send(
          'Ungültige Hauptkategorie.'
        );
      }
    }

    const duplicate = await pool.query(
      `
      SELECT id
      FROM categories
      WHERE
        LOWER(name) = LOWER($1)
        AND parent_id IS NOT DISTINCT FROM $2::uuid
        AND id <> $3
      `,
      [name, parentId, id]
    );

    if (duplicate.rowCount > 0) {
      return res.status(400).send(
        'Diese Kategorie existiert an dieser Stelle bereits.'
      );
    }

    const result = await pool.query(
      `
      UPDATE categories
      SET
        name = $1,
        parent_id = $2
      WHERE id = $3
      RETURNING id
      `,
      [name, parentId, id]
    );

    if (result.rowCount !== 1) {
      return res.status(404).send('Kategorie nicht gefunden.');
    }

    res.redirect('/categories');

  } catch (err) {
    console.error(err);
    res.status(500).send('Kategorie konnte nicht geändert werden.');
  }
});


app.post('/categories/:id/delete', requireLogin, requireCsrf, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const children = await client.query(
      `
      SELECT COUNT(*)::int AS count
      FROM categories
      WHERE parent_id = $1
      `,
      [req.params.id]
    );

    if (children.rows[0].count > 0) {
      await client.query('ROLLBACK');

      return res.status(400).send(
        'Diese Kategorie besitzt Unterkategorien. Diese müssen zuerst verschoben oder gelöscht werden.'
      );
    }

    /*
      Dokumente bleiben vollständig erhalten und
      werden lediglich auf "ohne Kategorie" gesetzt.
    */
    await client.query(
      `
      UPDATE documents
      SET category_id = NULL
      WHERE category_id = $1
      `,
      [req.params.id]
    );

    const result = await client.query(
      `
      DELETE FROM categories
      WHERE id = $1
      RETURNING id
      `,
      [req.params.id]
    );

    if (result.rowCount !== 1) {
      await client.query('ROLLBACK');
      return res.status(404).send('Kategorie nicht gefunden.');
    }

    await client.query('COMMIT');

    res.redirect('/categories');

  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).send('Kategorie konnte nicht gelöscht werden.');

  } finally {
    client.release();
  }
});




/* DMS-TAG-AUTOCOMPLETE */

/* -------------------------------------------------------
   Tag-Autovervollständigung
------------------------------------------------------- */

app.get('/api/tags', requireLogin, async (req, res) => {
  try {
    const q =
      String(req.query.q || '').trim();

    const pattern =
      `%${q}%`;

    const result = await pool.query(
      `
      SELECT
        t.name,
        COUNT(dt.document_id)::int AS usage_count

      FROM tags t

      LEFT JOIN document_tags dt
        ON dt.tag_id = t.id

      WHERE
        $1 = ''
        OR t.name ILIKE $2

      GROUP BY
        t.id,
        t.name

      ORDER BY
        CASE
          WHEN LOWER(t.name) = LOWER($1)
            THEN 0
          WHEN LOWER(t.name) LIKE LOWER($1) || '%'
            THEN 1
          ELSE 2
        END,

        COUNT(dt.document_id) DESC,
        t.name

      LIMIT 15
      `,
      [
        q,
        pattern
      ]
    );

    res.json(
      result.rows.map(row => ({
        name: row.name,
        usageCount: row.usage_count
      }))
    );

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Tags konnten nicht geladen werden.'
    });
  }
});




/* DMS-SETTINGS */

/* -------------------------------------------------------
   Einstellungen
------------------------------------------------------- */


/* DMS-SYSTEM-STATUS */

app.get('/system', requireAdmin, async (req, res) => {
  try {

    let hostStatus = null;
    let hostStatusError = null;

    try {
      const raw =
        fs.readFileSync(
          '/data/status/system.json',
          'utf8'
        );

      hostStatus =
        JSON.parse(raw);

    } catch (err) {

      hostStatusError =
        String(
          err.message ||
          err
        );
    }


    const dbStarted =
      Date.now();

    await pool.query(
      'SELECT 1'
    );

    const dbLatencyMs =
      Date.now() -
      dbStarted;


    const documentStatsResult =
      await pool.query(`
        SELECT

          COUNT(*) FILTER (
            WHERE status = 'inbox'
          )::int AS inbox_count,

          COUNT(*) FILTER (
            WHERE status = 'archived'
          )::int AS archived_count,

          COUNT(*) FILTER (
            WHERE ocr_status = 'pending'
          )::int AS ocr_pending,

          COUNT(*) FILTER (
            WHERE ocr_status = 'processing'
          )::int AS ocr_processing,

          COUNT(*) FILTER (
            WHERE ocr_status = 'error'
          )::int AS ocr_errors,

          COUNT(*) FILTER (
            WHERE suggestion_status = 'pending'
          )::int AS suggestion_pending,

          COUNT(*) FILTER (
            WHERE suggestion_status = 'processing'
          )::int AS suggestion_processing,

          COUNT(*) FILTER (
            WHERE suggestion_status = 'error'
          )::int AS suggestion_errors

        FROM documents
      `);


    const mailStatsResult =
      await pool.query(`
        SELECT

          COUNT(*)::int AS total,

          COUNT(*) FILTER (
            WHERE status = 'error'
          )::int AS errors,

          COUNT(*) FILTER (
            WHERE status = 'processed'
               OR status = 'done'
               OR status = 'imported'
          )::int AS successful,

          MAX(imported_at) AS last_imported_at,

          MAX(created_at) AS last_seen_at

        FROM mail_imports
      `);


    const latestOcrResult =
      await pool.query(`
        SELECT
          MAX(ocr_processed_at) AS last_ocr_at,
          MAX(suggestion_processed_at) AS last_suggestion_at
        FROM documents
      `);


    res.render(
      'system',
      {
        username:
          req.session.username,

        hostStatus,
        hostStatusError,

        dbLatencyMs,

        documentStats:
          documentStatsResult.rows[0],

        mailStats:
          mailStatsResult.rows[0],

        latestProcessing:
          latestOcrResult.rows[0]
      }
    );


  } catch (err) {

    console.error(
      'Systemstatus:',
      err
    );

    res
      .status(500)
      .send(
        'Systemstatus konnte nicht geladen werden.'
      );
  }
});



/* DMS-ERROR-CENTER */


/* -------------------------------------------------------
   Fehlerübersicht
------------------------------------------------------- */

app.get(
  '/system/errors',
  requireAdmin,
  async (req, res) => {

    try {

      const ocrErrors =
        await pool.query(`
          SELECT
            id,
            title,
            original_filename,
            ocr_error,
            ocr_processed_at,
            created_at

          FROM documents

          WHERE ocr_status = 'error'

          ORDER BY created_at DESC
        `);


      const suggestionErrors =
        await pool.query(`
          SELECT
            id,
            title,
            original_filename,
            suggestion_error,
            suggestion_processed_at,
            created_at

          FROM documents

          WHERE suggestion_status = 'error'

          ORDER BY created_at DESC
        `);


      const mailErrors =
        await pool.query(`
          SELECT
            id,
            sender,
            subject,
            received_at,
            error,
            created_at,
            imported_at

          FROM mail_imports

          WHERE status = 'error'

          ORDER BY created_at DESC
        `);


      res.render(
        'system-errors',
        {
          username:
            req.session.username,

          ocrErrors:
            ocrErrors.rows,

          suggestionErrors:
            suggestionErrors.rows,

          mailErrors:
            mailErrors.rows,

          message:
            req.query.message ||
            null
        }
      );


    } catch (err) {

      console.error(
        'Fehlerzentrale:',
        err
      );

      res
        .status(500)
        .send(
          'Fehlerzentrale konnte nicht geladen werden.'
        );
    }
  }
);


/* -------------------------------------------------------
   OCR erneut versuchen
------------------------------------------------------- */

app.post(
  '/system/errors/ocr/:id/retry',
  requireAdmin,
  requireCsrf,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            id,
            ocr_path

          FROM documents

          WHERE id = $1
          `,
          [
            req.params.id
          ]
        );


      if (result.rowCount !== 1) {

        return res.redirect(
          '/system/errors?message=' +
          encodeURIComponent(
            'Dokument wurde nicht gefunden.'
          )
        );
      }


      const document =
        result.rows[0];


      /*
        Eventuell vorhandene fehlerhafte OCR-Ausgabe
        entfernen. Originaldateien werden niemals
        angefasst.
      */
      if (
        document.ocr_path &&
        String(
          document.ocr_path
        ).startsWith(
          '/data/documents/'
        )
      ) {

        try {

          if (
            fs.existsSync(
              document.ocr_path
            )
          ) {

            fs.unlinkSync(
              document.ocr_path
            );
          }

        } catch (err) {

          console.warn(
            'Alte OCR-Datei konnte nicht entfernt werden:',
            err.message
          );
        }
      }


      await pool.query(
        `
        UPDATE documents

        SET
          ocr_status = 'pending',
          ocr_error = NULL,
          ocr_processed_at = NULL,
          ocr_path = NULL,

          suggestion_status = 'pending',
          suggestion_error = NULL,
          suggestion_processed_at = NULL,
          metadata_suggestions = '{}'::jsonb

        WHERE id = $1
        `,
        [
          req.params.id
        ]
      );


      return res.redirect(
        '/system/errors?message=' +
        encodeURIComponent(
          'OCR wurde erneut in die Warteschlange gestellt.'
        )
      );


    } catch (err) {

      console.error(
        'OCR-Retry:',
        err
      );

      return res.redirect(
        '/system/errors?message=' +
        encodeURIComponent(
          'OCR konnte nicht erneut gestartet werden.'
        )
      );
    }
  }
);


/* -------------------------------------------------------
   Metadatenanalyse erneut versuchen
------------------------------------------------------- */

app.post(
  '/system/errors/metadata/:id/retry',
  requireAdmin,
  requireCsrf,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          UPDATE documents

          SET
            suggestion_status = 'pending',
            suggestion_error = NULL,
            suggestion_processed_at = NULL,
            metadata_suggestions = '{}'::jsonb

          WHERE
            id = $1
            AND ocr_status = 'done'

          RETURNING id
          `,
          [
            req.params.id
          ]
        );


      if (result.rowCount !== 1) {

        return res.redirect(
          '/system/errors?message=' +
          encodeURIComponent(
            'Metadatenanalyse kann erst nach erfolgreicher OCR erneut gestartet werden.'
          )
        );
      }


      return res.redirect(
        '/system/errors?message=' +
        encodeURIComponent(
          'Metadatenanalyse wurde erneut in die Warteschlange gestellt.'
        )
      );


    } catch (err) {

      console.error(
        'Metadaten-Retry:',
        err
      );

      return res.redirect(
        '/system/errors?message=' +
        encodeURIComponent(
          'Metadatenanalyse konnte nicht erneut gestartet werden.'
        )
      );
    }
  }
);


app.get('/settings', requireAdmin, async (req, res) => {
  try {
    const categoriesResult =
      await pool.query(`
        SELECT
          c.id,
          c.name,
          c.parent_id,
          p.name AS parent_name

        FROM categories c

        LEFT JOIN categories p
          ON p.id = c.parent_id

        ORDER BY
          COALESCE(p.name, c.name),
          CASE
            WHEN c.parent_id IS NULL THEN 0
            ELSE 1
          END,
          c.name
      `);

    const mailResult =
      await pool.query(`
        SELECT
          enabled,
          host,
          port,
          secure,
          username,
          password_enc,
          mailbox,
          processed_folder,
          poll_seconds
        FROM mail_settings
        WHERE id = 1
      `);

    const mail =
      mailResult.rows[0];

    res.render('settings', {
      username: req.session.username,
      settings: settingsCache,
      categories: categoriesResult.rows,

      mailSettings: {
        enabled: Boolean(mail?.enabled),
        host: mail?.host || '',
        port: mail?.port || 993,
        secure: mail?.secure !== false,
        username: mail?.username || '',
        passwordConfigured:
          Boolean(mail?.password_enc),
        mailbox: mail?.mailbox || 'INBOX',
        processedFolder:
          mail?.processed_folder ||
          'DMS-Importiert',
        pollSeconds:
          mail?.poll_seconds || 30
      },

      message: req.query.message || null
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Einstellungen konnten nicht geladen werden.');
  }
});


/*
  IMAP-Verbindung testen.

  Es werden weder Einstellungen gespeichert
  noch Nachrichten importiert oder verschoben.
*/
app.post(
  '/settings/mail/test',
  requireAdmin,
  requireCsrf,
  async (req, res) => {

    let imap = null;
    let lock = null;

    try {

      const host =
        String(
          req.body.mail_host || ''
        ).trim();

      const port =
        Number(
          req.body.mail_port || 993
        );

      const secure =
        req.body.mail_secure === 'on';

      const username =
        String(
          req.body.mail_username || ''
        ).trim();

      let password =
        String(
          req.body.mail_password || ''
        );

      const mailbox =
        String(
          req.body.mail_mailbox || 'INBOX'
        ).trim() || 'INBOX';


      if (!host) {
        return res
          .status(400)
          .send(
            'IMAP-Test fehlgeschlagen: ' +
            'Server fehlt.'
          );
      }


      if (
        !Number.isInteger(port) ||
        port < 1 ||
        port > 65535
      ) {
        return res
          .status(400)
          .send(
            'IMAP-Test fehlgeschlagen: ' +
            'Port ist ungültig.'
          );
      }


      if (!username) {
        return res
          .status(400)
          .send(
            'IMAP-Test fehlgeschlagen: ' +
            'Benutzername fehlt.'
          );
      }


      /*
        Leeres Passwortfeld:
        bereits gespeichertes Kennwort verwenden.
      */
      if (!password) {

        const result =
          await pool.query(`
            SELECT password_enc
            FROM mail_settings
            WHERE id = 1
          `);

        const encrypted =
          result.rows[0]?.password_enc || '';

        if (encrypted) {
          password =
            decryptMailPassword(
              encrypted
            );
        }
      }


      if (!password) {
        return res
          .status(400)
          .send(
            'IMAP-Test fehlgeschlagen: ' +
            'Kennwort fehlt.'
          );
      }


      imap =
        new ImapFlow({
          host,
          port,
          secure,

          auth: {
            user: username,
            pass: password
          },

          logger: false
        });


      await imap.connect();

      lock =
        await imap.getMailboxLock(
          mailbox
        );


      /*
        Bis hierhin erfolgreich:
        Verbindung, Anmeldung und Zugriff
        auf das Postfach funktionieren.
      */
      lock.release();
      lock = null;

      await imap.logout();
      imap = null;


      return res
        .status(200)
        .send(
          'IMAP-Verbindung erfolgreich. ' +
          'Anmeldung und Zugriff auf das Postfach "' +
          mailbox +
          '" funktionieren. ' +
          'Es wurden keine Nachrichten verändert.'
        );


    } catch (err) {

      console.error(
        'IMAP-Verbindungstest fehlgeschlagen:',
        err
      );


      if (lock) {
        try {
          lock.release();
        } catch {}
      }


      if (imap) {
        try {
          await imap.logout();
        } catch {}
      }


      const code =
        err && err.code
          ? ' (' + String(err.code) + ')'
          : '';


      return res
        .status(400)
        .send(
          'IMAP-Verbindung fehlgeschlagen' +
          code +
          '. Bitte Server, Port, TLS, ' +
          'Benutzername, Kennwort und Postfach prüfen.'
        );
    }
  }
);


app.post('/settings', requireAdmin, requireCsrf, async (req, res) => {
  const client = await pool.connect();

  try {
    const appName =
      String(req.body.app_name || '').trim()
      || 'Dokumentenarchiv';

    const allowedLanguages =
      new Set([
        'deu',
        'eng',
        'nld',
        'swe'
      ]);

    let languages =
      req.body.ocr_languages || [];

    if (!Array.isArray(languages)) {
      languages = [languages];
    }

    languages =
      languages
        .map(value => String(value))
        .filter(value => allowedLanguages.has(value));

    if (languages.length === 0) {
      return res
        .status(400)
        .send('Mindestens eine OCR-Sprache muss aktiviert sein.');
    }

    const ocrLanguages =
      languages.join('+');

    const requireDocumentDate =
      req.body.require_document_date === 'on'
        ? 'true'
        : 'false';

    const defaultCategoryId =
      String(
        req.body.default_category_id || ''
      ).trim();


    const mailEnabled =
      req.body.mail_enabled === 'on';

    const mailHost =
      String(
        req.body.mail_host || ''
      ).trim();

    const mailPort =
      Number(
        req.body.mail_port || 993
      );

    const mailSecure =
      req.body.mail_secure === 'on';

    const mailUsername =
      String(
        req.body.mail_username || ''
      ).trim();

    const mailPassword =
      String(
        req.body.mail_password || ''
      );

    const mailMailbox =
      String(
        req.body.mail_mailbox || 'INBOX'
      ).trim() || 'INBOX';

    const mailProcessedFolder =
      String(
        req.body.mail_processed_folder ||
        'DMS-Importiert'
      ).trim() || 'DMS-Importiert';

    const mailPollSeconds =
      Number(
        req.body.mail_poll_seconds || 30
      );


    if (
      !Number.isInteger(mailPort) ||
      mailPort < 1 ||
      mailPort > 65535
    ) {
      return res
        .status(400)
        .send('Ungültiger IMAP-Port.');
    }


    if (
      !Number.isInteger(mailPollSeconds) ||
      mailPollSeconds < 10 ||
      mailPollSeconds > 3600
    ) {
      return res
        .status(400)
        .send(
          'Das Mail-Abfrageintervall muss ' +
          'zwischen 10 und 3600 Sekunden liegen.'
        );
    }


    if (
      mailEnabled &&
      (!mailHost || !mailUsername)
    ) {
      return res
        .status(400)
        .send(
          'Für einen aktiven Mailimport müssen ' +
          'IMAP-Server und Benutzername angegeben werden.'
        );
    }


    const currentMail =
      await client.query(`
        SELECT password_enc
        FROM mail_settings
        WHERE id = 1
      `);

    const existingMailPassword =
      currentMail.rows[0]?.password_enc || '';

    const effectiveMailPassword =
      mailPassword
        ? encryptMailPassword(mailPassword)
        : existingMailPassword;


    if (
      mailEnabled &&
      !effectiveMailPassword
    ) {
      return res
        .status(400)
        .send(
          'Für einen aktiven Mailimport ' +
          'muss ein IMAP-Kennwort hinterlegt sein.'
        );
    }


    if (defaultCategoryId) {
      const category =
        await client.query(
          `
          SELECT id
          FROM categories
          WHERE id = $1
          `,
          [defaultCategoryId]
        );

      if (category.rowCount !== 1) {
        return res
          .status(400)
          .send('Die gewählte Standardkategorie existiert nicht.');
      }
    }


    await client.query('BEGIN');

    await saveAppSetting(
      'app_name',
      appName,
      client
    );

    await saveAppSetting(
      'ocr_languages',
      ocrLanguages,
      client
    );

    await saveAppSetting(
      'require_document_date',
      requireDocumentDate,
      client
    );

    await saveAppSetting(
      'default_category_id',
      defaultCategoryId,
      client
    );


    await client.query(
      `
      UPDATE mail_settings
      SET
        enabled = $1,
        host = $2,
        port = $3,
        secure = $4,
        username = $5,
        password_enc = $6,
        mailbox = $7,
        processed_folder = $8,
        poll_seconds = $9,
        updated_at = NOW()
      WHERE id = 1
      `,
      [
        mailEnabled,
        mailHost,
        mailPort,
        mailSecure,
        mailUsername,
        effectiveMailPassword,
        mailMailbox,
        mailProcessedFolder,
        mailPollSeconds
      ]
    );

    await client.query('COMMIT');


    res.redirect(
      '/settings?message=' +
      encodeURIComponent(
        'Einstellungen wurden gespeichert.'
      )
    );

  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    console.error(err);

    /*
      Cache sicherheitshalber wieder aus DB laden,
      falls eine Transaktion fehlgeschlagen ist.
    */
    try {
      await loadAppSettings();
    } catch {}

    res.status(500).send(
      'Einstellungen konnten nicht gespeichert werden.'
    );

  } finally {
    client.release();
  }
});




/* DMS-USER-MANAGEMENT-FIX */

/* -------------------------------------------------------
   Benutzerverwaltung
------------------------------------------------------- */

app.get('/users', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id,
        username,
        display_name,
        is_admin,
        is_active,
        created_at,
        last_login_at
      FROM users
      ORDER BY
        is_admin DESC,
        username
    `);

    res.render('users', {
      username: req.session.username,
      currentUserId: req.session.userId,
      users: result.rows,
      message: req.query.message || null
    });

  } catch (err) {
    console.error(err);
    res.status(500).send(
      'Benutzerverwaltung konnte nicht geladen werden.'
    );
  }
});


app.post('/users/create', requireAdmin, requireCsrf, async (req, res) => {
  try {
    const username =
      String(req.body.username || '').trim();

    const displayName =
      String(req.body.display_name || '').trim();

    const password =
      String(req.body.password || '');

    const isAdmin =
      req.body.is_admin === 'on';

    if (!username) {
      return res.status(400).send(
        'Benutzername fehlt.'
      );
    }

    if (!/^[A-Za-z0-9._-]{3,50}$/.test(username)) {
      return res.status(400).send(
        'Der Benutzername muss 3–50 Zeichen lang sein.'
      );
    }

    if (password.length < 10) {
      return res.status(400).send(
        'Das Passwort muss mindestens 10 Zeichen lang sein.'
      );
    }

    const duplicate = await pool.query(
      `
      SELECT id
      FROM users
      WHERE LOWER(username) = LOWER($1)
      `,
      [username]
    );

    if (duplicate.rowCount > 0) {
      return res.status(400).send(
        'Dieser Benutzername existiert bereits.'
      );
    }

    const hash =
      await bcrypt.hash(password, 12);

    await pool.query(
      `
      INSERT INTO users (
        id,
        username,
        display_name,
        password_hash,
        is_admin,
        is_active
      )
      VALUES (
        $1, $2, $3, $4, $5, TRUE
      )
      `,
      [
        crypto.randomUUID(),
        username,
        displayName || username,
        hash,
        isAdmin
      ]
    );

    res.redirect(
      '/users?message=' +
      encodeURIComponent(
        `Benutzer "${username}" wurde angelegt.`
      )
    );

  } catch (err) {
    console.error(err);
    res.status(500).send(
      'Benutzer konnte nicht angelegt werden.'
    );
  }
});


app.post('/users/:id/update', requireAdmin, requireCsrf, async (req, res) => {
  try {
    const id = req.params.id;

    const displayName =
      String(req.body.display_name || '').trim();

    const isAdmin =
      req.body.is_admin === 'on';

    const isActive =
      req.body.is_active === 'on';

    const existing = await pool.query(
      `
      SELECT
        id,
        username
      FROM users
      WHERE id = $1
      `,
      [id]
    );

    if (existing.rowCount !== 1) {
      return res.status(404).send(
        'Benutzer nicht gefunden.'
      );
    }

    if (id === req.session.userId) {
      if (!isAdmin) {
        return res.status(400).send(
          'Du kannst dir deine eigenen Administratorrechte nicht entziehen.'
        );
      }

      if (!isActive) {
        return res.status(400).send(
          'Du kannst dein eigenes Benutzerkonto nicht deaktivieren.'
        );
      }
    }

    await pool.query(
      `
      UPDATE users
      SET
        display_name = $1,
        is_admin = $2,
        is_active = $3
      WHERE id = $4
      `,
      [
        displayName || existing.rows[0].username,
        isAdmin,
        isActive,
        id
      ]
    );

    res.redirect(
      '/users?message=' +
      encodeURIComponent(
        'Benutzer wurde aktualisiert.'
      )
    );

  } catch (err) {
    console.error(err);
    res.status(500).send(
      'Benutzer konnte nicht geändert werden.'
    );
  }
});


app.post('/users/:id/password', requireAdmin, requireCsrf, async (req, res) => {
  try {
    const password =
      String(req.body.password || '');

    if (password.length < 10) {
      return res.status(400).send(
        'Das neue Passwort muss mindestens 10 Zeichen lang sein.'
      );
    }

    const existing = await pool.query(
      `
      SELECT username
      FROM users
      WHERE id = $1
      `,
      [req.params.id]
    );

    if (existing.rowCount !== 1) {
      return res.status(404).send(
        'Benutzer nicht gefunden.'
      );
    }

    const hash =
      await bcrypt.hash(password, 12);

    await pool.query(
      `
      UPDATE users
      SET password_hash = $1
      WHERE id = $2
      `,
      [
        hash,
        req.params.id
      ]
    );

    res.redirect(
      '/users?message=' +
      encodeURIComponent(
        'Passwort wurde geändert.'
      )
    );

  } catch (err) {
    console.error(err);
    res.status(500).send(
      'Passwort konnte nicht geändert werden.'
    );
  }
});



/* DMS-ACCOUNT */

/* -------------------------------------------------------
   Eigenes Benutzerkonto
------------------------------------------------------- */

app.get('/account', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        username,
        display_name,
        is_admin,
        created_at,
        last_login_at
      FROM users
      WHERE id = $1
      `,
      [req.session.userId]
    );

    if (result.rowCount !== 1) {
      return res.status(404).send(
        'Benutzerkonto nicht gefunden.'
      );
    }

    res.render('account', {
      username: req.session.username,
      user: result.rows[0],
      message: req.query.message || null,
      error: req.query.error || null
    });

  } catch (err) {
    console.error(err);
    res.status(500).send(
      'Benutzerkonto konnte nicht geladen werden.'
    );
  }
});


app.post(
  '/account/password/change',
  requireLogin,
  requireCsrf,
  async (req, res) => {
    try {
      const currentPassword =
        String(req.body.current_password || '');

      const newPassword =
        String(req.body.new_password || '');

      const confirmPassword =
        String(req.body.confirm_password || '');


      if (newPassword.length < 10) {
        return res.redirect(
          '/account?error=' +
          encodeURIComponent(
            'Das neue Passwort muss mindestens 10 Zeichen lang sein.'
          )
        );
      }


      if (newPassword !== confirmPassword) {
        return res.redirect(
          '/account?error=' +
          encodeURIComponent(
            'Die beiden neuen Passwörter stimmen nicht überein.'
          )
        );
      }


      const result = await pool.query(
        `
        SELECT password_hash
        FROM users
        WHERE id = $1
          AND is_active = TRUE
        `,
        [req.session.userId]
      );


      if (result.rowCount !== 1) {
        return res.redirect('/login');
      }


      const valid =
        await bcrypt.compare(
          currentPassword,
          result.rows[0].password_hash
        );


      if (!valid) {
        return res.redirect(
          '/account?error=' +
          encodeURIComponent(
            'Das aktuelle Passwort ist nicht korrekt.'
          )
        );
      }


      const hash =
        await bcrypt.hash(
          newPassword,
          12
        );


      await pool.query(
        `
        UPDATE users
        SET
          password_hash = $1,
          must_change_password = FALSE
        WHERE id = $2
        `,
        [
          hash,
          req.session.userId
        ]
      );

      req.session.mustChangePassword = false;


      res.redirect(
        '/account?message=' +
        encodeURIComponent(
          'Dein Passwort wurde geändert.'
        )
      );

    } catch (err) {
      console.error(err);

      res.status(500).send(
        'Passwort konnte nicht geändert werden.'
      );
    }
  }
);


app.use((err, req, res, next) => {
  console.error(err);

  res.status(400).send(
    err.message || 'Fehler bei der Verarbeitung.'
  );
});

async function start() {
  await initDatabase();
  await loadAppSettings();

  await pool.query(`
    UPDATE documents
    SET ocr_status = 'pending'
    WHERE ocr_status = 'processing'
  `);

  setTimeout(() => {
    processOcrQueue().catch(console.error);
  }, 1500);

  setInterval(() => {
    processOcrQueue().catch(console.error);
  }, 5000);

  await pool.query(`
    UPDATE documents
    SET suggestion_status = 'pending'
    WHERE suggestion_status = 'processing'
  `);

  setTimeout(() => {
    processSuggestionQueue().catch(console.error);
  }, 3000);

  setInterval(() => {
    processSuggestionQueue().catch(console.error);
  }, 5000);

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`DMS läuft auf Port ${PORT}`);
  });
}

start().catch(err => {
  console.error('Start fehlgeschlagen:', err);
  process.exit(1);
});
