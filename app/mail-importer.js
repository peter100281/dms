const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const { Pool } = require('pg');

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');


if (!process.env.APP_SECRET) {
  throw new Error('APP_SECRET fehlt');
}


const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});


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
      'Unbekanntes Format des gespeicherten IMAP-Kennworts.'
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


async function loadMailSettings() {

  const result =
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

  if (result.rowCount !== 1) {
    return {
      enabled: false,
      host: '',
      port: 993,
      secure: true,
      username: '',
      password: '',
      mailbox: 'INBOX',
      processedFolder: 'DMS-Importiert',
      pollSeconds: 30
    };
  }

  const row =
    result.rows[0];

  const pollSeconds =
    Math.min(
      3600,
      Math.max(
        10,
        Number(row.poll_seconds || 30)
      )
    );

  return {
    enabled:
      Boolean(row.enabled),

    host:
      String(row.host || '').trim(),

    port:
      Number(row.port || 993),

    secure:
      Boolean(row.secure),

    username:
      String(row.username || '').trim(),

    password:
      decryptMailPassword(
        row.password_enc || ''
      ),

    mailbox:
      String(row.mailbox || 'INBOX').trim()
      || 'INBOX',

    processedFolder:
      String(
        row.processed_folder ||
        'DMS-Importiert'
      ).trim(),

    pollSeconds
  };
}


function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}


function sha256(buffer) {
  return crypto
    .createHash('sha256')
    .update(buffer)
    .digest('hex');
}


function safeTitle(filename) {
  const title =
    path.parse(filename || '').name.trim();

  return title || 'Scan per E-Mail';
}


function getSender(parsed) {
  if (parsed.from && parsed.from.text) {
    return parsed.from.text;
  }

  return null;
}


async function ensureProcessedFolder(
  client,
  processedFolder
) {
  if (!processedFolder) {
    return;
  }

  console.log(
    `Prüfe IMAP-Ordner "${processedFolder}".`
  );

  try {
    const result =
      await client.mailboxCreate(
        [processedFolder]
      );

    if (result.created) {
      console.log(
        `IMAP-Ordner angelegt: ${result.path}`
      );
    } else {
      console.log(
        `IMAP-Ordner vorhanden: ${result.path}`
      );
    }

  } catch (err) {
    console.error(
      'Ordner konnte nicht angelegt/geprüft werden.'
    );

    console.error(
      'Message:',
      err.message
    );

    console.error(
      'Code:',
      err.code
    );

    console.error(
      'Response:',
      err.response || ''
    );

    console.error(
      'ResponseStatus:',
      err.responseStatus || ''
    );

    console.error(
      'ServerResponseCode:',
      err.serverResponseCode || ''
    );

    throw err;
  }
}


async function registerMail(
  mailbox,
  uidValidity,
  message,
  parsed
) {
  const existing =
    await pool.query(
      `
      SELECT id
      FROM mail_imports
      WHERE
        mailbox = $1
        AND uidvalidity = $2
        AND uid = $3
      `,
      [
        mailbox,
        uidValidity,
        message.uid
      ]
    );

  if (existing.rowCount === 1) {
    const id =
      existing.rows[0].id;

    await pool.query(
      `
      UPDATE mail_imports
      SET
        status = 'processing',
        error = NULL
      WHERE id = $1
      `,
      [id]
    );

    return id;
  }


  const id =
    crypto.randomUUID();

  await pool.query(
    `
    INSERT INTO mail_imports (
      id,
      mailbox,
      uidvalidity,
      uid,
      message_id,
      sender,
      subject,
      received_at,
      status
    )

    VALUES (
      $1, $2, $3, $4,
      $5, $6, $7, $8,
      'processing'
    )
    `,
    [
      id,
      mailbox,
      uidValidity,
      message.uid,

      parsed.messageId || null,
      getSender(parsed),
      parsed.subject || null,

      parsed.date ||
      message.envelope?.date ||
      new Date()
    ]
  );

  return id;
}


async function processMessage(
  mailbox,
  uidValidity,
  message
) {
  let importId = null;

  try {
    const raw =
      Buffer.isBuffer(message.source)
        ? message.source
        : Buffer.from(message.source);


    const parsed =
      await simpleParser(raw);


    importId =
      await registerMail(
        mailbox,
        uidValidity,
        message,
        parsed
      );


    /*
      Original-Mail dauerhaft speichern.
    */

    const emlPath =
      `/data/mail/${importId}.eml`;

    if (!fs.existsSync(emlPath)) {
      fs.writeFileSync(
        emlPath,
        raw,
        {
          mode: 0o640
        }
      );
    }


    await pool.query(
      `
      UPDATE mail_imports
      SET eml_path = $1
      WHERE id = $2
      `,
      [
        emlPath,
        importId
      ]
    );


    /*
      Nur PDF-Anhänge werden als Dokument
      übernommen.
    */

    const pdfAttachments =
      (parsed.attachments || [])
        .filter(attachment => {

          const filename =
            String(
              attachment.filename || ''
            ).toLowerCase();

          const contentType =
            String(
              attachment.contentType || ''
            ).toLowerCase();

          return (
            contentType === 'application/pdf' ||
            filename.endsWith('.pdf')
          );
        });


    let importedCount = 0;
    let duplicateCount = 0;


    for (
      let index = 0;
      index < pdfAttachments.length;
      index++
    ) {
      const attachment =
        pdfAttachments[index];

      const content =
        Buffer.isBuffer(attachment.content)
          ? attachment.content
          : Buffer.from(attachment.content);


      const hash =
        sha256(content);


      /*
        Prüfen, ob genau diese Datei schon
        vorhanden ist.
      */

      const duplicate =
        await pool.query(
          `
          SELECT id
          FROM documents
          WHERE sha256 = $1
          `,
          [hash]
        );


      if (duplicate.rowCount > 0) {
        duplicateCount++;

        console.log(
          `Duplikat übersprungen: ${
            attachment.filename ||
            'PDF-Anhang'
          }`
        );

        continue;
      }


      const documentId =
        crypto.randomUUID();


      let originalFilename =
        attachment.filename;


      if (!originalFilename) {
        originalFilename =
          `Scan-${documentId}.pdf`;
      }


      if (
        !originalFilename
          .toLowerCase()
          .endsWith('.pdf')
      ) {
        originalFilename += '.pdf';
      }


      const destination =
        `/data/originals/${documentId}.pdf`;


      fs.writeFileSync(
        destination,
        content,
        {
          mode: 0o640,
          flag: 'wx'
        }
      );


      try {
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

            source,
            status,

            received_at,

            source_email_from,
            source_email_subject,
            source_email_message_id,

            ocr_status
          )

          VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            'email',
            'inbox',
            $8,
            $9, $10, $11,
            'pending'
          )
          `,
          [
            documentId,
            safeTitle(originalFilename),
            originalFilename,
            destination,
            'application/pdf',
            content.length,
            hash,

            parsed.date ||
            message.envelope?.date ||
            new Date(),

            getSender(parsed),
            parsed.subject || null,
            parsed.messageId || null
          ]
        );

        importedCount++;

        console.log(
          `PDF importiert: ${originalFilename}`
        );

      } catch (err) {

        if (fs.existsSync(destination)) {
          fs.unlinkSync(destination);
        }

        throw err;
      }
    }


    let status;

    if (pdfAttachments.length === 0) {
      status = 'no_pdf';

    } else if (
      importedCount === 0 &&
      duplicateCount > 0
    ) {
      status = 'duplicate';

    } else {
      status = 'imported';
    }


    await pool.query(
      `
      UPDATE mail_imports
      SET
        attachment_count = $1,
        imported_count = $2,
        duplicate_count = $3,
        status = $4,
        error = NULL,
        imported_at = NOW()

      WHERE id = $5
      `,
      [
        pdfAttachments.length,
        importedCount,
        duplicateCount,
        status,
        importId
      ]
    );


    console.log(
      `Mail verarbeitet: ${
        parsed.subject || '(ohne Betreff)'
      } | PDF: ${
        pdfAttachments.length
      } | neu: ${
        importedCount
      } | Duplikate: ${
        duplicateCount
      }`
    );


    return true;

  } catch (err) {

    console.error(
      'Mailimport fehlgeschlagen:',
      err.message || err
    );


    if (importId) {
      await pool.query(
        `
        UPDATE mail_imports
        SET
          status = 'error',
          error = $1
        WHERE id = $2
        `,
        [
          String(
            err.stack ||
            err.message ||
            err
          ).slice(0, 4000),

          importId
        ]
      );
    }


    /*
      Die Mail bleibt im Eingang und wird
      beim nächsten Lauf erneut versucht.
    */

    return false;
  }
}


async function pollMailbox(settings) {

  const {
    host,
    port,
    secure,
    username,
    password,
    mailbox,
    processedFolder
  } = settings;

  if (!host) {
    throw new Error(
      'IMAP-Server ist nicht gesetzt.'
    );
  }

  if (!username) {
    throw new Error(
      'IMAP-Benutzername ist nicht gesetzt.'
    );
  }

  if (!password) {
    throw new Error(
      'IMAP-Kennwort ist nicht gesetzt.'
    );
  }


  const client =
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


  try {
    console.log('IMAP: Verbindung herstellen ...');
    await client.connect();
    console.log('IMAP: Verbindung und Anmeldung erfolgreich.');

    await ensureProcessedFolder(
      client,
      processedFolder
    );


    console.log(
      `IMAP: Öffne Postfach "${mailbox}" ...`
    );

    const lock =
      await client.getMailboxLock(
        mailbox
      );

    console.log(
      `IMAP: Postfach geöffnet. Nachrichten: ${client.mailbox.exists}`
    );


    try {

      if (client.mailbox.exists === 0) {
        console.log('IMAP: Eingang ist leer.');
        return;
      }


      const uidValidity =
        String(
          client.mailbox.uidValidity || ''
        );


      /*
        Maximal 50 Mails pro Durchlauf.
        Importierte Nachrichten werden danach
        aus INBOX herausgeschoben.
      */

      console.log(
        'IMAP: Lade Nachrichten aus dem Eingang ...'
      );

      const fetchCount =
        Math.min(
          client.mailbox.exists,
          50
        );

      const fetchRange =
        `1:${fetchCount}`;

      console.log(
        `IMAP: FETCH-Bereich ${fetchRange}`
      );

      const messages =
        await client.fetchAll(
          fetchRange,
          {
            uid: true,
            envelope: true,
            source: true
          }
        );

      console.log(
        `IMAP: ${messages.length} Nachricht(en) geladen.`
      );


      const moveUids = [];


      for (const message of messages) {

        console.log(
          `IMAP: Verarbeite UID ${message.uid} ...`
        );

        const success =
          await processMessage(
            mailbox,
            uidValidity,
            message
          );


        if (success) {
          moveUids.push(
            message.uid
          );
        }
      }


      /*
        Erst nachdem alle Nachrichten
        verarbeitet wurden verschieben.
      */

      if (
        moveUids.length > 0 &&
        processedFolder
      ) {
        console.log(
          `IMAP: Verschiebe UIDs ${moveUids.join(', ')} nach "${processedFolder}" ...`
        );

        await client.messageMove(
          moveUids,
          [processedFolder],
          {
            uid: true
          }
        );

        console.log(
          `${moveUids.length} Mail(s) nach "${processedFolder}" verschoben.`
        );
      }


    } finally {
      lock.release();
    }


  } finally {

    try {
      await client.logout();
    } catch {
      // Verbindung war eventuell bereits geschlossen.
    }

  }
}


async function main() {

  console.log(
    'Scanner-Mailimport gestartet.'
  );

  let previousEnabled = null;

  while (true) {

    let pollSeconds = 30;

    try {

      const settings =
        await loadMailSettings();

      pollSeconds =
        settings.pollSeconds;

      if (!settings.enabled) {

        if (previousEnabled !== false) {
          console.log(
            'Scanner-Mailimport ist deaktiviert.'
          );
        }

        previousEnabled = false;

      } else {

        if (previousEnabled !== true) {
          console.log(
            `Scanner-Mailimport aktiv: ${
              settings.username
            }@${
              settings.host
            }`
          );

          console.log(
            `Postfach: ${settings.mailbox}`
          );

          console.log(
            `Intervall: ${
              settings.pollSeconds
            } Sekunden`
          );
        }

        previousEnabled = true;

        await pollMailbox(settings);
      }

    } catch (err) {

      console.error(
        '========== MAILIMPORT FEHLER =========='
      );

      console.error(
        'Message:',
        err.message || ''
      );

      console.error(
        'Code:',
        err.code || ''
      );

      console.error(
        '======================================='
      );
    }


    await sleep(
      pollSeconds * 1000
    );
  }
}


main().catch(err => {
  console.error(err);
  process.exit(1);
});
