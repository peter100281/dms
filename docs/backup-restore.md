# Backup und Wiederherstellung

Ein vollständiges DMS-Backup sollte sowohl die Datenbank als auch die
gespeicherten Dokumente und die lokale Konfiguration umfassen.

Nur die PDF-Dateien zu sichern reicht nicht aus.

## Relevante Daten

Unterhalb von `DMS_DATA_DIR` befinden sich unter anderem:

~~~text
postgres/
redis/
originals/
documents/
mail/
temp/
status/
backups/
~~~

Besonders wichtig für eine Wiederherstellung sind:

~~~text
postgres/
originals/
documents/
mail/
~~~

Zusätzlich muss die lokale Datei `.env` separat und sicher gesichert
werden.

## APP_SECRET

`APP_SECRET` ist besonders wichtig.

Das gespeicherte IMAP-Kennwort wird mit einem aus `APP_SECRET`
abgeleiteten Schlüssel verschlüsselt.

Geht `APP_SECRET` verloren oder wird es verändert, kann ein bereits
gespeichertes IMAP-Kennwort nicht mehr entschlüsselt werden.

Das Kennwort muss dann erneut in den Einstellungen eingegeben werden.

## PostgreSQL logisch sichern

Zusätzlich zu einem Dateisystem- oder VM-Backup empfiehlt sich ein
logischer PostgreSQL-Dump.

Beispiel:

~~~bash
docker compose exec -T postgres \
  sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' \
  > dms-postgres.sql
~~~

Die erzeugte Datei kann sensible Daten enthalten und muss entsprechend
geschützt werden.

## PostgreSQL-Dump komprimieren

Optional:

~~~bash
gzip dms-postgres.sql
~~~

Dadurch entsteht:

~~~text
dms-postgres.sql.gz
~~~

## Dokumentdateien sichern

Für eine möglichst konsistente Sicherung sollten Schreibzugriffe während
des Backups vermieden werden.

Eine einfache Vorgehensweise ist:

~~~bash
docker compose stop app mail-importer
~~~

Danach können die relevanten Verzeichnisse unter `DMS_DATA_DIR`
gesichert werden.

Anschließend:

~~~bash
docker compose up -d
~~~

## Beispiel für ein Datei-Backup

Bei Verwendung des Standardpfads:

~~~bash
tar -czf dms-files.tar.gz \
  /data/dms/originals \
  /data/dms/documents \
  /data/dms/mail
~~~

Bei einem abweichenden `DMS_DATA_DIR` muss der Pfad entsprechend
angepasst werden.

## Gesamtes Datenverzeichnis

Alternativ kann das vollständige Datenverzeichnis gesichert werden.

Beispiel:

~~~bash
tar -czf dms-data.tar.gz /data/dms
~~~

Dabei können je nach Datenmenge sehr große Backup-Dateien entstehen.

## .env sichern

Die Datei `.env` enthält wichtige Konfigurations- und Geheimwerte.

Sie sollte separat gesichert werden:

~~~bash
cp .env /sicherer/backup-pfad/dms.env
chmod 600 /sicherer/backup-pfad/dms.env
~~~

Die Datei darf nicht öffentlich zugänglich sein.

## Wiederherstellung der Dateien

Vor einer Wiederherstellung sollte zunächst die aktuelle Installation
gesichert werden.

Danach die schreibenden Dienste stoppen:

~~~bash
docker compose stop app mail-importer
~~~

Die gesicherten Daten anschließend in den vorgesehenen `DMS_DATA_DIR`
zurückkopieren.

Danach:

~~~bash
docker compose up -d
~~~

## PostgreSQL-Dump wiederherstellen

Ein unkomprimierter Dump kann beispielsweise so eingespielt werden:

~~~bash
cat dms-postgres.sql | \
docker compose exec -T postgres \
  sh -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"'
~~~

Bei einem mit `gzip` komprimierten Dump:

~~~bash
gzip -dc dms-postgres.sql.gz | \
docker compose exec -T postgres \
  sh -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"'
~~~

Die Datenbank muss zum Stand des Dumps passen.

## VM- und Host-Backups

Snapshots oder vollständige VM-Backups sind eine sinnvolle zusätzliche
Sicherungsebene.

Sie können insbesondere eine schnelle Wiederherstellung des kompletten
Systems ermöglichen.

Sie ersetzen jedoch nicht zwingend ein geprüftes anwendungsbezogenes
Backup.

## Backup-Prüfung

Ein Backup sollte nicht nur erstellt, sondern auch regelmäßig geprüft
werden.

Empfohlen wird:

- PostgreSQL-Dump auf Lesbarkeit prüfen
- Backup-Archive auf Fehler prüfen
- Dateigrößen kontrollieren
- regelmäßig eine Test-Wiederherstellung durchführen
- mehrere Generationen aufbewahren
- mindestens eine Kopie außerhalb des DMS-Hosts speichern

## Nicht in Git speichern

Folgende Inhalte gehören nicht in das Git-Repository:

~~~text
.env
Datenbank-Dumps
PDF-Dokumente
Backup-Archive
private Schlüssel
Mail-Zugangsdaten
~~~

Die mitgelieferte `.gitignore` schließt typische lokale Backup-Dateien
und `.env` bereits aus.

## Nach einer Wiederherstellung prüfen

Nach einem Restore sollten mindestens geprüft werden:

~~~bash
docker compose ps
docker compose logs --since=5m app
docker compose logs --since=5m mail-importer
~~~

Zusätzlich in der Weboberfläche prüfen:

- Login
- Archiv
- Dokumentvorschau
- Suche
- Einstellungen
- Systemstatus
- Mailimport
