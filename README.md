# DMS

Ein selbst gehostetes Dokumentenmanagementsystem für die private
Dokumentenablage.

Das DMS läuft vollständig auf der eigenen Infrastruktur und verwendet
Docker Compose, PostgreSQL und Redis. Dokumente können manuell oder über
ein IMAP-Postfach importiert, per OCR verarbeitet und anschließend
kategorisiert, verschlagwortet und durchsucht werden.

## Funktionen

- Dokumenten-Sammler für neue Dokumente
- Archivansicht
- chronologische Timeline
- Volltextsuche
- Kategorien und Tags
- PDF-Vorschau
- OCR mit mehreren Sprachen
- SHA-256-basierte Duplikaterkennung
- automatischer PDF-Import aus einem IMAP-Postfach
- verschlüsselte Speicherung des IMAP-Kennworts
- IMAP-Verbindungstest in der Weboberfläche
- Benutzerverwaltung
- Administrator- und Benutzerkonten
- Systemstatus für Docker-Container und Speicher
- PostgreSQL als Datenbank
- Redis für Laufzeitdaten
- persistente Speicherung auf dem Host
- Docker-Compose-Installation

## Voraussetzungen

Empfohlen wird ein aktuelles Linux-System mit:

- Docker Engine
- Docker Compose Plugin
- mindestens 2 GB RAM
- ausreichend Speicherplatz für Dokumente und Datenbank

Für OCR und größere Dokumentbestände sind mehr Arbeitsspeicher und
CPU-Leistung sinnvoll.

## Schnellstart

Repository klonen und in das Projektverzeichnis wechseln:

~~~bash
git clone https://github.com/peter100281/dms.git
cd dms
~~~

Beispielkonfiguration kopieren:

~~~bash
cp .env.example .env
chmod 600 .env
~~~

Anschließend die Werte in `.env` anpassen.

Sichere Zufallswerte können beispielsweise erzeugt werden mit:

~~~bash
openssl rand -hex 32
~~~

Danach starten:

~~~bash
docker compose up -d --build
~~~

Standardmäßig lauscht das DMS nur auf:

~~~text
127.0.0.1:3000
~~~

## Erster Login

Bei einer neuen, leeren Installation wird automatisch ein
Administratorkonto erzeugt:

~~~text
Benutzername: admin
Passwort:     admin
~~~

Beim ersten Login muss das Kennwort geändert werden.

Das DMS sollte nicht öffentlich erreichbar gemacht werden, bevor dieses
Kennwort geändert wurde.

## Datenverzeichnis

Der Speicherort der persistenten Daten wird über folgende Variable
konfiguriert:

~~~dotenv
DMS_DATA_DIR=/data/dms
~~~

Der Pfad kann an die eigene Umgebung angepasst werden.

Beispiel:

~~~dotenv
DMS_DATA_DIR=/srv/dms
~~~

## Mailimport

Die IMAP-Konfiguration erfolgt nach der Installation über:

~~~text
Einstellungen -> Scanner / Mailimport
~~~

Das IMAP-Kennwort wird verschlüsselt in PostgreSQL gespeichert.

Der dafür verwendete Schlüssel wird aus `APP_SECRET` abgeleitet.

**Wichtig:** `APP_SECRET` sollte nach der Einrichtung nicht verändert
werden. Andernfalls kann ein bereits gespeichertes IMAP-Kennwort nicht
mehr entschlüsselt werden und muss erneut eingegeben werden.

Weitere Informationen:

[Mailimport](docs/mail-import.md)

## Systemstatus

Das DMS kann zusätzliche Informationen über den Host und die
Docker-Container anzeigen.

Der optionale Collector wird installiert mit:

~~~bash
sudo ./scripts/install-system-stats.sh
~~~

Er aktualisiert die Statusinformationen standardmäßig einmal pro Minute.

## Reverse Proxy und HTTPS

Für produktiven Betrieb wird ein HTTPS-Reverse-Proxy empfohlen.

Hinweise zu `COOKIE_SECURE`, `TRUST_PROXY` und der lokalen Bind-Adresse:

[Reverse Proxy](docs/reverse-proxy.md)

## Dokumentation

Ausführliche Anleitungen:

- [Installation](docs/installation.md)
- [Mailimport](docs/mail-import.md)
- [Reverse Proxy](docs/reverse-proxy.md)
- [Backup und Wiederherstellung](docs/backup-restore.md)

## Sicherheit

Die Datei `.env` enthält geheime Zugangsdaten und darf nicht in ein
öffentliches Repository übernommen werden.

Sie ist deshalb über `.gitignore` ausgeschlossen.

Vor einer Veröffentlichung oder Weitergabe sollte zusätzlich immer ein
Secret-Scan des Repositorys durchgeführt werden.

## Lizenz

Dieses Projekt wird unter der GNU Affero General Public License
Version 3 (AGPL-3.0) veröffentlicht.

Siehe [LICENSE](LICENSE).
