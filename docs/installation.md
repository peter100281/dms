# Installation

## Voraussetzungen

Benötigt werden:

- Linux-Host
- Docker Engine
- Docker Compose Plugin
- Git
- OpenSSL

Prüfen:

~~~bash
docker --version
docker compose version
git --version
openssl version
~~~

## Repository herunterladen

~~~bash
git clone https://github.com/peter100281/dms.git
cd dms
~~~

## Konfiguration erstellen

~~~bash
cp .env.example .env
chmod 600 .env
~~~

Danach `.env` mit einem Texteditor bearbeiten.

Für Kennwörter und `APP_SECRET` sollten zufällige Werte verwendet werden.

Beispiel:

~~~bash
openssl rand -hex 32
~~~

Für jeden geheimen Wert sollte ein eigener Zufallswert erzeugt werden.

## Datenverzeichnis

Standardmäßig verwendet das DMS:

~~~text
/data/dms
~~~

Der Pfad wird über folgende Variable festgelegt:

~~~dotenv
DMS_DATA_DIR=/data/dms
~~~

Alternativ kann beispielsweise verwendet werden:

~~~dotenv
DMS_DATA_DIR=/srv/dms
~~~

Das Datenverzeichnis kann vor dem ersten Start vorbereitet werden:

~~~bash
mkdir -p /data/dms/{postgres,redis,originals,documents,temp,status,mail,backups}
~~~

Bei einem abweichenden `DMS_DATA_DIR` muss der Pfad entsprechend angepasst werden.

## Netzwerk

Standardmäßig wird die Weboberfläche nur lokal bereitgestellt:

~~~dotenv
APP_BIND_ADDRESS=127.0.0.1
APP_PORT=3000
~~~

Für einen direkten Zugriff aus dem LAN kann stattdessen die lokale
IP-Adresse des DMS-Hosts verwendet werden.

Beispiel:

~~~dotenv
APP_BIND_ADDRESS=192.0.2.20
~~~

Die Beispieladresse muss durch die tatsächliche Adresse ersetzt werden.

Für einen extern erreichbaren Dienst wird ein HTTPS-Reverse-Proxy empfohlen.

## Container starten

Zuerst die Compose-Konfiguration prüfen:

~~~bash
docker compose config --quiet
~~~

Danach den Stack bauen und starten:

~~~bash
docker compose up -d --build
~~~

Status prüfen:

~~~bash
docker compose ps
~~~

Logs der Anwendung anzeigen:

~~~bash
docker compose logs -f app
~~~

Logs des Mailimporters:

~~~bash
docker compose logs -f mail-importer
~~~

## Erstanmeldung

Bei einer neuen und leeren Datenbank wird automatisch folgendes
Administratorkonto angelegt:

~~~text
Benutzername: admin
Passwort:     admin
~~~

Beim ersten Login muss das Kennwort geändert werden.

Die Anwendung sollte nicht öffentlich freigegeben werden, bevor das
Initialkennwort geändert wurde.

## OCR

Das App-Image enthält:

- OCRmyPDF
- Tesseract OCR
- Poppler

Enthaltene Tesseract-Sprachen:

- Deutsch
- Englisch
- Niederländisch
- Schwedisch

Die gewünschten OCR-Sprachen können später in den Einstellungen des DMS
ausgewählt werden.

## Mailimport

Der Mailimport wird nicht über `.env` konfiguriert.

Die Einrichtung erfolgt als Administrator unter:

~~~text
Einstellungen -> Scanner / Mailimport
~~~

Weitere Informationen:

[Mailimport](mail-import.md)

## Systemstatus

Der optionale Systemstatus-Collector kann installiert werden mit:

~~~bash
sudo ./scripts/install-system-stats.sh
~~~

Status prüfen:

~~~bash
systemctl status dms-system-stats.timer
~~~

Der Collector schreibt seine Daten nach:

~~~text
<DMS_DATA_DIR>/status/system.json
~~~

## Aktualisierung

Vor einer Aktualisierung sollte ein Backup erstellt werden.

Danach kann das Repository aktualisiert werden:

~~~bash
git pull
docker compose build
docker compose up -d
~~~

Anschließend prüfen:

~~~bash
docker compose ps
docker compose logs --since=5m app
~~~
