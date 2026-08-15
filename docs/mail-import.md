# Mailimport

Das DMS kann PDF-Anhänge automatisch aus einem IMAP-Postfach übernehmen.

## Konfiguration

Die Einstellungen befinden sich als Administrator unter:

~~~text
Einstellungen -> Scanner / Mailimport
~~~

Konfiguriert werden können:

- IMAP-Server
- Port
- SSL/TLS
- Benutzername
- Kennwort
- Quellpostfach
- Ordner für verarbeitete Nachrichten
- Abfrageintervall

Für IMAPS wird typischerweise Port 993 mit aktiviertem SSL/TLS verwendet.

## Kennwortspeicherung

Das IMAP-Kennwort wird nicht im Klartext in `.env` gespeichert.

Es wird verschlüsselt in PostgreSQL abgelegt.

Der Schlüssel für die Verschlüsselung wird aus `APP_SECRET` abgeleitet.

Deshalb gilt:

~~~text
APP_SECRET nach der Einrichtung nicht ändern.
~~~

Wird `APP_SECRET` geändert, kann ein bereits gespeichertes
IMAP-Kennwort nicht mehr entschlüsselt werden und muss neu eingegeben
werden.

## Verbindung testen

Die Einstellungen enthalten die Funktion:

~~~text
IMAP-Verbindung testen
~~~

Dabei werden geprüft:

- Verbindung zum IMAP-Server
- Anmeldung mit Benutzername und Kennwort
- Zugriff auf das konfigurierte Postfach

Beim Verbindungstest werden keine Nachrichten importiert, verschoben
oder gelöscht.

## Mailimport aktivieren

Nach einem erfolgreichen Verbindungstest kann:

~~~text
Mailimport aktivieren
~~~

eingeschaltet und gespeichert werden.

Der Container `dms-mail-importer` liest die Konfiguration regelmäßig aus
PostgreSQL.

Änderungen an der Mailkonfiguration benötigen deshalb normalerweise
keinen Neustart des Containers.

## Verarbeitung

Der Importer prüft das konfigurierte Postfach in dem eingestellten
Intervall.

PDF-Anhänge werden verarbeitet und in den DMS-Sammler übernommen.

Erfolgreich verarbeitete Nachrichten werden anschließend in den
konfigurierten IMAP-Ordner verschoben.

Standard:

~~~text
DMS-Importiert
~~~

## Quellpostfach

Standardmäßig wird verwendet:

~~~text
INBOX
~~~

Es kann auch ein anderes IMAP-Postfach konfiguriert werden.

## Abfrageintervall

Das Intervall kann in Sekunden eingestellt werden.

Zulässiger Bereich:

~~~text
10 bis 3600 Sekunden
~~~

## Logs

Live-Anzeige:

~~~bash
docker compose logs -f mail-importer
~~~

Letzte 100 Meldungen:

~~~bash
docker compose logs --tail=100 mail-importer
~~~

## Fehlerbehebung

Wenn die Verbindung fehlschlägt, sollten insbesondere geprüft werden:

- IMAP-Server
- Port
- SSL/TLS-Einstellung
- Benutzername
- Kennwort
- Name des Postfachs
- Firewall
- DNS-Auflösung
- Erreichbarkeit des Mailservers

Vor dem Aktivieren des Imports sollte zuerst der integrierte
Verbindungstest verwendet werden.

## Sicherheit

Für das DMS sollte nach Möglichkeit ein eigenes Mailkonto oder
Scanner-Postfach verwendet werden.

Mail-Zugangsdaten dürfen nicht in:

- Git-Repositories
- Dokumentationen
- Screenshots
- Logdateien
- Shell-Historien

veröffentlicht werden.

Das Kennwortfeld in der Weboberfläche bleibt nach dem Speichern leer.
Ein bereits gespeichertes Kennwort bleibt erhalten, solange kein neues
Kennwort eingegeben wird.
