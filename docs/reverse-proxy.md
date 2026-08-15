# Reverse Proxy und HTTPS

Das DMS kann direkt per HTTP oder hinter einem Reverse Proxy betrieben
werden.

Für produktiven oder extern erreichbaren Betrieb wird HTTPS empfohlen.

## Lokale Bind-Adresse

Standardmäßig lauscht das DMS nur auf:

~~~dotenv
APP_BIND_ADDRESS=127.0.0.1
APP_PORT=3000
~~~

Damit ist Port 3000 nur lokal auf dem DMS-Host erreichbar.

Befindet sich der Reverse Proxy auf einem anderen System, kann
`APP_BIND_ADDRESS` auf die interne IP-Adresse des DMS-Hosts gesetzt
werden.

Beispiel:

~~~dotenv
APP_BIND_ADDRESS=192.0.2.20
APP_PORT=3000
~~~

Die Beispieladresse muss durch die tatsächliche interne IP-Adresse des
DMS-Hosts ersetzt werden.

Alternativ ist möglich:

~~~dotenv
APP_BIND_ADDRESS=0.0.0.0
~~~

Dabei sollte der Zugriff auf Port 3000 mit einer Firewall auf den
Reverse Proxy beziehungsweise das vertrauenswürdige interne Netz
beschränkt werden.

## HTTPS-Cookies

Bei direktem HTTP-Betrieb:

~~~dotenv
COOKIE_SECURE=false
~~~

Bei vollständigem HTTPS-Betrieb hinter einem korrekt konfigurierten
Reverse Proxy:

~~~dotenv
COOKIE_SECURE=true
~~~

Mit `COOKIE_SECURE=true` werden Sitzungs-Cookies nur über HTTPS
übertragen.

## TRUST_PROXY

`TRUST_PROXY` sollte nur gesetzt werden, wenn tatsächlich ein Reverse
Proxy vorgeschaltet ist.

Nach Möglichkeit sollte nur die konkrete vertrauenswürdige Proxy-Adresse
eingetragen werden.

Beispiel:

~~~dotenv
TRUST_PROXY=192.0.2.10
~~~

Die Beispieladresse muss durch die tatsächliche interne Adresse des
Reverse Proxys ersetzt werden.

Bei direktem Betrieb ohne Reverse Proxy sollte die Variable leer bleiben:

~~~dotenv
TRUST_PROXY=
~~~

Eine unnötig weit gefasste Proxy-Vertrauensstellung sollte vermieden
werden.

## Weitergeleitete Header

Der Reverse Proxy sollte mindestens die üblichen Header korrekt
weitergeben:

~~~text
Host
X-Forwarded-For
X-Forwarded-Proto
~~~

Bei HTTPS sollte `X-Forwarded-Proto` den Wert `https` enthalten.

## Empfohlene Architektur

~~~text
Internet
   |
 HTTPS
   |
Reverse Proxy
   |
 internes Netz
   |
DMS :3000
~~~

Port 3000 sollte nicht unnötig direkt aus dem Internet erreichbar sein.

## Beispiel für Nginx

Ein einfaches Beispiel:

~~~nginx
location / {
    proxy_pass http://192.0.2.20:3000;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_http_version 1.1;
}
~~~

Die Beispieladresse muss an die eigene Umgebung angepasst werden.

TLS-Zertifikat und HTTPS-Konfiguration werden vom Reverse Proxy
verwaltet.

## HSTS

Das DMS selbst erzwingt derzeit kein HSTS.

Der Grund ist, dass die Anwendung auch direkt über HTTP betrieben werden
kann.

Bei einer ausschließlich über HTTPS erreichbaren Installation kann HSTS
durch den Reverse Proxy gesetzt werden.

## Firewall

Wenn der Reverse Proxy auf einem separaten Host läuft, sollte Port 3000
nach Möglichkeit nur von diesem Host erreichbar sein.

Beispiel:

~~~text
erlaubt:
Reverse Proxy -> DMS:3000

nicht erforderlich:
Internet -> DMS:3000
~~~

## Fehlerbehebung

Bei Login- oder Session-Problemen sollten insbesondere geprüft werden:

- `COOKIE_SECURE`
- `TRUST_PROXY`
- `APP_BIND_ADDRESS`
- Weitergabe von `X-Forwarded-Proto`
- HTTPS-Konfiguration des Reverse Proxys
- Firewall-Regeln
- Erreichbarkeit von Port 3000

Wenn HTTPS verwendet wird und `COOKIE_SECURE=true` gesetzt ist, muss die
Anwendung tatsächlich über HTTPS aufgerufen werden.
