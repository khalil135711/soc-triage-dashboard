# SOC Alert Triage Dashboard

REST-API und Web-Oberfläche, mit der SOC-Analysten Security-Alerts einspielen, automatisch anreichern
(Severity-Score, MITRE-ATT&CK-Mapping), filtern, priorisieren und bearbeiten.

**Stack:** Python 3.12 · FastAPI · SQLite · JWT · Vanilla JS (kein Build-Schritt) · Docker · pytest · GitHub Actions

## Schnellstart

```bash
docker compose up --build
python scripts/seed_alerts.py      # optional: 60 Demo-Alerts
```

- UI: http://localhost:8000
- API-Doku (Swagger): http://localhost:8000/docs
- Demo-Logins: `analyst / analyst123`, `admin / admin123` (**vor Produktivbetrieb ändern**, siehe `.env`-Variablen)

Ohne Docker:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## REST-API

| Methode | Pfad | Zweck | Rolle |
|---|---|---|---|
| POST | `/api/auth/login` | JWT holen | alle |
| GET | `/api/alerts` | Liste (Filter: `severity`, `status`, `q`, `date_from`, `date_to`, Sortierung, Paging) | analyst, admin |
| POST | `/api/alerts` | Alert einspielen (wird angereichert) | analyst, admin |
| GET | `/api/alerts/{id}` | Details inkl. Notizen | analyst, admin |
| PATCH | `/api/alerts/{id}` | Status ändern | analyst, admin |
| DELETE | `/api/alerts/{id}` | Alert löschen | admin |
| POST | `/api/alerts/{id}/notes` | Notiz hinzufügen | analyst, admin |
| GET | `/api/stats` | Kennzahlen fürs Dashboard | analyst, admin |
| GET | `/api/rules` | Anreicherungsregeln | analyst, admin |
| GET | `/api/health` | Health-Check | offen |

Beispiel:

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"analyst123"}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -X POST localhost:8000/api/alerts -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-11-16T10:00:00Z","source_ip":"203.0.113.5","signature":"SSH brute force attempt","severity":"high"}'
```

## Anreicherung

`backend/app/enrichment.py` ordnet Alerts anhand von Signatur-Stichworten einer MITRE-ATT&CK-Technik zu
und berechnet einen Score (0–100) aus Basis-Score der Regel, Severity und ob die Quell-IP öffentlich ist.
Die Regeln sind bewusst einfach gehalten und leicht erweiterbar (z. B. Sigma- oder Threat-Intel-Feeds).

## Security-Maßnahmen

- Passwörter mit PBKDF2-HMAC-SHA256 (200k Runden, Salt), Vergleich mit `hmac.compare_digest`
- JWT (HS256) mit Ablaufzeit, Rollen `analyst` / `admin`
- Rate Limiting am Login (10 Versuche/Minute/IP)
- Eingabevalidierung mit Pydantic (IP-Format, Längen, Enums), parametrisierte SQL-Queries,
  Sortierfelder per Allowlist-Regex
- UI ohne `innerHTML` (kein XSS), strikte Content-Security-Policy, `X-Frame-Options`, `nosniff`
- Container läuft als Nicht-Root-Benutzer

## Threat Model (kurz)

| Bedrohung | Gegenmaßnahme | Restrisiko / To-do |
|---|---|---|
| Brute Force auf Login | Rate Limit, PBKDF2 | Limit liegt im Speicher (nicht verteilt) → Redis |
| Token-Diebstahl | kurze Laufzeit, CSP gegen XSS | Token in sessionStorage → HttpOnly-Cookie erwägen |
| SQL Injection | Prepared Statements, Allowlists | – |
| Stored XSS über Alert-Daten | nur `textContent`, CSP | – |
| Privilegieneskalation | serverseitige Rollenprüfung | Audit-Log ergänzen |
| Schwache Standard-Secrets | per Umgebungsvariable überschreibbar | Start verweigern, wenn Default-Secret in Produktion |

## Tests

```bash
cd backend && pytest -q
```

CI läuft über GitHub Actions (`.github/workflows/ci.yml`).

## Ideen für Erweiterungen

- Import von Suricata `eve.json` / Wazuh-Alerts
- IP-Reputation (AbuseIPDB), GeoIP
- PostgreSQL, Audit-Log, Benutzerverwaltung
- Sigma-Regeln als Anreicherungsquelle
- Screenshots/GIF in `docs/` und hier einbinden
