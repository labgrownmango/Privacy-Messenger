# Privacy Messenger (v1.0.4)

Ein hochsicherer, plattformübergreifender Desktop-Messenger für Ende-zu-Ende-verschlüsselte Kommunikation (E2EE) mit **Signal-Spezifikation** (Double Ratchet & Real X3DH), **At-Rest Tresor-Verschlüsselung** und **SOCKS5 / Tor-Metadaten-Minimierung**.

---

## 🔒 Sicherheits- & Kryptografie-Architektur

### 1. Extended Triple Diffie-Hellman (X3DH) & Double Ratchet
- **Echtes X3DH-Protokoll (`backend/ratchet.py`):** Nutzt Langzeit-Identitätsschlüssel ($IK$), signierte Prekeys ($SPK$) und kryptografische Ed25519-Signaturprüfungen zur Ableitung von Master Shared Secrets.
- **Signal Double Ratchet:** Bietet perfekte Vorwärtsgeheimhaltung (**Forward Secrecy**) und **Post-Compromise Security**.
- **Header-Integrität (PyNaCl AEAD AAD):** Bindet die unverschlüsselten Nachrichten-Header `(dh || pn || n)` als *Associated Data* (AAD) in `crypto_aead_chacha20poly1305_ietf` ein. Jede Manipulation führt zum sofortigen Entschlüsselungsfehler.

### 2. At-Rest Tresor-Verschlüsselung (PBKDF2 + SecretBox)
- **Key Derivation Function:** Leitet einen 256-Bit Master-Key mittels **PBKDF2-HMAC-SHA256 (600.000 Iterationen)** aus der Nutzer-Passphrase ab.
- **Encrypted Storage:** Sämtliche sensiblen Daten (Private Schlüssel `sign_sk`/`dh_sk`, `ratchet_state`, `shared_key`, Gruppen-Schlüssel `sender_key` und Nachrichten-Inhalte) liegen mit `SecretBox` verschlüsselt in den SQLite-Datenbanken (`keys.db`, `messages.db`, `groups.db`).
- **Strict Vault Access:** Schreibversuche ohne entsperrten Tresor brechen hart mit `HTTP 423 (Vault Locked)` ab.

### 3. Gehärtete API & Localhost-Drive-by-Schutz
- **Zwingende API-Token-Authentifizierung:** Der Server generiert einen kryptografischen 32-Byte-Token (`X-API-Token`), der bei **jedem** HTTP- und WebSocket-Request zwingend geprüft wird. Offenes CORS ist deaktiviert.
- **Zip-Slip-Schutz:** Der Backup-Import (`/backup/import`) prüft Zielpfade mittels `.resolve()`, um Pfadüberschreitungen (`../`) vollständig zu verhindern.
- **XSS-Schutz:** Nachrichteninhalt wird im Frontend vor dem Rendern im DOM konsequent sanitized (`escapeHtml`).

### 4. SOCKS5 / Tor Proxy & Zero-Knowledge Relay Transport
- **Outbound SOCKS5 RFC 1928 Client:** Alle ausgehenden Netzwerkverbindungen werden bei aktiviertem Proxy über den Tor-SOCKS5-Proxy (`127.0.0.1:9050`) geroutet.
- **Metadaten-Minimierung:** Keine IP-Adress-Protokollierung in Logs, gerundete stündliche Zeitstempel.
- **Standalone E2EE Relay Server (`backend/relay_server.py`):** Unabhängiger Weiterleitungsdienst, der ausschließlich verschlüsselte E2EE-Pakete weiterreicht und keinen Zugriff auf Schlüssel oder Nachrichteninhalte hat.

---

## 🛠️ Schnellstart & Ausführung

### Backend starten:
```bash
python backend/server.py --api-token CHOOSE_OR_AUTO_GENERATE_TOKEN
```

### E2EE Relay Server starten (optional):
```bash
python backend/relay_server.py
```

### Electron Desktop App starten:
```bash
npm install
npm start
```

---

## ⚖️ Lizenz & Nutzungsbedingungen

Lizenziert unter der **`Privacy Messenger Custom Non-Commercial License 1.0`** (siehe [LICENSE](LICENSE)).
- **Erlaubt:** Private, persönliche Nutzung, Quellcode-Einsicht, Modifikationen für den Eigenbedarf und Weitergabe im Freundeskreis.
- **Nicht erlaubt:** Kommerzielle Nutzung, gewerblicher Vertrieb oder automatisierte Massenweiterverteilung ohne ausdrückliche Genehmigung des Rechteinhabers.
