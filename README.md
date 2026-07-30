# 🔐 Privacy Messenger v1.0.2

Ein hochmoderner, tragbarer **Zero-Server P2P Ende-zu-Ende verschlüsselter Messenger** mit lokalem Tresor-Speicher, Double Ratchet Protokoll (Signal Standard) und Streamer-IP-Schutz.

---

## ✨ Hauptmerkmale

- **🔒 Ende-zu-Ende Verschlüsselung:** AES-256-GCM + PyNaCl Double Ratchet Protokoll (Forward Secrecy pro Nachricht).
- **⚡ Dual-Mode Architektur:** Einsteigerfreundlicher 1-Klick-Modus & erweiterter Power-User-Modus (Custom Relays, Fingerprint-Prüfung, Live-Inspector).
- **🛡️ Datenschutz & Streamer-Schutz:** Integrierte IP-Maskierung & Master-PIN Tresor-Sperre.
- **📁 Medien & P2P:** Drag-and-Drop Dateiverschlüsselung, Audio-Sprachnachrichten & 1-Klick-Einladungstoken.

---

## 🚀 Schnelleinrichtung (Local Development)

```bash
# 1. Repository klonen
git clone https://github.com/labgrownmango/Privacy-Messenger.git
cd Privacy-Messenger

# 2. Abhängigkeiten installieren
npm install

# 3. App im Entwicklungsmodus starten
npm start
```

---

## 📦 Portable Standalone Build

Um eine tragbare `.exe`-Datei ohne Installation zu erstellen:

```bash
npm run build
```

---

## 📄 Lizenz

Dieses Projekt steht unter der **Privacy Messenger Custom Non-Commercial License 1.0**:
- ✅ **Erlaubt:** Ansehen, Kompilieren, Modifizieren und Weitergeben für nicht-kommerzielle Zwecke.
- ❌ **Verboten für Dritte:** Kommerzielle Nutzung/Monetarisierung und Massen-Weiterverteilung ohne schriftliche Genehmigung.
- ⚖️ **Rechteinhaber-Vorbehalt:** Offizielle Releases und Monetarisierung durch die Urheber (auf GitHub Releases, offiziellen Webseiten etc.) sind ausdrücklich gestattet.
- 🏛️ **Gerichtsstand:** Deutsches Recht.

Siehe die [LICENSE](LICENSE) Datei für Details.
