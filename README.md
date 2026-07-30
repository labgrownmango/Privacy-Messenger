# 🔐 Privacy Messenger v1.0.2

Ein hochmoderner, tragbarer **Zero-Server P2P Ende-zu-Ende verschlüsselter Messenger** mit lokalem Tresor-Speicher, Double Ratchet Protokoll (Signal Standard) und Streamer-IP-Schutz.

---

## ✨ Hauptmerkmale

- **🔒 Ende-zu-Ende Verschlüsselung:** AES-256-GCM + PyNaCl Double Ratchet Protokoll.
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

Dieses Projekt steht unter einer **Nicht-Kommerziellen & Eingeschränkten Weitergabe-Lizenz**:
- ✅ **Erlaubt:** Ansehen, Kompilieren, Modifizieren und Weitergeben im privaten/nicht-kommerziellen Rahmen (z. B. an Freunde).
- ❌ **Verboten:** Kommerzielle Nutzung (Verkauf/Monetarisierung) sowie groß angelegte Massen-Weiterverteilung oder Hosting auf kommerziellen Portalen ohne schriftliche Genehmigung der Urheber.

Siehe die [LICENSE](LICENSE) Datei für Details.
