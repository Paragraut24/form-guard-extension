# PhishGuard — Real-Time Phishing Detector

A Chrome browser extension (Manifest V3) that protects you from phishing attacks in real time. PhishGuard analyzes every URL you visit, flags suspicious links on the page, intercepts dangerous form submissions, detects clipboard hijacking, and blocks confirmed phishing pages before they can do harm.

---

## Features

- **Auto URL Scanning** — every page you navigate to is analyzed automatically
- **Link Hover Warnings** — suspicious links are highlighted with a yellow warning border and tooltip before you even click
- **Click Interception** — links with a high risk score trigger a full background analysis before navigation proceeds
- **Form Protection** — detects and blocks suspicious form submissions (HTTP forms, cross-domain submits, hidden forms, combined password/PIN/SSN fields)
- **Clipboard Hijack Detection** — alerts you when a website tries to silently swap what you paste (common in crypto address theft)
- **Full Block Screen** — confirmed phishing pages are redirected to a warning screen with options to go back, preview safely, or proceed with double confirmation
- **Browser Notifications** — desktop notification fires every time a threat is blocked
- **Global Threats Dashboard** — live feed of active phishing URLs pulled from OpenPhish, filterable by category
- **Whitelist & Blacklist** — manually trust or block any domain
- **Scan History** — last 100 scanned URLs with scores and timestamps
- **VirusTotal Integration** — optional API key for cloud-based scanning against 70+ security engines
- **Dark/Light Theme** — persisted theme toggle in the popup

---

## How It Works

### Detection Pipeline

Every URL goes through this analysis chain:

1. **Whitelist** — user-trusted domains are passed immediately as safe
2. **Blacklist** — user-blocked domains are flagged as malicious instantly
3. **Hardcoded Trusted Domains** — well-known domains (Google, GitHub, etc.) are passed without further checks
4. **Phishing Indicator Scoring** — a rule-based engine scores the URL across multiple signals:
   - Free hosting platforms (Weebly, Wix, WordPress.com, Blogspot, etc.)
   - Suspicious TLDs (`.tk`, `.ml`, `.ga`, `.xyz`, `.top`, etc.)
   - Keywords in the URL (`login`, `verify`, `password`, `banking`, `paypal`, etc.)
   - No HTTPS
   - IP address used instead of a domain name
   - `@` symbol in the URL
   - Excessively long domain or too many subdomains
   - Score ≥ 70 → blocked immediately without API call
5. **VirusTotal API** *(optional)* — submits the URL, waits for engine results, then combines scores:
   ```
   final score = (indicator score × 0.3) + (VirusTotal score × 0.7)
   ```
6. **Final verdict**: `safe` (< 40), `suspicious` (40–69), or `malicious` (≥ 70)

### ML Analyzer

The `MLAnalyzer` module adds deeper feature extraction on top of the basic indicator checks:

- **Typosquatting detection** using Levenshtein distance against popular domains (e.g., `gooogle.com`, `paypa1.com`)
- URL length, special character counts, encoded character ratios
- Unicode characters in URLs (homograph attacks)
- Free hosting detection

### Content Script (In-Page Protection)

Injected into every webpage to provide real-time protection without leaving the page:

- Listens for `mouseover` events on links and runs a quick client-side check
- Intercepts `click` events on suspicious links and requests a full analysis before navigating
- Intercepts `submit` events on forms and analyzes them for phishing patterns
- Monitors `copy`/`paste` events and compares what was copied vs. what actually gets pasted

---

## Project Structure

```
phishguard-extension/
├── manifest.json                  # Extension manifest (MV3)
├── background/
│   ├── service-worker.js          # Core analysis engine, navigation listener
│   ├── ml-analyzer.js             # Feature extraction & typosquatting detection
│   ├── virustotal-api.js          # VirusTotal API v3 integration
│   ├── cache-manager.js           # IndexedDB cache (7-day TTL)
│   ├── rate-limiter.js            # API rate limiting (sliding window)
│   ├── clipboard-protector.js     # Clipboard hijack detection module
│   ├── dom-monitor.js             # MutationObserver for dynamic DOM changes
│   └── render-fingerprint.js      # CSS/font fingerprinting for clone detection
├── content/
│   ├── content-script.js          # In-page link, form, clipboard monitoring
│   └── warning-styles.css         # Styles for in-page warnings and tooltips
├── popup/
│   ├── popup.html                 # Toolbar popup UI
│   ├── popup.js                   # Popup logic (stats, history, lists)
│   └── popup.css                  # Popup styles
├── options/
│   ├── options.html               # Settings page
│   ├── options.js                 # Settings logic
│   └── options.css                # Settings styles
├── blocked.html                   # Full-screen block warning page
├── blocked.js                     # Block page logic (back, preview, proceed)
├── preview.html                   # Sandboxed site preview
├── preview.js                     # Preview page logic
├── global-threats.html            # Live phishing feed dashboard
├── global-threats.js              # OpenPhish feed + filter logic
├── global-threats.css             # Threats dashboard styles
├── theme.js                       # Dark/light theme manager
└── icons/                         # Extension icons (16, 48, 128px)
```

---

## Installation

1. Clone or download this repository
2. Open Chrome and go to `chrome://extensions/`
3. Enable **Developer mode** (top right toggle)
4. Click **Load unpacked** and select the `phishguard-extension` folder
5. The PhishGuard shield icon will appear in your toolbar

---

## Configuration

Open the settings page by clicking the gear icon in the popup:

| Setting | Description |
|---------|-------------|
| VirusTotal API Key | Get a free key at [virustotal.com](https://www.virustotal.com). Without it, only the local indicator engine runs. |
| Sensitivity | Detection threshold (low / medium / high) |
| Privacy Mode | Hashes URLs before sending to VirusTotal |
| Show Notifications | Toggle desktop notifications on block |

---

## Storage

| Storage | Key | Contents |
|---------|-----|----------|
| `chrome.storage.sync` | `apiKey`, `whitelist`, `blacklist`, `sensitivity`, `privacyMode`, `showNotifications` | User settings (synced across devices) |
| `chrome.storage.local` | `history` | Last 100 scanned URLs with results |
| `chrome.storage.local` | `stats` | Scan counters (total, malicious, suspicious, safe) |
| IndexedDB | `PhishGuardCache` | URL scan result cache (7-day expiry) |

---

## Permissions

| Permission | Reason |
|------------|--------|
| `storage` | Save settings, history, and stats |
| `tabs` | Read the active tab URL for popup scans |
| `webNavigation` | Intercept navigation events for auto-scanning |
| `notifications` | Show block alerts |
| `<all_urls>` | Inject content script and analyze any URL |

---

## Tech Stack

- **Chrome Extension Manifest V3**
- **Vanilla JavaScript** (no frameworks)
- **IndexedDB** for caching
- **VirusTotal API v3** for cloud threat intelligence
- **OpenPhish** for live phishing feed

---

## License

MIT
