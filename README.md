# 🛡️ URL Guard — URL Safety Checker

A lightweight tool that checks whether a URL is safe to visit. Paste any link and get an instant risk score, a breakdown of what's suspicious, and a plain-English explanation of the findings.

Built as a hackathon project around the problem: *"Users often click unknown links without checking safety."*

----------------------------------------------------------------------------------------

## 🚀 Demo

![URL Guard Dashboard](screenshot.png)

> Paste a URL → Get a risk score (0–100) → See exactly why it's flagged

----------------------------------------------------------------------------------------

## ✨ Features

- **Real-time risk score** from 0 (safe) to 100 (dangerous)
- **Live SSL certificate check** — verifies the actual certificate, not just the `https://` prefix
- **WHOIS domain age lookup** — flags domains registered less than 30 days ago
- **Redirect chain tracking** — follows the URL and counts every hop
- **TLD and blacklist check** — catches abused free TLDs like `.tk`, `.xyz`, `.ml`
- **Phishing keyword detection** — scans for common phishing words in the URL
- **URL structure analysis** — detects IP addresses, deep subdomains, encoding tricks
- **Interactive world map** — shows global activity dots for the scanned URL
- **Animated risk gauge** — smooth needle animation with color-coded verdict
- **IST live clock** in the header

----------------------------------------------------------------------------------------

## 🧠 How the Score is Calculated

Each check produces a score from 0–100. The final risk score is a weighted average:

| Check | Weight | What it does |
|---|---|---|
| SSL / HTTPS | 35% | Live SSL handshake — valid, expired, or missing |
| Blacklist / TLD | 20% | Abused TLDs, shorteners, encoding tricks |
| Domain Age | 15% | Real WHOIS lookup for registration date |
| URL Structure | 10% | IP usage, subdomains, entropy, @ tricks |
| Phishing Keywords | 10% | Known phishing words in the URL |
| Redirect Chain | 10% | Counts actual HTTP redirect hops |

**Verdicts:**
- 🟢 `0–25` → **Safe**
- 🟡 `26–60` → **Moderate Risk**
- 🔴 `61–100` → **High Risk**

----------------------------------------------------------------------------------------

## 🗂️ Project Structure

```
url-guard/
├── app.py          # Python Flask backend — all the analysis logic
├── website.html    # Frontend dashboard — runs in any browser
└── README.md
```

----------------------------------------------------------------------------------------

## ⚙️ Setup

**Requirements:** Python 3.8+

**1. Install dependencies**
```bash
pip3 install flask flask-cors requests python-whois certifi
```

**2. Start the backend**
```bash
python3 app.py
```
The API will be live at `http://localhost:5000`

**3. Open the frontend**

Just double-click `website.html` — it opens in your browser. No extra setup needed.

**4. Scan a URL**

Paste any URL into the input field and hit **Scan**. Results appear in 2–5 seconds.

> ⚠️ The backend must be running before you open the frontend.

----------------------------------------------------------------------------------------

## 🔌 API

The backend exposes a single endpoint:

```
POST http://localhost:5000/api/check
```

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "risk_score": 75,
  "verdict": "danger",
  "summary": "HIGH RISK: 2 critical issues detected...",
  "global_visits": 12400,
  "countries_count": 34,
  "threat_reports": 87,
  "last_seen": "2 hrs ago",
  "breakdown": {
    "ssl":        { "score": 85, "label": "NO HTTPS" },
    "domain_age": { "score": 55, "label": "45 DAYS OLD" },
    "redirects":  { "score": 20, "label": "1 HOP(S)" },
    "blacklist":  { "score": 85, "label": "SUSPICIOUS TLD: .tk" }
  },
  "checks": {
    "ssl":       { "status": "bad",  "label": "NO HTTPS",    "detail": "..." },
    "domain":    { "status": "warn", "label": "45 DAYS OLD", "detail": "..." },
    "phishing":  { "status": "ok",   "label": "CLEAN",       "detail": "..." },
    "blacklist": { "status": "bad",  "label": "SUSP. TLD",   "detail": "..." },
    "redirects": { "status": "ok",   "label": "1 HOP(S)",    "detail": "..." },
    "structure": { "status": "ok",   "label": "NORMAL",      "detail": "..." }
  }
}
```

----------------------------------------------------------------------------------------

## 🧪 Example URLs to Test

| URL | Expected Result |
|---|---|
| `https://google.com` | ✅ Safe |
| `https://github.com` | ✅ Safe |
| `https://bit.ly/3xABCdef` | 🟡 Moderate Risk |
| `https://login.support.mybank-secure.com` | 🟡 Moderate Risk |
| `http://free-bonus-login.tk` | 🔴 High Risk |
| `http://192.168.1.1/verify/account` | 🔴 High Risk |

----------------------------------------------------------------------------------------

## 📦 Dependencies

```
flask
flask-cors
requests
python-whois
certifi
```

----------------------------------------------------------------------------------------

## ⚠️ Known Limitations

- WHOIS lookups can be slow (1–3s) or return no data for privacy-protected domains
- URLs that block bot traffic may show `TIMEOUT` or `UNREACHABLE` for the redirect check
- No integration with real-time threat databases (Google Safe Browsing, VirusTotal)
- Global map activity data is estimated, not from live threat feeds

----------------------------------------------------------------------------------------

## 🔮 Future Ideas

- Google Safe Browsing / VirusTotal API integration
- Browser extension for real-time protection
- QR code URL scanner
- Historical scan database

----------------------------------------------------------------------------------------

This project was built for a hackathon. Feel free to use, modify, and build on it
