# 🔗 Link Safety Checker

A real-world URL threat analysis tool built with **Python + FastAPI**. Paste any link and get an instant trust score based on SSL, domain age, redirect chains, and phishing patterns.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ Features

- **Trust Score (0–100)** — single verdict: Safe / Suspicious / Dangerous
- **SSL Certificate Check** — validates cert, expiry, and HTTPS enforcement
- **WHOIS / Domain Age** — new domains (< 30 days) are a major red flag
- **Redirect Chain Analysis** — exposes hidden multi-hop redirects
- **Pattern Detection** — catches raw IPs, URL shorteners, suspicious keywords, risky TLDs

---

## 🖥️ Preview

```
URL: http://paypa1-secure-login.xyz/verify
Trust Score: 12 / 100  ← DANGEROUS
Flags:
  ✗ No HTTPS — connection is unencrypted
  ✗ Domain is only 3 days old
  ✗ Contains suspicious keyword: "login"
  ✗ Uses a high-risk TLD: ".xyz"
```

---

## 🚀 Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/NishilA18/link-safety-checker.git
cd link-safety-checker
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the server
```bash
cd backend
python main.py
```

### 4. Open in browser
```
http://localhost:8000
```

---

## 📁 Project Structure

```
link-safety-checker/
├── backend/
│   ├── main.py          # FastAPI server & routes
│   └── checker.py       # Core analysis logic
├── frontend/
│   ├── index.html       # UI
│   └── static/
│       ├── css/style.css
│       └── js/app.js
├── tests/
│   └── test_checker.py  # Unit tests (pytest)
├── requirements.txt
└── README.md
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

---

## 🔬 How the Trust Score Works

| Check | Max Penalty |
|---|---|
| Invalid/missing SSL | −35 |
| Domain < 30 days old | −30 |
| Excessive redirects | −20 |
| WHOIS not found | −20 |
| Each pattern warning | −10 |
| Domain < 180 days old | −15 |

Score ≥ 75 → **SAFE** 🟢  
Score 45–74 → **SUSPICIOUS** 🟠  
Score < 45 → **DANGEROUS** 🔴  

---

## 🛣️ Roadmap

- [ ] VirusTotal API integration
- [ ] Google Safe Browsing API
- [ ] History of checked URLs (localStorage)
- [ ] Browser extension version
- [ ] Bulk URL checking (CSV upload)

---

## 📄 License

MIT
