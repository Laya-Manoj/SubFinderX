SubHunter 🐍🔍

SubHunter is a modern, Kali Linux–friendly subdomain enumeration tool designed for penetration testers and bug bounty hunters.  
It performs passive OSINT discovery + active DNS resolution + HTTP probing in a single command, producing real-time and historical attack surface intelligence.

---

✨ Features

- 🔎 Passive subdomain enumeration (OSINT-based)
- 🌐 Active DNS resolution & HTTP probing
- ✅ LIVE / DEAD subdomain classification
- 🧠 Historical tracking (first seen / last seen)
- 🆕 Change detection (`--only-new`)
- 📦 pip-installable CLI tool
- ⚡ Asynchronous & fast
- 🧾 JSON and TXT output support
- 🐧 Designed for Kali Linux & pentesting workflows

---

📦 Installation (Kali Linux)

Recommended (virtual environment)

```bash
git clone https://github.com/Laya-Manoj/Subhunter.git
cd subhunter
python3 -m venv venv
source venv/bin/activate
pip install .


---

🚀 Usage
Basic full reconnaissance (default behavior)
subhunter -d example.com

Show only newly discovered subdomains
subhunter -d example.com --only-new

JSON output (for automation / pipelines)
subhunter -d example.com --json

Plain text output
subhunter -d example.com --txt

Control concurrency
subhunter -d example.com --threads 50

🆘 Help
subhunter --help

🖥️ Sample Output
[+] Domain: example.com
[+] Total Subdomains Found: 18
[+] Live: 10
[+] Historical (DEAD): 8

[LIVE] api.example.com
[LIVE] www.example.com
[DEAD] dev.example.com
[DEAD] intranet.example.com

⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only.
Do not use against systems you do not own or have explicit permission to test.

👩‍💻 Author

Laya Manoj
Built as part of a personal penetration testing toolkit.