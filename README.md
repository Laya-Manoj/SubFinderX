SubFinderX 🐍🔍

SubFinderX is a modern, Kali Linux–friendly subdomain enumeration tool designed for penetration testers and bug bounty hunters.

It performs:

- Passive OSINT discovery
- Active DNS resolution
- HTTP probing
- LIVE / DEAD classification
- Historical tracking
- Aggressive brute-force enumeration

All in a single command.

---

✨ Features

- 🔎 Passive subdomain enumeration (OSINT-based)
- 💣 Optional aggressive brute-force mode
- 🌐 Active DNS resolution
- ⚡ HTTP probing with status detection
- ✅ LIVE / DEAD classification
- 🧠 Historical tracking (first seen / last seen)
- 🆕 Change detection (`--only-new`)
- 📦 pip-installable CLI tool
- ⚡ Asynchronous & fast
- 🧾 JSON and TXT output support
- 🐧 Designed for Kali Linux & pentesting workflows

---

📦 Installation (Kali Linux)

Recommended (Virtual Environment)

```bash
git clone https://github.com/Laya-Manoj/SubFinderX.git
cd SubFinderX
python3 -m venv venv
source venv/bin/activate
pip install .

🚀 Usage
Basic reconnaissance
subfinderx -d example.com

Aggressive brute-force mode
subfinderx -d example.com --bruteforce

JSON output (automation)
subfinderx -d example.com --json

Plain text output
subfinderx -d example.com --txt

Show only newly discovered subdomains
subfinderx -d example.com --only-new

Control concurrency
subfinderx -d example.com --threads 50

🆘 Help
subfinderx --help


🖥️ Sample Output
[*] Starting SubFinderX against example.com
[*] Launching passive enumeration...
[*] Performing DNS resolution...
[*] Probing HTTP...

[+] Domain: example.com
[+] Total Subdomains Found: 25
[+] Live: 12
[+] Historical (DEAD): 13

[LIVE] api.example.com
[LIVE] www.example.com (200 OK)
[DEAD] dev.example.com


⚠️ Disclaimer
This tool is intended for educational purposes and authorized security testing only.
Do NOT use against systems you do not own or have explicit permission to test.

👩‍💻 Author
Laya Manoj
Cybersecurity Enthusiast | Pentesting Toolkit Builder