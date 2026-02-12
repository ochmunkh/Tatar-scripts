<img width="676" height="608" alt="image" src="https://github.com/user-attachments/assets/a174cfb3-4690-4b3e-985b-7e11d70d8454" />

**🕵️ Windows систем дээр хурдан, аюулгүй forensic triage хийх PowerShell скрипт**

Хэрэв таны windows үйлдлийн системтэй компьютер вирустэй сайтруу нэвтэрсэн, вирустэй файл татсан, удааширсан зэрэг шинж тэмдэгтэй бол энэхүү скриптыг ашиглан логуудаа гаргаж авч шинжилгээ хийх боломжтой юм. Ингэснээр цуглуулсан логуудаас тухайн асуудлыг хялбар, хурдан шийдэх боломжтой болох юм.
Tatar_Quick_Triage.ps1 нь Windows endpoint дээр анхны forensic / incident response triage хийхэд зориулагдсан. Скрипт нь системийн, хэрэглэгчийн, процесс, сүлжээ, registry, event log болон browser artifact зэрэг чухал мэдээллүүдийг read-only аргаар цуглуулж, нэгтгэсэн тайлан үүсгэнэ.


**⚠️ Анхааруулга**

Скан дуусахаас өмнө компьютерийг унтраах, restart хийхийг хориглоно.
Administrator эрхтэй ажиллуулахыг зөвлөж байна (зарим artifact admin эрхгүй үед бүрэн лог цуглуулж чадахгүй)


**🔎 Зорилго**

🚑 Incident Response – Initial Triage
🧪 Malware / Suspicious activity detection (quick visibility)
🧾 Forensic evidence preservation
⏱️ Fast & user-focused (production endpoint-д аюул багатай)

Гаралт (Output Structure)
C:\Forensic\
 └─ <HOSTNAME>_<YYYY-MM-DD_HH-mm>\
    ├─ WinQuickTriage_<HOST>_<DATE>.txt
    ├─ BrowserArtifacts\
    │   └─ browser_artifacts_summary.txt
    ├─ RegistryHives\
    ├─ EventLogs\
    ├─ dns_cache.txt
    ├─ arp.txt
    ├─ manifest_hashes.csv
    └─ (optional) Forensic_<HOST>_<DATE>.zip

**Гол боломжууд**

🖥️ System & User
OS info, uptime, hostname
User accounts, admin group, active sessions
Installed applications

**⚙️ Process & Persistence**

Running processes (PID, command line, parent)
Suspicious process pattern detection
Startup items, scheduled tasks, services
Prefetch files

**🌐 Network**

Active TCP connections (PID mapping)
netstat, ARP, routing table
DNS cache dump
Firewall profiles & rules

**🧾 Logs & Registry**

Security Event Logs (4624, 4688)
Full EVTX export (Security, System, Application, Sysmon)
Registry hives (SYSTEM, SAM, SECURITY, SOFTWARE)
NTUSER.DAT copy (all users)

**📜 PowerShell & Scripts**

PowerShell history
Transcript search
Obfuscated script quick-scan (IEX, Base64, Invoke-Expression…)

**🌍 Browser Artifacts (Safe mode)**

Chrome / Edge / Firefox profiles
SQLite / JSON / History files

⚠️ Passwords NOT decrypted


**🚀 Ашиглах заавар**

1️⃣ git clone https://github.com/ochmunkh/Tatar-scripts.git
cd Tatar-scripts

2️⃣ PowerShell-ийг Administrator-аар нээх
Start Menu → Windows PowerShell → Right-click → Run as administrator
эсвэл: Start-Process powershell -Verb RunAs

Execution Policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

3️⃣ Скрипт ажиллуулах
cd C:\Path\To\Script
.\Tatar_Quick_Triage.ps1
📝 Main report: WinQuickTriage_<HOST>_<DATE>.txt


**🧩 Техникийн шаардлага**

Windows 10 / Windows 11

PowerShell 5.1+ (PowerShell 7 дэмжинэ)

Administrator privilege шаардлагатай


Enkhbat.O

Security Analyst
