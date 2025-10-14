🕵️ Windows Forensic Triage — README

WinQuickTriage_Enhanced.ps1 — Windows систем дээр хурдан forensic triage хийх PowerShell скрипт. Системийн, хэрэглэгчийн, сүлжээ, аюулгүй байдлын үндсэн мэдээллийг цуглуулж тайлан үүсгэнэ.

⚠️ Чухал: Скан дуусахаас өмнө машин унтраах, restart хийхгүй байх. Сканад бүрэн нэвтрэхийн тулд Administrator эрх хэрэгтэй.

🔎 Товч танилцуулга

Зорилго: Анхны forensic/incident-response цуглуулга (triage) хийх — хурдан, хэрэглэгч төвтэй.

Гаралт файлууд: C:\Forensic\<HOST>_<YYYY-MM-DD_HH-mm>\WinQuickTriage_<HOST>_<date>.txt болон BrowserArtifacts хавтсанд файлуудыг хуулна.

Анхаар: Скрипт saved passwords-ыг тайлж гаргахгүй. Хэрвээ Login Data / logins.json файлыг КОПИ хийж авбал тэнд нуугдсан/шифрлэгдсэн өгөгдөл байж болно — энэ скрипт тэдгээрийг задлахгүй.

⚙️ Гол функцууд (өндөр түвшинд)

System info, uptime, OS

User accounts, current sessions

Running processes (top CPU)

Startup/autorun items, scheduled tasks, services

Network connections (netstat / TCP), ARP, routing

Security event log — сүүлийн logon эвэнтүүд (4624)

PowerShell history

Obfuscated script quick-scan (user folders only)

Hosts file, shadow copies

Installed applications, installed updates

Drivers, firewall status & rules

Browser artifacts: profile files, history/bookmarks (copied only — passwords NOT extracted)

Recent files (user) — сүүлийн 7 хоног гэх мэт

(Бараг 20+ artifact; дэлгэрэнгүйг скриптийг эндээс харна.)

🧾 Гаралт

Текст тайлан: C:\Forensic\WinQuickTriage_<hostname>_<date>.txt

Хэрвээ байвал браузерийн профайл файлууд: C:\Forensic\<hostname>_<date>\BrowserArtifacts\

🚀 Ашиглах заавар (админ эрхтэй)

PowerShell-ийг администратор байдлаар нээнэ

Start Menu → Windows PowerShell (эсвэл PowerShell) → Right-click → Run as administrator

Эсвэл энгийн PowerShell-ээс elevated терминал нээх:

Start-Process powershell -Verb RunAs


Execution policy-г түр хугацаанд нээх (хэрэв шаардлагатай бол)
(цор ганц session-д хүчинтэй)

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force


Скрипт ажиллуулах
Скрипт байрлах хавтсанд шилжээд:

cd C:\Path\To\Script
.\WinQuickTriage_Enhanced.ps1

📌 Техникийн шаардлага

Windows 10 / Windows 11 ; PowerShell 5.1+ (PowerShell 7 зөвшөөрнө)

Администратор эрх

✍️ Зохиогч

Enkhbat.O
Senior Security Analyst — Cybersecurity & Forensics