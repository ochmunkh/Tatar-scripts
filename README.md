<img width="676" height="608" alt="image" src="https://github.com/user-attachments/assets/a174cfb3-4690-4b3e-985b-7e11d70d8454" />

*****Windows систем дээр хурдан, аюулгүй forensic triage хийх PowerShell скрипт*****

Хэрэв таны windows үйлдлийн системтэй компьютер вирустэй сайтруу нэвтэрсэн, вирустэй файл татсан, удааширсан зэрэг шинж тэмдэгтэй бол энэхүү скриптыг ашиглан логуудаа гаргаж авч шинжилгээ хийх боломжтой юм. Ингэснээр цуглуулсан логуудаас тухайн асуудлыг хялбар, хурдан шийдэх боломжтой болох юм.
Tatar_Quick_Triage.ps1 нь Windows endpoint дээр анхны forensic / incident response triage хийхэд зориулагдсан. Скрипт нь системийн, хэрэглэгчийн, процесс, сүлжээ, registry, event log болон browser artifact зэрэг чухал мэдээллүүдийг read-only аргаар цуглуулж, нэгтгэсэн тайлан үүсгэнэ.


*****Анхааруулга*****

Скан дуусахаас өмнө компьютерийг унтраах, restart хийхийг хориглоно.
Administrator эрхтэй ажиллуулахыг зөвлөж байна (зарим artifact admin эрхгүй үед бүрэн лог цуглуулж чадахгүй)


*****Зорилго*****

🚑 Incident Response – Initial Triage
🧪 Malware / Suspicious activity detection (quick visibility)
🧾 Forensic evidence preservation
⏱️ Fast & user-focused (production endpoint -д аюул багатай)

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

*****Гол боломжуудын тайлбарууд*****

1/30 – System Information - \Системийн ерөнхий мэдээлэл\
2/30 – User Accounts - \Хэрэглэгчийн бүртгэлийн мэдээлэл\
3/30 – Network Configuration - \Сүлжээний тохиргооны мэдээлэл\
4/30 – Running Processes - \Ажиллаж буй процессууд\
5/30 – Services - \Системийн үйлчилгээ (Service)-үүд\
6/30 – Startup Entries - \Автоматаар асах програмууд\
7/30 – Scheduled Tasks - \Төлөвлөсөн даалгаврууд\
8/30 – Event Logs - \Системийн Event Log бүртгэл\
9/30 – Installed Programs - \Суусан програмуудын лист\
10/30 – Open Ports - \Нээлттэй порт болон сүлжээний холболтууд\
11/30 – ARP Cache - \ARP кэш мэдээлэл\
12/30 – DNS Cache - \DNS кэш бүртгэл\
13/30 – Browser History - \Веб хөтчийн түүх\
14/30 – Recent Files - \Сүүлд нээгдсэн файлууд\
15/30 – USB History - \USB төхөөрөмжийн холболтын түүх\
16/30 – Prefetch Files - \Prefetch гүйцэтгэлийн бүртгэл\
17/30 – Registry Autoruns - \Registry -ийн автомат ачааллын бүртгэлүүд\
18/30 – Firewall Rules - \Firewall дүрмийн тохиргоо\
19/30 – RDP Activity - \Remote Desktop хандалтын бүртгэл\
20/30 – Shadow Copies - \Volume Shadow Copy мэдээлэл\
21/30 – SAM Dump - \Хэрэглэгчийн нууц үгийн hash мэдээлэл (SAM)\
22/30 – Memory Information - \Санах ойд байх мэдээлэл\
23/30 – MFT Analysis - \NTFS Master File Table шинжилгээ\
24/30 – Deleted Files - \Устгагдсан файлын мэдээлэл\
25/30 – Suspicious Indicators - \Сэжигтэй үйл ажиллагааны шинж тэмдэг\
26/30 – Hash Collection - \Файлын hash утгууд (MD5/SHA256)\
27/30 – Persistence Mechanisms - \Системд тогтвортой байрших механизм\
28/30 – Privilege Escalation Indicators - \Эрхийн түвшин нэмэгдүүлсэн шинж тэмдэг\
29/30 – Lateral Movement Artifacts - \Сүлжээгээр тархалтын ул мөр\
30/30 – Timeline Generation - \Үйл ажиллагааны цагийн дараалал\


*****Ашиглах заавар*****

1. git clone https://github.com/ochmunkh/Tatar-scripts.git
   
1.1 cd Tatar-scripts

PowerShell-ийг Administrator-аар нээх
   
2.1 Start Menu → Windows PowerShell → Right-click → Run as administrator

эсвэл: Start-Process powershell -Verb RunAs

Execution Policy

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

Скрипт ажиллуулах

cd C:\Path\To\Script
.\Tatar_Quick_Triage.ps1
Report: WinQuickTriage_<HOST>_<DATE>.txt


*****Техникийн шаардлага******

Windows 10 / Windows 11

PowerShell 5.1+ (PowerShell 7 дэмжинэ)

Administrator privilege шаардлагатай


*****Author*****

Enkhbat.O
Security Analyst
