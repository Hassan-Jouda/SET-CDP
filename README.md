أكيد. هذه نسخة **README.md مطوّرة ومتكاملة** ومناسبة فعلياً لمشروعكم الحالي، وتشمل أدوات الفحص، الاختبار الأمني المصرح به، المحاكاة، Mini-EDR، المتجر، الامتحانات، التقارير، والمساعد الذكي.

انسخها مباشرة إلى ملف:

```text
README.md
```

````markdown
# 🛡️ SET-CDP

## Security Education, Testing & Cyber Defense Platform

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-000000?logo=flask)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite)](https://www.sqlite.org/)
[![Bootstrap](https://img.shields.io/badge/UI-Bootstrap%205-7952B3?logo=bootstrap&logoColor=white)](https://getbootstrap.com/)
[![Manifest V3](https://img.shields.io/badge/Browser%20Extensions-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white)]()
[![Project](https://img.shields.io/badge/Type-Academic%20Graduation%20Project-success)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)]()

**SET-CDP** is a comprehensive cybersecurity education, authorized security testing, threat simulation, endpoint monitoring, and cyber defense platform.

The project combines defensive security tools, controlled penetration-testing simulations, browser protection extensions, security awareness training, Mini-SOC monitoring, user assessment, and centralized reporting inside one unified environment.

SET-CDP is designed for students, educators, researchers, training centers, and organizations that need a practical and controlled environment for understanding modern cyber threats and defensive security practices.

---

# 🎯 Project Vision

The vision of SET-CDP is to bridge the gap between cybersecurity theory and practical experience.

The platform enables users to understand cybersecurity from multiple perspectives:

- Defensive security assessment.
- Authorized penetration testing.
- Red Team threat simulation.
- Blue Team detection and analysis.
- Endpoint monitoring.
- Security awareness training.
- Browser-based protection.
- Incident monitoring and reporting.
- User behavior assessment.

The platform focuses on practical learning while maintaining ethical, educational, and authorized-use principles.

---

# 🚀 Main Platform Components

SET-CDP is divided into several integrated cybersecurity modules:

## 🔵 Blue Teaming

Defensive tools for scanning, analyzing, monitoring, and improving security posture.

## 🔴 Authorized Penetration Testing & Attack Simulation

Controlled simulation tools for understanding attack techniques and user behavior inside approved training environments.

## 🟢 Security Awareness & Education

Interactive training modules, threat explanations, exams, certificates, and awareness recommendations.

## 📡 Mini-SOC & Mini-EDR

Live monitoring of authorized endpoint devices, processes, connections, system resources, and generated security alerts.

## 🧩 Browser Extension Store

Local-first browser extensions for link analysis, privacy protection, cookie management, password security, and advertisement blocking.

## 📊 Administration & Reporting

Centralized dashboards for users, scans, devices, quizzes, simulations, reports, and activity tracking.

---

# 🔵 Defensive Security Tools

SET-CDP provides a collection of defensive scanners and security analysis tools.

## 🌐 Website Security Scanner

Analyzes the security posture of a website and evaluates:

- HTTPS usage.
- HTTP response status.
- Redirect chains.
- Security Headers.
- Cookie security attributes.
- Web forms.
- Password input fields.
- Mixed-content indicators.
- Server information disclosure.
- General security score.
- Risk classification.
- Recommended security improvements.

---

## 🔐 SSL/TLS Certificate Inspector

Inspects the SSL/TLS certificate of a domain and displays:

- Certificate status.
- Issuer.
- Subject.
- Issue date.
- Expiration date.
- Remaining days.
- Subject Alternative Names.
- TLS version.
- Cipher suite.
- Expiration warnings.
- Certificate security score.

---

## 🧱 Security Headers Analyzer

Analyzes important HTTP response security headers, including:

- Content-Security-Policy.
- Strict-Transport-Security.
- X-Frame-Options.
- X-Content-Type-Options.
- Referrer-Policy.
- Permissions-Policy.
- Cross-Origin-Opener-Policy.
- Cross-Origin-Resource-Policy.
- Cross-Origin-Embedder-Policy.
- Cache-Control.
- Clear-Site-Data.

The tool provides:

- Header status.
- Current value.
- Missing-header detection.
- Warnings.
- Security score.
- Remediation recommendations.

---

## 🔗 URL Safety Checker

Examines URLs for phishing and suspicious indicators such as:

- HTTP instead of HTTPS.
- Raw IP addresses.
- Punycode domains.
- Excessive subdomains.
- Suspicious top-level domains.
- Shortened URLs.
- Long URLs.
- Excessive hyphens.
- Hidden domain indicators.
- Brand impersonation patterns.
- Sensitive query parameters.
- Suspicious characters.

The result includes:

- URL risk score.
- Risk level.
- Detected indicators.
- Safety recommendations.

---

## 🔀 URL Expander

Expands shortened links and follows controlled redirect chains.

The tool displays:

- Original URL.
- Final destination.
- Redirect count.
- Redirect chain.
- HTTP status.
- Final URL risk analysis.
- Warnings and recommendations.

---

## 🔑 Password Strength Analyzer

Evaluates password security based on:

- Password length.
- Uppercase and lowercase letters.
- Numbers.
- Symbols.
- Repeated characters.
- Sequential patterns.
- Common-password detection.
- Estimated entropy.
- Overall security score.

Password analysis is designed for awareness and should not store the entered password.

---

## 🎲 Secure Password Generator

Generates cryptographically random passwords using configurable combinations of:

- Uppercase letters.
- Lowercase letters.
- Numbers.
- Symbols.
- Adjustable password length.

The generated password is evaluated immediately using the Password Strength Analyzer.

---

## 📧 Email Phishing Detector

Analyzes email or message text for social-engineering indicators such as:

- Urgent language.
- Account-verification requests.
- Password requests.
- Payment warnings.
- Fake prizes.
- Suspicious attachments.
- Verification-code requests.
- Suspicious URLs.
- Psychological pressure techniques.

The result includes:

- Phishing risk score.
- Detected indicators.
- Extracted URLs.
- URL risk analysis.
- Protection recommendations.

---

## 📁 File Hash & Metadata Analyzer

Analyzes uploaded files for security and forensic purposes.

The tool extracts:

- File name.
- File size.
- Extension.
- MIME type.
- File signature.
- MD5 hash.
- SHA-1 hash.
- SHA-256 hash.
- File entropy.
- Image dimensions.
- EXIF metadata.
- PDF metadata.
- Page count.
- Office macro indicators.
- Embedded PDF action indicators.
- Executable-file warnings.

Supported educational uses include:

- Digital forensics.
- File integrity verification.
- Malware-analysis preparation.
- Incident response.
- Evidence comparison.

---

# 🔴 Authorized Penetration Testing & Attack Simulation

SET-CDP contains controlled modules designed to demonstrate how common cyberattacks and social-engineering techniques operate.

These modules must only be used inside authorized training environments.

## 🧬 Training Clone Generator

Creates a training copy of an approved web page for awareness demonstrations.

Main functions include:

- Importing approved page structure.
- Preparing a local training version.
- Correcting relative resources.
- Adding awareness interaction tracking.
- Saving generated templates.
- Displaying generated training links.
- Recording controlled simulation events.
- Redirecting users to an awareness page after interaction.

The module is intended to teach users how cloned pages may appear and how to recognize them.

---

## 🎭 Social Engineering Templates

The platform provides ready-made awareness templates representing common online services and environments, such as:

- Social media login pages.
- Corporate login portals.
- University portals.
- Session-expired pages.
- Security-verification pages.
- Awareness landing pages.

Templates are designed for controlled security-awareness demonstrations only.

---

## 📱 Quishing Simulation

Generates QR codes for authorized security-awareness scenarios.

The module helps demonstrate:

- QR-based phishing risks.
- Hidden URL destinations.
- Mobile-device attack surfaces.
- Link verification before opening.
- QR-code awareness practices.

---

## ⌛ Fake Session Expired Simulation

Demonstrates how fake session-expiration messages may pressure users into entering information.

The simulation teaches users to:

- Verify the domain.
- Avoid urgent login requests.
- open the official site manually.
- Report suspicious login prompts.

---

## 💾 USB Security Awareness Simulation

Explains the risk of unknown USB devices and removable media.

The module is intended to teach:

- USB-drop attack awareness.
- Safe handling of unknown devices.
- Device reporting procedures.
- Endpoint-protection importance.
- Risks of auto-running or unknown files.

---

## 📈 Simulation Tracking

Authorized training activities can be recorded for awareness evaluation.

The platform can track:

- Simulation type.
- Training page.
- Interaction time.
- Awareness result.
- User response.
- Redirect outcome.
- Training statistics.

Real credentials or sensitive personal information should never be used during simulations.

---

# 📡 Mini-SOC & Mini-EDR

SET-CDP contains a lightweight Security Operations Center and endpoint-monitoring module.

The goal of this module is to teach centralized monitoring, alert review, endpoint telemetry, and basic incident-response concepts.

---

## 💻 Endpoint Agent

The SET-CDP Endpoint Agent is a Python-based program that runs on authorized endpoint devices.

The agent can send:

- Agent ID.
- Hostname.
- Logged-in username.
- Operating system.
- Local IP address.
- CPU usage.
- RAM usage.
- Disk usage.
- Running processes.
- Active network connections.
- Heartbeat timestamp.
- Device status.

The Agent must only be installed on devices with clear authorization.

---

## 📡 Mini-EDR Live Monitor

The live monitoring dashboard displays:

- CPU usage.
- RAM usage.
- Disk usage.
- Last-update time.
- Running processes.
- Process IDs.
- Process resource usage.
- Local network addresses.
- Remote network addresses.
- Connection status.
- Listening ports.
- External connections.
- Risk classifications.
- Live alerts.

---

## ⚠️ Security Alert Engine

The monitoring system evaluates endpoint activity and generates educational alerts for indicators such as:

- External public connections.
- Unusual remote ports.
- High CPU usage.
- High RAM usage.
- Suspicious process names.
- Unexpected listening services.
- Repeated network activity.
- Endpoint communication failure.
- Agent heartbeat timeout.

Alerts may be classified as:

- Low.
- Medium.
- High.
- Critical.

---

## 🖥️ Device Center

The Device Center provides centralized endpoint management and visibility.

It displays:

- Connected devices.
- Online or offline status.
- Last heartbeat.
- Hostname.
- Username.
- Operating system.
- IP address.
- CPU and RAM status.
- Device risk score.
- Device details.
- Recent endpoint alerts.

---

# 🧩 Browser Extension Store

SET-CDP includes a built-in browser extension store.

The extensions are designed to operate locally whenever possible and follow Manifest V3 architecture.

## 🛡️ SET-CDP WebShield Ultimate

A browser security toolkit that may include:

- URL Risk Analyzer.
- QR Code Scanner.
- Password Analyzer.
- Secure Password Generator.
- Email Header Analyzer.
- File Hash Generator.
- Security Headers Checker.
- Privacy Scanner.
- Suspicious-link detection.
- Local security recommendations.

---

## 🍪 SET-CDP CookieShield Pro

A privacy-focused Cookie management extension.

Main capabilities include:

- Viewing website Cookies.
- Creating Cookies.
- Editing Cookies.
- Deleting Cookies.
- Clearing site Cookies.
- Inspecting Cookie attributes.
- Detecting missing Secure flags.
- Detecting missing HttpOnly flags.
- Detecting missing SameSite attributes.
- Identifying third-party Cookies.
- Cookie security scoring.

---

## 🚫 SET-CDP AdShield Pro

A browser extension designed to reduce exposure to:

- Intrusive advertisements.
- Pop-up windows.
- Tracking requests.
- Known advertising domains.
- Malicious advertisement redirects.
- Social-engineering pop-ups.

The extension uses browser-supported filtering rules and local settings.

---

## ✅ Advanced To-Do List

A secure local productivity extension for managing:

- Daily tasks.
- Training activities.
- Security-review checklists.
- Awareness tasks.
- Personal notes.
- Local workflow organization.

---

# 🟢 Security Awareness & Education

## 🤖 SET-CDP Awareness Chatbot

The platform includes a built-in interactive awareness assistant.

The Chatbot can explain:

- SET-CDP platform features.
- URL security.
- SSL certificates.
- Security Headers.
- Password security.
- File hashes.
- Email phishing.
- Mini-EDR.
- Endpoint Agent.
- Browser extensions.
- Security-awareness templates.
- Quiz system.
- General protection recommendations.

The Chatbot includes ethical guardrails and refuses requests related to account theft, credential theft, unauthorized access, or harmful activity.

---

## 📚 Cyber Threat Library

The built-in Cyber Threat Library contains educational content covering:

- Phishing.
- Spear Phishing.
- Smishing.
- Vishing.
- Quishing.
- Malware.
- Ransomware.
- Spyware.
- Adware.
- SQL Injection.
- Cross-Site Scripting.
- Cross-Site Request Forgery.
- Man-in-the-Middle attacks.
- Password attacks.
- USB-drop attacks.
- Clickjacking.
- Fake pop-ups.
- Social engineering.
- Session risks.
- Malicious attachments.

Each threat record can include:

- Threat title.
- Category.
- Risk level.
- Description.
- Attack method.
- Indicators.
- Prevention techniques.
- Awareness recommendations.
- References.

Administrators can publish and manage threat-library content from the administration panel.

---

# 📝 Security Awareness Quiz System

The Quiz System evaluates users' cybersecurity awareness.

Main features include:

- Dynamic question builder.
- Multiple-choice questions.
- Correct-answer selection.
- Question activation and deactivation.
- Question deletion.
- Automatic scoring.
- Pass and fail evaluation.
- Percentage calculation.
- Quiz-history storage.
- Administrative results dashboard.
- Search and filtering.
- Certificate generation.
- Print and PDF support.

Quiz topics include:

- Phishing.
- Suspicious links.
- Password security.
- Wi-Fi safety.
- USB security.
- Social engineering.
- QR security.
- Safe browsing.
- Multi-factor authentication.
- File and email safety.

---

# 🏆 Certificate System

Users who successfully complete the awareness quiz can receive a training certificate containing:

- Official participant name.
- Quiz title.
- Score.
- Percentage.
- Completion status.
- Certificate date.
- Platform name.
- Project management signature.
- Printable certificate layout.
- PDF-saving support.

---

# 👥 User Management & Profiles

SET-CDP uses a Role-Based Access Control model.

## Administrator

The Administrator can:

- Access the administrative dashboard.
- Manage users.
- Manage quiz questions.
- View all quiz results.
- View all scan records.
- View reports.
- Publish threat-library content.
- Manage simulations.
- View connected endpoint devices.
- Access Mini-SOC.
- Download Endpoint Agent.
- View platform analytics.

## Standard User

A Standard User can:

- Access defensive tools.
- Use authorized training simulations.
- Take awareness quizzes.
- View personal quiz results.
- Access personal reports.
- Manage profile information.
- View personal activity history.
- Download available browser extensions.
- Use the awareness Chatbot.

---

## 👤 User Profiles

User profiles may contain:

- Username.
- Official certificate name.
- Role.
- Profile image.
- Biography.
- Quiz results.
- Scan history.
- Training history.
- Certificate links.
- Activity statistics.

---

# 📊 Dashboards & Reports

SET-CDP provides multiple dashboards for monitoring platform activity.

## User Dashboard

Displays:

- Personal scan count.
- Personal quiz results.
- Training activities.
- Recent security scans.
- Risk levels.
- User progress.

## Administrative Dashboard

Displays:

- Total users.
- Total scans.
- Total quizzes.
- Training interactions.
- Generated clones.
- Connected devices.
- Alerts.
- Platform activity.

## Reports Center

The Reports Center includes:

- Executive summary.
- Scan statistics.
- File-analysis statistics.
- Simulation statistics.
- Quiz statistics.
- Scan distribution.
- Daily activity charts.
- Recent scans.
- Recent quiz results.
- Printable reports.
- PDF-export support.

Charts are powered by Chart.js.

---

# 🔐 Platform Security Controls

SET-CDP includes defensive controls to reduce unintended or unauthorized use:

- Role-Based Access Control.
- Session-based authentication.
- Password hashing using Werkzeug.
- File-size limitations.
- File-type validation.
- Safe filename handling.
- Private and local IP filtering.
- SSRF protection for server-side URL checks.
- Redirect limits.
- Network request timeouts.
- Authorized Agent API key.
- Input normalization.
- Output escaping.
- Ethical warnings.
- Local-first browser analysis.
- Activity logging.
- Restricted administration routes.

---

# 🏗️ Technology Stack

## Backend

- Python 3.
- Flask.
- SQLite.
- Werkzeug.
- REST-style APIs.

## Frontend

- HTML5.
- CSS3.
- JavaScript.
- Bootstrap 5.
- Jinja2.
- Chart.js.
- Font Awesome.

## Security & Analysis Libraries

- Requests.
- BeautifulSoup4.
- Hashlib.
- SSL.
- Socket.
- IPAddress.
- QRCode.
- Pillow.
- PyPDF2.
- Psutil.

## Browser Extensions

- Manifest V3.
- JavaScript.
- Chrome Storage API.
- Cookies API.
- Tabs API.
- Declarative Net Request.
- Content Scripts.
- Service Workers.

## Development Tools

- Visual Studio Code.
- Git.
- GitHub.
- DB Browser for SQLite.
- PyInstaller.
- Chrome Extension Developer Mode.

---

# 📂 Project Structure

```text
SET-CDP/
│
├── app.py                         # Main Flask application and APIs
├── requirements.txt               # Python dependencies
├── README.md                      # Project documentation
├── database.db                    # SQLite runtime database
│
├── Endpoint_Agent/
│   ├── agent.py                   # Endpoint Agent source code
│   ├── agent.spec                 # PyInstaller configuration
│   └── dist/
│       └── agent.exe              # Compiled Windows Agent
│
├── static/
│   ├── style.css                  # Main platform styling
│   ├── script.js                  # Frontend tools and interaction logic
│   ├── agent.py                   # Downloadable Agent source
│   ├── agent.exe                  # Downloadable Windows Agent
│   │
│   └── extensions/
│       ├── webshield.zip
│       ├── SET-CDP-CookieShield-Pro-v1.0.zip
│       ├── SET-CDP-AdShield-Pro-v1.0.zip
│       └── Advanced-To-Do-List-main.zip
│
├── templates/
│   ├── index.html                 # Main security tools interface
│   ├── login.html                 # Login page
│   ├── register.html              # User registration
│   ├── profile.html               # User profile and personal history
│   ├── dashboard.html             # Platform dashboard
│   ├── reports.html               # Reports center
│   ├── about.html                 # Project information
│   ├── 403.html                   # Unauthorized access page
│   │
│   ├── attack.html                # Authorized simulation interface
│   ├── ready_templates.html       # Training templates
│   ├── awareness_training.html    # Awareness landing page
│   │
│   ├── threat_library.html        # Cyber Threat Library
│   ├── admin_threats.html         # Threat publishing management
│   │
│   ├── quiz_start.html            # Quiz introduction
│   ├── quiz_take.html             # Quiz questions
│   ├── quiz_result.html           # Quiz result and certificate
│   ├── quiz_admin.html            # Administrative quiz results
│   ├── quiz_builder.html          # Question management
│   │
│   ├── extensions.html            # Browser Extension Store
│   ├── chatbot_widget.html        # Floating awareness Chatbot
│   ├── base_nav.html              # Navigation and global theme
│   │
│   ├── edr.html                   # Mini-EDR Live Monitor
│   ├── edr_devices.html           # Endpoint Device Center
│   ├── edr_device_details.html    # Endpoint details
│   ├── device_center.html         # Device management interface
│   ├── agent_download.html        # Agent download page
│   │
│   ├── social/                    # Awareness templates
│   └── clones/                    # Generated training clones
│
├── uploads/                       # User profile images
├── captured_files/                # Controlled training records
└── .gitignore
````

---

# ⚙️ Installation

## 1. Clone the Repository

```bash
git clone https://github.com/Hassan-Jouda/SET-CDP.git
cd SET-CDP
```

## 2. Create a Virtual Environment

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## 4. Run the Platform

```bash
python app.py
```

Open the platform in your browser:

```text
http://127.0.0.1:5000
```

---

# 📡 Endpoint Agent Setup

The Endpoint Agent must only be installed on authorized devices.

## Run from Python Source

Open:

```text
Endpoint_Agent/agent.py
```

Update the server address:

```python
SERVER_URL = "http://SERVER_IP:5000/api/agent/heartbeat"
```

Then run:

```bash
python agent.py
```

## Windows Executable

The compiled Agent may be downloaded from the Agent Download page or executed from:

```text
Endpoint_Agent/dist/agent.exe
```

The Flask server must be reachable from the endpoint device.

---

# 🧩 Browser Extension Installation

1. Download the required extension ZIP file from the SET-CDP Extension Store.
2. Extract the ZIP file.
3. Open Chrome or Edge.
4. Navigate to:

```text
chrome://extensions/
```

or:

```text
edge://extensions/
```

5. Enable **Developer Mode**.
6. Select **Load Unpacked**.
7. Choose the extracted extension folder.

---

# 🔄 Platform Workflow

```text
User Registration / Login
            ↓
Defensive Security Tools
            ↓
Authorized Awareness Simulation
            ↓
Activity Logging and Analysis
            ↓
Mini-SOC and Endpoint Monitoring
            ↓
Quiz and Awareness Evaluation
            ↓
Reports and Certificates
```

---

# 🎯 Project Objectives

SET-CDP aims to:

* Improve cybersecurity awareness.
* Support practical cybersecurity education.
* Demonstrate defensive scanning concepts.
* Explain authorized penetration-testing concepts.
* Teach Red Team and Blue Team workflows.
* Provide endpoint-monitoring experience.
* Introduce SOC and EDR concepts.
* Protect users through browser extensions.
* Improve phishing and social-engineering detection.
* Provide measurable awareness assessments.
* Encourage ethical cybersecurity practices.
* Support academic cybersecurity research.

---

# 🔒 Ethical Notice

SET-CDP is an academic cybersecurity graduation project developed for:

* Education.
* Research.
* Security awareness.
* Defensive security assessment.
* Controlled threat simulation.
* Authorized penetration testing.
* Approved endpoint monitoring.

All scans, simulations, training templates, cloned pages, Agents, and monitoring modules must only be used in systems and environments where clear authorization has been obtained.

The platform must not be used for:

* Unauthorized access.
* Account theft.
* Credential theft.
* Session theft.
* Privacy violations.
* Monitoring devices without permission.
* Targeting real users without consent.
* Damaging systems or data.
* Bypassing laws or organizational policies.

The developers are not responsible for illegal, harmful, or unauthorized use of the platform.

---

# 👨‍💻 Development Team

## Founder, Project Lead & System Architect

**Hassan Jouda**

## UI/UX Designer

**Ismail Al-Nahhal**

## Software Developer

**Bilal**

---

# 🔮 Future Roadmap

Planned future developments include:

* AI-Assisted Threat Analysis.
* Behavior-based endpoint detection.
* Advanced anomaly detection.
* SIEM integration.
* Telegram and email alerts.
* Advanced incident timelines.
* Endpoint isolation research.
* Enhanced security reports.
* PDF and Excel export.
* Student leaderboards.
* Gamified cybersecurity learning.
* Advanced certificate verification.
* Awareness campaign management.
* Multi-language support.
* Expanded browser extension store.
* Cloud deployment.
* Multi-tenant organizational support.
* Integration with threat-intelligence platforms.

---

# 📜 License

**Academic Graduation Project**

Developed for educational, research, cybersecurity awareness, defensive assessment, and authorized security-testing purposes.

© 2026 SET-CDP
Security Education, Testing & Cyber Defense Platform

```

ملاحظة مهمة: في README استخدمت عبارة **Authorized Penetration Testing & Attack Simulation** لأنها أقوى وتوضح وجود أدوات الاختراق والمحاكاة، وفي نفس الوقت تحمي المشروع أكاديمياً وقانونياً أمام لجنة المناقشة وGitHub.
```
