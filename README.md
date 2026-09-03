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

The project combines defensive security scanners, controlled Red Team simulations, browser protection extensions, security-awareness training, Mini-SOC monitoring, endpoint telemetry, user assessment, reports, certificates, and centralized administration inside one unified environment.

SET-CDP is designed for students, educators, researchers, training centers, and organizations that need a practical and controlled environment for understanding modern cyber threats from both offensive and defensive perspectives.

> **Important:** SET-CDP must only be used in systems, devices, accounts, and environments where explicit authorization has been granted.

---

# 📑 Table of Contents

- [Project Vision](#-project-vision)
- [Main Platform Components](#-main-platform-components)
- [Defensive Security Tools](#-defensive-security-tools)
- [Authorized Penetration Testing and Simulations](#-authorized-penetration-testing--attack-simulation)
- [Mini-SOC and Mini-EDR](#-mini-soc--mini-edr)
- [Browser Extension Store](#-browser-extension-store)
- [Security Awareness and Education](#-security-awareness--education)
- [User Management](#-user-management--profiles)
- [Dashboards and Reports](#-dashboards--reports)
- [Technology Stack](#️-technology-stack)
- [Project Structure](#-project-structure)
- [Installation and Running](#️-installation--running)
- [Endpoint Agent Setup](#-endpoint-agent-setup)
- [Browser Extension Installation](#-browser-extension-installation)
- [Platform Workflow](#-platform-workflow)
- [Troubleshooting](#-troubleshooting)
- [Ethical Notice](#-ethical-notice--privacy-principles)
- [Development Team](#-development-team)
- [Future Roadmap](#-future-roadmap)
- [License](#-license)

---

# 🎯 Project Vision

The vision of SET-CDP is to bridge the gap between cybersecurity theory and practical experience by providing a safe, educational, interactive, and controlled environment.

The platform enables users to learn cybersecurity through:

- Defensive security assessment.
- Authorized penetration-testing concepts.
- Red Team threat simulation.
- Blue Team detection and analysis.
- Endpoint monitoring and telemetry.
- Security-awareness training.
- Browser-based protection.
- Incident monitoring and reporting.
- User-behavior assessment.
- Quiz-based evaluation and certificates.

---

# 🚀 Main Platform Components

## 🔵 Blue Teaming

Defensive tools for scanning, analyzing, monitoring, and improving security posture.

## 🔴 Authorized Penetration Testing & Attack Simulation

Controlled educational simulations for understanding attack techniques, social-engineering risks, and user behavior inside approved training environments.

## 🟢 Security Awareness & Education

Interactive training modules, threat explanations, quizzes, certificates, and protection recommendations.

## 📡 Mini-SOC & Mini-EDR

Live monitoring of authorized endpoint devices, system resources, processes, network connections, alerts, and device status.

## 🧩 Browser Extension Store

Local-first browser extensions for URL analysis, privacy protection, cookie auditing, password security, productivity, and advertisement reduction.

## 📊 Administration & Reporting

Centralized dashboards for users, scans, simulations, endpoint devices, quizzes, threat-library content, reports, and activity tracking.

---

# 🔵 Defensive Security Tools

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
- Security recommendations.

## 🔐 SSL/TLS Certificate Inspector

Inspects a domain certificate and displays:

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

The tool provides current values, missing-header detection, warnings, a security score, and remediation recommendations.

## 🔗 URL Safety Checker

Examines links for phishing and suspicious indicators such as:

- HTTP instead of HTTPS.
- Raw IP addresses.
- Punycode domains.
- Excessive subdomains.
- Suspicious top-level domains.
- Shortened URLs.
- Very long URLs.
- Excessive hyphens.
- Brand-impersonation patterns.
- Sensitive query parameters.
- Suspicious characters.

The result includes a risk score, risk level, detected indicators, and protection recommendations.

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

## 🔑 Password Strength Analyzer

Evaluates password security based on:

- Length.
- Uppercase and lowercase letters.
- Numbers.
- Symbols.
- Repeated characters.
- Sequential patterns.
- Common-password detection.
- Estimated entropy.
- Overall security score.

Password analysis is intended for awareness and should not store the entered password.

## 🎲 Secure Password Generator

Generates cryptographically random passwords using configurable combinations of uppercase letters, lowercase letters, numbers, symbols, and adjustable length.

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
- Psychological-pressure techniques.

The result includes a phishing risk score, detected indicators, extracted URLs, URL analysis, and protection recommendations.

## 📁 File Hash & Metadata Analyzer

Analyzes uploaded files for security and forensic purposes.

The tool may extract:

- File name and size.
- Extension and MIME type.
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

Educational uses include file-integrity verification, digital forensics, malware-analysis preparation, incident response, and evidence comparison.

---

# 🔴 Authorized Penetration Testing & Attack Simulation

SET-CDP contains controlled modules designed to demonstrate how common cyberattacks and social-engineering techniques operate.

These modules must only be used inside authorized training environments.

## 🧬 Training Clone Generator

Creates a controlled training copy of an approved web page for awareness demonstrations.

Main functions include:

- Importing an approved page structure.
- Preparing a local training version.
- Correcting relative resources.
- Adding awareness interaction tracking.
- Saving generated templates.
- Displaying generated training links.
- Recording controlled simulation events.
- Redirecting users to awareness content after interaction.

The purpose is to teach users how cloned pages may appear and how to recognize warning signs.

## 🎭 Social Engineering Templates

The platform includes awareness templates representing common environments, such as:

- Social media login pages.
- Corporate login portals.
- University portals.
- Session-expired pages.
- Security-verification pages.
- Awareness landing pages.

## 📱 Quishing Simulation

Generates QR codes for authorized awareness scenarios and demonstrates:

- QR-based phishing risks.
- Hidden URL destinations.
- Mobile-device attack surfaces.
- Link verification before opening.
- QR-code awareness practices.

## ⌛ Fake Session Expired Simulation

Demonstrates how fake session-expiration messages can pressure users into unsafe actions and teaches users to verify the domain, avoid urgent login prompts, use official access paths, and report suspicious pages.

## 💾 USB Security Awareness Simulation

Explains the risks of unknown USB devices and removable media, including safe handling, reporting procedures, endpoint-protection importance, and the risks of unknown or auto-running files.

## 📈 Simulation Tracking

Authorized training activities may record:

- Simulation type.
- Training page.
- Interaction time.
- Awareness result.
- User response.
- Redirect outcome.
- Training statistics.

Real credentials or sensitive personal information must never be used during simulations.

---

# 📡 Mini-SOC & Mini-EDR

SET-CDP includes a lightweight Security Operations Center and endpoint-monitoring module designed to teach centralized monitoring, alert review, endpoint telemetry, and basic incident-response concepts.

## 💻 Endpoint Agent

The SET-CDP Endpoint Agent is a Python-based program that runs on authorized endpoint devices.

The Agent may send:

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

## 📡 Mini-EDR Live Monitor

The live dashboard displays:

- CPU, RAM, and Disk usage.
- Last-update time.
- Running processes and process IDs.
- Process resource usage.
- Local and remote network addresses.
- Connection status.
- Listening ports.
- External connections.
- Risk classifications.
- Live alerts.

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

Alerts may be classified as Low, Medium, High, or Critical.

## 🖥️ Device Center

The Device Center provides centralized endpoint visibility and displays:

- Connected devices.
- Online or offline status.
- Last heartbeat.
- Hostname and username.
- Operating system.
- IP address.
- CPU and RAM status.
- Device risk score.
- Device details.
- Recent endpoint alerts.

---

# 🧩 Browser Extension Store

SET-CDP includes a built-in browser extension store. Extensions are designed to operate locally whenever possible and follow Manifest V3 architecture.

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

## 🍪 SET-CDP CookieShield Pro

A privacy-focused Cookie management and auditing extension with capabilities such as:

- Viewing, creating, editing, and deleting Cookies.
- Clearing site Cookies.
- Inspecting Cookie attributes.
- Detecting missing Secure, HttpOnly, and SameSite attributes.
- Identifying third-party Cookies.
- Cookie security scoring.

## 🚫 SET-CDP AdShield Pro

Reduces exposure to intrusive advertisements, pop-up windows, tracking requests, known advertising domains, malicious advertisement redirects, and social-engineering pop-ups.

## ✅ Advanced To-Do List

A secure local productivity extension for managing daily tasks, training activities, security-review checklists, awareness tasks, personal notes, and local workflow organization.

---

# 🟢 Security Awareness & Education

## 🤖 SET-CDP Awareness Chatbot

The platform includes a local rule-based interactive awareness assistant that can explain:

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
- Awareness templates.
- Quiz system.
- General protection recommendations.

The Chatbot includes ethical guardrails and refuses requests related to account theft, credential theft, unauthorized access, or harmful activity.

## 📚 Cyber Threat Library

The built-in threat library covers topics such as:

- Phishing, Spear Phishing, Smishing, Vishing, and Quishing.
- Malware, Ransomware, Spyware, and Adware.
- SQL Injection.
- Cross-Site Scripting.
- Cross-Site Request Forgery.
- Man-in-the-Middle attacks.
- Password attacks.
- USB-drop attacks.
- Clickjacking and fake pop-ups.
- Social engineering.
- Session risks.
- Malicious attachments.

Each threat record may contain a title, category, risk level, description, attack method, indicators, prevention techniques, awareness recommendations, and references.

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

Quiz topics include phishing, suspicious links, password security, public Wi-Fi, USB security, social engineering, QR security, safe browsing, multi-factor authentication, and file/email safety.

## 🏆 Certificate System

Users who successfully complete the awareness quiz can receive a training certificate containing:

- Official participant name.
- Quiz title.
- Score and percentage.
- Completion status.
- Certificate date.
- Platform name.
- Project management signature.
- Printable layout.
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
- Manage authorized simulations.
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

## User Dashboard

Displays personal scan count, quiz results, training activities, recent security scans, risk levels, and user progress.

## Administrative Dashboard

Displays total users, scans, quizzes, training interactions, generated clones, connected devices, alerts, and platform activity.

## Reports Center

Includes:

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
- Git and GitHub.
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
│   └── extensions/                # Downloadable browser-extension ZIP files
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
│   ├── attack.html                # Authorized simulation interface
│   ├── ready_templates.html       # Training templates
│   ├── awareness_training.html    # Awareness landing page
│   ├── threat_library.html        # Cyber Threat Library
│   ├── admin_threats.html         # Threat publishing management
│   ├── quiz_start.html            # Quiz introduction
│   ├── quiz_take.html             # Quiz questions
│   ├── quiz_result.html           # Quiz result and certificate
│   ├── quiz_admin.html            # Administrative quiz results
│   ├── quiz_builder.html          # Question management
│   ├── extensions.html            # Browser Extension Store
│   ├── chatbot_widget.html        # Floating awareness Chatbot
│   ├── base_nav.html              # Navigation and global theme
│   ├── edr.html                   # Mini-EDR Live Monitor
│   ├── edr_devices.html           # Endpoint Device Center
│   ├── edr_device_details.html    # Endpoint details
│   ├── device_center.html         # Device management interface
│   ├── agent_download.html        # Agent download page
│   ├── social/                    # Awareness templates
│   └── clones/                    # Generated training clones
│
├── uploads/                       # User profile images
├── captured_files/                # Controlled training records
└── .gitignore
```

---

# ⚙️ Installation & Running

## System Requirements

- Python 3.8 or newer.
- Git.
- A modern browser such as Chrome or Edge.
- Windows, Linux, or macOS.
- Network access between the Flask server and authorized Agent devices when using Mini-EDR.

## 1. Clone the Repository

```bash
git clone https://github.com/Hassan-Jouda/SET-CDP.git
cd SET-CDP
```

## 3. Upgrade pip

```bash
python -m pip install --upgrade pip
```

## 4. Install Dependencies

```bash
pip install -r requirements.txt
```

## 5. Run the Platform

```bash
python app.py
```

## 6. Open the Platform

Open the following address in your browser:

```text
http://127.0.0.1:5000
```

The SQLite database is used by the application to store accounts, scan history, quiz results, simulation events, endpoint devices, alerts, and platform data.

## 7. Stop the Platform

Return to the terminal and press:

```text
Ctrl + C
```

## 8. Run Again Later

Activate the virtual environment first, then start the application:

### Windows PowerShell

```powershell
cd "D:\path\to\SET-CDP"
venv\Scripts\Activate.ps1
python app.py
```

### Linux or macOS

```bash
cd /path/to/SET-CDP
source venv/bin/activate
python app.py
```

---

# 🌐 Running on a Local Network

To use Mini-EDR from another authorized device, the Flask server must be reachable from that device.

1. Connect both devices to the same local network.
2. Find the server computer's local IP address.
3. Configure Flask to listen on the network interface if required by your current `app.py` setup.
4. Allow the selected Flask port through the local firewall only for the trusted network.
5. Set the Agent server address to the Flask server IP.

Example Agent endpoint:

```python
SERVER_URL = "http://192.168.1.10:5000/api/agent/heartbeat"
```

Then access the platform from another device using:

```text
http://192.168.1.10:5000
```

Use LAN deployment only in a trusted, authorized lab environment.

---

# 📡 Endpoint Agent Setup

The Endpoint Agent must only be installed or executed on authorized devices.

## Option A: Run from Python Source

Open:

```text
Endpoint_Agent/agent.py
```

Update the server address:

```python
SERVER_URL = "http://SERVER_IP:5000/api/agent/heartbeat"
```

Install Agent dependencies if they are not already included in the main requirements:

```bash
pip install requests psutil
```

Run the Agent:

```bash
python Endpoint_Agent/agent.py
```

The Agent should begin sending heartbeat and system telemetry to the Mini-SOC server.

## Option B: Run the Windows Executable

The compiled Agent may be available at:

```text
Endpoint_Agent/dist/agent.exe
```

or from the Agent Download page inside the platform.

Before running it, ensure that the configured server address points to the correct Flask server IP.

## Verify Agent Connection

1. Start the Flask server.
2. Run the Agent on the authorized endpoint.
3. Log in to SET-CDP as an administrator.
4. Open **Endpoint Devices** or **Mini-EDR Live Monitor**.
5. Confirm that the device appears online and that `last_seen` is updating.

---

# 🧩 Browser Extension Installation

1. Open the **Extension Store** inside SET-CDP.
2. Download the required ZIP file.
3. Extract the ZIP file into a permanent folder.
4. Open Chrome or Edge.
5. Navigate to:

```text
chrome://extensions/
```

or:

```text
edge://extensions/
```

6. Enable **Developer Mode**.
7. Select **Load Unpacked**.
8. Choose the extracted extension folder that contains `manifest.json`.
9. Pin the extension to the browser toolbar if needed.

Do not select the ZIP file directly. The extension must be extracted first.

---

# 🧭 Basic Platform Usage

## Standard User Workflow

1. Register or log in.
2. Open **Security Tools**.
3. Select a defensive scanner.
4. Enter the authorized URL, domain, text, password sample, or file.
5. Review the risk score, indicators, and recommendations.
6. Open the Threat Library for additional learning.
7. Complete the Security Awareness Quiz.
8. View personal results and certificate from the profile page.
9. Download approved browser extensions from the Extension Store.

## Administrator Workflow

1. Log in with an administrator account.
2. Open the **Administration** menu.
3. Manage quiz questions and review quiz results.
4. Publish or update threat-library content.
5. Open Reports Center to review platform activity.
6. Open Endpoint Devices and Mini-EDR to monitor authorized endpoints.
7. Review scans, simulations, alerts, users, and training statistics.

## Authorized Simulation Workflow

1. Define the approved training scope.
2. Use only test accounts and non-sensitive demonstration data.
3. Select an approved training template or create a controlled clone.
4. Run the scenario only with informed participants or in an approved awareness campaign.
5. Record training results.
6. Redirect participants to awareness and protection guidance.
7. Delete unnecessary temporary training data after completion.

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

# 🧰 Troubleshooting

## `ModuleNotFoundError`

Install the project dependencies again:

```bash
pip install -r requirements.txt
```

Make sure the correct virtual environment is active.

## Port 5000 Is Already in Use

Close the old Flask process or configure the project to use another available port.

On Windows, you can inspect the port with:

```powershell
netstat -ano | findstr :5000
```

## The Agent Cannot Connect

Check the following:

- Flask is running.
- `SERVER_URL` contains the correct IP address and port.
- The server and Agent devices can communicate over the network.
- The firewall allows the selected port on the trusted network.
- The Agent API key matches the server configuration.
- The heartbeat endpoint is correct.

## Browser Extension Does Not Load

Check that:

- The ZIP file was extracted.
- The selected folder contains `manifest.json`.
- Developer Mode is enabled.
- Required browser permissions are valid.
- The extension does not contain unsupported Manifest V2 settings.

## Download Says “File Wasn’t Available on Site”

Verify that:

- The ZIP file exists inside `static/extensions/`.
- The filename in `extensions.html` exactly matches the real filename.
- Flask is serving the `static` directory.
- The download URL uses the correct path.

Example:

```html
<a href="/static/extensions/webshield.zip" download>Download</a>
```

## Database Errors

- Stop Flask before manually opening or modifying `database.db`.
- Keep a backup before database changes.
- Do not delete the runtime database unless you intend to reset stored application data.

## Theme or CSS Changes Do Not Appear

Restart Flask if templates were changed, then perform a hard refresh:

```text
Ctrl + F5
```

## Git Line-Ending Warning

The following warning on Windows is generally informational:

```text
LF will be replaced by CRLF
```

It does not normally prevent commits or pushes.

---

# 🎯 Project Objectives

SET-CDP aims to:

- Improve cybersecurity awareness.
- Support practical cybersecurity education.
- Demonstrate defensive scanning concepts.
- Explain authorized penetration-testing concepts.
- Teach Red Team and Blue Team workflows.
- Provide endpoint-monitoring experience.
- Introduce SOC and EDR concepts.
- Protect users through browser extensions.
- Improve phishing and social-engineering detection.
- Provide measurable awareness assessments.
- Encourage ethical cybersecurity practices.
- Support academic cybersecurity research.

---

# 🔒 Ethical Notice & Privacy Principles

SET-CDP is an academic cybersecurity graduation project developed for:

- Education.
- Research.
- Security awareness.
- Defensive security assessment.
- Controlled threat simulation.
- Authorized penetration testing.
- Approved endpoint monitoring.

All scans, simulations, training templates, cloned pages, Agents, and monitoring modules must only be used in systems and environments where clear authorization has been obtained.

The platform must not be used for:

- Unauthorized access.
- Account theft.
- Credential theft.
- Session theft.
- Privacy violations.
- Monitoring devices without permission.
- Targeting real users without consent.
- Damaging systems or data.
- Bypassing laws or organizational policies.

Browser extensions should operate locally whenever possible, and sensitive user data should not be transmitted to unnecessary external services.

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

- AI-Assisted Threat Analysis.
- Behavior-based endpoint detection.
- Advanced anomaly detection.
- SIEM integration.
- Telegram and email alerts.
- Advanced incident timelines.
- Endpoint-isolation research.
- Enhanced security reports.
- PDF and Excel export.
- Student leaderboards.
- Gamified cybersecurity learning.
- Advanced certificate verification.
- Awareness campaign management.
- Multi-language support.
- Expanded browser extension store.
- Cloud deployment.
- Multi-tenant organizational support.
- Integration with threat-intelligence platforms.

---

# 📜 License

**Academic Graduation Project**

Developed for educational, research, cybersecurity-awareness, defensive-assessment, and authorized security-testing purposes.

© 2026 SET-CDP — Security Education, Testing & Cyber Defense Platform
